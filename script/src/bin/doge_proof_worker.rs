use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use psy_bridge_sp1_script::proof_protocol::{
    decode_hex_32, DaemonErrorCode, DaemonErrorResponse, DaemonIdentityResponse,
    DaemonProofResponse, ProofJob, ProofJobState, ProofResultOutcome, QueueKeys,
    DAEMON_PROTOCOL_VERSION, GROTH16_PROOF_BYTES, PROOF_NAMESPACE_PREFIX, PROOF_SCHEMA_VERSION,
    PUBLIC_VALUES_BYTES,
};
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    time::{self, Instant},
};

const DEFAULT_LEASE_MS: u64 = 120_000;
const DEFAULT_HEARTBEAT_MS: u64 = 30_000;
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
const DEFAULT_SETUP_TIMEOUT_SECS: u64 = 600;
const DEFAULT_EXECUTE_TIMEOUT_SECS: u64 = 900;
const DEFAULT_PROVE_TIMEOUT_SECS: u64 = 7_200;
const DAEMON_TIMEOUT_EXIT_CODE: i32 = 75;
const REQUEUE_BATCH: usize = 64;
const IDLE_POLL_MS: u64 = 1_000;
const PHASE_GRACE_SECS: u64 = 30;
const MAX_PROTOCOL_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const DAEMON_WRITE_TIMEOUT_SECS: u64 = 30;
const DAEMON_EXIT_WAIT_SECS: u64 = 5;
const REDIS_RETRY_MS: u64 = 250;
const REDIS_OPERATION_TIMEOUT_SECS: u64 = 2;
const REDIS_CONNECT_MAX_BACKOFF_SECS: u64 = 30;
const LEASE_EXPIRED_MAX_ATTEMPTS_ERROR: &str =
    "proof lease expired after reaching maximum attempts";

const CLAIM_SCRIPT: &str = r#"
local queue_key = KEYS[1]
local leases_key = KEYS[2]
local state_prefix = ARGV[1]
local job_prefix = ARGV[2]
local attempt_prefix = ARGV[3]
local worker_id = ARGV[4]
local lease_id = ARGV[5]
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local lease_expires_ms = now_ms + tonumber(ARGV[6])
while true do
  local job_id = redis.call('LPOP', queue_key)
  if not job_id then return nil end
  local state_key = state_prefix .. job_id
  local job_json = redis.call('GET', job_prefix .. job_id)
  local state_json = redis.call('GET', state_key)
  if job_json and state_json then
    local ok, state = pcall(cjson.decode, state_json)
    if ok and state['status'] == 'Queued' then
      local attempt = redis.call('INCR', attempt_prefix .. job_id)
      local claimed = cjson.encode({status='Claimed', worker_id=worker_id,
        lease_id=lease_id, lease_expires_ms=lease_expires_ms, attempt=attempt})
      redis.call('SET', state_key, claimed)
      redis.call('ZADD', leases_key, lease_expires_ms, job_id)
      return {job_id, job_json, tostring(attempt)}
    end
  end
end
"#;

const HEARTBEAT_SCRIPT: &str = r#"
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local state_json = redis.call('GET', KEYS[1])
if not state_json then return 0 end
local ok, state = pcall(cjson.decode, state_json)
if not ok or state['status'] ~= 'Claimed' or state['worker_id'] ~= ARGV[1]
   or state['lease_id'] ~= ARGV[2]
   or tonumber(state['lease_expires_ms']) <= now_ms then return 0 end
local lease_expires_ms = now_ms + tonumber(ARGV[3])
state['lease_expires_ms'] = lease_expires_ms
redis.call('SET', KEYS[1], cjson.encode(state))
redis.call('ZADD', KEYS[2], lease_expires_ms, ARGV[4])
return 1
"#;

const COMPLETE_SCRIPT: &str = r#"
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local state_json = redis.call('GET', KEYS[1])
if not state_json then return 0 end
local ok, state = pcall(cjson.decode, state_json)
if not ok or state['status'] ~= 'Claimed' or state['worker_id'] ~= ARGV[1]
   or state['lease_id'] ~= ARGV[2]
   or tonumber(state['lease_expires_ms']) <= now_ms then return 0 end
redis.call('SET', KEYS[2], ARGV[3])
redis.call('SET', KEYS[1], cjson.encode({status='Completed',
  completed_ms=now_ms, attempt=state['attempt']}))
redis.call('ZREM', KEYS[3], ARGV[4])
redis.call('LPUSH', KEYS[4], ARGV[4])
return 1
"#;

const FINISH_ERROR_SCRIPT: &str = r#"
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local state_json = redis.call('GET', KEYS[1])
if not state_json then return 0 end
local ok, state = pcall(cjson.decode, state_json)
if not ok or state['status'] ~= 'Claimed' or state['worker_id'] ~= ARGV[1]
   or state['lease_id'] ~= ARGV[2]
   or tonumber(state['lease_expires_ms']) <= now_ms then return 0 end
redis.call('ZREM', KEYS[3], ARGV[6])
if ARGV[3] == '1' and tonumber(state['attempt']) < tonumber(ARGV[4]) then
  redis.call('SET', KEYS[1], cjson.encode({status='Queued'}))
  redis.call('RPUSH', KEYS[4], ARGV[6])
  return 2
end
redis.call('SET', KEYS[2], ARGV[5])
redis.call('SET', KEYS[1], cjson.encode({status='Failed', failed_ms=now_ms,
  attempt=state['attempt'], error=ARGV[7]}))
redis.call('LPUSH', KEYS[5], ARGV[6])
return 1
"#;

const FAIL_INVALID_CLAIM_SCRIPT: &str = r#"
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local state_json = redis.call('GET', KEYS[1])
if not state_json then return 0 end
local ok, state = pcall(cjson.decode, state_json)
if not ok or state['status'] ~= 'Claimed' or state['worker_id'] ~= ARGV[1]
   or state['lease_id'] ~= ARGV[2]
   or tonumber(state['lease_expires_ms']) <= now_ms then return 0 end
redis.call('SET', KEYS[1], cjson.encode({status='Failed', failed_ms=now_ms,
  attempt=state['attempt'], error=ARGV[4]}))
redis.call('ZREM', KEYS[2], ARGV[3])
redis.call('LPUSH', KEYS[3], ARGV[3])
return 1
"#;

const REQUEUE_EXPIRED_SCRIPT: &str = r#"
local redis_time = redis.call('TIME')
local now_ms = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now_ms, 'LIMIT', 0, ARGV[7])
local requeued = 0
local failed = 0
for _, job_id in ipairs(expired) do
  local state_key = ARGV[1] .. job_id
  local state_json = redis.call('GET', state_key)
  if state_json then
    local ok, state = pcall(cjson.decode, state_json)
    if ok and state['status'] == 'Claimed'
       and tonumber(state['lease_expires_ms']) <= now_ms then
      local counter_attempt = tonumber(redis.call('GET', ARGV[4] .. job_id)) or 0
      local state_attempt = tonumber(state['attempt']) or 0
      local attempt = math.max(counter_attempt, state_attempt)
      if attempt >= tonumber(ARGV[5]) then
        local job_json = redis.call('GET', ARGV[2] .. job_id)
        local job_ok, job = pcall(cjson.decode, job_json or '')
        if job_ok then
          local result = {
            schema_version=job['schema_version'], job_id=job['job_id'], network=job['network'],
            height=job['height'], parent_checkpoint_sha256=job['parent_checkpoint_sha256'],
            input_fingerprint=job['input_fingerprint'], guest_id=job['guest_id'],
            block_elf_sha256=job['block_elf_sha256'], vkey_hash=job['vkey_hash'],
            outcome={status='Error', error=ARGV[6]}
          }
          redis.call('SET', ARGV[3] .. job_id, cjson.encode(result))
          redis.call('SET', state_key, cjson.encode({status='Failed', failed_ms=now_ms,
            attempt=attempt, error=ARGV[6]}))
          redis.call('LPUSH', KEYS[3], job_id)
          failed = failed + 1
        end
      else
        redis.call('SET', state_key, cjson.encode({status='Queued'}))
        redis.call('RPUSH', KEYS[2], job_id)
        requeued = requeued + 1
      end
    end
  end
  redis.call('ZREM', KEYS[1], job_id)
end
return {requeued, failed}
"#;

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum Network {
    Regtest,
    Testnet,
}

impl Network {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet => "testnet",
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "doge-proof-worker", about = "Claim and prove SP1 block-transition jobs from Redis")]
struct Args {
    #[arg(long, env = "REDIS_URL")]
    redis_url: String,
    #[arg(long, env = "DOGE_NETWORK", value_enum)]
    network: Network,
    #[arg(long, env = "DOGE_REDIS_SEED")]
    redis_seed: String,
    #[arg(long, env = "DOGE_PROOF_QUEUE_PREFIX", default_value = PROOF_NAMESPACE_PREFIX)]
    queue_prefix: String,
    #[arg(long, env = "PROVER_WORKER_ID")]
    worker_id: String,
    #[arg(long, env = "SP1_GEN_PROOF_PATH", default_value = "gen-proof")]
    gen_proof_path: String,
    #[arg(long, env = "PROVER_LEASE_MS", default_value_t = DEFAULT_LEASE_MS)]
    lease_ms: u64,
    #[arg(long, env = "PROVER_HEARTBEAT_MS", default_value_t = DEFAULT_HEARTBEAT_MS)]
    heartbeat_ms: u64,
    #[arg(long, env = "PROVER_MAX_ATTEMPTS", default_value_t = DEFAULT_MAX_ATTEMPTS)]
    max_attempts: u32,
    #[arg(long, env = "SP1_SETUP_TIMEOUT_SECS", default_value_t = DEFAULT_SETUP_TIMEOUT_SECS)]
    setup_timeout_secs: u64,
    #[arg(long, env = "SP1_EXECUTE_TIMEOUT_SECS", default_value_t = DEFAULT_EXECUTE_TIMEOUT_SECS)]
    execute_timeout_secs: u64,
    #[arg(long, env = "SP1_PROVE_TIMEOUT_SECS", default_value_t = DEFAULT_PROVE_TIMEOUT_SECS)]
    prove_timeout_secs: u64,
    #[arg(long, env = "SP1_CUDA_DEVICE_ID", default_value_t = 0)]
    cuda_device_id: u32,
}

impl Args {
    fn validate(&self) -> Result<()> {
        if self.worker_id.is_empty() || self.redis_seed.is_empty() || self.queue_prefix.is_empty() {
            bail!("worker id, Redis seed, and proof queue prefix must be non-empty");
        }
        if self.lease_ms == 0 || self.heartbeat_ms == 0 || self.heartbeat_ms >= self.lease_ms {
            bail!("heartbeat must be non-zero and strictly shorter than the lease");
        }
        if self.max_attempts == 0 {
            bail!("max attempts must be non-zero");
        }
        if self.setup_timeout_secs == 0
            || self.execute_timeout_secs == 0
            || self.prove_timeout_secs == 0
        {
            bail!("phase deadlines must be non-zero");
        }
        Ok(())
    }
}

fn gen_proof_daemon_args(args: &Args) -> Vec<String> {
    vec![
        "--network".to_owned(),
        args.network.as_str().to_owned(),
        "--daemon".to_owned(),
        "--setup-timeout-secs".to_owned(),
        args.setup_timeout_secs.to_string(),
        "--execute-timeout-secs".to_owned(),
        args.execute_timeout_secs.to_string(),
        "--prove-timeout-secs".to_owned(),
        args.prove_timeout_secs.to_string(),
        "--cuda-device-id".to_owned(),
        args.cuda_device_id.to_string(),
    ]
}

#[derive(Clone)]
struct ProofQueue {
    connection: ConnectionManager,
    keys: QueueKeys,
}

#[derive(Debug)]
struct Claim {
    job: ProofJob,
    lease_id: String,
    attempt: u32,
    retry_deadline: Mutex<Instant>,
}

#[derive(Debug)]
struct InvalidClaim {
    job_id: String,
    lease_id: String,
    retry_deadline: Instant,
    error: String,
}

#[derive(Debug)]
enum ClaimOutcome {
    Empty,
    Valid(Claim),
    Invalid(InvalidClaim),
}

impl ProofQueue {
    async fn connect(redis_url: &str, keys: QueueKeys) -> Result<Self> {
        let client = redis::Client::open(redis_url).context("parse REDIS_URL")?;
        let config = ConnectionManagerConfig::new()
            .set_number_of_retries(3)
            .set_max_delay(REDIS_RETRY_MS)
            .set_response_timeout(Duration::from_secs(REDIS_OPERATION_TIMEOUT_SECS))
            .set_connection_timeout(Duration::from_secs(REDIS_OPERATION_TIMEOUT_SECS));
        let connection = client
            .get_connection_manager_with_config(config)
            .await
            .context("connect to Redis")?;
        Ok(Self { connection, keys })
    }

    async fn requeue_expired(&self, max_attempts: u32) -> Result<(usize, usize)> {
        let mut connection = self.connection.clone();
        redis::Script::new(REQUEUE_EXPIRED_SCRIPT)
            .key(&self.keys.leases)
            .key(&self.keys.queue)
            .key(&self.keys.notify)
            .arg(&self.keys.state_prefix)
            .arg(&self.keys.job_prefix)
            .arg(&self.keys.result_prefix)
            .arg(&self.keys.attempt_prefix)
            .arg(max_attempts)
            .arg(LEASE_EXPIRED_MAX_ATTEMPTS_ERROR)
            .arg(REQUEUE_BATCH)
            .invoke_async(&mut connection)
            .await
            .context("resolve expired proof leases")
    }

    async fn claim(&self, worker_id: &str, lease_ms: u64) -> Result<ClaimOutcome> {
        let lease_id = new_lease_id(worker_id)?;
        let claim_started = Instant::now();
        let mut connection = self.connection.clone();
        let claimed: Option<(String, String, String)> = redis::Script::new(CLAIM_SCRIPT)
            .key(&self.keys.queue)
            .key(&self.keys.leases)
            .arg(&self.keys.state_prefix)
            .arg(&self.keys.job_prefix)
            .arg(&self.keys.attempt_prefix)
            .arg(worker_id)
            .arg(&lease_id)
            .arg(lease_ms)
            .invoke_async(&mut connection)
            .await
            .context("claim proof job")?;
        let Some((job_id, job_json, attempt)) = claimed else {
            return Ok(ClaimOutcome::Empty);
        };
        let attempt = attempt.parse().context("decode claimed attempt")?;
        let retry_deadline = claim_started + Duration::from_millis(lease_ms);
        match serde_json::from_str::<ProofJob>(&job_json) {
            Ok(job) if job.job_id == job_id => Ok(ClaimOutcome::Valid(Claim {
                job,
                lease_id,
                attempt,
                retry_deadline: Mutex::new(retry_deadline),
            })),
            Ok(job) => Ok(ClaimOutcome::Invalid(InvalidClaim {
                error: format!(
                    "queue job id {job_id} disagrees with ProofJob job_id {}",
                    job.job_id
                ),
                job_id,
                lease_id,
                retry_deadline,
            })),
            Err(error) => Ok(ClaimOutcome::Invalid(InvalidClaim {
                error: format!("decode claimed ProofJob: {error}"),
                job_id,
                lease_id,
                retry_deadline,
            })),
        }
    }

    async fn heartbeat(&self, claim: &Claim, worker_id: &str, lease_ms: u64) -> Result<bool> {
        let heartbeat_started = Instant::now();
        let mut connection = self.connection.clone();
        let accepted: i32 = redis::Script::new(HEARTBEAT_SCRIPT)
            .key(self.keys.state(&claim.job.job_id))
            .key(&self.keys.leases)
            .arg(worker_id)
            .arg(&claim.lease_id)
            .arg(lease_ms)
            .arg(&claim.job.job_id)
            .invoke_async(&mut connection)
            .await
            .context("heartbeat proof lease")?;
        if accepted == 1 {
            let deadline = heartbeat_started + Duration::from_millis(lease_ms);
            *claim.retry_deadline.lock().await = deadline;
        }
        Ok(accepted == 1)
    }

    async fn complete(&self, claim: &Claim, worker_id: &str, result_json: &str) -> Result<bool> {
        let mut connection = self.connection.clone();
        let accepted: i32 = redis::Script::new(COMPLETE_SCRIPT)
            .key(self.keys.state(&claim.job.job_id))
            .key(self.keys.result(&claim.job.job_id))
            .key(&self.keys.leases)
            .key(&self.keys.notify)
            .arg(worker_id)
            .arg(&claim.lease_id)
            .arg(result_json)
            .arg(&claim.job.job_id)
            .invoke_async(&mut connection)
            .await
            .context("publish proof result")?;
        Ok(accepted == 1)
    }

    async fn finish_error(
        &self,
        claim: &Claim,
        worker_id: &str,
        failure: &WorkerFailure,
        max_attempts: u32,
    ) -> Result<FinishDisposition> {
        let result = claim
            .job
            .result_with(ProofResultOutcome::Error { error: failure.message.clone() });
        let result_json = serde_json::to_string(&result)?;
        let mut connection = self.connection.clone();
        let disposition: i32 = redis::Script::new(FINISH_ERROR_SCRIPT)
            .key(self.keys.state(&claim.job.job_id))
            .key(self.keys.result(&claim.job.job_id))
            .key(&self.keys.leases)
            .key(&self.keys.queue)
            .key(&self.keys.notify)
            .arg(worker_id)
            .arg(&claim.lease_id)
            .arg(if failure.retryable { 1 } else { 0 })
            .arg(max_attempts)
            .arg(result_json)
            .arg(&claim.job.job_id)
            .arg(&failure.message)
            .invoke_async(&mut connection)
            .await
            .context("fail or requeue proof job")?;
        Ok(match disposition {
            2 => FinishDisposition::Requeued,
            1 => FinishDisposition::Failed,
            _ => FinishDisposition::Stale,
        })
    }

    async fn fail_invalid_claim(
        &self,
        claim: &InvalidClaim,
        worker_id: &str,
    ) -> Result<bool> {
        let mut connection = self.connection.clone();
        let accepted: i32 = redis::Script::new(FAIL_INVALID_CLAIM_SCRIPT)
            .key(self.keys.state(&claim.job_id))
            .key(&self.keys.leases)
            .key(&self.keys.notify)
            .arg(worker_id)
            .arg(&claim.lease_id)
            .arg(&claim.job_id)
            .arg(&claim.error)
            .invoke_async(&mut connection)
            .await
            .context("fail malformed claimed proof job")?;
        Ok(accepted == 1)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum FinishDisposition {
    Requeued,
    Failed,
    Stale,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct WorkerFailure {
    message: String,
    retryable: bool,
    restart_daemon: bool,
}

impl WorkerFailure {
    fn permanent(message: impl Into<String>) -> Self {
        Self { message: message.into(), retryable: false, restart_daemon: false }
    }

    fn transient(message: impl Into<String>) -> Self {
        Self { message: message.into(), retryable: true, restart_daemon: true }
    }

    fn timeout(phase: &str) -> Self {
        Self::transient(format!("gen-proof {phase} timed out"))
    }

    fn daemon_error(error: DaemonErrorResponse) -> Self {
        match error.code {
            DaemonErrorCode::ExecuteTimeout | DaemonErrorCode::ProveTimeout => {
                Self::transient(error.error)
            }
            DaemonErrorCode::InvalidRequest
            | DaemonErrorCode::InvalidInput
            | DaemonErrorCode::ProofFailure => Self::permanent(error.error),
        }
    }
}

#[derive(Debug, Default)]
struct BoundedStderr {
    bytes: VecDeque<u8>,
    start_offset: u64,
    end_offset: u64,
}

impl BoundedStderr {
    fn append(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
        self.end_offset = self.end_offset.saturating_add(bytes.len() as u64);
        let excess = self.bytes.len().saturating_sub(MAX_STDERR_BYTES);
        if excess > 0 {
            self.bytes.drain(..excess);
            self.start_offset = self.start_offset.saturating_add(excess as u64);
        }
    }

    fn offset(&self) -> u64 {
        self.end_offset
    }

    fn since(&self, offset: u64) -> Vec<u8> {
        let retained_offset = offset.max(self.start_offset).min(self.end_offset);
        self.bytes
            .iter()
            .skip((retained_offset - self.start_offset) as usize)
            .copied()
            .collect()
    }
}

struct GenProofDaemon {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: Arc<Mutex<BoundedStderr>>,
    identity: DaemonIdentityResponse,
}

fn decode_daemon_identity(identity_line: &str, network: Network) -> Result<DaemonIdentityResponse> {
    let identity: DaemonIdentityResponse =
        serde_json::from_str(identity_line).context("decode gen-proof identity")?;
    if identity.protocol_version != DAEMON_PROTOCOL_VERSION {
        bail!(
            "gen-proof daemon protocol version mismatch: expected {DAEMON_PROTOCOL_VERSION}, got {}",
            identity.protocol_version
        );
    }
    if identity.kind != "identity" || identity.network != network.as_str() {
        bail!("unexpected gen-proof daemon identity: {identity_line}");
    }
    validate_digest("daemon ELF SHA", &identity.block_elf_sha256)?;
    validate_digest("daemon vkey hash", &identity.vkey_hash)?;
    Ok(identity)
}

struct ShutdownReport {
    preexisting_status: Option<std::process::ExitStatus>,
    detail: String,
}

async fn bounded_shutdown(child: &mut Child) -> ShutdownReport {
    let inspect_error = match child.try_wait() {
        Ok(Some(status)) => {
            return ShutdownReport {
                preexisting_status: Some(status),
                detail: format!("gen-proof already exited with {status}"),
            };
        }
        Ok(None) => None,
        Err(error) => Some(error),
    };

    let kill_error = child.start_kill().err();
    let wait_result = time::timeout(
        Duration::from_secs(DAEMON_EXIT_WAIT_SECS),
        child.wait(),
    )
    .await;
    let mut details = Vec::with_capacity(3);
    if let Some(error) = inspect_error {
        details.push(format!("failed to inspect gen-proof before shutdown: {error}"));
    }
    if let Some(error) = kill_error {
        details.push(format!("failed to kill gen-proof: {error}"));
    }
    match wait_result {
        Ok(Ok(status)) => details.push(format!("gen-proof terminated with {status}")),
        Ok(Err(error)) => details.push(format!("failed waiting for gen-proof: {error}")),
        Err(_) => details.push(format!(
            "gen-proof did not exit within {DAEMON_EXIT_WAIT_SECS}s after kill"
        )),
    }
    ShutdownReport { preexisting_status: None, detail: details.join("; ") }
}

impl GenProofDaemon {
    async fn start(args: &Args) -> Result<Self> {
        let mut command = Command::new(&args.gen_proof_path);
        command
            .args(gen_proof_daemon_args(args))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().context("start gen-proof --daemon")?;
        let startup_result: Result<_> = async {
            let stdin = child.stdin.take().context("capture gen-proof stdin")?;
            let stdout = child.stdout.take().context("capture gen-proof stdout")?;
            let mut stderr_reader = child.stderr.take().context("capture gen-proof stderr")?;
            let stderr = Arc::new(Mutex::new(BoundedStderr::default()));
            let stderr_sink = Arc::clone(&stderr);
            tokio::spawn(async move {
                let mut chunk = [0_u8; 8_192];
                loop {
                    match stderr_reader.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => stderr_sink.lock().await.append(&chunk[..read]),
                    }
                }
            });
            let mut stdout = BufReader::new(stdout);
            let identity_line = time::timeout(
                Duration::from_secs(args.setup_timeout_secs.saturating_add(PHASE_GRACE_SECS)),
                read_protocol_line(&mut stdout),
            )
            .await
            .map_err(|_| anyhow!("gen-proof setup/identity timed out"))??;
            let identity = decode_daemon_identity(&identity_line, args.network)?;
            Ok((stdin, stdout, stderr, identity))
        }
        .await;

        match startup_result {
            Ok((stdin, stdout, stderr, identity)) => {
                Ok(Self { child, stdin, stdout, stderr, identity })
            }
            Err(error) => {
                let shutdown = bounded_shutdown(&mut child).await;
                let context = format!(
                    "gen-proof startup failed: {error}; shutdown result: {}",
                    shutdown.detail
                );
                Err(error.context(context))
            }
        }
    }

    async fn stderr_offset(&self) -> u64 {
        self.stderr.lock().await.offset()
    }

    async fn stderr_since(&self, offset: u64) -> Vec<u8> {
        self.stderr.lock().await.since(offset)
    }

    async fn send_request(
        &mut self,
        job: &ProofJob,
        queue: &ProofQueue,
        claim: &Claim,
        args: &Args,
    ) -> Result<(), WorkerFailure> {
        let mut request = serde_json::to_vec(&job.request)
            .map_err(|error| WorkerFailure::permanent(format!("serialize gen-proof request: {error}")))?;
        if request.len() > MAX_PROTOCOL_LINE_BYTES {
            return Err(WorkerFailure::permanent(format!(
                "serialized gen-proof request exceeds {MAX_PROTOCOL_LINE_BYTES} bytes"
            )));
        }
        request.push(b'\n');

        let write_deadline = Instant::now() + Duration::from_secs(DAEMON_WRITE_TIMEOUT_SECS);
        let mut heartbeat = time::interval(Duration::from_millis(args.heartbeat_ms));
        heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        let child = &mut self.child;
        let stdin = &mut self.stdin;
        let write = async {
            stdin.write_all(&request).await.context("write gen-proof request")?;
            stdin.flush().await.context("flush gen-proof request")
        };
        tokio::pin!(write);
        loop {
            tokio::select! {
                result = &mut write => {
                    return result.map_err(|error| WorkerFailure::transient(error.to_string()));
                }
                status = child.wait() => {
                    return Err(child_status_failure(status));
                }
                _ = heartbeat.tick() => {
                    heartbeat_until_resolved(queue, claim, args).await?;
                }
                _ = time::sleep_until(write_deadline) => {
                    return Err(WorkerFailure::timeout("request write"));
                }
            }
        }
    }

    async fn stop(mut self) {
        let _ = bounded_shutdown(&mut self.child).await;
    }

    async fn protocol_failure(&mut self, protocol_error: anyhow::Error) -> WorkerFailure {
        let shutdown = bounded_shutdown(&mut self.child).await;
        match shutdown.preexisting_status {
            Some(status) => child_status_failure(Ok(status)),
            None => WorkerFailure::transient(format!(
                "gen-proof protocol failure: {protocol_error}; {}",
                shutdown.detail
            )),
        }
    }
}

fn child_status_failure(status: std::io::Result<std::process::ExitStatus>) -> WorkerFailure {
    match status {
        Ok(status) if status.code() == Some(DAEMON_TIMEOUT_EXIT_CODE) => {
            WorkerFailure::transient("gen-proof exited with timeout status 75")
        }
        Ok(status) => WorkerFailure::transient(format!("gen-proof exited unexpectedly: {status}")),
        Err(error) => WorkerFailure::transient(format!("failed waiting for gen-proof: {error}")),
    }
}

async fn read_protocol_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<String> {
    read_protocol_line_with_limit(reader, MAX_PROTOCOL_LINE_BYTES).await
}

async fn read_protocol_line_with_limit<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<String> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await.context("read gen-proof protocol")?;
        if buffer.is_empty() {
            bail!("gen-proof protocol reached EOF");
        }
        let take = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |position| position + 1);
        if line.len().saturating_add(take) > max_bytes {
            bail!("gen-proof protocol line exceeds {max_bytes} bytes");
        }
        line.extend_from_slice(&buffer[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            return String::from_utf8(line).context("gen-proof protocol is not UTF-8");
        }
    }
}

fn validate_job(job: &ProofJob, network: Network) -> Result<(), WorkerFailure> {
    let invalid = |message: String| Err(WorkerFailure::permanent(message));
    if job.schema_version != PROOF_SCHEMA_VERSION {
        return invalid(format!("unsupported proof schema version {}", job.schema_version));
    }
    if job.network != network.as_str() {
        return invalid(format!("job network {} does not match worker network {}", job.network, network.as_str()));
    }
    for (name, value) in [
        ("parent checkpoint SHA", &job.parent_checkpoint_sha256),
        ("input fingerprint", &job.input_fingerprint),
        ("ELF SHA", &job.block_elf_sha256),
        ("vkey hash", &job.vkey_hash),
    ] {
        if let Err(error) = validate_digest(name, value) {
            return invalid(error.to_string());
        }
    }
    let computed_fingerprint = job
        .request
        .computed_input_fingerprint()
        .map_err(|error| WorkerFailure::permanent(format!("canonicalize proof request: {error}")))?;
    if computed_fingerprint != job.input_fingerprint {
        return invalid(format!(
            "input_fingerprint mismatch: expected {computed_fingerprint}, got {}",
            job.input_fingerprint
        ));
    }
    let computed = job
        .computed_job_id()
        .map_err(|error| WorkerFailure::permanent(format!("canonicalize job identity: {error}")))?;
    if computed != job.job_id {
        return invalid(format!("job_id mismatch: expected {computed}, got {}", job.job_id));
    }
    if job.request.request_id.is_empty() {
        return invalid("daemon request_id must be non-empty".to_owned());
    }
    Ok(())
}

fn validate_digest(name: &str, value: &str) -> Result<()> {
    decode_hex_32(value).map(|_| ()).map_err(|error| anyhow!("{name} {error}"))
}

fn validate_daemon_identity(job: &ProofJob, identity: &DaemonIdentityResponse) -> Result<(), WorkerFailure> {
    if identity.kind != "identity"
        || identity.protocol_version != DAEMON_PROTOCOL_VERSION
        || identity.network != job.network
        || identity.guest_id != job.guest_id
        || identity.block_elf_sha256 != job.block_elf_sha256
        || identity.vkey_hash != job.vkey_hash
    {
        return Err(WorkerFailure::permanent(format!(
            "job identity does not match gen-proof daemon identity for {}",
            job.job_id
        )));
    }
    Ok(())
}

fn validate_proof_response(job: &ProofJob, response: &DaemonProofResponse) -> Result<(), WorkerFailure> {
    if response.kind != "proof" || !response.ok {
        return Err(WorkerFailure::permanent("invalid successful proof response discriminator"));
    }
    if response.request_id != job.request.request_id
        || response.network != job.network
        || response.guest_id != job.guest_id
        || response.block_elf_sha256 != job.block_elf_sha256
        || response.vkey_hash != job.vkey_hash
    {
        return Err(WorkerFailure::permanent("proof response identity/request_id mismatch"));
    }
    let proof_bytes = hex::decode(&response.proof_bytes)
        .map_err(|error| WorkerFailure::permanent(format!("invalid proof hex: {error}")))?;
    let public_values = hex::decode(&response.public_values)
        .map_err(|error| WorkerFailure::permanent(format!("invalid public values hex: {error}")))?;
    if response.proof_size != GROTH16_PROOF_BYTES
        || response.public_values_size != PUBLIC_VALUES_BYTES
        || proof_bytes.len() != GROTH16_PROOF_BYTES
        || public_values.len() != PUBLIC_VALUES_BYTES
    {
        return Err(WorkerFailure::permanent(format!(
            "proof response sizes must be {GROTH16_PROOF_BYTES} proof bytes and {PUBLIC_VALUES_BYTES} public-value bytes"
        )));
    }
    Ok(())
}

async fn heartbeat_until_resolved(
    queue: &ProofQueue,
    claim: &Claim,
    args: &Args,
) -> Result<(), WorkerFailure> {
    loop {
        match queue.heartbeat(claim, &args.worker_id, args.lease_ms).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                return Err(WorkerFailure::transient(
                    "proof lease was fenced by another worker",
                ));
            }
            Err(error) => {
                if Instant::now() >= *claim.retry_deadline.lock().await {
                    return Err(WorkerFailure::transient(format!(
                        "proof heartbeat failed until local lease deadline: {error}"
                    )));
                }
                time::sleep(Duration::from_millis(REDIS_RETRY_MS)).await;
            }
        }
    }
}

async fn complete_until_resolved(
    queue: &ProofQueue,
    claim: &Claim,
    worker_id: &str,
    result_json: &str,
) -> bool {
    loop {
        match queue.complete(claim, worker_id, result_json).await {
            Ok(accepted) => return accepted,
            Err(error) => {
                if Instant::now() >= *claim.retry_deadline.lock().await {
                    eprintln!("publish proof result exceeded lease deadline: {error:#}");
                    return false;
                }
                time::sleep(Duration::from_millis(REDIS_RETRY_MS)).await;
            }
        }
    }
}

async fn finish_error_until_resolved(
    queue: &ProofQueue,
    claim: &Claim,
    worker_id: &str,
    failure: &WorkerFailure,
    max_attempts: u32,
) -> FinishDisposition {
    loop {
        match queue.finish_error(claim, worker_id, failure, max_attempts).await {
            Ok(disposition) => return disposition,
            Err(error) => {
                if Instant::now() >= *claim.retry_deadline.lock().await {
                    eprintln!("finish proof failure exceeded lease deadline: {error:#}");
                    return FinishDisposition::Stale;
                }
                time::sleep(Duration::from_millis(REDIS_RETRY_MS)).await;
            }
        }
    }
}

async fn fail_invalid_until_resolved(
    queue: &ProofQueue,
    claim: &InvalidClaim,
    worker_id: &str,
) -> bool {
    loop {
        match queue.fail_invalid_claim(claim, worker_id).await {
            Ok(accepted) => return accepted,
            Err(error) => {
                if Instant::now() >= claim.retry_deadline {
                    eprintln!("fail malformed claim exceeded lease deadline: {error:#}");
                    return false;
                }
                time::sleep(Duration::from_millis(REDIS_RETRY_MS)).await;
            }
        }
    }
}

async fn prove_claim(
    queue: &ProofQueue,
    daemon: &mut GenProofDaemon,
    claim: &Claim,
    args: &Args,
) -> Result<(DaemonProofResponse, Vec<u8>), WorkerFailure> {
    validate_job(&claim.job, args.network)?;
    validate_daemon_identity(&claim.job, &daemon.identity)?;
    let stderr_offset = daemon.stderr_offset().await;
    daemon
        .send_request(&claim.job, queue, claim, args)
        .await?;

    let response_deadline = Instant::now()
        + Duration::from_secs(
            args.execute_timeout_secs
                .saturating_add(args.prove_timeout_secs)
                .saturating_add(PHASE_GRACE_SECS),
        );
    let mut heartbeat = time::interval(Duration::from_millis(args.heartbeat_ms));
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let response_line = loop {
        tokio::select! {
            line = read_protocol_line(&mut daemon.stdout) => {
                match line {
                    Ok(line) => break line,
                    Err(error) => return Err(daemon.protocol_failure(error).await),
                }
            }
            _ = heartbeat.tick() => {
                heartbeat_until_resolved(queue, claim, args).await?;
            }
            _ = time::sleep_until(response_deadline) => {
                return Err(WorkerFailure::timeout("response"));
            }
        }
    };
    let value: Value = serde_json::from_str(&response_line)
        .map_err(|error| WorkerFailure::permanent(format!("invalid gen-proof response JSON: {error}")))?;
    let ok = value.get("ok").and_then(Value::as_bool).ok_or_else(|| {
        WorkerFailure::permanent("gen-proof response is missing boolean ok")
    })?;
    if !ok {
        let error: DaemonErrorResponse = serde_json::from_value(value).map_err(|error| {
            WorkerFailure::permanent(format!("invalid gen-proof error response: {error}"))
        })?;
        if error.kind != "proof" || error.request_id.as_deref() != Some(&claim.job.request.request_id) {
            return Err(WorkerFailure::permanent("gen-proof error response request_id mismatch"));
        }
        return Err(WorkerFailure::daemon_error(error));
    }
    let response: DaemonProofResponse = serde_json::from_value(value)
        .map_err(|error| WorkerFailure::permanent(format!("invalid gen-proof proof response: {error}")))?;
    validate_proof_response(&claim.job, &response)?;
    Ok((response, daemon.stderr_since(stderr_offset).await))
}

async fn run(args: Args) -> Result<()> {
    args.validate()?;
    let keys = QueueKeys::new(&args.queue_prefix, args.network.as_str(), &args.redis_seed);
    let mut redis_backoff = Duration::from_millis(REDIS_RETRY_MS);
    let queue = loop {
        match ProofQueue::connect(&args.redis_url, keys.clone()).await {
            Ok(queue) => break queue,
            Err(error) => {
                eprintln!("failed to connect to Redis: {error:#}; retrying in {redis_backoff:?}");
                time::sleep(redis_backoff).await;
                redis_backoff = (redis_backoff * 2).min(Duration::from_secs(REDIS_CONNECT_MAX_BACKOFF_SECS));
            }
        }
    };
    let mut daemon: Option<GenProofDaemon> = None;

    loop {
        if daemon.is_none() {
            match GenProofDaemon::start(&args).await {
                Ok(started) => daemon = Some(started),
                Err(error) => {
                    eprintln!("failed to start gen-proof daemon: {error:#}");
                    time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
        if let Err(error) = queue.requeue_expired(args.max_attempts).await {
            eprintln!("failed to requeue expired leases: {error:#}");
            time::sleep(Duration::from_millis(IDLE_POLL_MS)).await;
            continue;
        }
        let claim = match queue.claim(&args.worker_id, args.lease_ms).await {
            Ok(ClaimOutcome::Empty) => {
                time::sleep(Duration::from_millis(IDLE_POLL_MS)).await;
                continue;
            }
            Ok(ClaimOutcome::Invalid(claim)) => {
                eprintln!("malformed claimed proof job {}: {}", claim.job_id, claim.error);
                if !fail_invalid_until_resolved(&queue, &claim, &args.worker_id).await {
                    eprintln!("discarded stale malformed claim for {}", claim.job_id);
                }
                continue;
            }
            Ok(ClaimOutcome::Valid(claim)) => claim,
            Err(error) => {
                eprintln!("failed to claim proof job: {error:#}");
                time::sleep(Duration::from_millis(IDLE_POLL_MS)).await;
                continue;
            }
        };
        eprintln!("claimed proof job {} attempt {}", claim.job.job_id, claim.attempt);
        let proof_result = prove_claim(&queue, daemon.as_mut().expect("daemon exists"), &claim, &args).await;
        match proof_result {
            Ok((response, stderr)) => {
                let result = claim.job.result_with(ProofResultOutcome::Success {
                    response,
                    stderr: hex::encode(stderr),
                });
                let result_json = serde_json::to_string(&result)?;
                if complete_until_resolved(&queue, &claim, &args.worker_id, &result_json).await {
                    eprintln!("completed proof job {}", claim.job.job_id);
                } else {
                    eprintln!("discarded stale proof result for {}", claim.job.job_id);
                }
            }
            Err(failure) => {
                eprintln!("proof job {} failed: {}", claim.job.job_id, failure.message);
                let restart = failure.restart_daemon;
                let disposition = finish_error_until_resolved(
                    &queue,
                    &claim,
                    &args.worker_id,
                    &failure,
                    args.max_attempts,
                )
                .await;
                eprintln!("proof job {} disposition: {disposition:?}", claim.job.job_id);
                if restart {
                    if let Some(old) = daemon.take() {
                        old.stop().await;
                    }
                }
            }
        }
    }
}

fn new_lease_id(worker_id: &str) -> Result<String> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random).context("generate proof lease id entropy")?;
    let mut hasher = Sha256::new();
    hasher.update(worker_id.as_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(random);
    hasher.update(sequence.to_be_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[tokio::main]
async fn main() -> Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_bridge_sp1_script::proof_protocol::{DaemonRequest, ProofResult};

    fn fixture_job() -> ProofJob {
        let mut job = ProofJob {
            schema_version: PROOF_SCHEMA_VERSION,
            job_id: String::new(),
            network: "regtest".to_owned(),
            height: 42,
            parent_checkpoint_sha256: "11".repeat(32),
            input_fingerprint: String::new(),
            guest_id: "block-transition".to_owned(),
            block_elf_sha256: "33".repeat(32),
            vkey_hash: "44".repeat(32),
            request: DaemonRequest {
                request_id: "request-42".to_owned(),
                old_state: "00".to_owned(),
                witness: "01".to_owned(),
                finalized_witness: String::new(),
                custody_script_config: "02".repeat(32),
                required_confirmations: 6,
                flat_fee: 7,
                fee_num: 8,
                fee_den: 9,
                old_header: "0a".repeat(320),
                new_header: "0b".repeat(320),
                config_params: "0c".repeat(48),
            },
        };
        job.input_fingerprint = job.request.computed_input_fingerprint().unwrap();
        job.job_id = job.computed_job_id().unwrap();
        job
    }

    #[test]
    fn namespace_and_keys_match_v2_contract() {
        let keys = QueueKeys::new(PROOF_NAMESPACE_PREFIX, "regtest", "alpha");
        assert_eq!(keys.namespace, "PDOGE-SP1-PROOF-V2-regtest-alpha");
        assert_eq!(keys.queue, "PDOGE-SP1-PROOF-V2-regtest-alpha:queue");
        assert_eq!(keys.job("abc"), "PDOGE-SP1-PROOF-V2-regtest-alpha:job:abc");
        assert_eq!(keys.state("abc"), "PDOGE-SP1-PROOF-V2-regtest-alpha:state:abc");
        assert_eq!(keys.result("abc"), "PDOGE-SP1-PROOF-V2-regtest-alpha:result:abc");
        assert_eq!(keys.attempt("abc"), "PDOGE-SP1-PROOF-V2-regtest-alpha:attempt:abc");
        let custom = QueueKeys::new("custom", "testnet", "seed");
        assert_eq!(custom.notify, "custom-testnet-seed:notify");
        assert_eq!(custom.leases, "custom-testnet-seed:leases");
    }

    #[test]
    fn lease_cas_rejects_stale_worker_and_lease() {
        let state = ProofJobState::Claimed {
            worker_id: "worker-a".to_owned(),
            lease_id: "lease-new".to_owned(),
            lease_expires_ms: 123,
            attempt: 2,
        };
        assert!(state.matches_lease("worker-a", "lease-new"));
        assert!(!state.matches_lease("worker-a", "lease-old"));
        assert!(!state.matches_lease("worker-b", "lease-new"));
    }

    #[test]
    fn protocol_fixture_round_trips_with_stable_tags() {
        let job = fixture_job();
        validate_job(&job, Network::Regtest).unwrap();
        let job_json = serde_json::to_string(&job).unwrap();
        let decoded: ProofJob = serde_json::from_str(&job_json).unwrap();
        assert_eq!(decoded, job);

        let result = job.result_with(ProofResultOutcome::Error { error: "bad input".to_owned() });
        let result_json = serde_json::to_string(&result).unwrap();
        let decoded_result: ProofResult = serde_json::from_str(&result_json).unwrap();
        assert_eq!(decoded_result, result);
        assert_eq!(serde_json::to_value(ProofJobState::Queued).unwrap(), serde_json::json!({"status":"Queued"}));
    }

    #[test]
    fn daemon_identity_protocol_version_is_required_and_strict() {
        let mut value = serde_json::json!({
            "kind": "identity",
            "protocol_version": DAEMON_PROTOCOL_VERSION,
            "network": "regtest",
            "guest_id": "block-transition",
            "block_elf_sha256": "11".repeat(32),
            "vkey_hash": "22".repeat(32),
        });

        let current = decode_daemon_identity(&value.to_string(), Network::Regtest).unwrap();
        assert_eq!(current.protocol_version, DAEMON_PROTOCOL_VERSION);

        value["protocol_version"] = serde_json::json!(DAEMON_PROTOCOL_VERSION + 1);
        let wrong_version = decode_daemon_identity(&value.to_string(), Network::Regtest).unwrap_err();
        assert!(wrong_version.to_string().contains(
            &format!(
                "protocol version mismatch: expected {DAEMON_PROTOCOL_VERSION}, got {}",
                DAEMON_PROTOCOL_VERSION + 1
            )
        ));

        value.as_object_mut().unwrap().remove("protocol_version");
        let missing_version = decode_daemon_identity(&value.to_string(), Network::Regtest).unwrap_err();
        assert!(missing_version.to_string().contains("decode gen-proof identity"));
        assert!(format!("{missing_version:#}").contains("missing field `protocol_version`"));
    }

    #[test]
    fn matches_ibc_canonical_proof_job_fixture() {
        let request = DaemonRequest {
            request_id: "block-42".to_owned(),
            old_state: "00".to_owned(),
            witness: "11".to_owned(),
            finalized_witness: String::new(),
            custody_script_config: "22".repeat(32),
            required_confirmations: 6,
            flat_fee: 1,
            fee_num: 2,
            fee_den: 3,
            old_header: "33".repeat(320),
            new_header: "44".repeat(320),
            config_params: "55".repeat(48),
        };
        let input_fingerprint = request.computed_input_fingerprint().unwrap();
        assert_eq!(
            input_fingerprint,
            "d4c614aabb9a4514d37497c7f85ca12bb8787433a8325ecbe1a534a13e727b7e"
        );
        let job = ProofJob {
            schema_version: PROOF_SCHEMA_VERSION,
            job_id: String::new(),
            network: "testnet".to_owned(),
            height: 42,
            parent_checkpoint_sha256: "66".repeat(32),
            input_fingerprint,
            guest_id: "block-transition-testnet".to_owned(),
            block_elf_sha256: "77".repeat(32),
            vkey_hash: "88".repeat(32),
            request,
        };
        assert_eq!(
            job.computed_job_id().unwrap(),
            "4ad41f1f9a93976bba08fe7a0b419e9526ac0ed4ce894e37f82abeac6dd83f94"
        );
    }

    #[test]
    fn timeout_and_exit_75_are_retryable_but_identity_errors_are_permanent() {
        let timeout = WorkerFailure::timeout("response");
        assert!(timeout.retryable);
        assert!(timeout.restart_daemon);
        let daemon_timeout = WorkerFailure::daemon_error(DaemonErrorResponse {
            kind: "proof".to_owned(),
            request_id: Some("request-42".to_owned()),
            ok: false,
            code: DaemonErrorCode::ProveTimeout,
            error: "prove timed out after 12s".to_owned(),
        });
        assert!(daemon_timeout.retryable);
        let identity = WorkerFailure::permanent("identity mismatch");
        assert!(!identity.retryable);
        assert!(!identity.restart_daemon);
        assert_eq!(DAEMON_TIMEOUT_EXIT_CODE, 75);
    }

    #[test]
    fn proof_response_checks_request_identity_and_decoded_sizes() {
        let job = fixture_job();
        let response = DaemonProofResponse {
            kind: "proof".to_owned(),
            request_id: job.request.request_id.clone(),
            ok: true,
            network: job.network.clone(),
            guest_id: job.guest_id.clone(),
            block_elf_sha256: job.block_elf_sha256.clone(),
            vkey_hash: job.vkey_hash.clone(),
            proof_size: GROTH16_PROOF_BYTES,
            proof_bytes: "aa".repeat(GROTH16_PROOF_BYTES),
            public_values_size: PUBLIC_VALUES_BYTES,
            public_values: "bb".repeat(PUBLIC_VALUES_BYTES),
        };
        validate_proof_response(&job, &response).unwrap();
        let mut stale = response.clone();
        stale.request_id = "other".to_owned();
        assert!(validate_proof_response(&job, &stale).is_err());
        let mut wrong_size = response;
        wrong_size.proof_size = 3;
        assert!(validate_proof_response(&job, &wrong_size).is_err());
    }

    #[test]
    fn rejects_request_fingerprint_mismatch() {
        let mut job = fixture_job();
        job.request.flat_fee += 1;
        let error = validate_job(&job, Network::Regtest).unwrap_err();
        assert!(error.message.contains("input_fingerprint mismatch"));
    }

    #[test]
    fn stderr_ring_keeps_only_new_bounded_tail() {
        let mut stderr = BoundedStderr::default();
        stderr.append(&vec![1; MAX_STDERR_BYTES - 2]);
        let job_offset = stderr.offset();
        stderr.append(&[2, 3, 4, 5]);
        assert_eq!(stderr.bytes.len(), MAX_STDERR_BYTES);
        assert_eq!(stderr.since(job_offset), [2, 3, 4, 5]);
        assert_eq!(stderr.since(0).len(), MAX_STDERR_BYTES);
    }

    #[tokio::test]
    async fn protocol_reader_rejects_over_limit_without_consuming_overflow() {
        let mut input = BufReader::new(std::io::Cursor::new(vec![b'x'; MAX_PROTOCOL_LINE_BYTES + 1]));
        let error = read_protocol_line(&mut input).await.unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        assert_eq!(input.buffer().len(), 1);
    }

    #[tokio::test]
    async fn bounded_shutdown_terminates_and_reaps_live_child() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 60"])
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let started = Instant::now();
        let shutdown = bounded_shutdown(&mut child).await;

        assert!(started.elapsed() <= Duration::from_secs(DAEMON_EXIT_WAIT_SECS + 1));
        assert!(shutdown.preexisting_status.is_none());
        assert!(shutdown.detail.contains("gen-proof terminated with"));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn bounded_shutdown_handles_already_exited_child() {
        let mut child = Command::new("sh")
            .args(["-c", "exit 7"])
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let status = time::timeout(Duration::from_secs(1), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.code(), Some(7));

        let shutdown = bounded_shutdown(&mut child).await;

        assert_eq!(shutdown.preexisting_status.and_then(|status| status.code()), Some(7));
        assert!(shutdown.detail.contains("already exited"));
    }

    fn build_args(overrides: &[&str]) -> Args {
        // Start from a valid base, then apply (flag, value) pairs. A flag already
        // present in the base is overridden in place (clap rejects duplicate Set
        // args); a flag absent from the base is appended.
        let mut argv: Vec<String> = [
            "doge-proof-worker",
            "--redis-url",
            "redis://127.0.0.1:6379",
            "--network",
            "regtest",
            "--redis-seed",
            "alpha",
            "--worker-id",
            "worker-a",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut index = 0;
        while index + 1 < overrides.len() {
            let flag = overrides[index];
            let value = overrides[index + 1];
            if let Some(position) = argv.iter().position(|arg| arg == flag) {
                argv[position + 1] = value.to_string();
            } else {
                argv.push(flag.to_string());
                argv.push(value.to_string());
            }
            index += 2;
        }
        Args::try_parse_from(argv).expect("base CLI parses")
    }

    #[test]
    fn args_validate_rejects_invalid_combinations() {
        let cases: &[(&str, &[&str], &str)] = &[
            ("empty worker id", &["--worker-id", ""], "must be non-empty"),
            ("empty redis seed", &["--redis-seed", ""], "must be non-empty"),
            ("empty queue prefix", &["--queue-prefix", ""], "must be non-empty"),
            ("zero lease", &["--lease-ms", "0"], "heartbeat must be non-zero"),
            ("zero heartbeat", &["--heartbeat-ms", "0"], "heartbeat must be non-zero"),
            (
                "heartbeat equals lease",
                &["--heartbeat-ms", "5000", "--lease-ms", "5000"],
                "strictly shorter than the lease",
            ),
            (
                "heartbeat exceeds lease",
                &["--heartbeat-ms", "6000", "--lease-ms", "5000"],
                "strictly shorter than the lease",
            ),
            ("zero max attempts", &["--max-attempts", "0"], "max attempts must be non-zero"),
            (
                "zero setup deadline",
                &["--setup-timeout-secs", "0"],
                "phase deadlines must be non-zero",
            ),
            (
                "zero execute deadline",
                &["--execute-timeout-secs", "0"],
                "phase deadlines must be non-zero",
            ),
            (
                "zero prove deadline",
                &["--prove-timeout-secs", "0"],
                "phase deadlines must be non-zero",
            ),
        ];
        for (name, extra, expected_fragment) in cases {
            let args = build_args(extra);
            let error = args.validate().unwrap_err();
            assert!(
                error.to_string().contains(expected_fragment),
                "{name}: expected `{expected_fragment}` in `{}`",
                error
            );
        }
    }

    #[test]
    fn args_validate_accepts_strict_heartbeat_below_lease() {
        let args = build_args(&["--heartbeat-ms", "1000", "--lease-ms", "5000"]);
        args.validate().expect("strict shorter heartbeat is valid");
    }

    #[test]
    fn gen_proof_launch_arguments_include_valid_cuda_flag() {
        let args = build_args(&[
            "--setup-timeout-secs",
            "11",
            "--execute-timeout-secs",
            "22",
            "--prove-timeout-secs",
            "33",
            "--cuda-device-id",
            "7",
        ]);
        assert_eq!(
            gen_proof_daemon_args(&args),
            [
                "--network",
                "regtest",
                "--daemon",
                "--setup-timeout-secs",
                "11",
                "--execute-timeout-secs",
                "22",
                "--prove-timeout-secs",
                "33",
                "--cuda-device-id",
                "7",
            ]
        );
    }

    #[test]
    fn cli_surface_excludes_solana_sender_credential_and_mint_flags() {
        // The worker must never expose a credential / signer / mint / checkpoint
        // authority surface: it has no Solana signing privileges and must not be
        // able to mint or advance checkpoints. Each of these flags MUST be rejected
        // as unknown by the public CLI parser.
        let forbidden_flags: &[&str] = &[
            "--solana-key",
            "--solana-keypair",
            "--solana-pubkey",
            "--sender",
            "--sender-key",
            "--signer",
            "--keypair",
            "--secret-key",
            "--private-key",
            "--mint",
            "--mint-authority",
            "--checkpoint",
            "--checkpoint-authority",
            "--bridge-authority",
            "--custody-key",
            "--admin-key",
        ];
        for flag in forbidden_flags {
            let mut argv: Vec<&str> = [
                "doge-proof-worker",
                "--redis-url",
                "redis://127.0.0.1:6379",
                "--network",
                "regtest",
                "--redis-seed",
                "alpha",
                "--worker-id",
                "worker-a",
            ]
            .into_iter()
            .collect();
            argv.extend_from_slice(&[*flag, "value"]);
            let error = Args::try_parse_from(argv).unwrap_err();
            assert!(
                matches!(error.kind(), clap::error::ErrorKind::UnknownArgument),
                "worker CLI unexpectedly accepted forbidden credential flag `{flag}`"
            );
        }
    }

    #[test]
    fn queue_keys_custom_prefix_lays_out_full_namespace() {
        let keys = QueueKeys::new("custom-pfx", "testnet", "seed-7");
        assert_eq!(keys.namespace, "custom-pfx-testnet-seed-7");
        assert_eq!(keys.queue, "custom-pfx-testnet-seed-7:queue");
        assert_eq!(keys.notify, "custom-pfx-testnet-seed-7:notify");
        assert_eq!(keys.leases, "custom-pfx-testnet-seed-7:leases");
        assert_eq!(
            keys.attempt("job-1"),
            "custom-pfx-testnet-seed-7:attempt:job-1"
        );
        assert_eq!(keys.job("job-1"), "custom-pfx-testnet-seed-7:job:job-1");
        assert_eq!(keys.state("job-1"), "custom-pfx-testnet-seed-7:state:job-1");
        assert_eq!(
            keys.result("job-1"),
            "custom-pfx-testnet-seed-7:result:job-1"
        );
    }

    #[test]
    fn decode_hex_32_accepts_only_lowercase_64_hex() {
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let expected: [u8; 32] = hex::decode(valid).unwrap().try_into().unwrap();
        assert_eq!(decode_hex_32(valid).unwrap(), expected);
        let cases: &[(&str, &str, &str)] = &[
            ("too short", "ab", "exactly 64 hexadecimal characters"),
            ("too long", &"a".repeat(65), "exactly 64 hexadecimal characters"),
            (
                "uppercase rejected",
                &"A".repeat(64),
                "must use lowercase hexadecimal",
            ),
        ];
        for (name, input, expected_fragment) in cases {
            let error = decode_hex_32(input).unwrap_err();
            assert!(
                error.contains(expected_fragment),
                "{name}: expected `{expected_fragment}` in `{error}`"
            );
        }
    }

    #[test]
    fn proof_job_state_matches_lease_only_for_matching_claimed() {
        let claimed = ProofJobState::Claimed {
            worker_id: "worker-a".to_owned(),
            lease_id: "lease-1".to_owned(),
            lease_expires_ms: 100,
            attempt: 1,
        };
        assert!(claimed.matches_lease("worker-a", "lease-1"));
        assert!(!claimed.matches_lease("worker-a", "lease-2"));
        assert!(!claimed.matches_lease("worker-b", "lease-1"));
        // Non-Claimed variants never match a lease, even with the right ids.
        assert!(!ProofJobState::Queued.matches_lease("worker-a", "lease-1"));
        assert!(!ProofJobState::Completed {
            completed_ms: 1,
            attempt: 1,
        }
        .matches_lease("worker-a", "lease-1"));
        assert!(!ProofJobState::Failed {
            failed_ms: 1,
            attempt: 1,
            error: "boom".to_owned(),
        }
        .matches_lease("worker-a", "lease-1"));
    }

    #[test]
    fn proof_job_state_round_trips_with_stable_tags() {
        let variants: &[ProofJobState] = &[
            ProofJobState::Queued,
            ProofJobState::Claimed {
                worker_id: "w".to_owned(),
                lease_id: "l".to_owned(),
                lease_expires_ms: 9,
                attempt: 3,
            },
            ProofJobState::Completed {
                completed_ms: 5,
                attempt: 2,
            },
            ProofJobState::Failed {
                failed_ms: 7,
                attempt: 4,
                error: "bad".to_owned(),
            },
        ];
        for variant in variants {
            let value = serde_json::to_value(variant).unwrap();
            let round_trip: ProofJobState = serde_json::from_value(value).unwrap();
            assert_eq!(&round_trip, variant);
        }
        // Claimed tag must carry every CAS field so fencing can compare it.
        let claimed_value = serde_json::to_value(ProofJobState::Claimed {
            worker_id: "w".to_owned(),
            lease_id: "l".to_owned(),
            lease_expires_ms: 9,
            attempt: 3,
        })
        .unwrap();
        assert_eq!(claimed_value["status"], "Claimed");
        assert_eq!(claimed_value["worker_id"], "w");
        assert_eq!(claimed_value["lease_id"], "l");
        assert_eq!(claimed_value["lease_expires_ms"], 9);
        assert_eq!(claimed_value["attempt"], 3);
    }

    #[test]
    fn bounded_stderr_keeps_exactly_max_then_advances_on_overflow() {
        let mut stderr = BoundedStderr::default();
        stderr.append(&vec![7; MAX_STDERR_BYTES]);
        assert_eq!(stderr.bytes.len(), MAX_STDERR_BYTES);
        assert_eq!(stderr.offset(), MAX_STDERR_BYTES as u64);
        assert_eq!(stderr.since(0).len(), MAX_STDERR_BYTES);

        // One byte of overflow drops exactly one byte from the front.
        let before = stderr.offset();
        stderr.append(&[8]);
        assert_eq!(stderr.bytes.len(), MAX_STDERR_BYTES);
        assert_eq!(stderr.offset(), before + 1);
        assert_eq!(stderr.since(before), vec![8]);
        // The ring retained MAX bytes: the front 7 is evicted but the tail now
        // holds the newly appended 8. since(0) clamps to the retained window and
        // returns MAX bytes ending in 8.
        assert_eq!(stderr.since(0).len(), MAX_STDERR_BYTES);
        assert_eq!(stderr.since(0)[0], 7);
        assert_eq!(stderr.since(0).last().copied(), Some(8));
    }

    #[test]
    fn bounded_stderr_since_clamps_to_retained_window() {
        let mut stderr = BoundedStderr::default();
        // Empty ring: any offset yields nothing.
        assert!(stderr.since(0).is_empty());
        assert!(stderr.since(1_000).is_empty());

        stderr.append(&vec![1; MAX_STDERR_BYTES]);
        stderr.append(&vec![2; MAX_STDERR_BYTES]);
        // After 2*MAX appended with MAX retained, the front half is gone.
        assert_eq!(stderr.offset(), 2 * MAX_STDERR_BYTES as u64);
        assert_eq!(stderr.since(0).len(), MAX_STDERR_BYTES);
        assert!(stderr.since(0).iter().all(|byte| *byte == 2));
        // Offset beyond end clamps to empty.
        assert!(stderr.since(3 * MAX_STDERR_BYTES as u64).is_empty());
        // Offset inside the retained window returns the suffix from there.
        let mid = MAX_STDERR_BYTES as u64 + 10;
        assert_eq!(stderr.since(mid).len(), MAX_STDERR_BYTES - 10);
    }

    #[tokio::test]
    async fn protocol_line_accepts_exactly_max_bytes_ending_in_newline() {
        // A line whose total length (including the trailing newline) equals the
        // 16 MiB cap must be accepted; the limit is inclusive of MAX.
        let mut payload = vec![b'x'; MAX_PROTOCOL_LINE_BYTES - 1];
        payload.push(b'\n');
        let mut input = BufReader::new(std::io::Cursor::new(payload));
        let line = read_protocol_line(&mut input).await.expect("max-size line is accepted");
        assert_eq!(line.len(), MAX_PROTOCOL_LINE_BYTES);
        assert_eq!(line.as_bytes().last().copied(), Some(b'\n'));
    }

    #[tokio::test]
    async fn protocol_line_bails_on_eof_without_newline() {
        let mut input = BufReader::new(std::io::Cursor::new(b"no newline here".to_vec()));
        let error = read_protocol_line(&mut input).await.unwrap_err();
        assert!(error.to_string().contains("EOF"));
    }

    #[tokio::test]
    async fn protocol_line_rejects_non_utf8_payload() {
        let mut payload = vec![b'\xff'; 4];
        payload.push(b'\n');
        let mut input = BufReader::new(std::io::Cursor::new(payload));
        let error = read_protocol_line(&mut input).await.unwrap_err();
        assert!(error.to_string().contains("UTF-8"));
    }

    #[test]
    fn child_status_failure_classifies_exit_75_as_retryable() {
        // A daemon that exits 75 signals a CUDA timeout; the worker must treat it
        use std::os::unix::process::ExitStatusExt as _;
        let exit_75 = child_status_failure(Ok(std::process::ExitStatus::from_raw(75)));
        assert!(exit_75.retryable);
        assert!(exit_75.restart_daemon);
        assert!(exit_75.message.contains("75"));

        let other_exit = child_status_failure(Ok(std::process::ExitStatus::from_raw(1)));
        assert!(other_exit.retryable);
        assert!(other_exit.restart_daemon);

        let io_error = child_status_failure(Err(std::io::Error::other("wait failed")));
        assert!(io_error.retryable);
        assert!(io_error.message.contains("failed waiting"));
    }

    #[test]
    fn daemon_error_classification_uses_code_not_message() {
        let timeout = WorkerFailure::daemon_error(DaemonErrorResponse {
            kind: "proof".to_owned(),
            request_id: Some("r".to_owned()),
            ok: false,
            code: DaemonErrorCode::ProveTimeout,
            error: "message without timeout words".to_owned(),
        });
        assert!(timeout.retryable);
        assert!(timeout.restart_daemon);

        let logic = WorkerFailure::daemon_error(DaemonErrorResponse {
            kind: "proof".to_owned(),
            request_id: Some("r".to_owned()),
            ok: false,
            code: DaemonErrorCode::ProofFailure,
            error: "prove timed out after 7200s".to_owned(),
        });
        assert!(!logic.retryable);
        assert!(!logic.restart_daemon);
    }

    #[test]
    fn validate_job_rejects_each_field_violation() {
        let base = fixture_job();
        let cases: &[(fn(&mut ProofJob), &str)] = &[
            (
                |job| job.schema_version = 0,
                "unsupported proof schema version",
            ),
            (|job| job.network = "testnet".to_owned(), "does not match worker network"),
            (
                |job: &mut ProofJob| {
                    // Clearing request_id changes the request hash, so recompute the
                    // fingerprint and job_id to keep them consistent and reach the
                    // dedicated request_id-non-empty check downstream.
                    job.request.request_id.clear();
                    job.input_fingerprint = job.request.computed_input_fingerprint().unwrap();
                    job.job_id = job.computed_job_id().unwrap();
                },
                "request_id must be non-empty",
            ),
            (
                |job| job.parent_checkpoint_sha256 = "zz".repeat(32),
                "parent checkpoint SHA",
            ),
            (|job| job.block_elf_sha256 = "AA".repeat(32), "ELF SHA"),
        ];
        for (mutate, expected_fragment) in cases {
            let mut job = base.clone();
            mutate(&mut job);
            let error = validate_job(&job, Network::Regtest).unwrap_err();
            assert!(
                error.message.contains(expected_fragment),
                "expected `{expected_fragment}` in `{}`",
                error.message
            );
        }
        // job_id mismatch is defended separately because it requires recomputation.
        let mut job = base.clone();
        job.job_id = "00".repeat(32);
        let error = validate_job(&job, Network::Regtest).unwrap_err();
        assert!(error.message.contains("job_id mismatch"));
    }

    #[test]
    fn validate_daemon_identity_rejects_each_field_mismatch() {
        let job = fixture_job();
        let base = DaemonIdentityResponse {
            kind: "identity".to_owned(),
            protocol_version: DAEMON_PROTOCOL_VERSION,
            network: job.network.clone(),
            guest_id: job.guest_id.clone(),
            block_elf_sha256: job.block_elf_sha256.clone(),
            vkey_hash: job.vkey_hash.clone(),
        };
        assert!(validate_daemon_identity(&job, &base).is_ok());

        let mismatches: &[(fn(&mut DaemonIdentityResponse) -> (), &str)] = &[
            (|id| id.kind = "proof".to_owned(), "identity does not match"),
            (|id| id.protocol_version += 1, "identity does not match"),
            (|id| id.network = "testnet".to_owned(), "identity does not match"),
            (|id| id.guest_id = "other-guest".to_owned(), "identity does not match"),
            (
                |id| id.block_elf_sha256 = "ff".repeat(32),
                "identity does not match",
            ),
            (|id| id.vkey_hash = "ee".repeat(32), "identity does not match"),
        ];
        for (mutate, _) in mismatches {
            let mut id = base.clone();
            mutate(&mut id);
            assert!(validate_daemon_identity(&job, &id).is_err());
        }
    }

    #[test]
    fn validate_proof_response_rejects_decoded_length_and_hex_errors() {
        let job = fixture_job();
        let base = DaemonProofResponse {
            kind: "proof".to_owned(),
            request_id: job.request.request_id.clone(),
            ok: true,
            network: job.network.clone(),
            guest_id: job.guest_id.clone(),
            block_elf_sha256: job.block_elf_sha256.clone(),
            vkey_hash: job.vkey_hash.clone(),
            proof_size: GROTH16_PROOF_BYTES,
            proof_bytes: "aa".repeat(GROTH16_PROOF_BYTES),
            public_values_size: PUBLIC_VALUES_BYTES,
            public_values: "bb".repeat(PUBLIC_VALUES_BYTES),
        };
        assert!(validate_proof_response(&job, &base).is_ok());

        // Declared size correct but decoded hex shorter than 356 -> reject.
        let mut bad_decoded_proof = base.clone();
        bad_decoded_proof.proof_bytes = "aa".repeat(GROTH16_PROOF_BYTES - 1);
        bad_decoded_proof.proof_size = GROTH16_PROOF_BYTES;
        let err = validate_proof_response(&job, &bad_decoded_proof).unwrap_err();
        assert!(err.message.contains("sizes must be"));

        // Public values hex is invalid -> reject before size check.
        let mut bad_hex = base.clone();
        bad_hex.public_values = "zz".repeat(PUBLIC_VALUES_BYTES);
        let err = validate_proof_response(&job, &bad_hex).unwrap_err();
        assert!(err.message.contains("invalid public values hex"));

        // ok=false and kind!=proof are not successful proof responses.
        let mut not_ok = base.clone();
        not_ok.ok = false;
        assert!(validate_proof_response(&job, &not_ok).is_err());

        let mut wrong_kind = base.clone();
        wrong_kind.kind = "error".to_owned();
        assert!(validate_proof_response(&job, &wrong_kind).is_err());
    }


    #[tokio::test]
    async fn proof_queue_connect_surfaces_url_parse_error_without_network() {
        // A malformed REDIS URL must fail at parse time, before any connection is
        // attempted, so the caller's reconnect loop can back off without ever
        // touching the network. `redis://[` is a syntactically invalid URL.
        let keys = QueueKeys::new(PROOF_NAMESPACE_PREFIX, "regtest", "alpha");
        let error = ProofQueue::connect("redis://[", keys).await.err().expect("malformed URL must error before any connection");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("REDIS_URL"),
            "expected REDIS_URL parse context in `{rendered}`"
        );
    }

    fn fixture_job_with_request_id(request_id: &str) -> ProofJob {
        let mut job = fixture_job();
        job.request.request_id = request_id.to_owned();
        job.input_fingerprint = job.request.computed_input_fingerprint().unwrap();
        job.job_id = job.computed_job_id().unwrap();
        job
    }

    fn daemon_proof_response_for(job: &ProofJob) -> DaemonProofResponse {
        DaemonProofResponse {
            kind: "proof".to_owned(),
            request_id: job.request.request_id.clone(),
            ok: true,
            network: job.network.clone(),
            guest_id: job.guest_id.clone(),
            block_elf_sha256: job.block_elf_sha256.clone(),
            vkey_hash: job.vkey_hash.clone(),
            proof_size: GROTH16_PROOF_BYTES,
            proof_bytes: "aa".repeat(GROTH16_PROOF_BYTES),
            public_values_size: PUBLIC_VALUES_BYTES,
            public_values: "bb".repeat(PUBLIC_VALUES_BYTES),
        }
    }

    // --- Isolated-Redis behavior test helpers ---------------------------------
    //
    // These run ONLY when `--ignored` is passed and TEST_REDIS_URL points at an
    // isolated, throwaway Redis (never the live 6379 E2E instance). The default
    // full-suite run never touches Redis: the test early-returns when the env var
    // is unset, and every key lives under a per-run random prefix that is cleaned
    // up at the end.

    fn test_redis_url() -> Option<String> {
        std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    fn random_test_prefix() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        format!("qa-rb-{}-{nanos:x}-{sequence:x}", std::process::id())
    }

    macro_rules! require {
        ($cond:expr $(, $($arg:tt)+)?) => {{
            if !$cond {
                return Err(anyhow!($($($arg)+)?));
            }
        }};
    }

    async fn reset_shared_keys(queue: &ProofQueue) {
        let mut conn = queue.connection.clone();
        let _: () = redis::cmd("DEL")
            .arg(&queue.keys.queue)
            .arg(&queue.keys.notify)
            .arg(&queue.keys.leases)
            .query_async(&mut conn)
            .await
            .expect("reset shared queue/notify/leases");
    }

    async fn seed_job_payload(queue: &ProofQueue, job: &ProofJob) {
        let mut conn = queue.connection.clone();
        let job_json = serde_json::to_string(job).unwrap();
        let _: () = redis::cmd("SET")
            .arg(queue.keys.job(&job.job_id))
            .arg(job_json)
            .query_async(&mut conn)
            .await
            .expect("seed job payload");
    }

    async fn seed_queued_job(queue: &ProofQueue, job: &ProofJob) {
        seed_job_payload(queue, job).await;
        let mut conn = queue.connection.clone();
        let state_json = serde_json::to_string(&ProofJobState::Queued).unwrap();
        let _: () = redis::cmd("SET")
            .arg(queue.keys.state(&job.job_id))
            .arg(state_json)
            .query_async(&mut conn)
            .await
            .expect("seed Queued state");
        let _: () = redis::cmd("RPUSH")
            .arg(&queue.keys.queue)
            .arg(&job.job_id)
            .query_async(&mut conn)
            .await
            .expect("enqueue job id");
    }

    async fn set_state(queue: &ProofQueue, job_id: &str, state: &ProofJobState) {
        let mut conn = queue.connection.clone();
        let state_json = serde_json::to_string(state).unwrap();
        let _: () = redis::cmd("SET")
            .arg(queue.keys.state(job_id))
            .arg(state_json)
            .query_async(&mut conn)
            .await
            .expect("overwrite job state");
    }

    async fn set_attempt_counter(queue: &ProofQueue, job_id: &str, value: i64) {
        let mut conn = queue.connection.clone();
        let _: () = redis::cmd("SET")
            .arg(queue.keys.attempt(job_id))
            .arg(value)
            .query_async(&mut conn)
            .await
            .expect("seed attempt counter");
    }

    async fn zadd_lease(queue: &ProofQueue, job_id: &str, score: i64) {
        let mut conn = queue.connection.clone();
        let _: () = redis::cmd("ZADD")
            .arg(&queue.keys.leases)
            .arg(score)
            .arg(job_id)
            .query_async(&mut conn)
            .await
            .expect("seed lease score");
    }

    async fn read_state(queue: &ProofQueue, job_id: &str) -> ProofJobState {
        let mut conn = queue.connection.clone();
        let state_json: String = redis::cmd("GET")
            .arg(queue.keys.state(job_id))
            .query_async(&mut conn)
            .await
            .expect("read job state");
        serde_json::from_str(&state_json).expect("state decodes")
    }

    async fn read_result(queue: &ProofQueue, job_id: &str) -> Option<String> {
        let mut conn = queue.connection.clone();
        redis::cmd("GET")
            .arg(queue.keys.result(job_id))
            .query_async(&mut conn)
            .await
            .expect("read result")
    }

    async fn lrange(queue: &ProofQueue, key: &str) -> Vec<String> {
        let mut conn = queue.connection.clone();
        redis::cmd("LRANGE")
            .arg(key)
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .expect("read list")
    }

    async fn zscore(queue: &ProofQueue, key: &str, member: &str) -> Option<f64> {
        let mut conn = queue.connection.clone();
        redis::cmd("ZSCORE")
            .arg(key)
            .arg(member)
            .query_async(&mut conn)
            .await
            .expect("read zset score")
    }

    async fn cleanup_namespace(queue: &ProofQueue, namespace: &str) {
        let mut conn = queue.connection.clone();
        let pattern = format!("{namespace}*");
        let mut cursor: u64 = 0;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(500)
                .query_async(&mut conn)
                .await
                .unwrap_or((0, Vec::new()));
            if !keys.is_empty() {
                let _: () = redis::cmd("DEL")
                    .arg(&keys)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(());
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
    }

    const CONTRACT_WORKER: &str = "qa-worker";
    const CONTRACT_LEASE_MS: u64 = 5_000;
    // Strictly larger than CONTRACT_LEASE_MS so a heartbeat issued in the same
    // Redis millisecond as the claim provably extends the lease expiry.
    const CONTRACT_HEARTBEAT_LEASE_MS: u64 = 60_000;
    const CONTRACT_MAX_ATTEMPTS: u32 = 3;
    const CONTRACT_FAR_FUTURE_MS: u64 = 9_999_999_999_999;

    async fn claim_valid(queue: &ProofQueue, job: &ProofJob) -> Result<Claim> {
        seed_queued_job(queue, job).await;
        match queue.claim(CONTRACT_WORKER, CONTRACT_LEASE_MS).await? {
            ClaimOutcome::Valid(claim) => {
                require!(claim.job.job_id == job.job_id, "claim returned wrong job");
                Ok(claim)
            }
            other => Err(anyhow!("expected Valid claim, got {other:?}")),
        }
    }

    /// Real execution of the worker Lua state machine against an isolated Redis.
    /// Verifies claim fencing, lease lifecycle, complete, retry requeue, max-
    /// attempt failure, malformed-claim failure, and expired-lease requeue — all
    /// through the real Lua scripts rather than substring assertions on source.
    ///
    /// Run with:
    ///   TEST_REDIS_URL=redis://127.0.0.1:6390 \
    ///     cargo test -p psy-bridge-sp1-script --bin doge-proof-worker -- \
    ///       --ignored --exact redis_lua_state_machine_contract
    #[tokio::test]
    #[ignore]
    async fn redis_lua_state_machine_contract() {
        let Some(redis_url) = test_redis_url() else {
            eprintln!("skipped: TEST_REDIS_URL not set");
            return;
        };
        let prefix = random_test_prefix();
        let keys = QueueKeys::new(&prefix, "regtest", "isolated");
        let queue = match ProofQueue::connect(&redis_url, keys.clone()).await {
            Ok(queue) => queue,
            Err(error) => panic!("connect to isolated Redis failed: {error:#}"),
        };

        let outcome = run_state_machine_contract(&queue).await;
        cleanup_namespace(&queue, &keys.namespace).await;
        if let Err(error) = outcome {
            panic!("behavior contract failed: {error:#}");
        }
    }

    async fn run_state_machine_contract(queue: &ProofQueue) -> Result<()> {
        // --- Claim atomically moves Queued -> Claimed and INCRs attempt ---
        reset_shared_keys(queue).await;
        let job_a = fixture_job_with_request_id("claim-a");
        let claim_a = claim_valid(queue, &job_a).await?;
        require!(claim_a.attempt == 1, "first claim must record attempt 1");
        match read_state(queue, &job_a.job_id).await {
            ProofJobState::Claimed { worker_id, lease_id, attempt, lease_expires_ms } => {
                require!(worker_id == CONTRACT_WORKER, "claimed state worker_id mismatch");
                require!(lease_id == claim_a.lease_id, "claimed state lease_id mismatch");
                require!(attempt == 1, "claimed state attempt mismatch");
                require!(
                    lease_expires_ms > 0
                        && zscore(queue, &queue.keys.leases, &job_a.job_id).await
                            == Some(lease_expires_ms as f64),
                    "claim must register lease expiry in the leases ZSET"
                );
            }
            other => return Err(anyhow!("expected Claimed after claim, got {other:?}")),
        }
        require!(
            lrange(queue, &queue.keys.queue).await.is_empty(),
            "claim must drain the queue"
        );

        // INCR does not reset: a pre-existing attempt counter of 2 -> claim records 3.
        reset_shared_keys(queue).await;
        let job_a2 = fixture_job_with_request_id("claim-a2");
        set_attempt_counter(queue, &job_a2.job_id, 2).await;
        let claim_a2 = claim_valid(queue, &job_a2).await?;
        require!(
            claim_a2.attempt == 3,
            "claim must INCR the existing attempt counter (2 -> 3), got {}",
            claim_a2.attempt
        );

        // Claim skips non-Queued state entries (drains them, never double-claims).
        reset_shared_keys(queue).await;
        let job_a3 = fixture_job_with_request_id("claim-a3");
        seed_job_payload(queue, &job_a3).await;
        set_state(queue, &job_a3.job_id, &ProofJobState::Claimed {
            worker_id: "someone-else".to_owned(),
            lease_id: "other-lease".to_owned(),
            lease_expires_ms: CONTRACT_FAR_FUTURE_MS,
            attempt: 9,
        }).await;
        let mut conn = queue.connection.clone();
        let _: () = redis::cmd("RPUSH")
            .arg(&queue.keys.queue)
            .arg(&job_a3.job_id)
            .query_async(&mut conn)
            .await
            .expect("enqueue non-queued job");
        match queue.claim(CONTRACT_WORKER, CONTRACT_LEASE_MS).await? {
            ClaimOutcome::Empty => {}
            other => return Err(anyhow!("claim must skip non-Queued entries, got {other:?}")),
        }
        match read_state(queue, &job_a3.job_id).await {
            ProofJobState::Claimed { worker_id, .. } => {
                require!(
                    worker_id == "someone-else",
                    "claim must not mutate a skipped non-Queued state"
                );
            }
            other => return Err(anyhow!("skipped job state must remain Claimed, got {other:?}")),
        }
        require!(
            lrange(queue, &queue.keys.queue).await.is_empty(),
            "claim must drain skipped queue entries"
        );

        // --- Heartbeat rejects foreign worker, foreign lease, and expired lease ---
        reset_shared_keys(queue).await;
        let job_h = fixture_job_with_request_id("heartbeat");
        let claim_h = claim_valid(queue, &job_h).await?;
        let original_expiry = match read_state(queue, &job_h.job_id).await {
            ProofJobState::Claimed { lease_expires_ms, .. } => lease_expires_ms,
            other => return Err(anyhow!("expected Claimed, got {other:?}")),
        };
        require!(
            !queue.heartbeat(&claim_h, "foreign-worker", CONTRACT_LEASE_MS).await?,
            "heartbeat with a foreign worker id must be rejected"
        );
        let spoofed_lease = Claim {
            job: claim_h.job.clone(),
            lease_id: "bogus-lease".to_owned(),
            attempt: claim_h.attempt,
            retry_deadline: Mutex::new(Instant::now() + Duration::from_secs(60)),
        };
        require!(
            !queue.heartbeat(&spoofed_lease, CONTRACT_WORKER, CONTRACT_LEASE_MS).await?,
            "heartbeat with a foreign lease id must be rejected"
        );
        set_state(queue, &job_h.job_id, &ProofJobState::Claimed {
            worker_id: CONTRACT_WORKER.to_owned(),
            lease_id: claim_h.lease_id.clone(),
            lease_expires_ms: 0,
            attempt: claim_h.attempt,
        }).await;
        require!(
            !queue.heartbeat(&claim_h, CONTRACT_WORKER, CONTRACT_LEASE_MS).await?,
            "heartbeat with an expired lease must be rejected"
        );
        match read_state(queue, &job_h.job_id).await {
            ProofJobState::Claimed { lease_expires_ms, .. } => {
                require!(
                    lease_expires_ms == 0,
                    "rejected heartbeat must not extend the lease (was {original_expiry})"
                );
            }
            other => return Err(anyhow!("expired-lease state must remain Claimed, got {other:?}")),
        }

        // --- Live heartbeat extends the lease and re-registers in the ZSET ---
        reset_shared_keys(queue).await;
        let job_h2 = fixture_job_with_request_id("heartbeat-live");
        let claim_h2 = claim_valid(queue, &job_h2).await?;
        let live_expiry = match read_state(queue, &job_h2.job_id).await {
            ProofJobState::Claimed { lease_expires_ms, .. } => lease_expires_ms,
            other => return Err(anyhow!("expected Claimed, got {other:?}")),
        };
        require!(
            queue.heartbeat(&claim_h2, CONTRACT_WORKER, CONTRACT_HEARTBEAT_LEASE_MS).await?,
            "live heartbeat must be accepted"
        );
        match read_state(queue, &job_h2.job_id).await {
            ProofJobState::Claimed { lease_expires_ms, .. } => {
                require!(
                    lease_expires_ms > live_expiry,
                    "live heartbeat must extend the lease expiry"
                );
                require!(
                    zscore(queue, &queue.keys.leases, &job_h2.job_id).await
                        == Some(lease_expires_ms as f64),
                    "live heartbeat must re-register the new expiry in the leases ZSET"
                );
            }
            other => return Err(anyhow!("expected Claimed after heartbeat, got {other:?}")),
        }

        // --- Complete rejects foreign worker, foreign lease, and expired lease ---
        reset_shared_keys(queue).await;
        let job_c = fixture_job_with_request_id("complete");
        let claim_c = claim_valid(queue, &job_c).await?;
        let result_json = serde_json::to_string(&job_c.result_with(ProofResultOutcome::Error {
            error: "terminal".to_owned(),
        })).unwrap();
        require!(
            !queue.complete(&claim_c, "foreign-worker", &result_json).await?,
            "complete with a foreign worker id must be rejected"
        );
        let spoofed_complete = Claim {
            job: claim_c.job.clone(),
            lease_id: "bogus-lease".to_owned(),
            attempt: claim_c.attempt,
            retry_deadline: Mutex::new(Instant::now() + Duration::from_secs(60)),
        };
        require!(
            !queue.complete(&spoofed_complete, CONTRACT_WORKER, &result_json).await?,
            "complete with a foreign lease id must be rejected"
        );
        set_state(queue, &job_c.job_id, &ProofJobState::Claimed {
            worker_id: CONTRACT_WORKER.to_owned(),
            lease_id: claim_c.lease_id.clone(),
            lease_expires_ms: 0,
            attempt: claim_c.attempt,
        }).await;
        require!(
            !queue.complete(&claim_c, CONTRACT_WORKER, &result_json).await?,
            "complete with an expired lease must be rejected"
        );
        require!(
            read_result(queue, &job_c.job_id).await.is_none(),
            "rejected complete must not write the result"
        );
        match read_state(queue, &job_c.job_id).await {
            ProofJobState::Claimed { lease_expires_ms, .. } => {
                require!(
                    lease_expires_ms == 0,
                    "rejected complete must leave the expired lease untouched"
                );
            }
            other => return Err(anyhow!("expired-lease complete must remain Claimed, got {other:?}")),
        }

        // --- Live complete writes result, Completed state, ZREM lease, LPUSH notify ---
        reset_shared_keys(queue).await;
        let job_c2 = fixture_job_with_request_id("complete-live");
        let claim_c2 = claim_valid(queue, &job_c2).await?;
        let success_json = serde_json::to_string(&job_c2.result_with(ProofResultOutcome::Success {
            response: daemon_proof_response_for(&job_c2),
            stderr: "00".to_owned(),
        })).unwrap();
        require!(
            queue.complete(&claim_c2, CONTRACT_WORKER, &success_json).await?,
            "live complete must be accepted"
        );
        let stored = read_result(queue, &job_c2.job_id).await;
        require!(
            stored.as_deref() == Some(success_json.as_str()),
            "complete must persist the result JSON"
        );
        match read_state(queue, &job_c2.job_id).await {
            ProofJobState::Completed { attempt, .. } => {
                require!(attempt == 1, "completed state must preserve the attempt counter");
            }
            other => return Err(anyhow!("expected Completed, got {other:?}")),
        }
        require!(
            zscore(queue, &queue.keys.leases, &job_c2.job_id).await.is_none(),
            "complete must remove the job from the leases ZSET"
        );
        require!(
            lrange(queue, &queue.keys.notify).await.contains(&job_c2.job_id),
            "complete must LPUSH the job id to notify"
        );

        // --- finish_error requeues below max attempts without a terminal result ---
        reset_shared_keys(queue).await;
        let job_f = fixture_job_with_request_id("finish-requeue");
        let claim_f = claim_valid(queue, &job_f).await?;
        let disposition = queue
            .finish_error(&claim_f, CONTRACT_WORKER, &WorkerFailure::transient("retry me"), CONTRACT_MAX_ATTEMPTS)
            .await?;
        require!(
            disposition == FinishDisposition::Requeued,
            "retryable finish below max must requeue, got {disposition:?}"
        );
        match read_state(queue, &job_f.job_id).await {
            ProofJobState::Queued => {}
            other => return Err(anyhow!("expected Queued after requeue, got {other:?}")),
        }
        require!(
            lrange(queue, &queue.keys.queue).await.contains(&job_f.job_id),
            "requeue must RPUSH the job id back into the queue"
        );
        require!(
            read_result(queue, &job_f.job_id).await.is_none(),
            "requeue must not write a terminal result"
        );
        require!(
            zscore(queue, &queue.keys.leases, &job_f.job_id).await.is_none(),
            "requeue must release the lease from the ZSET"
        );

        // --- finish_error fails at max attempts with notify and a terminal result ---
        reset_shared_keys(queue).await;
        let job_f2 = fixture_job_with_request_id("finish-fail");
        let claim_f2 = claim_valid(queue, &job_f2).await?;
        set_state(queue, &job_f2.job_id, &ProofJobState::Claimed {
            worker_id: CONTRACT_WORKER.to_owned(),
            lease_id: claim_f2.lease_id.clone(),
            lease_expires_ms: CONTRACT_FAR_FUTURE_MS,
            attempt: CONTRACT_MAX_ATTEMPTS,
        }).await;
        let disposition = queue
            .finish_error(&claim_f2, CONTRACT_WORKER, &WorkerFailure::transient("exhausted"), CONTRACT_MAX_ATTEMPTS)
            .await?;
        require!(
            disposition == FinishDisposition::Failed,
            "retryable finish at max attempts must fail, got {disposition:?}"
        );
        match read_state(queue, &job_f2.job_id).await {
            ProofJobState::Failed { attempt, error, .. } => {
                require!(attempt == CONTRACT_MAX_ATTEMPTS, "failed state must preserve the attempt counter");
                require!(error == "exhausted", "failed state must record the error message");
            }
            other => return Err(anyhow!("expected Failed, got {other:?}")),
        }
        require!(
            read_result(queue, &job_f2.job_id).await.is_some(),
            "max-attempts failure must write a terminal result"
        );
        require!(
            zscore(queue, &queue.keys.leases, &job_f2.job_id).await.is_none(),
            "failure must release the lease from the ZSET"
        );
        require!(
            lrange(queue, &queue.keys.notify).await.contains(&job_f2.job_id),
            "failure must LPUSH the job id to notify"
        );

        // --- fail_invalid_claim transitions a malformed claim to Failed + notify, no requeue ---
        reset_shared_keys(queue).await;
        let job_i = fixture_job_with_request_id("invalid");
        let claim_i = claim_valid(queue, &job_i).await?;
        let invalid = InvalidClaim {
            job_id: claim_i.job.job_id.clone(),
            lease_id: claim_i.lease_id.clone(),
            retry_deadline: Instant::now(),
            error: "malformed payload".to_owned(),
        };
        require!(
            queue.fail_invalid_claim(&invalid, CONTRACT_WORKER).await?,
            "fail_invalid_claim must accept a live Claimed lease"
        );
        match read_state(queue, &job_i.job_id).await {
            ProofJobState::Failed { error, .. } => {
                require!(error == "malformed payload", "invalid claim must record its error");
            }
            other => return Err(anyhow!("expected Failed after invalid claim, got {other:?}")),
        }
        require!(
            zscore(queue, &queue.keys.leases, &job_i.job_id).await.is_none(),
            "fail_invalid_claim must release the lease from the ZSET"
        );
        require!(
            lrange(queue, &queue.keys.notify).await.contains(&job_i.job_id),
            "fail_invalid_claim must LPUSH the job id to notify"
        );
        require!(
            !lrange(queue, &queue.keys.queue).await.contains(&job_i.job_id),
            "fail_invalid_claim must never requeue a malformed job"
        );

        // --- requeue_expired requeues a Claimed job past its expiry and cleans the ZSET ---
        reset_shared_keys(queue).await;
        let job_r = fixture_job_with_request_id("requeue-expired");
        seed_job_payload(queue, &job_r).await;
        set_state(queue, &job_r.job_id, &ProofJobState::Claimed {
            worker_id: CONTRACT_WORKER.to_owned(),
            lease_id: "expired-lease".to_owned(),
            lease_expires_ms: 0,
            attempt: 2,
        }).await;
        zadd_lease(queue, &job_r.job_id, 0).await;
        let (requeued, failed) = queue.requeue_expired(CONTRACT_MAX_ATTEMPTS).await?;
        require!(
            requeued == 1 && failed == 0,
            "expired lease below max must requeue once without failing, got ({requeued}, {failed})"
        );
        match read_state(queue, &job_r.job_id).await {
            ProofJobState::Queued => {}
            other => return Err(anyhow!("expired Claimed must be reset to Queued, got {other:?}")),
        }
        require!(
            lrange(queue, &queue.keys.queue).await.contains(&job_r.job_id),
            "requeue_expired must RPUSH the job id back into the queue"
        );
        require!(
            zscore(queue, &queue.keys.leases, &job_r.job_id).await.is_none(),
            "requeue_expired must remove the requeued job from the leases ZSET"
        );

        // --- requeue_expired finalizes an expired lease at max attempts ---
        reset_shared_keys(queue).await;
        let job_m = fixture_job_with_request_id("expire-at-max");
        seed_job_payload(queue, &job_m).await;
        set_attempt_counter(queue, &job_m.job_id, CONTRACT_MAX_ATTEMPTS.into()).await;
        set_state(queue, &job_m.job_id, &ProofJobState::Claimed {
            worker_id: CONTRACT_WORKER.to_owned(),
            lease_id: "max-attempt-lease".to_owned(),
            lease_expires_ms: 0,
            attempt: CONTRACT_MAX_ATTEMPTS - 1,
        }).await;
        zadd_lease(queue, &job_m.job_id, 0).await;
        let (requeued, failed) = queue.requeue_expired(CONTRACT_MAX_ATTEMPTS).await?;
        require!(
            requeued == 0 && failed == 1,
            "expired lease at max must fail once without requeueing, got ({requeued}, {failed})"
        );
        match read_state(queue, &job_m.job_id).await {
            ProofJobState::Failed { attempt, error, .. } => {
                require!(attempt == CONTRACT_MAX_ATTEMPTS, "Failed state attempt mismatch");
                require!(
                    error == LEASE_EXPIRED_MAX_ATTEMPTS_ERROR,
                    "Failed state must record the lease-expiry error"
                );
            }
            other => return Err(anyhow!("expired lease at max must become Failed, got {other:?}")),
        }
        let result_json = read_result(queue, &job_m.job_id)
            .await
            .ok_or_else(|| anyhow!("expired lease at max must write a durable result"))?;
        let result: ProofResult = serde_json::from_str(&result_json)?;
        require!(
            result == job_m.result_with(ProofResultOutcome::Error {
                error: LEASE_EXPIRED_MAX_ATTEMPTS_ERROR.to_owned(),
            }),
            "expired lease result must preserve the complete job identity"
        );
        require!(
            !lrange(queue, &queue.keys.queue).await.contains(&job_m.job_id),
            "expired lease at max must not be re-enqueued"
        );
        require!(
            lrange(queue, &queue.keys.notify).await.contains(&job_m.job_id),
            "expired lease at max must notify result waiters"
        );
        require!(
            zscore(queue, &queue.keys.leases, &job_m.job_id).await.is_none(),
            "expired lease at max must be removed from the leases ZSET"
        );

        // --- requeue_expired only ZREMs terminal and unexpired leases (no requeue) ---
        reset_shared_keys(queue).await;
        let job_t = fixture_job_with_request_id("requeue-terminal");
        seed_job_payload(queue, &job_t).await;
        set_state(queue, &job_t.job_id, &ProofJobState::Completed { completed_ms: 1, attempt: 1 }).await;
        let job_u = fixture_job_with_request_id("requeue-unexpired");
        seed_job_payload(queue, &job_u).await;
        set_state(queue, &job_u.job_id, &ProofJobState::Claimed {
            worker_id: CONTRACT_WORKER.to_owned(),
            lease_id: "live-lease".to_owned(),
            lease_expires_ms: CONTRACT_FAR_FUTURE_MS,
            attempt: 1,
        }).await;
        zadd_lease(queue, &job_t.job_id, 0).await;
        zadd_lease(queue, &job_u.job_id, 0).await;
        let (requeued, failed) = queue.requeue_expired(CONTRACT_MAX_ATTEMPTS).await?;
        require!(
            requeued == 0 && failed == 0,
            "terminal or unexpired leases must not transition, got ({requeued}, {failed})"
        );
        match read_state(queue, &job_t.job_id).await {
            ProofJobState::Completed { .. } => {}
            other => return Err(anyhow!("terminal lease must stay Completed, got {other:?}")),
        }
        match read_state(queue, &job_u.job_id).await {
            ProofJobState::Claimed { lease_expires_ms, .. } => {
                require!(
                    lease_expires_ms == CONTRACT_FAR_FUTURE_MS,
                    "unexpired Claimed must be left untouched"
                );
            }
            other => return Err(anyhow!("unexpired lease must stay Claimed, got {other:?}")),
        }
        let queue_after = lrange(queue, &queue.keys.queue).await;
        require!(
            !queue_after.contains(&job_t.job_id) && !queue_after.contains(&job_u.job_id),
            "terminal and unexpired leases must not be re-enqueued"
        );
        require!(
            zscore(queue, &queue.keys.leases, &job_t.job_id).await.is_none()
                && zscore(queue, &queue.keys.leases, &job_u.job_id).await.is_none(),
            "requeue_expired must still ZREM terminal and unexpired leases"
        );

        Ok(())
    }
}

use clap::{Parser, ValueEnum};
use psy_bridge_sp1_lib::{block_transition_public_inputs, sha256, HASH_SIZE};
use psy_bridge_sp1_script::proof_protocol::{DaemonErrorCode, DAEMON_PROTOCOL_VERSION};
use psy_doge_bridge_helper::tx_template::{
    CustodyScriptConfig, LocalRegtestManagerCustody, OfficialTestnetManagerCustody,
};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, CudaProver, HashableKey, ProveRequest, Prover, ProverClient, SP1Stdin,
};
use std::{
    error::Error,
    fmt,
    io::{BufRead, Write},
    path::Path,
    process,
    time::Duration,
};

const BLOCK_TRANSITION_REGTEST_ELF: sp1_sdk::Elf = include_elf!("block-transition");
const BLOCK_TRANSITION_TESTNET_ELF: sp1_sdk::Elf = include_elf!("block-transition-testnet");
const BLOCK_TRANSITION_REGTEST_GUEST_ID: &str = "block-transition";
const BLOCK_TRANSITION_TESTNET_GUEST_ID: &str = "block-transition-testnet";
const HEADER_SIZE: usize = 320;
const CUSTODY_SCRIPT_CONFIG_SIZE: usize = HASH_SIZE;
const CONFIG_PARAMS_SIZE: usize = 48;

/// Default wall-clock budget for `client.setup(ELF)` (daemon boot or one-shot).
const DEFAULT_SETUP_TIMEOUT_SECS: u64 = 600;
/// Default wall-clock budget for the guest `execute` dry-run before proving.
const DEFAULT_EXECUTE_TIMEOUT_SECS: u64 = 900;
/// Default wall-clock budget for Groth16 `prove` on CUDA.
const DEFAULT_PROVE_TIMEOUT_SECS: u64 = 7_200;
/// Process exit status used after a timed-out CUDA phase so supervisors restart cleanly.
const TIMEOUT_EXIT_CODE: i32 = 75;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
enum Network {
    #[default]
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

    fn custodian_hash(
        self,
        custody_script_config: &CustodyScriptConfig,
    ) -> [u8; HASH_SIZE] {
        match self {
            Self::Regtest => custody_script_config.hash::<LocalRegtestManagerCustody>(),
            Self::Testnet => custody_script_config.hash::<OfficialTestnetManagerCustody>(),
        }
    }
}

/// Path-independent guest identity: stable id + embedded ELF bytes for a network.
struct BlockProgram {
    network: Network,
    elf: sp1_sdk::Elf,
    guest_id: &'static str,
}

fn block_program(network: Network) -> BlockProgram {
    match network {
        Network::Regtest => BlockProgram {
            network,
            elf: BLOCK_TRANSITION_REGTEST_ELF.clone(),
            guest_id: BLOCK_TRANSITION_REGTEST_GUEST_ID,
        },
        Network::Testnet => BlockProgram {
            network,
            elf: BLOCK_TRANSITION_TESTNET_ELF.clone(),
            guest_id: BLOCK_TRANSITION_TESTNET_GUEST_ID,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeadlineConfig {
    setup: Duration,
    execute: Duration,
    prove: Duration,
}

impl DeadlineConfig {
    fn from_secs(setup_secs: u64, execute_secs: u64, prove_secs: u64) -> Result<Self, String> {
        if setup_secs == 0 || execute_secs == 0 || prove_secs == 0 {
            return Err(
                "setup/execute/prove timeout seconds must be non-zero hard deadlines".to_owned(),
            );
        }
        Ok(Self {
            setup: Duration::from_secs(setup_secs),
            execute: Duration::from_secs(execute_secs),
            prove: Duration::from_secs(prove_secs),
        })
    }

    fn default_config() -> Self {
        Self::from_secs(
            DEFAULT_SETUP_TIMEOUT_SECS,
            DEFAULT_EXECUTE_TIMEOUT_SECS,
            DEFAULT_PROVE_TIMEOUT_SECS,
        )
        .expect("default deadlines are non-zero")
    }
}

#[derive(Debug, Parser)]
#[command(about = "Generate an SP1 Groth16 block-transition proof")]
struct Args {
    /// Dogecoin consensus profile compiled into the selected block-transition guest.
    #[arg(long, value_enum)]
    network: Network,
    /// CUDA device index used by the SP1 prover.
    #[arg(long, env = "SP1_CUDA_DEVICE_ID", default_value_t = 0)]
    cuda_device_id: u32,
    /// Run a line-delimited JSON request/response daemon on stdin/stdout.
    #[arg(long)]
    daemon: bool,
    /// Derive and print the release block-transition verifying-key hash without proving.
    #[arg(long, conflicts_with = "daemon")]
    vkey_only: bool,

    /// Hard wall-clock seconds for `client.setup` (daemon boot / one-shot / vkey-only).
    #[arg(long, default_value_t = DEFAULT_SETUP_TIMEOUT_SECS)]
    setup_timeout_secs: u64,
    /// Hard wall-clock seconds for guest `execute` before proving.
    #[arg(long, default_value_t = DEFAULT_EXECUTE_TIMEOUT_SECS)]
    execute_timeout_secs: u64,
    /// Hard wall-clock seconds for CUDA Groth16 `prove`.
    #[arg(long, default_value_t = DEFAULT_PROVE_TIMEOUT_SECS)]
    prove_timeout_secs: u64,

    /// Previous Dogecoin bridge state bytes as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    old_state: Option<String>,

    /// Block-transition witness bytes as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    witness: Option<String>,

    /// 32-byte manager custody script config (emitter bridge PDA) as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    custody_script_config: Option<String>,

    /// Required Dogecoin block confirmations.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    required_confirmations: Option<u32>,

    /// Flat bridge fee in the guest's integer fee unit.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    flat_fee: Option<u64>,

    /// Proportional fee numerator.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    fee_num: Option<u64>,

    /// Proportional fee denominator.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    fee_den: Option<u64>,

    /// 320-byte repr(C) header as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    old_header: Option<String>,

    /// 320-byte repr(C) header as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    new_header: Option<String>,

    /// 48-byte repr(C) bridge config as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present_any = ["vkey_only", "daemon"])]
    config_params: Option<String>,
}

impl Args {
    fn deadlines(&self) -> Result<DeadlineConfig, String> {
        DeadlineConfig::from_secs(
            self.setup_timeout_secs,
            self.execute_timeout_secs,
            self.prove_timeout_secs,
        )
    }
}

struct BlockTransitionInputs {
    old_state: Vec<u8>,
    witness: Vec<u8>,
    custody_script_config: Vec<u8>,
    required_confirmations: u32,
    flat_fee: u64,
    fee_num: u64,
    fee_den: u64,
    old_header: Vec<u8>,
    new_header: Vec<u8>,
    config_params: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct DaemonRequest {
    request_id: String,
    old_state: String,
    witness: String,
    custody_script_config: String,
    required_confirmations: u32,
    flat_fee: u64,
    fee_num: u64,
    fee_den: u64,
    old_header: String,
    new_header: String,
    config_params: String,
}

/// Path-independent daemon identity: network + stable guest id + ELF digest + VK.
#[derive(Debug, Serialize)]
struct IdentityResponse<'a> {
    kind: &'static str,
    protocol_version: u32,
    network: &'a str,
    guest_id: &'a str,
    block_elf_sha256: String,
    vkey_hash: String,
}

#[derive(Debug, Serialize)]
struct ProofResponse<'a> {
    kind: &'static str,
    request_id: &'a str,
    ok: bool,
    network: &'a str,
    guest_id: &'a str,
    block_elf_sha256: &'a str,
    vkey_hash: &'a str,
    proof_size: usize,
    proof_bytes: String,
    public_values_size: usize,
    public_values: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse<'a> {
    kind: &'static str,
    request_id: Option<&'a str>,
    ok: bool,
    code: DaemonErrorCode,
    error: String,
}

struct ProofArtifacts {
    proof_bytes: Vec<u8>,
    public_values: Vec<u8>,
}

#[derive(Debug)]
enum ProofWorkError {
    InvalidInput(String),
    Failed(String),
    TimedOut {
        phase: &'static str,
        timeout: Duration,
    },
}

impl ProofWorkError {
    fn failed(error: impl ToString) -> Self {
        Self::Failed(error.to_string())
    }

    fn is_timeout(&self) -> bool {
        matches!(self, Self::TimedOut { .. })
    }

    fn daemon_error_code(&self) -> DaemonErrorCode {
        match self {
            Self::InvalidInput(_) => DaemonErrorCode::InvalidInput,
            Self::Failed(_) => DaemonErrorCode::ProofFailure,
            Self::TimedOut { phase: "execute", .. } => DaemonErrorCode::ExecuteTimeout,
            Self::TimedOut { phase: "prove", .. } => DaemonErrorCode::ProveTimeout,
            Self::TimedOut { .. } => DaemonErrorCode::ProofFailure,
        }
    }
}

impl fmt::Display for ProofWorkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::Failed(message) => formatter.write_str(message),
            Self::TimedOut { phase, timeout } => write!(
                formatter,
                "{phase} timed out after {}s; CUDA cancellation may leave GPU state unusable so this process will exit",
                timeout.as_secs()
            ),
        }
    }
}

impl Error for ProofWorkError {}

impl BlockTransitionInputs {
    fn into_stdin(self) -> SP1Stdin {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(self.old_state);
        stdin.write_vec(self.witness);
        stdin.write_vec(self.custody_script_config);
        stdin.write_vec(self.required_confirmations.to_le_bytes().to_vec());
        stdin.write_vec(self.flat_fee.to_le_bytes().to_vec());
        stdin.write_vec(self.fee_num.to_le_bytes().to_vec());
        stdin.write_vec(self.fee_den.to_le_bytes().to_vec());
        stdin.write_vec(self.old_header);
        stdin.write_vec(self.new_header);
        stdin.write_vec(self.config_params);
        stdin
    }
}

fn read_hex_bytes(value: &str, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let explicit_path = value.strip_prefix('@');
    let hex_text = if let Some(path) = explicit_path {
        std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read {name} from {path}: {error}"))?
    } else if Path::new(value).is_file() {
        std::fs::read_to_string(value)
            .map_err(|error| format!("failed to read {name} from {value}: {error}"))?
    } else {
        value.to_owned()
    };

    let normalized: String = hex_text
        .trim()
        .strip_prefix("0x")
        .unwrap_or(hex_text.trim())
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    hex::decode(&normalized).map_err(|error| format!("invalid {name} hex: {error}").into())
}

fn decode_inline_hex_bytes(value: &str, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let normalized: String = value
        .trim()
        .strip_prefix("0x")
        .unwrap_or(value.trim())
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    hex::decode(&normalized).map_err(|error| format!("invalid {name} hex: {error}").into())
}

fn decode_inline_hex_input(
    value: &str,
    name: &str,
    expected_len: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = decode_inline_hex_bytes(value, name)?;
    if bytes.len() != expected_len {
        return Err(format!(
            "{name} must decode to {expected_len} bytes, got {}",
            bytes.len()
        )
        .into());
    }
    Ok(bytes)
}

fn read_hex_input(value: &str, name: &str, expected_len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let bytes = read_hex_bytes(value, name)?;
    if bytes.len() != expected_len {
        return Err(format!(
            "{name} must decode to {expected_len} bytes, got {}",
            bytes.len()
        )
        .into());
    }
    Ok(bytes)
}

impl DaemonRequest {
    fn into_inputs(self) -> Result<BlockTransitionInputs, Box<dyn Error>> {
        Ok(BlockTransitionInputs {
            old_state: decode_inline_hex_bytes(&self.old_state, "old state")?,
            witness: decode_inline_hex_bytes(&self.witness, "witness")?,
            custody_script_config: decode_inline_hex_input(
                &self.custody_script_config,
                "custody script config",
                CUSTODY_SCRIPT_CONFIG_SIZE,
            )?,
            required_confirmations: self.required_confirmations,
            flat_fee: self.flat_fee,
            fee_num: self.fee_num,
            fee_den: self.fee_den,
            old_header: decode_inline_hex_input(&self.old_header, "old header", HEADER_SIZE)?,
            new_header: decode_inline_hex_input(&self.new_header, "new header", HEADER_SIZE)?,
            config_params: decode_inline_hex_input(
                &self.config_params,
                "config parameters",
                CONFIG_PARAMS_SIZE,
            )?,
        })
    }
}

fn args_into_inputs(args: Args) -> Result<BlockTransitionInputs, Box<dyn Error>> {
    Ok(BlockTransitionInputs {
        old_state: read_hex_bytes(
            args.old_state.as_deref().expect("required by clap"),
            "old state",
        )?,
        witness: read_hex_bytes(
            args.witness.as_deref().expect("required by clap"),
            "witness",
        )?,
        custody_script_config: read_hex_input(
            args.custody_script_config
                .as_deref()
                .expect("required by clap"),
            "custody script config",
            CUSTODY_SCRIPT_CONFIG_SIZE,
        )?,
        required_confirmations: args.required_confirmations.expect("required by clap"),
        flat_fee: args.flat_fee.expect("required by clap"),
        fee_num: args.fee_num.expect("required by clap"),
        fee_den: args.fee_den.expect("required by clap"),
        old_header: read_hex_input(
            args.old_header.as_deref().expect("required by clap"),
            "old header",
            HEADER_SIZE,
        )?,
        new_header: read_hex_input(
            args.new_header.as_deref().expect("required by clap"),
            "new header",
            HEADER_SIZE,
        )?,
        config_params: read_hex_input(
            args.config_params.as_deref().expect("required by clap"),
            "config parameters",
            CONFIG_PARAMS_SIZE,
        )?,
    })
}

async fn setup_proving_key(
    client: &CudaProver,
    elf: sp1_sdk::Elf,
    deadlines: DeadlineConfig,
) -> Result<<CudaProver as Prover>::ProvingKey, ProofWorkError> {
    tokio::time::timeout(deadlines.setup, client.setup(elf))
        .await
        .map_err(|_| ProofWorkError::TimedOut {
            phase: "setup",
            timeout: deadlines.setup,
        })?
        .map_err(|error| ProofWorkError::failed(format!("failed to setup proving key: {error}")))
}

async fn generate_proof(
    client: &CudaProver,
    proving_key: &<CudaProver as Prover>::ProvingKey,
    network: Network,
    inputs: BlockTransitionInputs,
    deadlines: DeadlineConfig,
) -> Result<ProofArtifacts, ProofWorkError> {
    let old_header_hash = sha256(&inputs.old_header);
    let new_header_hash = sha256(&inputs.new_header);
    let config_hash = sha256(&inputs.config_params);
    let custody_script_config_array: [u8; CUSTODY_SCRIPT_CONFIG_SIZE] = inputs
        .custody_script_config
        .as_slice()
        .try_into()
        .expect("custody script config length was checked");
    let custodian_hash = network.custodian_hash(&CustodyScriptConfig::new(
        custody_script_config_array,
    ));
    let expected_public_values = block_transition_public_inputs(
        &old_header_hash,
        &new_header_hash,
        &config_hash,
        &custodian_hash,
    );
    let stdin = inputs.into_stdin();

    let (_, execution_report) = tokio::time::timeout(
        deadlines.execute,
        client.execute(proving_key.elf().clone(), stdin.clone()),
    )
    .await
    .map_err(|_| ProofWorkError::TimedOut {
        phase: "execute",
        timeout: deadlines.execute,
    })?
    .map_err(|error| ProofWorkError::failed(format!("failed to execute guest: {error}")))?;

    if execution_report.exit_code != 0 {
        return Err(ProofWorkError::failed(format!(
            "block-transition guest exited with code {}; report: {:?}",
            execution_report.exit_code, execution_report
        )));
    }

    let proof = tokio::time::timeout(deadlines.prove, client.prove(proving_key, stdin).groth16())
        .await
        .map_err(|_| ProofWorkError::TimedOut {
            phase: "prove",
            timeout: deadlines.prove,
        })?
        .map_err(|error| ProofWorkError::failed(format!("failed to generate Groth16 proof: {error}")))?;

    client
        .verify(&proof, proving_key.verifying_key(), None)
        .map_err(|error| ProofWorkError::failed(format!("SP1 SDK verify failed: {error}")))?;

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.to_vec();
    if public_values.as_slice() != expected_public_values.as_slice() {
        return Err(ProofWorkError::failed(format!(
            "zkVM public values mismatch: expected {}, got {}",
            hex::encode(expected_public_values),
            hex::encode(&public_values)
        )));
    }

    Ok(ProofArtifacts {
        proof_bytes,
        public_values,
    })
}

fn write_json_line(
    protocol_stdout: &mut impl Write,
    value: &impl Serialize,
) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *protocol_stdout, value)?;
    protocol_stdout.write_all(b"\n")?;
    protocol_stdout.flush()?;
    Ok(())
}

fn exit_after_timeout_response() -> ! {
    // Cancelling an in-flight CUDA future does not reliably reclaim GPU resources.
    // Fail fast so the supervisor restarts a clean prover process instead of serving
    // further requests from a potentially polluted daemon.
    process::exit(TIMEOUT_EXIT_CODE);
}

#[cfg(unix)]
fn duplicate_protocol_stdout() -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let stdout = std::io::stdout();
    let protocol_fd = unsafe { dup_for_protocol(stdout.as_raw_fd()) };
    if protocol_fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let stderr = std::io::stderr();
    if unsafe { dup2_for_child_process(stderr.as_raw_fd(), stdout.as_raw_fd()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(protocol_fd) })
}

#[cfg(not(unix))]
fn duplicate_protocol_stdout() -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "daemon protocol stdout isolation requires Unix",
    ))
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "dup"]
    fn dup_for_protocol(fd: i32) -> i32;
    #[link_name = "dup2"]
    fn dup2_for_child_process(oldfd: i32, newfd: i32) -> i32;
}

async fn run_daemon(
    program: BlockProgram,
    deadlines: DeadlineConfig,
    cuda_device_id: u32,
) -> Result<(), Box<dyn Error>> {
    let mut protocol_stdout = duplicate_protocol_stdout()?;
    let client = ProverClient::builder().cuda().with_device_id(cuda_device_id).build().await;
    let proving_key = match setup_proving_key(&client, program.elf.clone(), deadlines).await {
        Ok(proving_key) => proving_key,
        Err(error) => {
            // No identity line yet; surface the failure on stderr and exit.
            eprintln!("gen-proof daemon setup failed: {error}");
            if error.is_timeout() {
                exit_after_timeout_response();
            }
            return Err(error.into());
        }
    };
    let elf_sha256 = hex::encode(sha256(&program.elf));
    let vkey_hash = proving_key.verifying_key().bytes32();
    write_json_line(
        &mut protocol_stdout,
        &IdentityResponse {
            kind: "identity",
            protocol_version: DAEMON_PROTOCOL_VERSION,
            network: program.network.as_str(),
            guest_id: program.guest_id,
            block_elf_sha256: elf_sha256.clone(),
            vkey_hash: vkey_hash.clone(),
        },
    )?;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<DaemonRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                write_json_line(
                    &mut protocol_stdout,
                    &ErrorResponse {
                        kind: "proof",
                        request_id: None,
                        ok: false,
                        code: DaemonErrorCode::InvalidRequest,
                        error: format!("invalid request JSON: {error}"),
                    },
                )?;
                continue;
            }
        };
        let request_id = request.request_id.clone();
        let proof_result = match request.into_inputs() {
            Ok(inputs) => {
                generate_proof(&client, &proving_key, program.network, inputs, deadlines).await
            }
            Err(error) => Err(ProofWorkError::InvalidInput(error.to_string())),
        };
        match proof_result {
            Ok(artifacts) => write_json_line(
                &mut protocol_stdout,
                &ProofResponse {
                    kind: "proof",
                    request_id: &request_id,
                    ok: true,
                    network: program.network.as_str(),
                    guest_id: program.guest_id,
                    block_elf_sha256: &elf_sha256,
                    vkey_hash: &vkey_hash,
                    proof_size: artifacts.proof_bytes.len(),
                    proof_bytes: hex::encode(&artifacts.proof_bytes),
                    public_values_size: artifacts.public_values.len(),
                    public_values: hex::encode(&artifacts.public_values),
                },
            )?,
            Err(error) => {
                let timed_out = error.is_timeout();
                write_json_line(
                    &mut protocol_stdout,
                    &ErrorResponse {
                        kind: "proof",
                        request_id: Some(&request_id),
                        ok: false,
                        code: error.daemon_error_code(),
                        error: error.to_string(),
                    },
                )?;
                if timed_out {
                    exit_after_timeout_response();
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let deadlines = args.deadlines().map_err(|error| -> Box<dyn Error> { error.into() })?;
    let cuda_device_id = args.cuda_device_id;
    let program = block_program(args.network);
    let runtime = tokio::runtime::Runtime::new()?;
    if args.daemon {
        return runtime.block_on(run_daemon(program, deadlines, cuda_device_id));
    }
    if args.vkey_only {
        return runtime.block_on(async move {
            let client = ProverClient::builder().cuda().with_device_id(cuda_device_id).build().await;
            let proving_key = setup_proving_key(&client, program.elf.clone(), deadlines)
                .await
                .map_err(|error| -> Box<dyn Error> {
                    if error.is_timeout() {
                        eprintln!("{error}");
                        exit_after_timeout_response();
                    }
                    error.into()
                })?;
            println!("network: {}", program.network.as_str());
            println!("guest_id: {}", program.guest_id);
            println!("block_elf_sha256: {}", hex::encode(sha256(&program.elf)));
            println!("vkey_hash: {}", proving_key.verifying_key().bytes32());
            Ok::<(), Box<dyn Error>>(())
        });
    }

    let inputs = args_into_inputs(args)?;
    runtime.block_on(async move {
        let client = ProverClient::builder().cuda().with_device_id(cuda_device_id).build().await;
        let proving_key = setup_proving_key(&client, program.elf.clone(), deadlines)
            .await
            .map_err(|error| -> Box<dyn Error> {
                if error.is_timeout() {
                    eprintln!("{error}");
                    exit_after_timeout_response();
                }
                error.into()
            })?;
        let artifacts = generate_proof(&client, &proving_key, program.network, inputs, deadlines)
            .await
            .map_err(|error| -> Box<dyn Error> {
                if error.is_timeout() {
                    eprintln!("{error}");
                    exit_after_timeout_response();
                }
                error.into()
            })?;
        println!("network: {}", program.network.as_str());
        println!("guest_id: {}", program.guest_id);
        println!("block_elf_sha256: {}", hex::encode(sha256(&program.elf)));
        println!("proof_size: {}", artifacts.proof_bytes.len());
        println!("proof_bytes: {}", hex::encode(&artifacts.proof_bytes));
        println!("public_values_size: {}", artifacts.public_values.len());
        println!("public_values: {}", hex::encode(&artifacts.public_values));
        println!("vkey_hash: {}", proving_key.verifying_key().bytes32());

        Ok::<(), Box<dyn Error>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        block_program, read_hex_bytes, read_hex_input, Args, BlockTransitionInputs, DaemonRequest,
        DeadlineConfig, ErrorResponse, IdentityResponse, Network, ProofResponse, ProofWorkError,
        BLOCK_TRANSITION_REGTEST_GUEST_ID, BLOCK_TRANSITION_TESTNET_GUEST_ID,
        DEFAULT_EXECUTE_TIMEOUT_SECS, DEFAULT_PROVE_TIMEOUT_SECS, DEFAULT_SETUP_TIMEOUT_SECS,
        TIMEOUT_EXIT_CODE,
    };
    use clap::{error::ErrorKind, Parser};
    use psy_bridge_sp1_script::proof_protocol::{DaemonErrorCode, DAEMON_PROTOCOL_VERSION};
    use psy_doge_bridge_helper::tx_template::CustodyScriptConfig;
    use std::time::Duration;

    #[test]
    fn parses_all_guest_cli_inputs() {
        let args = Args::try_parse_from([
            "gen-proof",
            "--network",
            "regtest",
            "--old-state",
            "00",
            "--witness",
            "01",
            "--custody-script-config",
            &"02".repeat(32),
            "--required-confirmations",
            "6",
            "--flat-fee",
            "7",
            "--fee-num",
            "8",
            "--fee-den",
            "9",
            "--old-header",
            &"0a".repeat(320),
            "--new-header",
            &"0b".repeat(320),
            "--config-params",
            &"0c".repeat(48),
        ])
        .unwrap();

        assert_eq!(args.required_confirmations, Some(6));
        assert_eq!(args.flat_fee, Some(7));
        assert_eq!(args.fee_num, Some(8));
        assert_eq!(args.fee_den, Some(9));
        assert_eq!(args.custody_script_config, Some("02".repeat(32)));
        assert_eq!(args.network, Network::Regtest);
        assert_eq!(args.setup_timeout_secs, DEFAULT_SETUP_TIMEOUT_SECS);
        assert_eq!(args.execute_timeout_secs, DEFAULT_EXECUTE_TIMEOUT_SECS);
        assert_eq!(args.prove_timeout_secs, DEFAULT_PROVE_TIMEOUT_SECS);
    }

    #[test]
    fn parses_vkey_only_without_proof_inputs() {
        let args = Args::try_parse_from(["gen-proof", "--network", "regtest", "--vkey-only"]).unwrap();
        assert!(args.vkey_only);
        assert!(args.old_state.is_none());
        assert!(args.custody_script_config.is_none());
    }

    #[test]
    fn selects_testnet_guest_explicitly() {
        let args = Args::try_parse_from(["gen-proof", "--network", "testnet", "--vkey-only"])
            .unwrap();
        assert_eq!(args.network, Network::Testnet);
        let program = block_program(args.network);
        assert_eq!(program.network, Network::Testnet);
        assert_eq!(program.guest_id, BLOCK_TRANSITION_TESTNET_GUEST_ID);
        assert!(!program.elf.is_empty());
    }

    #[test]
    fn selects_regtest_guest_identifier() {
        let program = block_program(Network::Regtest);
        assert_eq!(program.guest_id, BLOCK_TRANSITION_REGTEST_GUEST_ID);
        assert!(!program.elf.is_empty());
    }

    #[test]
    fn rejects_missing_network() {
        let error = Args::try_parse_from(["gen-proof", "--vkey-only"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn rejects_legacy_free_script_inputs() {
        for option in ["--bridge-pubkey-hash", "--custodian-hash"] {
            let error = Args::try_parse_from(["gen-proof", option, &"00".repeat(32)])
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn parses_custom_deadline_overrides() {
        let args = Args::try_parse_from([
            "gen-proof",
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
        ])
        .unwrap();
        let deadlines = args.deadlines().unwrap();
        assert_eq!(deadlines.setup, Duration::from_secs(11));
        assert_eq!(deadlines.execute, Duration::from_secs(22));
        assert_eq!(deadlines.prove, Duration::from_secs(33));
        assert_eq!(args.cuda_device_id, 7);
    }

    #[test]
    fn rejects_zero_deadline_seconds() {
        assert!(DeadlineConfig::from_secs(0, 1, 1).is_err());
        assert!(DeadlineConfig::from_secs(1, 0, 1).is_err());
        assert!(DeadlineConfig::from_secs(1, 1, 0).is_err());

        let args = Args::try_parse_from([
            "gen-proof",
            "--network",
            "regtest",
            "--vkey-only",
            "--setup-timeout-secs",
            "0",
        ])
        .unwrap();
        let error = args.deadlines().unwrap_err();
        assert!(error.contains("non-zero"));
    }

    #[test]
    fn default_deadlines_are_hard_positive_budgets() {
        let deadlines = DeadlineConfig::default_config();
        assert!(deadlines.setup > Duration::ZERO);
        assert!(deadlines.execute > Duration::ZERO);
        assert!(deadlines.prove > Duration::ZERO);
        assert_eq!(deadlines.setup.as_secs(), DEFAULT_SETUP_TIMEOUT_SECS);
        assert_eq!(deadlines.execute.as_secs(), DEFAULT_EXECUTE_TIMEOUT_SECS);
        assert_eq!(deadlines.prove.as_secs(), DEFAULT_PROVE_TIMEOUT_SECS);
        assert_ne!(TIMEOUT_EXIT_CODE, 0);
    }

    #[test]
    fn timeout_errors_are_structured_and_fail_fast_flagged() {
        let error = ProofWorkError::TimedOut {
            phase: "prove",
            timeout: Duration::from_secs(12),
        };
        let rendered = error.to_string();
        assert!(error.is_timeout());
        assert!(rendered.contains("prove timed out after 12s"));
        assert!(rendered.contains("will exit"));

        let failed = ProofWorkError::failed("guest boom");
        assert!(!failed.is_timeout());
        assert_eq!(failed.to_string(), "guest boom");
    }

    #[test]
    fn identity_response_is_path_independent() {
        let identity = IdentityResponse {
            kind: "identity",
            protocol_version: DAEMON_PROTOCOL_VERSION,
            network: "regtest",
            guest_id: BLOCK_TRANSITION_REGTEST_GUEST_ID,
            block_elf_sha256: "ab".repeat(32),
            vkey_hash: "cd".repeat(32),
        };
        let value = serde_json::to_value(&identity).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.get("kind").unwrap(), "identity");
        assert_eq!(object.get("protocol_version").unwrap(), DAEMON_PROTOCOL_VERSION);
        assert_eq!(object.get("network").unwrap(), "regtest");
        assert_eq!(
            object.get("guest_id").unwrap(),
            BLOCK_TRANSITION_REGTEST_GUEST_ID
        );
        assert!(object.contains_key("block_elf_sha256"));
        assert!(object.contains_key("vkey_hash"));
        assert!(!object.contains_key("block_elf_path"));
    }

    #[test]
    fn proof_and_error_responses_serialize_timeout_contract() {
        let proof = ProofResponse {
            kind: "proof",
            request_id: "req-1",
            ok: true,
            network: "testnet",
            guest_id: BLOCK_TRANSITION_TESTNET_GUEST_ID,
            block_elf_sha256: "11",
            vkey_hash: "22",
            proof_size: 356,
            proof_bytes: "aa".into(),
            public_values_size: 32,
            public_values: "bb".into(),
        };
        let proof_value = serde_json::to_value(&proof).unwrap();
        assert!(!proof_value
            .as_object()
            .unwrap()
            .contains_key("block_elf_path"));
        assert_eq!(
            proof_value.get("guest_id").unwrap(),
            BLOCK_TRANSITION_TESTNET_GUEST_ID
        );

        let timeout = ProofWorkError::TimedOut {
            phase: "execute",
            timeout: Duration::from_secs(9),
        };
        let error = ErrorResponse {
            kind: "proof",
            request_id: Some("req-2"),
            ok: false,
            code: timeout.daemon_error_code(),
            error: timeout.to_string(),
        };
        let error_json = serde_json::to_string(&error).unwrap();
        assert!(error_json.contains("\"ok\":false"));
        assert!(error_json.contains("execute timed out after 9s"));
        assert!(error_json.contains("req-2"));
        assert!(error_json.contains("\"code\":\"EXECUTE_TIMEOUT\""));
    }

    #[test]
    fn derives_profile_specific_wallet_config_hashes_from_script_config() {
        let custody_script_config = hex::decode(
            "f02732708965bb9473177495e608496b0af3bdbe5bd62ec062d8cddb1824a813",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let config = CustodyScriptConfig::new(custody_script_config);

        assert_eq!(
            hex::encode(Network::Regtest.custodian_hash(&config)),
            "6b6c33fa023611fdd672361f9c198353580959ad34af813af69178d61ca955eb"
        );
        assert_eq!(
            hex::encode(Network::Testnet.custodian_hash(&config)),
            "2621f9ac4de46226f85b48bcf2e20c87e6bb62ff946a9b12becb8c35a4e90ab0"
        );
    }

    #[test]
    fn serializes_vectors_in_guest_read_order() {
        let stdin = BlockTransitionInputs {
            old_state: vec![0],
            witness: vec![1],
            custody_script_config: vec![2; 32],
            required_confirmations: 0x0605_0403,
            flat_fee: 0x0e0d_0c0b_0a09_0807,
            fee_num: 0x1615_1413_1211_100f,
            fee_den: 0x1e1d_1c1b_1a19_1817,
            old_header: vec![31; 320],
            new_header: vec![32; 320],
            config_params: vec![33; 48],
        }
        .into_stdin();

        assert_eq!(stdin.buffer.len(), 10);
        assert_eq!(stdin.buffer[0], [0]);
        assert_eq!(stdin.buffer[1], [1]);
        assert_eq!(stdin.buffer[2], [2; 32]);
        assert_eq!(stdin.buffer[3], [3, 4, 5, 6]);
        assert_eq!(stdin.buffer[4], [7, 8, 9, 10, 11, 12, 13, 14]);
        assert_eq!(stdin.buffer[5], [15, 16, 17, 18, 19, 20, 21, 22]);
        assert_eq!(stdin.buffer[6], [23, 24, 25, 26, 27, 28, 29, 30]);
        assert_eq!(stdin.buffer[7], vec![31; 320]);
        assert_eq!(stdin.buffer[8], vec![32; 320]);
        assert_eq!(stdin.buffer[9], vec![33; 48]);
    }

    #[test]
    fn reads_inline_prefixed_hex() {
        assert_eq!(
            read_hex_input("0x0001ff", "test input", 3).unwrap(),
            [0, 1, 255]
        );
    }

    #[test]
    fn reads_variable_length_hex() {
        assert_eq!(
            read_hex_bytes("0x00 01 ff", "test input").unwrap(),
            [0, 1, 255]
        );
    }

    #[test]
    fn rejects_incorrect_decoded_length() {
        let error = read_hex_input("00", "test input", 2).unwrap_err();
        assert_eq!(
            error.to_string(),
            "test input must decode to 2 bytes, got 1"
        );
    }

    fn daemon_request(old_state: String) -> DaemonRequest {
        DaemonRequest {
            request_id: "req-inline".to_owned(),
            old_state,
            witness: "01".to_owned(),
            custody_script_config: "02".repeat(32),
            required_confirmations: 6,
            flat_fee: 7,
            fee_num: 8,
            fee_den: 9,
            old_header: "0a".repeat(320),
            new_header: "0b".repeat(320),
            config_params: "0c".repeat(48),
        }
    }

    #[test]
    fn daemon_inputs_never_interpret_paths() {
        let path = std::env::temp_dir().join(format!(
            "gen-proof-inline-only-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "00").unwrap();
        let path_text = path.to_string_lossy().into_owned();

        assert!(daemon_request(path_text.clone()).into_inputs().is_err());
        assert!(daemon_request(format!("@{path_text}")).into_inputs().is_err());
        assert_eq!(read_hex_bytes(&format!("@{path_text}"), "old state").unwrap(), [0]);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn proof_work_error_codes_are_stable() {
        assert_eq!(
            ProofWorkError::InvalidInput("bad".to_owned()).daemon_error_code(),
            DaemonErrorCode::InvalidInput
        );
        assert_eq!(
            ProofWorkError::failed("proof failed").daemon_error_code(),
            DaemonErrorCode::ProofFailure
        );
        assert_eq!(
            ProofWorkError::TimedOut {
                phase: "prove",
                timeout: Duration::from_secs(1),
            }
            .daemon_error_code(),
            DaemonErrorCode::ProveTimeout
        );
    }

    #[test]
    fn cli_surface_excludes_solana_sender_credential_and_mint_flags() {
        // The gen-proof daemon is the worker's child process. It must never expose
        // a Solana signer / sender / mint / checkpoint-authority surface: it only
        // consumes Dogecoin block-transition inputs and emits a Groth16 proof.
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
            let argv: Vec<&str> = ["gen-proof", "--network", "regtest", "--vkey-only", flag, "value"]
                .into_iter()
                .collect();
            let error = Args::try_parse_from(argv).unwrap_err();
            assert!(
                matches!(error.kind(), clap::error::ErrorKind::UnknownArgument),
                "gen-proof CLI unexpectedly accepted forbidden credential flag `{flag}`"
            );
        }
    }
}

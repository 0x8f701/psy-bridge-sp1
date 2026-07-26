use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROOF_SCHEMA_VERSION: u32 = 1;
pub const PROOF_NAMESPACE_PREFIX: &str = "PDOGE-SP1-PROOF-V1";
pub const GROTH16_PROOF_BYTES: usize = 356;
pub const PUBLIC_VALUES_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueKeys {
    pub namespace: String,
    pub queue: String,
    pub notify: String,
    pub leases: String,
    pub attempt_prefix: String,
    pub job_prefix: String,
    pub state_prefix: String,
    pub result_prefix: String,
}

impl QueueKeys {
    pub fn new(prefix: &str, network: &str, seed: &str) -> Self {
        let namespace = format!("{prefix}-{network}-{seed}");
        Self {
            queue: format!("{namespace}:queue"),
            notify: format!("{namespace}:notify"),
            leases: format!("{namespace}:leases"),
            attempt_prefix: format!("{namespace}:attempt:"),
            job_prefix: format!("{namespace}:job:"),
            state_prefix: format!("{namespace}:state:"),
            result_prefix: format!("{namespace}:result:"),
            namespace,
        }
    }

    pub fn job(&self, job_id: &str) -> String {
        format!("{}{job_id}", self.job_prefix)
    }

    pub fn state(&self, job_id: &str) -> String {
        format!("{}{job_id}", self.state_prefix)
    }

    pub fn result(&self, job_id: &str) -> String {
        format!("{}{job_id}", self.result_prefix)
    }

    pub fn attempt(&self, job_id: &str) -> String {
        format!("{}{job_id}", self.attempt_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonRequest {
    pub request_id: String,
    pub old_state: String,
    pub witness: String,
    pub custody_script_config: String,
    pub required_confirmations: u32,
    pub flat_fee: u64,
    pub fee_num: u64,
    pub fee_den: u64,
    pub old_header: String,
    pub new_header: String,
    pub config_params: String,
}

impl DaemonRequest {
    pub fn computed_input_fingerprint(&self) -> Result<String, serde_json::Error> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonIdentityResponse {
    pub kind: String,
    pub network: String,
    pub guest_id: String,
    pub block_elf_sha256: String,
    pub vkey_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonProofResponse {
    pub kind: String,
    pub request_id: String,
    pub ok: bool,
    pub network: String,
    pub guest_id: String,
    pub block_elf_sha256: String,
    pub vkey_hash: String,
    pub proof_size: usize,
    pub proof_bytes: String,
    pub public_values_size: usize,
    pub public_values: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonErrorResponse {
    pub kind: String,
    pub request_id: Option<String>,
    pub ok: bool,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofJob {
    pub schema_version: u32,
    pub job_id: String,
    pub network: String,
    pub height: u32,
    pub parent_checkpoint_sha256: String,
    pub input_fingerprint: String,
    pub guest_id: String,
    pub block_elf_sha256: String,
    pub vkey_hash: String,
    pub request: DaemonRequest,
}

impl ProofJob {
    pub fn computed_job_id(&self) -> Result<String, serde_json::Error> {
        let parent_checkpoint_sha256 = decode_hex_32(&self.parent_checkpoint_sha256)
            .expect("computed_job_id requires validated parent checkpoint hash");
        let input_fingerprint = decode_hex_32(&self.input_fingerprint)
            .expect("computed_job_id requires validated input fingerprint");
        let block_elf_sha256 = decode_hex_32(&self.block_elf_sha256)
            .expect("computed_job_id requires validated ELF hash");
        let vkey_hash = decode_hex_32(&self.vkey_hash)
            .expect("computed_job_id requires validated verifying-key hash");
        let request_json = serde_json::to_vec(&self.request)?;

        let mut hasher = Sha256::new();
        hasher.update(self.schema_version.to_be_bytes());
        hash_length_prefixed(&mut hasher, self.network.as_bytes());
        hasher.update(self.height.to_be_bytes());
        hasher.update(parent_checkpoint_sha256);
        hasher.update(input_fingerprint);
        hash_length_prefixed(&mut hasher, self.guest_id.as_bytes());
        hasher.update(block_elf_sha256);
        hasher.update(vkey_hash);
        hash_length_prefixed(&mut hasher, &request_json);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn result_with(&self, outcome: ProofResultOutcome) -> ProofResult {
        ProofResult {
            schema_version: self.schema_version,
            job_id: self.job_id.clone(),
            network: self.network.clone(),
            height: self.height,
            parent_checkpoint_sha256: self.parent_checkpoint_sha256.clone(),
            input_fingerprint: self.input_fingerprint.clone(),
            guest_id: self.guest_id.clone(),
            block_elf_sha256: self.block_elf_sha256.clone(),
            vkey_hash: self.vkey_hash.clone(),
            outcome,
        }
    }
}

fn hash_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("proof identity component exceeds u32::MAX");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

pub fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err("must be exactly 64 hexadecimal characters".to_owned());
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err("must use lowercase hexadecimal".to_owned());
    }
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes
        .try_into()
        .map_err(|_| "must decode to exactly 32 bytes".to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ProofJobState {
    Queued,
    Claimed {
        worker_id: String,
        lease_id: String,
        lease_expires_ms: u64,
        attempt: u32,
    },
    Completed {
        completed_ms: u64,
        attempt: u32,
    },
    Failed {
        failed_ms: u64,
        attempt: u32,
        error: String,
    },
}

impl ProofJobState {
    pub fn matches_lease(&self, worker_id: &str, lease_id: &str) -> bool {
        matches!(
            self,
            Self::Claimed {
                worker_id: claimed_worker_id,
                lease_id: claimed_lease_id,
                ..
            } if claimed_worker_id == worker_id && claimed_lease_id == lease_id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofResult {
    pub schema_version: u32,
    pub job_id: String,
    pub network: String,
    pub height: u32,
    pub parent_checkpoint_sha256: String,
    pub input_fingerprint: String,
    pub guest_id: String,
    pub block_elf_sha256: String,
    pub vkey_hash: String,
    pub outcome: ProofResultOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum ProofResultOutcome {
    Success {
        response: DaemonProofResponse,
        stderr: String,
    },
    Error {
        error: String,
    },
}

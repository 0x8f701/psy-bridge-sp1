use clap::{Parser, ValueEnum};
use psy_bridge_sp1_lib::{block_transition_public_inputs, sha256, HASH_SIZE};
use psy_doge_bridge_helper::tx_template::CustodyScriptConfig;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    include_elf, CudaProver, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey,
    SP1Stdin,
};
use std::{
    error::Error,
    io::{BufRead, Write},
    path::Path,
};

const BLOCK_TRANSITION_REGTEST_ELF: sp1_sdk::Elf = include_elf!("block-transition");
const BLOCK_TRANSITION_REGTEST_ELF_PATH: &str = env!("SP1_ELF_block-transition");
const BLOCK_TRANSITION_TESTNET_ELF: sp1_sdk::Elf = include_elf!("block-transition-testnet");
const BLOCK_TRANSITION_TESTNET_ELF_PATH: &str = env!("SP1_ELF_block-transition-testnet");
const HEADER_SIZE: usize = 320;
const CUSTODY_SCRIPT_CONFIG_SIZE: usize = HASH_SIZE;
const CONFIG_PARAMS_SIZE: usize = 48;
const PROOF_PATH: &str = "/tmp/bridge-block-transition-proof.bin";
const PUBLIC_VALUES_PATH: &str = "/tmp/bridge-block-transition-pubvals.bin";

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
}

struct BlockProgram {
    network: Network,
    elf: sp1_sdk::Elf,
    path: &'static str,
}

fn block_program(network: Network) -> BlockProgram {
    match network {
        Network::Regtest => BlockProgram {
            network,
            elf: BLOCK_TRANSITION_REGTEST_ELF.clone(),
            path: BLOCK_TRANSITION_REGTEST_ELF_PATH,
        },
        Network::Testnet => BlockProgram {
            network,
            elf: BLOCK_TRANSITION_TESTNET_ELF.clone(),
            path: BLOCK_TRANSITION_TESTNET_ELF_PATH,
        },
    }
}

#[derive(Debug, Parser)]
#[command(about = "Generate an SP1 Groth16 block-transition proof")]
struct Args {
    /// Dogecoin consensus profile compiled into the selected block-transition guest.
    #[arg(long, value_enum, default_value_t)]
    network: Network,
    /// Run a line-delimited JSON request/response daemon on stdin/stdout.
    #[arg(long)]
    daemon: bool,
    /// Derive and print the release block-transition verifying-key hash without proving.
    #[arg(long, conflicts_with = "daemon")]
    vkey_only: bool,

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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
struct IdentityResponse<'a> {
    kind: &'static str,
    network: &'a str,
    block_elf_path: &'a str,
    block_elf_sha256: String,
    vkey_hash: String,
}

#[derive(Debug, Serialize)]
struct ProofResponse<'a> {
    kind: &'static str,
    request_id: &'a str,
    ok: bool,
    network: &'a str,
    block_elf_path: &'a str,
    block_elf_sha256: &'a str,
    vkey_hash: &'a str,
    proof_path: &'static str,
    proof_size: usize,
    proof_bytes: String,
    public_values_path: &'static str,
    public_values_size: usize,
    public_values: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse<'a> {
    kind: &'static str,
    request_id: Option<&'a str>,
    ok: bool,
    error: String,
}

struct ProofArtifacts {
    proof_bytes: Vec<u8>,
    public_values: Vec<u8>,
}

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
            old_state: read_hex_bytes(&self.old_state, "old state")?,
            witness: read_hex_bytes(&self.witness, "witness")?,
            custody_script_config: read_hex_input(
                &self.custody_script_config,
                "custody script config",
                CUSTODY_SCRIPT_CONFIG_SIZE,
            )?,
            required_confirmations: self.required_confirmations,
            flat_fee: self.flat_fee,
            fee_num: self.fee_num,
            fee_den: self.fee_den,
            old_header: read_hex_input(&self.old_header, "old header", HEADER_SIZE)?,
            new_header: read_hex_input(&self.new_header, "new header", HEADER_SIZE)?,
            config_params: read_hex_input(
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

async fn generate_proof(
    client: &CudaProver,
    proving_key: &<CudaProver as Prover>::ProvingKey,
    inputs: BlockTransitionInputs,
) -> Result<ProofArtifacts, Box<dyn Error>> {
    let old_header_hash = sha256(&inputs.old_header);
    let new_header_hash = sha256(&inputs.new_header);
    let config_hash = sha256(&inputs.config_params);
    let custody_script_config_array: [u8; CUSTODY_SCRIPT_CONFIG_SIZE] = inputs
        .custody_script_config
        .as_slice()
        .try_into()
        .expect("custody script config length was checked");
    let custodian_hash = CustodyScriptConfig::new(custody_script_config_array).hash();
    let expected_public_values = block_transition_public_inputs(
        &old_header_hash,
        &new_header_hash,
        &config_hash,
        &custodian_hash,
    );
    let stdin = inputs.into_stdin();
    let (_, execution_report) = client
        .execute(proving_key.elf().clone(), stdin.clone())
        .await?;
    if execution_report.exit_code != 0 {
        return Err(format!(
            "block-transition guest exited with code {}; report: {:?}",
            execution_report.exit_code, execution_report
        )
        .into());
    }

    let proof = client
        .prove(proving_key, stdin)
        .groth16()
        .await
        .map_err(|error| format!("failed to generate Groth16 proof: {error}"))?;
    client.verify(&proof, proving_key.verifying_key(), None)?;

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.to_vec();
    if public_values.as_slice() != expected_public_values.as_slice() {
        return Err(format!(
            "zkVM public values mismatch: expected {}, got {}",
            hex::encode(expected_public_values),
            hex::encode(&public_values)
        )
        .into());
    }

    std::fs::write(PROOF_PATH, &proof_bytes)?;
    std::fs::write(PUBLIC_VALUES_PATH, &public_values)?;
    Ok(ProofArtifacts {
        proof_bytes,
        public_values,
    })
}

async fn run_daemon(program: BlockProgram) -> Result<(), Box<dyn Error>> {
    let client = ProverClient::builder().cuda().build().await;
    let proving_key = client.setup(program.elf.clone()).await?;
    let elf_sha256 = hex::encode(sha256(&program.elf));
    let vkey_hash = proving_key.verifying_key().bytes32();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(
        &mut stdout,
        &IdentityResponse {
            kind: "identity",
            network: program.network.as_str(),
            block_elf_path: program.path,
            block_elf_sha256: elf_sha256.clone(),
            vkey_hash: vkey_hash.clone(),
        },
    )?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<DaemonRequest>(&line) {
            Ok(request) => request,
            Err(error) => {
                serde_json::to_writer(
                    &mut stdout,
                    &ErrorResponse {
                        kind: "proof",
                        request_id: None,
                        ok: false,
                        error: format!("invalid request JSON: {error}"),
                    },
                )?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
                continue;
            }
        };
        let request_id = request.request_id.clone();
        let proof_result = match request.into_inputs() {
            Ok(inputs) => generate_proof(&client, &proving_key, inputs).await,
            Err(error) => Err(error),
        };
        match proof_result {
            Ok(artifacts) => serde_json::to_writer(
                &mut stdout,
                &ProofResponse {
                    kind: "proof",
                    request_id: &request_id,
                    ok: true,
                    network: program.network.as_str(),
                    block_elf_path: program.path,
                    block_elf_sha256: &elf_sha256,
                    vkey_hash: &vkey_hash,
                    proof_path: PROOF_PATH,
                    proof_size: artifacts.proof_bytes.len(),
                    proof_bytes: hex::encode(&artifacts.proof_bytes),
                    public_values_path: PUBLIC_VALUES_PATH,
                    public_values_size: artifacts.public_values.len(),
                    public_values: hex::encode(&artifacts.public_values),
                },
            )?,
            Err(error) => serde_json::to_writer(
                &mut stdout,
                &ErrorResponse {
                    kind: "proof",
                    request_id: Some(&request_id),
                    ok: false,
                    error: error.to_string(),
                },
            )?,
        }
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let program = block_program(args.network);
    let runtime = tokio::runtime::Runtime::new()?;
    if args.daemon {
        return runtime.block_on(run_daemon(program));
    }
    if args.vkey_only {
        return runtime.block_on(async move {
            let client = ProverClient::builder().cuda().build().await;
            let proving_key = client.setup(program.elf.clone()).await?;
            println!("network: {}", program.network.as_str());
            println!("block_elf_path: {}", program.path);
            println!("block_elf_sha256: {}", hex::encode(sha256(&program.elf)));
            println!("vkey_hash: {}", proving_key.verifying_key().bytes32());
            Ok::<(), Box<dyn Error>>(())
        });
    }

    let inputs = args_into_inputs(args)?;
    runtime.block_on(async move {
        let client = ProverClient::builder().cuda().build().await;
        let proving_key = client.setup(program.elf.clone()).await?;
        let artifacts = generate_proof(&client, &proving_key, inputs).await?;
        println!("network: {}", program.network.as_str());
        println!("block_elf_path: {}", program.path);
        println!("block_elf_sha256: {}", hex::encode(sha256(&program.elf)));

        println!("proof_path: {PROOF_PATH}");
        println!("proof_size: {}", artifacts.proof_bytes.len());
        println!("proof_bytes: {}", hex::encode(&artifacts.proof_bytes));
        println!("public_values_path: {PUBLIC_VALUES_PATH}");
        println!("public_values_size: {}", artifacts.public_values.len());
        println!("public_values: {}", hex::encode(&artifacts.public_values));
        println!("vkey_hash: {}", proving_key.verifying_key().bytes32());

        Ok::<(), Box<dyn Error>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::{block_program, read_hex_bytes, read_hex_input, Args, BlockTransitionInputs, Network};
    use clap::{error::ErrorKind, Parser};
    use psy_doge_bridge_helper::tx_template::CustodyScriptConfig;

    #[test]
    fn parses_all_guest_cli_inputs() {
        let args = Args::try_parse_from([
            "gen-proof",
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
    }

    #[test]
    fn parses_vkey_only_without_proof_inputs() {
        let args = Args::try_parse_from(["gen-proof", "--vkey-only"]).unwrap();
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
        assert!(program.path.ends_with("/block-transition-testnet"));
        assert!(!program.elf.is_empty());
    }

    #[test]
    fn regtest_remains_the_default_guest() {
        let args = Args::try_parse_from(["gen-proof", "--vkey-only"]).unwrap();
        assert_eq!(args.network, Network::Regtest);
        let program = block_program(args.network);
        assert!(program.path.ends_with("/block-transition"));
        assert!(!program.elf.is_empty());
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
    fn derives_canonical_wallet_config_hash_from_script_config() {
        let custody_script_config = [
            0x84, 0xb2, 0x67, 0xdd, 0x47, 0x47, 0x4d, 0xd7, 0xee, 0x3b, 0x7d, 0x7f, 0xb5,
            0xb1, 0x0d, 0x86, 0x26, 0xbf, 0x52, 0xff, 0x8d, 0x2c, 0x82, 0x13, 0x57, 0x70,
            0xfe, 0xad, 0x3a, 0x5a, 0xb1, 0xba,
        ];
        assert_eq!(
            CustodyScriptConfig::new(custody_script_config).hash(),
            [
                0xaf, 0xae, 0x95, 0x79, 0xf6, 0x7e, 0xcf, 0xf7, 0x9e, 0xa3, 0x29, 0x7a, 0x58,
                0xa4, 0xc8, 0x14, 0xa4, 0x58, 0x20, 0x20, 0xab, 0xd4, 0xe6, 0xd3, 0xf5, 0xe3,
                0xb1, 0x9b, 0x46, 0xf1, 0xab, 0x69,
            ]
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
}

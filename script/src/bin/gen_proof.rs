use clap::Parser;
use psy_bridge_sp1_lib::{block_transition_public_inputs, sha256, HASH_SIZE};
use psy_doge_bridge_helper::tx_template::CustodyScriptConfig;
use sp1_sdk::{include_elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::{error::Error, future::IntoFuture, path::Path};

const BLOCK_TRANSITION_ELF: sp1_sdk::Elf = include_elf!("block-transition");
const BLOCK_TRANSITION_ELF_PATH: &str = env!("SP1_ELF_block-transition");
const HEADER_SIZE: usize = 320;
const CUSTODY_SCRIPT_CONFIG_SIZE: usize = HASH_SIZE;
const CONFIG_PARAMS_SIZE: usize = 48;
const PROOF_PATH: &str = "/tmp/bridge-block-transition-proof.bin";
const PUBLIC_VALUES_PATH: &str = "/tmp/bridge-block-transition-pubvals.bin";

#[derive(Debug, Parser)]
#[command(about = "Generate an SP1 Groth16 block-transition proof")]
struct Args {
    /// Derive and print the release block-transition verifying-key hash without proving.
    #[arg(long)]
    vkey_only: bool,

    /// Previous Dogecoin bridge state bytes as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present = "vkey_only")]
    old_state: Option<String>,

    /// Block-transition witness bytes as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present = "vkey_only")]
    witness: Option<String>,

    /// 32-byte manager custody script config (emitter bridge PDA) as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present = "vkey_only")]
    custody_script_config: Option<String>,

    /// Required Dogecoin block confirmations.
    #[arg(long, required_unless_present = "vkey_only")]
    required_confirmations: Option<u32>,

    /// Flat bridge fee in the guest's integer fee unit.
    #[arg(long, required_unless_present = "vkey_only")]
    flat_fee: Option<u64>,

    /// Proportional fee numerator.
    #[arg(long, required_unless_present = "vkey_only")]
    fee_num: Option<u64>,

    /// Proportional fee denominator.
    #[arg(long, required_unless_present = "vkey_only")]
    fee_den: Option<u64>,

    /// 320-byte repr(C) header as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present = "vkey_only")]
    old_header: Option<String>,

    /// 320-byte repr(C) header as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present = "vkey_only")]
    new_header: Option<String>,

    /// 48-byte repr(C) bridge config as hex, or @path/path to a file containing hex.
    #[arg(long, required_unless_present = "vkey_only")]
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

fn main() -> Result<(), Box<dyn Error>> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    let runtime = tokio::runtime::Runtime::new()?;
    if args.vkey_only {
        return runtime.block_on(async move {
            let client = ProverClient::builder().cpu().build().await;
            let proving_key = client.setup(BLOCK_TRANSITION_ELF).await?;
            println!("block_elf_path: {BLOCK_TRANSITION_ELF_PATH}");
            println!("vkey_hash: {}", proving_key.verifying_key().bytes32());
            Ok::<(), Box<dyn Error>>(())
        });
    }

    let old_state = read_hex_bytes(args.old_state.as_deref().expect("required by clap"), "old state")?;
    let witness = read_hex_bytes(args.witness.as_deref().expect("required by clap"), "witness")?;
    let custody_script_config = read_hex_input(
        args.custody_script_config.as_deref().expect("required by clap"),
        "custody script config",
        CUSTODY_SCRIPT_CONFIG_SIZE,
    )?;
    let old_header = read_hex_input(
        args.old_header.as_deref().expect("required by clap"),
        "old header",
        HEADER_SIZE,
    )?;
    let new_header = read_hex_input(
        args.new_header.as_deref().expect("required by clap"),
        "new header",
        HEADER_SIZE,
    )?;
    let config_params = read_hex_input(
        args.config_params.as_deref().expect("required by clap"),
        "config parameters",
        CONFIG_PARAMS_SIZE,
    )?;
    let old_header_hash = sha256(&old_header);
    let new_header_hash = sha256(&new_header);
    let config_hash = sha256(&config_params);
    let custody_script_config_array: [u8; CUSTODY_SCRIPT_CONFIG_SIZE] = custody_script_config
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

    runtime.block_on(async move {
        let client = ProverClient::builder().cpu().build().await;
        let stdin = BlockTransitionInputs {
            old_state,
            witness,
            custody_script_config,
            required_confirmations: args.required_confirmations.expect("required by clap"),
            flat_fee: args.flat_fee.expect("required by clap"),
            fee_num: args.fee_num.expect("required by clap"),
            fee_den: args.fee_den.expect("required by clap"),
            old_header,
            new_header,
            config_params,
        }
        .into_stdin();
        let (_, execution_report) = client.execute(BLOCK_TRANSITION_ELF, stdin.clone()).await?;
        if execution_report.exit_code != 0 {
            return Err(format!("block-transition guest exited with code {}; report: {:?}", execution_report.exit_code, execution_report).into());
        }

        let proving_key = client.setup(BLOCK_TRANSITION_ELF).await?;
        let proof = client
            .prove(&proving_key, stdin)
            .groth16()
            .await
            .map_err(|error| format!("failed to generate Groth16 proof: {error}"))?;
        let verifying_key = proving_key.verifying_key();
        client.verify(&proof, verifying_key, None)?;

        let proof_bytes = proof.bytes();
        let public_values = proof.public_values.to_vec();
        if public_values.as_slice() != expected_public_values {
            return Err(format!(
                "zkVM public values mismatch: expected {}, got {}",
                hex::encode(expected_public_values),
                hex::encode(&public_values)
            )
            .into());
        }

        std::fs::write(PROOF_PATH, &proof_bytes)?;
        std::fs::write(PUBLIC_VALUES_PATH, &public_values)?;

        println!("proof_path: {PROOF_PATH}");
        println!("proof_size: {}", proof_bytes.len());
        println!("proof_bytes: {}", hex::encode(&proof_bytes));
        println!("public_values_path: {PUBLIC_VALUES_PATH}");
        println!("public_values_size: {}", public_values.len());
        println!("public_values: {}", hex::encode(&public_values));
        println!("vkey_hash: {}", verifying_key.bytes32());

        Ok::<(), Box<dyn Error>>(())
    })
}

#[cfg(test)]
mod tests {
    use super::{read_hex_bytes, read_hex_input, Args, BlockTransitionInputs};
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
    }

    #[test]
    fn parses_vkey_only_without_proof_inputs() {
        let args = Args::try_parse_from(["gen-proof", "--vkey-only"]).unwrap();
        assert!(args.vkey_only);
        assert!(args.old_state.is_none());
        assert!(args.custody_script_config.is_none());
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

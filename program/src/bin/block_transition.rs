#![no_main]
sp1_zkvm::entrypoint!(main);

use psy_bridge_sp1_lib::{block_transition_public_inputs, sha256};

use doge_light_client::constants::DogeRegTestConfig;
use psy_doge_bridge_helper::{
    block_transition::prover_guest::{
        prover_guest_run_with_bytes, prover_guest_verify_block_transition_detailed,
    },
    tx_template::{CustodyScriptConfig, LocalRegtestManagerCustody},
};

const SOLANA_HEADER_SIZE: usize = 320;
const CONFIG_PARAMS_SIZE: usize = 48;

/// Solana PsyBridgeHeader finalized_state field offsets within the 320-byte header.
/// finalized_state starts at offset 72 (after tip_state which is 72 bytes).
const FS_OFFSET: usize = 72;
const FS_BLOCK_HASH: usize = FS_OFFSET + 0; // 32 bytes
const FS_BLOCK_MERKLE_ROOT: usize = FS_OFFSET + 32; // 32 bytes
                                                    // FS_PENDING_MINTS_HASH at +64 — Solana-only, not checked
                                                    // FS_TXO_LIST_HASH at +96 — Solana-only, not checked
const FS_AUTO_CLAIMED_TXO_ROOT: usize = FS_OFFSET + 128; // 32 bytes
const FS_AUTO_CLAIMED_DEPOSITS_ROOT: usize = FS_OFFSET + 160; // 32 bytes
const FS_AUTO_CLAIMED_NEXT_INDEX: usize = FS_OFFSET + 192; // u32 LE
const FS_BLOCK_HEIGHT: usize = FS_OFFSET + 196; // u32 LE

pub fn main() {
    // --- Read inputs ---
    let old_state_bytes = sp1_zkvm::io::read_vec();
    let witness_bytes = sp1_zkvm::io::read_vec();

    let custody_script_config_bytes = sp1_zkvm::io::read_vec();
    let custody_script_config = CustodyScriptConfig::new(
        custody_script_config_bytes
            .try_into()
            .expect("custody script config must be the 32-byte emitter bridge PDA"),
    );

    let required_confirmations =
        u32::from_le_bytes(sp1_zkvm::io::read_vec().try_into().expect("confirmations"));
    let flat_fee = u64::from_le_bytes(sp1_zkvm::io::read_vec().try_into().expect("flat_fee"));
    let fee_num = u64::from_le_bytes(sp1_zkvm::io::read_vec().try_into().expect("fee_num"));
    let fee_den = u64::from_le_bytes(sp1_zkvm::io::read_vec().try_into().expect("fee_den"));

    let solana_old_header = sp1_zkvm::io::read_vec();
    assert_eq!(solana_old_header.len(), SOLANA_HEADER_SIZE);
    let solana_new_header = sp1_zkvm::io::read_vec();
    assert_eq!(solana_new_header.len(), SOLANA_HEADER_SIZE);

    let config_params = sp1_zkvm::io::read_vec();
    assert_eq!(config_params.len(), CONFIG_PARAMS_SIZE);
    let custodian_hash = custody_script_config.hash::<LocalRegtestManagerCustody>();

    // --- Build helper input and verify ---
    let mut helper_input = Vec::with_capacity(4 + old_state_bytes.len() + witness_bytes.len());
    helper_input.extend_from_slice(&(old_state_bytes.len() as u32).to_le_bytes());
    helper_input.extend_from_slice(&old_state_bytes);
    helper_input.extend_from_slice(&witness_bytes);

    let (witness, mut state) =
        prover_guest_run_with_bytes(&helper_input).expect("failed to parse witness/state");

    let verified = match prover_guest_verify_block_transition_detailed::<
        DogeRegTestConfig,
        LocalRegtestManagerCustody,
    >(
        custody_script_config,
        required_confirmations,
        witness,
        &mut state,
        flat_fee,
        fee_num,
        fee_den,
    ) {
        Ok(verified) => verified,
        Err(error) => panic!("block transition verification failed: {error:#}"),
    };

    // --- B14: verify Solana header finalized_state fields match helper's verified values ---
    // Check overlapping fields between helper's finalized_state and Solana header bytes.
    verify_finalized_state_fields(&solana_old_header, &verified.old_finalized_state, "old");
    verify_finalized_state_fields(&solana_new_header, &verified.new_finalized_state, "new");

    // --- Compute public inputs from Solana header bytes ---
    let old_header_hash = sha256(&solana_old_header);
    let new_header_hash = sha256(&solana_new_header);
    let config_hash = sha256(&config_params);

    let public_inputs = block_transition_public_inputs(
        &old_header_hash,
        &new_header_hash,
        &config_hash,
        &custodian_hash,
    );
    sp1_zkvm::io::commit(&public_inputs);
}

/// Verify that the consensus-related fields in a Solana PsyBridgeHeader
/// (320 bytes) match the helper's verified finalized_state.
/// Solana-only fields (pending_mints_finalized_hash, txo_output_list_finalized_hash)
/// are NOT checked here — they're verified on-chain via buffer hashes.
fn verify_finalized_state_fields(
    solana_header: &[u8],
    verified_state: &doge_light_client::block_state::PsyBridgeStateCommitment,
    label: &str,
) {
    let get = |offset: usize, len: usize| -> &[u8] { &solana_header[offset..offset + len] };

    assert_eq!(
        get(FS_BLOCK_HASH, 32),
        verified_state.block_hash,
        "B14: {} header block_hash mismatch",
        label
    );
    assert_eq!(
        get(FS_BLOCK_MERKLE_ROOT, 32),
        verified_state.block_merkle_tree_root,
        "B14: {} header block_merkle_tree_root mismatch",
        label
    );
    assert_eq!(
        get(FS_AUTO_CLAIMED_TXO_ROOT, 32),
        verified_state.auto_claimed_txo_tree_root,
        "B14: {} header auto_claimed_txo_tree_root mismatch",
        label
    );
    assert_eq!(
        get(FS_AUTO_CLAIMED_DEPOSITS_ROOT, 32),
        verified_state.auto_claimed_deposits_tree_root,
        "B14: {} header auto_claimed_deposits_tree_root mismatch",
        label
    );
    assert_eq!(
        u32::from_le_bytes(get(FS_AUTO_CLAIMED_NEXT_INDEX, 4).try_into().unwrap()),
        verified_state.auto_claimed_deposits_next_index,
        "B14: {} header auto_claimed_next_index mismatch",
        label
    );
    assert_eq!(
        u32::from_le_bytes(get(FS_BLOCK_HEIGHT, 4).try_into().unwrap()),
        verified_state.block_height,
        "B14: {} header block_height mismatch",
        label
    );
}

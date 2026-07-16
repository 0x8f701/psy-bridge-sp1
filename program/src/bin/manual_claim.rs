#![no_main]
sp1_zkvm::entrypoint!(main);

use psy_bridge_sp1_lib::{manual_claim_public_inputs, HASH_SIZE, MANUAL_CLAIM_INPUT_SIZE};

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    assert_eq!(input.len(), MANUAL_CLAIM_INPUT_SIZE);

    let mut offset = 0;
    let recent_block_merkle_tree_root = take_array::<HASH_SIZE>(&input, &mut offset);
    let recent_auto_claim_txo_root = take_array::<HASH_SIZE>(&input, &mut offset);
    let old_manual_claim_deposit_txo_root = take_array::<HASH_SIZE>(&input, &mut offset);
    let new_manual_claim_txo_root = take_array::<HASH_SIZE>(&input, &mut offset);
    let tx_hash = take_array::<HASH_SIZE>(&input, &mut offset);
    let user_ata = take_array::<HASH_SIZE>(&input, &mut offset);
    let custodian_wallet_config_hash = take_array::<HASH_SIZE>(&input, &mut offset);
    let combined_txo_index = u64::from_le_bytes(take_array::<8>(&input, &mut offset));
    let deposit_amount_sats = u64::from_le_bytes(take_array::<8>(&input, &mut offset));
    assert_eq!(offset, input.len());

    let public_inputs = manual_claim_public_inputs(
        &recent_block_merkle_tree_root,
        &recent_auto_claim_txo_root,
        &old_manual_claim_deposit_txo_root,
        &new_manual_claim_txo_root,
        &tx_hash,
        &user_ata,
        &custodian_wallet_config_hash,
        combined_txo_index,
        deposit_amount_sats,
    );
    sp1_zkvm::io::commit_slice(&public_inputs);
}

#[inline]
fn take_array<const N: usize>(input: &[u8], offset: &mut usize) -> [u8; N] {
    let end = *offset + N;
    let value = input[*offset..end].try_into().unwrap();
    *offset = end;
    value
}

#![no_std]

use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
pub const RETURN_OUTPUT_SIZE: usize = 48;

#[inline]
pub fn sha256(bytes: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[inline]
pub fn block_transition_public_inputs(
    previous_header_hash: &[u8; HASH_SIZE],
    new_header_hash: &[u8; HASH_SIZE],
    config_hash: &[u8; HASH_SIZE],
    custodian_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(previous_header_hash);
    hasher.update(new_header_hash);
    let transition_hash: [u8; HASH_SIZE] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(transition_hash);
    hasher.update(config_hash);
    hasher.update(custodian_hash);
    hasher.finalize().into()
}


/// Input size for the manual-claim guest.
/// 7 * 32B hashes + 2 * 8B u64s = 240 bytes.
pub const MANUAL_CLAIM_INPUT_SIZE: usize = HASH_SIZE * 7 + 8 + 8; // recent_block, auto_claim, old_manual, new_manual, tx_hash, user_ata, custodian + combined_index + amount

/// Input size for the custodian-transition guest.
/// 2 * 48B raw return outputs + 2 * 32B custodian hashes = 160 bytes.
pub const CUSTODIAN_TRANSITION_INPUT_SIZE: usize =
    RETURN_OUTPUT_SIZE + RETURN_OUTPUT_SIZE + HASH_SIZE + HASH_SIZE;

/// Manual-claim PI formula matching on-chain `get_manual_deposit_proof_public_inputs`.
#[inline]
pub fn manual_claim_public_inputs(
    recent_block_merkle_tree_root: &[u8; HASH_SIZE],
    recent_auto_claim_txo_root: &[u8; HASH_SIZE],
    old_manual_claim_deposit_txo_root: &[u8; HASH_SIZE],
    new_manual_claim_txo_root: &[u8; HASH_SIZE],
    tx_hash: &[u8; HASH_SIZE],
    user_ata: &[u8; HASH_SIZE],
    custodian_wallet_config_hash: &[u8; HASH_SIZE],
    combined_txo_index: u64,
    deposit_amount_sats: u64,
) -> [u8; HASH_SIZE] {
    let recent_info = sha256_2to1(recent_block_merkle_tree_root, recent_auto_claim_txo_root);
    let manual_claim_txo_transition =
        sha256_2to1(old_manual_claim_deposit_txo_root, new_manual_claim_txo_root);
    let recent_info_with_user_txo_root = sha256_2to1(&recent_info, &manual_claim_txo_transition);

    let mut hasher = Sha256::new();
    hasher.update(tx_hash);
    hasher.update(user_ata);
    hasher.update(combined_txo_index.to_le_bytes());
    hasher.update(deposit_amount_sats.to_le_bytes());
    let tx_info: [u8; HASH_SIZE] = hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(recent_info_with_user_txo_root);
    hasher.update(tx_info);
    hasher.update(custodian_wallet_config_hash);
    hasher.finalize().into()
}

/// Custodian-transition PI formula matching on-chain
/// `get_custodian_transition_proof_public_inputs`.
/// Takes raw PsyReturnTxOutput bytes (48B each) and hashes internally.
#[inline]
pub fn custodian_transition_public_inputs(
    old_return_output: &[u8; RETURN_OUTPUT_SIZE],
    new_return_output: &[u8; RETURN_OUTPUT_SIZE],
    old_custodian_wallet_config_hash: &[u8; HASH_SIZE],
    new_custodian_wallet_config_hash: &[u8; HASH_SIZE],
) -> [u8; HASH_SIZE] {
    let old_ret_hash = sha256(old_return_output);
    let new_ret_hash = sha256(new_return_output);
    let return_output_transition = sha256_2to1(&old_ret_hash, &new_ret_hash);
    let custodian_transition = sha256_2to1(
        old_custodian_wallet_config_hash,
        new_custodian_wallet_config_hash,
    );
    sha256_2to1(&return_output_transition, &custodian_transition)
}

#[inline]
fn sha256_2to1(a: &[u8; HASH_SIZE], b: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_transition_pi() {
        let zero = [0u8; 32];
        let pi = block_transition_public_inputs(&zero, &zero, &zero, &zero);
        assert_eq!(pi.len(), 32);
    }


    #[test]
    fn test_manual_claim_pi() {
        let zero = [0u8; 32];
        let pi = manual_claim_public_inputs(&zero, &zero, &zero, &zero, &zero, &zero, &zero, 0, 0);
        assert_eq!(pi.len(), 32);
        let pi2 = manual_claim_public_inputs(&zero, &zero, &zero, &zero, &zero, &zero, &zero, 0, 0);
        assert_eq!(pi, pi2);
    }

    #[test]
    fn test_custodian_transition_pi() {
        let zero_hash = [0u8; 32];
        let zero_ret = [0u8; 48];
        let pi = custodian_transition_public_inputs(&zero_ret, &zero_ret, &zero_hash, &zero_hash);
        assert_eq!(pi.len(), 32);
        let pi2 = custodian_transition_public_inputs(&zero_ret, &zero_ret, &zero_hash, &zero_hash);
        assert_eq!(pi, pi2);
    }

    #[test]
    fn test_manual_claim_input_size() {
        assert_eq!(MANUAL_CLAIM_INPUT_SIZE, 240);
    }

    #[test]
    fn test_custodian_transition_input_size() {
        assert_eq!(CUSTODIAN_TRANSITION_INPUT_SIZE, 160);
    }
}

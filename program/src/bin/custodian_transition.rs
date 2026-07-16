#![no_main]
sp1_zkvm::entrypoint!(main);

use psy_bridge_sp1_lib::{
    custodian_transition_public_inputs, CUSTODIAN_TRANSITION_INPUT_SIZE, HASH_SIZE,
    RETURN_OUTPUT_SIZE,
};

pub fn main() {
    let input = sp1_zkvm::io::read_vec();
    assert_eq!(input.len(), CUSTODIAN_TRANSITION_INPUT_SIZE);

    let mut offset = 0;
    let old_return_output = take_array::<RETURN_OUTPUT_SIZE>(&input, &mut offset);
    let new_return_output = take_array::<RETURN_OUTPUT_SIZE>(&input, &mut offset);
    let old_custodian_wallet_config_hash = take_array::<HASH_SIZE>(&input, &mut offset);
    let new_custodian_wallet_config_hash = take_array::<HASH_SIZE>(&input, &mut offset);
    assert_eq!(offset, input.len());

    let public_inputs = custodian_transition_public_inputs(
        &old_return_output,
        &new_return_output,
        &old_custodian_wallet_config_hash,
        &new_custodian_wallet_config_hash,
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

library;

use std::{
    bytes::Bytes,
    string::String,
};

use zap_utils::{
    merkle_utils::{MerkleUtils, V1Predicate, V2Predicate},
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
};

// Tests:
// forc test test_01_v1_addr --logs
#[test()]
fn test_01_v1_addr() {

    // Create v1 predicate instance
    let v1_predicate = V1Predicate::new();

    // Create example bytecode
    let mut wallet_bytecode: Bytes = Bytes::new();
    let mut i = 0;
    while i < 6000 {
        wallet_bytecode.push(1u8);
        i += 1;
    }

    // Example EVM address
    let owner_evm_addr: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

    // Calculate address
    let wallet_addr = v1_predicate.calculate_predicate_address(
        wallet_bytecode,
        owner_evm_addr
    );

    // Expected address
    let expected_addr: b256 = 0x5de5051f6b75a113714aeec6b64ad2d08cf6cd24a5d98780c6b75d5e444fe5a0;

    // Log results
    log(String::from_ascii_str("Computed V1 Address:"));
    log(b256_to_hex(wallet_addr));
    log(String::from_ascii_str("Expected V1 Address:"));
    log(b256_to_hex(expected_addr));

    // Assert the result matches expected
    // assert(wallet_addr == expected_addr);
}


// forc test test_02_v2_addr --logs
#[test()]
fn test_02_v2_addr() {
    // Define the leaf hashes (example values)
    let leaf_hashes: [b256; 8] = [
        0x5a87dc701ab39fcbb7e85d759efa73c4f5117708d5da260438abf29562527f73, // H1
        0xb1801cb3c24946da303cf876e1c53faf93c7254bd6a0f909039ed1b9c046ca78, // H2
        b256::min(), // H3
        b256::min(), // H4
        // Fill the rest of the array with zeros (these will be ignored)
        b256::min(), b256::min(), b256::min(), b256::min(),
    ];

    // pred_root: 097d805ec414b3f26fee4b5cf633cd81cead901425a299b80825ef6d25f1ffa4
    // pred_addr: 5de5051f6b75a113714aeec6b64ad2d08cf6cd24a5d98780c6b75d5e444fe5a0

    // Specify the actual number of leaves (4 in this case)
    let num_leaves = 2;
    let swap_position = 200;
    let evm_addr: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

    let mut final_leaf_bytes: Bytes = Bytes::new();
    let mut a = 600;
    while a > 0 {
        final_leaf_bytes.push(1u8);
        a -= 1;
    }

    // Compute the Merkle root from the leaf hashes
    // let computed_root = get_merkle_root_from_leaf_hashes(leaf_hashes, num_leaves);

    let v2_predicate = V2Predicate::new(leaf_hashes, num_leaves, swap_position);
    let v2_address = v2_predicate.calculate_predicate_address(final_leaf_bytes, evm_addr);

    // Expected v2 address
    let expected_addr: b256 = 0x5de5051f6b75a113714aeec6b64ad2d08cf6cd24a5d98780c6b75d5e444fe5a0;

    // Log the computed and expected roots for debugging
    log(String::from_ascii_str("Computed V2 Address:"));
    log(b256_to_hex(v2_address));
    log(String::from_ascii_str("Expected V2 Address:"));
    log(b256_to_hex(expected_addr));

    // Assert that the computed root matches the expected root
    // assert_eq(computed_root, expected_root);
}

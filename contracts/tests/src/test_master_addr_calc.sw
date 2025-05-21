library;

use std::{
    bytes::Bytes,
    string::String,
};
use zap_utils::{
    merkle_utils::{MerkleUtils, V1Predicate, V2Predicate},
    merkle_utils::{calculate_leaf_hash, calculate_predi_addr_from_root},
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
    blob_utils::*,
};


// forc test test_87_v1_blob_addr --logs
#[test()]
fn test_87_v1_blob_addr() {

    let mut known_custom_loader_hex_string = String::from_ascii_str("1a403000504100301a445000ba49000032400481504100205d490000504100083240048220451300524510044a44000000938064c3f312f0030a8af7b51114dba5c7163fd0306f92334885e448a351190000000000000280657f2e0854ae306a93f94d17ba327713df902785f98bed3cae4e61296c14dc4b326b30f851a788d310c21e782e9d36d2668494e27311b0824839f806c7e3fcc625dd773665a535982f504592f3034fcbc98ee4198ffbfd0302faf1b2b3da61be17a83329a497a44d604ecf8839438c1e6d7269f2457d00e872b020c460f2a9164d51057b96b023e9ee865ee8fcc086eb7bb880ac3538197e0b3611ae055267655267d6e84c37cd3905ddee2b6d86cf1d167933a16c76e808493545b7f0f61d15f0d7adbb9179766fb920ab789eebb6fb0a9b03109c7c477fc557674660111b8aa5bbbe3cf28ce1f64deb90e49aabf0fd82453b5335c1ad7813507753d3b4aa256270cc8e631ba8609793e161f22303aa9aca42449d061b19dc7b897e546f0968281dd8a997254988768837d99f1c75f0268a7ddf60f9bd7978e2995b4b1474b6d157213dce5a83d615f35791f6357d5af64781e262deceb6adffeaf3dd588317573c39518c5899dd17476162dccf4a95350bba296981bd1ae953c334348e3a9f098fc34e0b1f1b2122ffa3b1a1fffd8affd0e68b8ea7940c0f80e64ed67bedddddf052ef1a25e40d873afea6e959490de0b6e5cef53e405aa0ee6edbb38f179c59364d36469722d848419ca0d5ed868ee89fcb92a185479cdd76d9acf763a67344bcb3a988b63b8aa05ac1638ede8d2199206df3f36e8b2b7515b020bbbecd61e09f517a8274f139b516226248115fdb6fae1eee6e12e0c1f3bd939eaa926163e6968611d410dc000dbc31cda278f62534eb225c720f59f2f8b9ab0508c0dd04000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14646576656c6f706d656e7400000000000000000000000000000076302e312e37");
    let known_custom_loader = hex_string_to_bytes(known_custom_loader_hex_string).unwrap();

    let code_root = calculate_simple_merkle_root(known_custom_loader);

    // Code root
    let expected_code_root: b256 = 0x297e274e761e83498645f3b3a5e02405f94a613240d11a0d6e7e0deef73ec594;
    log(String::from_ascii_str("Code Root:"));
    log(b256_to_hex(code_root));
    assert_eq(expected_code_root, code_root);

    let bp_addr = calculate_simple_merkle_predicate(known_custom_loader);
    // Blob Predicate addr
    let expected_bp_addr: b256 = 0xe040d1311403871cc748b791c97faf9d7ebbc8d670c2fa5b747f764a401e612a;
    log(String::from_ascii_str("Blob Predicate addr:"));
    log(b256_to_hex(bp_addr));
    assert_eq(expected_bp_addr, bp_addr);

}

// forc test test_88_v1_blob_addr --logs
#[test()]
fn test_88_v1_blob_addr() {

    // Add loader instructions
    let instructions_bytes_hex = String::from_ascii_str("1a403000504100301a445000ba49000032400481504100205d490000504100083240048220451300524510044a440000");
    let instructions_bytes = hex_string_to_bytes(instructions_bytes_hex).unwrap();
    let mut custom_loader = Bytes::new();
    custom_loader.append(
        instructions_bytes
    );
    // Add Master Blob ID
    let master_blob_id: b256 = 0x00938064c3f312f0030a8af7b51114dba5c7163fd0306f92334885e448a35119;
    custom_loader.append(
        master_blob_id.to_be_bytes()
    );
    // Add Section length
    let section_length: u64 = 640;
    custom_loader.append(
        section_length.to_be_bytes()
    );

    let module00_assetid: b256 = 0x657f2e0854ae306a93f94d17ba327713df902785f98bed3cae4e61296c14dc4b;
    let module01_assetid: b256 = 0x326b30f851a788d310c21e782e9d36d2668494e27311b0824839f806c7e3fcc6;
    let module02_assetid: b256 = 0x25dd773665a535982f504592f3034fcbc98ee4198ffbfd0302faf1b2b3da61be;
    let module03_assetid: b256 = 0x17a83329a497a44d604ecf8839438c1e6d7269f2457d00e872b020c460f2a916;
    let module04_assetid: b256 = 0x4d51057b96b023e9ee865ee8fcc086eb7bb880ac3538197e0b3611ae05526765;
    let module05_assetid: b256 = 0x5267d6e84c37cd3905ddee2b6d86cf1d167933a16c76e808493545b7f0f61d15;
    let module06_assetid: b256 = 0xf0d7adbb9179766fb920ab789eebb6fb0a9b03109c7c477fc557674660111b8a;
    let module07_assetid: b256 = 0xa5bbbe3cf28ce1f64deb90e49aabf0fd82453b5335c1ad7813507753d3b4aa25;
    let module08_assetid: b256 = 0x6270cc8e631ba8609793e161f22303aa9aca42449d061b19dc7b897e546f0968;

    let module00_addr: b256 = 0x281dd8a997254988768837d99f1c75f0268a7ddf60f9bd7978e2995b4b1474b6;
    let module01_addr: b256 = 0xd157213dce5a83d615f35791f6357d5af64781e262deceb6adffeaf3dd588317;
    let module02_addr: b256 = 0x573c39518c5899dd17476162dccf4a95350bba296981bd1ae953c334348e3a9f;
    let module03_addr: b256 = 0x098fc34e0b1f1b2122ffa3b1a1fffd8affd0e68b8ea7940c0f80e64ed67beddd;
    let module04_addr: b256 = 0xddf052ef1a25e40d873afea6e959490de0b6e5cef53e405aa0ee6edbb38f179c;
    let module05_addr: b256 = 0x59364d36469722d848419ca0d5ed868ee89fcb92a185479cdd76d9acf763a673;
    let module06_addr: b256 = 0x44bcb3a988b63b8aa05ac1638ede8d2199206df3f36e8b2b7515b020bbbecd61;
    let module07_addr: b256 = 0xe09f517a8274f139b516226248115fdb6fae1eee6e12e0c1f3bd939eaa926163;
    let module08_addr: b256 = 0xe6968611d410dc000dbc31cda278f62534eb225c720f59f2f8b9ab0508c0dd04;

    let owner_pubkey: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;
    let master_version: b256 = 0x646576656c6f706d656e7400000000000000000000000000000076302e312e37;
    let mut configurables_bytes = Bytes::new();
    configurables_bytes.append(module00_assetid.to_be_bytes());
    configurables_bytes.append(module01_assetid.to_be_bytes());
    configurables_bytes.append(module02_assetid.to_be_bytes());
    configurables_bytes.append(module03_assetid.to_be_bytes());
    configurables_bytes.append(module04_assetid.to_be_bytes());
    configurables_bytes.append(module05_assetid.to_be_bytes());
    configurables_bytes.append(module06_assetid.to_be_bytes());
    configurables_bytes.append(module07_assetid.to_be_bytes());
    configurables_bytes.append(module08_assetid.to_be_bytes());

    configurables_bytes.append(module00_addr.to_be_bytes());
    configurables_bytes.append(module01_addr.to_be_bytes());
    configurables_bytes.append(module02_addr.to_be_bytes());
    configurables_bytes.append(module03_addr.to_be_bytes());
    configurables_bytes.append(module04_addr.to_be_bytes());
    configurables_bytes.append(module05_addr.to_be_bytes());
    configurables_bytes.append(module06_addr.to_be_bytes());
    configurables_bytes.append(module07_addr.to_be_bytes());
    configurables_bytes.append(module08_addr.to_be_bytes());

    configurables_bytes.append(owner_pubkey.to_be_bytes());
    configurables_bytes.append(master_version.to_be_bytes());

    // Add Configurables
    custom_loader.append(
        configurables_bytes
    );

    // Code root
    let code_root = calculate_simple_merkle_root(custom_loader);
    log(String::from_ascii_str("Code Root:"));
    log(b256_to_hex(code_root));

    // Blob Predicate addr
    let bp_addr = calculate_simple_merkle_predicate(custom_loader);
    log(String::from_ascii_str("Blob Predicate addr:"));
    log(b256_to_hex(bp_addr));

    let expected_code_root: b256 = 0x297e274e761e83498645f3b3a5e02405f94a613240d11a0d6e7e0deef73ec594;
    assert_eq(expected_code_root, code_root);

    let expected_bp_addr: b256 = 0xe040d1311403871cc748b791c97faf9d7ebbc8d670c2fa5b747f764a401e612a;
    assert_eq(expected_bp_addr, bp_addr);

}


// Tests:
// forc test test_89_blobutils_addr --logs
#[test()]
fn test_89_blobutils_addr() {

    // Add Master Blob ID
    let master_blob_id: b256 = 0x00938064c3f312f0030a8af7b51114dba5c7163fd0306f92334885e448a35119;

    let module00_assetid: b256 = 0x657f2e0854ae306a93f94d17ba327713df902785f98bed3cae4e61296c14dc4b;
    let module01_assetid: b256 = 0x326b30f851a788d310c21e782e9d36d2668494e27311b0824839f806c7e3fcc6;
    let module02_assetid: b256 = 0x25dd773665a535982f504592f3034fcbc98ee4198ffbfd0302faf1b2b3da61be;
    let module03_assetid: b256 = 0x17a83329a497a44d604ecf8839438c1e6d7269f2457d00e872b020c460f2a916;
    let module04_assetid: b256 = 0x4d51057b96b023e9ee865ee8fcc086eb7bb880ac3538197e0b3611ae05526765;
    let module05_assetid: b256 = 0x5267d6e84c37cd3905ddee2b6d86cf1d167933a16c76e808493545b7f0f61d15;
    let module06_assetid: b256 = 0xf0d7adbb9179766fb920ab789eebb6fb0a9b03109c7c477fc557674660111b8a;
    let module07_assetid: b256 = 0xa5bbbe3cf28ce1f64deb90e49aabf0fd82453b5335c1ad7813507753d3b4aa25;
    let module08_assetid: b256 = 0x6270cc8e631ba8609793e161f22303aa9aca42449d061b19dc7b897e546f0968;

    let module00_addr: b256 = 0x281dd8a997254988768837d99f1c75f0268a7ddf60f9bd7978e2995b4b1474b6;
    let module01_addr: b256 = 0xd157213dce5a83d615f35791f6357d5af64781e262deceb6adffeaf3dd588317;
    let module02_addr: b256 = 0x573c39518c5899dd17476162dccf4a95350bba296981bd1ae953c334348e3a9f;
    let module03_addr: b256 = 0x098fc34e0b1f1b2122ffa3b1a1fffd8affd0e68b8ea7940c0f80e64ed67beddd;
    let module04_addr: b256 = 0xddf052ef1a25e40d873afea6e959490de0b6e5cef53e405aa0ee6edbb38f179c;
    let module05_addr: b256 = 0x59364d36469722d848419ca0d5ed868ee89fcb92a185479cdd76d9acf763a673;
    let module06_addr: b256 = 0x44bcb3a988b63b8aa05ac1638ede8d2199206df3f36e8b2b7515b020bbbecd61;
    let module07_addr: b256 = 0xe09f517a8274f139b516226248115fdb6fae1eee6e12e0c1f3bd939eaa926163;
    let module08_addr: b256 = 0xe6968611d410dc000dbc31cda278f62534eb225c720f59f2f8b9ab0508c0dd04;

    let owner_pubkey: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

    // Setup Configurables
    let mut configurables_bytes = Bytes::new();
    configurables_bytes.append(module00_assetid.to_be_bytes());
    configurables_bytes.append(module01_assetid.to_be_bytes());
    configurables_bytes.append(module02_assetid.to_be_bytes());
    configurables_bytes.append(module03_assetid.to_be_bytes());
    configurables_bytes.append(module04_assetid.to_be_bytes());
    configurables_bytes.append(module05_assetid.to_be_bytes());
    configurables_bytes.append(module06_assetid.to_be_bytes());
    configurables_bytes.append(module07_assetid.to_be_bytes());
    configurables_bytes.append(module08_assetid.to_be_bytes());

    configurables_bytes.append(module00_addr.to_be_bytes());
    configurables_bytes.append(module01_addr.to_be_bytes());
    configurables_bytes.append(module02_addr.to_be_bytes());
    configurables_bytes.append(module03_addr.to_be_bytes());
    configurables_bytes.append(module04_addr.to_be_bytes());
    configurables_bytes.append(module05_addr.to_be_bytes());
    configurables_bytes.append(module06_addr.to_be_bytes());
    configurables_bytes.append(module07_addr.to_be_bytes());
    configurables_bytes.append(module08_addr.to_be_bytes());

    let master_blob_info = MasterBlob {
        blob_id: master_blob_id,
        section_len: 640,
        configurables: configurables_bytes,
        owner_addr: owner_pubkey,
    };

    // Blob Predicate addr
    let bp_addr = calculate_master_blob_addr(master_blob_info);
    log(String::from_ascii_str("Blob Predicate addr:"));
    log(b256_to_hex(bp_addr));

    let expected_bp_addr: b256 = 0xe040d1311403871cc748b791c97faf9d7ebbc8d670c2fa5b747f764a401e612a;
    assert_eq(expected_bp_addr, bp_addr);

}



/// Calculates a simple merkle root from a single leaf.
///
/// # Arguments
///
/// * `single_leaf` - The bytes of the single leaf.
///
/// # Returns
///
/// * [b256] - The calculated merkle root.
///
pub fn calculate_simple_merkle_root(single_leaf: Bytes) -> b256 {
    // First calculate the leaf hash with the leaf prefix
    let leaf_hash = calculate_leaf_hash(single_leaf);

    // For a single leaf, the leaf hash is the merkle root
    // No further combining is needed since there are no pairs

    // Return the leaf hash as the root
    leaf_hash
}

/// Calculates a simple merkle root and predicate address from a single leaf.
///
/// # Arguments
///
/// * `single_leaf` - The bytes of the single leaf.
///
/// # Returns
///
/// * [b256] - The calculated predicate address.
///
pub fn calculate_simple_merkle_predicate(single_leaf: Bytes) -> b256 {
    // First calculate the leaf hash with the leaf prefix
    let leaf_hash = calculate_leaf_hash(single_leaf);

    // For a single leaf, the leaf hash is the merkle root
    // Calculate the predicate address from this root
    calculate_predi_addr_from_root(leaf_hash)
}
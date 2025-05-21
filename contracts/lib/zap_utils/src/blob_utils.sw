library;

use std::{
    bytes::Bytes,
    string::String,
};
use ::{
    merkle_utils::{calculate_leaf_hash, calculate_predi_addr_from_root},
    hex::*,
    string_helpers::*,
};

pub struct MasterBlob {
    pub blob_id: b256,
    pub section_len: u64,
    pub configurables: Bytes,
    pub owner_addr: b256,
}

pub const MASTER_V1_VERSION: b256 = 0x646576656c6f706d656e7400000000000000000000000000000076302e312e37;


pub fn calculate_master_blob_addr(blob_info: MasterBlob) -> b256 {

    // Add loader instructions
    let instructions_bytes_hex = String::from_ascii_str("1a403000504100301a445000ba49000032400481504100205d490000504100083240048220451300524510044a440000");
    let instructions_bytes = hex_string_to_bytes(instructions_bytes_hex).unwrap();
    let mut custom_loader = Bytes::new();
    custom_loader.append(
        instructions_bytes
    );
    // Add Master Blob ID
    custom_loader.append(
        blob_info.blob_id.to_be_bytes()
    );
    // Add Section length
    let section_length: u64 = 640;
    custom_loader.append(
        section_length.to_be_bytes()
    );
    // Add Configurables
    custom_loader.append(blob_info.configurables);
    // Add owner address
    custom_loader.append(blob_info.owner_addr.to_be_bytes());
    // Add master version
    custom_loader.append(MASTER_V1_VERSION.to_be_bytes());

    // Calculate predicate addr
    calculate_simple_merkle_predicate(custom_loader)
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
fn calculate_simple_merkle_predicate(single_leaf: Bytes) -> b256 {
    // First calculate the leaf hash with the leaf prefix
    let leaf_hash = calculate_leaf_hash(single_leaf);

    // For a single leaf, the leaf hash is the merkle root
    // Calculate the predicate address from this root
    calculate_predi_addr_from_root(leaf_hash)
}


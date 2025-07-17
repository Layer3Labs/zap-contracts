library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    vm::evm::evm_address::EvmAddress,
};

use std::*;
use std::bytes_conversions::{u64::*, b256::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use ::rlp_helpers::*;

const LEAF_PREFIX: u64 = 0;
#[allow(dead_code)]
const NODE_PREFIX: u64 = 1;


/// Calculates the hash of a leaf by prepending a leaf prefix to the input data.
///
/// # Arguments
///
/// * `data` - The bytes to be hashed.
///
/// # Returns
///
/// * [b256] - The SHA-256 hash of the prefixed data.
///
pub fn calculate_leaf_hash(data: Bytes) -> b256 {

    let mut j = 0;

    let mut leafbytes = Bytes::new();
    leafbytes.push(LEAF_PREFIX.try_as_u8().unwrap());
    j = 0;
    let data_len = data.len();
    while j < (data_len) {
        leafbytes.push(data.get(j).unwrap());
        j += 1;
    }
    let chunk_hash = hash_bytes_sha256(leafbytes);

    chunk_hash
}

/// Calculates a predicate address from a 32-byte root by prepending a contract ID seed.
///
/// # Arguments
///
/// * `digest` - The 32-byte root value.
///
/// # Returns
///
/// * [b256] - The SHA-256 hash of the seeded root value.
///
pub fn calculate_predi_addr_from_root(digest: b256) -> b256 {
    let root_bytes: Bytes = Bytes::from(digest);
    // let mut result_buffer = b256::min();
    let mut bytes_to_hash = Bytes::new();
    let contractid_seed = [0x46u8, 0x55u8, 0x45u8, 0x4Cu8];
    let mut i = 0;
    while i < 4 {
        bytes_to_hash.push(contractid_seed[i]);
        i += 1;
    };
    let mut j = 0;
    while j < (32u64) {
        bytes_to_hash.push(root_bytes.get(j).unwrap());
        j += 1;
    }
    return(hash_bytes_sha256(bytes_to_hash));
}

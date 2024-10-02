library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    vm::evm::evm_address::EvmAddress,
};

use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

const LEAF_SIZE: u64 = 16 * 1024;
const PADDING_BYTE: u8 = 0u8;
const MULTIPLE: u64 = 8;
const LEAF_PREFIX: u64 = 0;
const NODE_PREFIX: u64 = 1;


pub fn get_predi_addr_from_bytes(data: Bytes) -> b256 {
    let calcd_addr = get_predi_addr_from_root(
        get_merkle_root(data)
    );
    calcd_addr
}

/// Calculate merkle root from bytes.
//FIXME - UNTESTED - Work in Progress.
//FIXME - routine breaks for > 131KB
pub fn get_merkle_root(data: Bytes) -> b256 {
    let data_len = data.len();
    let mut tree_hashes: [b256; 64] = [b256::min(); 64]; // hard max 64 leaves
    let mut tree_size: u64 = 0;
    let mut i = 0u64;
    while i < data_len {
        let chunk_size = if LEAF_SIZE < (data_len - i) {
            LEAF_SIZE
        } else {
            data_len - i
        };
        let mut chunk = [0u8; 16384];
        let mut j = 0;
        while j < chunk_size {
            chunk[j] = data.get(i + j).unwrap();
            j += 1;
        }
        let mut amount_to_add: u64 = 0;
        if chunk_size % MULTIPLE != 0 {
            let padded_size = ((chunk_size + MULTIPLE - 1) / MULTIPLE) * MULTIPLE;
            amount_to_add = padded_size - chunk_size;
            j = chunk_size;
            while j < padded_size {
                chunk[j] = PADDING_BYTE;
                j += 1;
            }
        }
        let new_len = (chunk_size + amount_to_add);
        let chunk_slice = raw_slice::from_parts::<u8>(__addr_of(chunk), new_len);
        let mut bytes = Bytes::from(chunk_slice);
        let mut leafbytes = Bytes::new();
        leafbytes.push(LEAF_PREFIX.try_as_u8().unwrap());
        j = 0;
        let data_len = bytes.len();
        while j < (data_len) {
            leafbytes.push(bytes.get(j).unwrap());
            j += 1;
        }
        let chunk_hash = sha256_digest(leafbytes);
        tree_hashes[tree_size] = chunk_hash;
        tree_size += 1;
        i += LEAF_SIZE;
    }
    while tree_size > 1 {
        let mut next_tree_size = 0;
        let mut j = 0;
        while j < tree_size - 1 {
            let com0to31 = Bytes::from(tree_hashes[j]);
            let com32to63 = Bytes::from(tree_hashes[j + 1]);
            let mut combined_bytes = Bytes::new();
            combined_bytes.push(NODE_PREFIX.try_as_u8().unwrap());
            let mut k = 0;
            while k < 32 {
                combined_bytes.push(com0to31.get(k).unwrap());
                k += 1;
            }
            k = 0;
            while k < 32 {
                combined_bytes.push(com32to63.get(k).unwrap());
                k += 1;
            }
            tree_hashes[next_tree_size] = sha256_digest(combined_bytes);
            next_tree_size += 1;
            j += 2;
        }
        if tree_size % 2 != 0 {
            tree_hashes[next_tree_size] = tree_hashes[tree_size - 1];
            next_tree_size += 1;
        }
        tree_size = next_tree_size;
    }
    return tree_hashes[0];
}

/// calculate the predicate address from the 32-byte root.
pub fn get_predi_addr_from_root(digest: b256) -> b256 {
    let root_bytes: Bytes = Bytes::from(digest);
    let mut result_buffer = b256::min();
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
    return(sha256_digest(bytes_to_hash));
}


pub fn sha256_digest(bytes_to_hash: Bytes) -> b256 {
    let mut result_buffer = b256::min();

    let len = bytes_to_hash.len();
    let a_size = len + 1;
    let a_buflen = a_size - 1;
    let x_src = bytes_to_hash.ptr();
    asm(
        hash: result_buffer,            // result buffer.
        ptrdata: x_src,                 // the payload data bytes.
        length: a_buflen,               // the length of the payload data.
        size: a_size,                   // the size of the buffer to alloc on stack.
        buflen: a_buflen,               // the size of the buffer to hash.
        memptr                          //
        ) {
        aloc size;                              // allocate memory to the stack
        addi memptr hp i1;                      // increase memory pointer for copying payload items
        mcp  memptr ptrdata length;             // copy
        addi memptr hp i1;                      // move memory pointer back to the beginning
        s256 hash memptr buflen;
        hash: b256
    };
    return(result_buffer);
}






// Test
// get the predicate address from its bytecode.
#[test()]
fn test_get_predi_addr_from_bytes(){

    // the below tests multiple leaves. make a predicate that is just full of 0xff's as bytecode, but
    // specify the length of the predicate bytecode, the boundary for a leaf is 16KB (16384 bytes).

    // leaf hash 7bf2a906bb353d0bf26de581fdae34b8a189b6f7b738c2714ad6f855475d0de8
    // addr: 520db4939794a49fce6dbacf7181877023cdd9280142ee2a67e7606da7e2422b
    // this is a full leaf
    let testbytes = make_ff_bytes_to_len(16384);
    let pred_root = get_merkle_root(testbytes);
    let pred_addr = get_predi_addr_from_root(pred_root);
    let paddr: b256 = 0x520db4939794a49fce6dbacf7181877023cdd9280142ee2a67e7606da7e2422b;
    assert_eq(paddr, pred_addr);

    // leaf hash
    // this is a full leaf of 0xff's + another leaf containing only ff00000000000000 (excluding leaf prefix)
    // two leaves total.
    // 1st leaf hash: 7bf2a906bb353d0bf26de581fdae34b8a189b6f7b738c2714ad6f855475d0de8
    // 2nd leaf hash: a0ef68a7875c94fe6e0060a37314c25ebd162cac3f9ff3f926eec89a8642bfdc
    // add the node prefix (0x01)
    // 017bf2a906bb353d0bf26de581fdae34b8a189b6f7b738c2714ad6f855475d0de8a0ef68a7875c94fe6e0060a37314c25ebd162cac3f9ff3f926eec89a8642bfdc
    // node hash: bd40b2ac475d60b49c7c92c3c2f79c44f71093e5bb6cd4755505a8b5d8357fe9
    // addr: 6b8113fc6e3d2ab90f45ea7959898bfb1f9cccdf61a19f242c84e59ca729e3c9
    let testbytes = make_ff_bytes_to_len(16385);
    let pred_root = get_merkle_root(testbytes);
    let pred_addr = get_predi_addr_from_root(pred_root);
    let paddr: b256 = 0x6b8113fc6e3d2ab90f45ea7959898bfb1f9cccdf61a19f242c84e59ca729e3c9;
    assert_eq(paddr, pred_addr);

    // pred_root: da361ef46053498cdac7f3a7da9dc1dc09ce34773697fb52d7c44ba9ee1bbeb2
    // pred_addr: 3e11c04acfdf8bd10b262b6f7799e7a29dc7e93aaf607d15b581ed8a8504278d
    // uses 35923567 gas (~0.0359 GWei)
    let testbytes = make_ff_bytes_to_len((16384 * 4));
    let pred_root = get_merkle_root(testbytes);
    let pred_addr = get_predi_addr_from_root(pred_root);
    let paddr: b256 = 0x3e11c04acfdf8bd10b262b6f7799e7a29dc7e93aaf607d15b581ed8a8504278d;
    assert_eq(paddr, pred_addr);

}

// test helper
fn make_ff_bytes_to_len(byte_length: u64) -> Bytes {
    let mut predi_bytes = Bytes::new();
    let mut j = 0;
    while j < (byte_length) {
        predi_bytes.push(0xffu8);
        j += 1;
    }
    predi_bytes
}
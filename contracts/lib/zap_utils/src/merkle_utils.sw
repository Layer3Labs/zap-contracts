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

// const LEAF_SIZE: u64 = 16 * 1024;
// const PADDING_BYTE: u8 = 0u8;
// const MULTIPLE: u64 = 8;
const LEAF_PREFIX: u64 = 0;
const NODE_PREFIX: u64 = 1;



// ------------------------------
// only for debug
use helpers::{
    general_helpers::*,
    hex::*,
    numeric_utils::*,
};
// ------------------------------





/// Return the master address of a V1 ZapWallet, by calculating the master address from
/// the receiver's bytecode and given EVM address.
///
/// # Arguments
///
/// * `receiver_code` - The bytecode of the receiver's ZapWallet as mutable Bytes
/// * `receiver_evm_addr` - The EVM address (as b256).
///
/// # Returns
///
/// * `b256` - Returns the V1 ZapWallet address that was calculated.
///
/// The function works by:
/// 1. Swapping in the EVM address at a specific position in the bytecode.
/// 2. Calculating the master address from the modified bytecode.
///
pub fn get_zapwallet_address_from_code(
    ref mut receiver_code: Bytes,
    receiver_evm_addr: b256,
) -> b256 {

    // let swap_position = 8208u64;        // Position to swap at
    // let swap_position = 8528u64;        // Position to swap at - debug
    // let swap_position = 3576u64;        // Position to swap at - release

    let receiver_master_addr = get_master_addr_with_right_leaf_bytes(
        receiver_code,
        receiver_evm_addr,
        // swap_position
    );

    // if receiving_addr == receiver_master_addr {
    //     return true;
    // }
    // return false;

    //NOTE - DEBUG
    // return true;

    receiver_master_addr
}


///
pub fn get_master_addr_with_right_leaf_bytes(
    ref mut right_bytes: Bytes,
    swap_value: b256,
    // swap_position: u64
) -> b256 {

    // Add left leaf hash bytes
    //REVIEW - This is the left leaf hash for a debug build of Master.
    // let left_hash: b256 = 0x59fae45635d0f7f560d4fbfe02899305e2d5e7d16e864eb5e506c46b85dd3223;

    //REVIEW - OG - This is the left leaf hash for a release build of Master.
    // let left_hash: b256 = 0x03c0ca1ee820cc8d85c0082e4a7b1b091b1ec6a06ad5bdcb4153d9b0d5c0e78d;
    // let swap_position = 3576u64;        // Position to swap at - release


    //REVIEW - This is the left leaf hash for a release build of Master.
    let left_hash: b256 = 0x887f618e0e5af1cc4ff0269243f7ce0dc8f0a8e2d240a62027fd2be36e805110;
    let swap_position = 3600u64;        // Position to swap at - release



    // First perform the swap in the OWNER PUBKEY bytes
    let swap_success = swap_bytes_at_position(
        right_bytes,
        swap_position,
        swap_value
    );

    // Return zero hash if swap failed
    if !swap_success {
        return b256::min();
    }

    // Calculate the right leaf hash with the swapped OWNER PUBKEY bytes
    let right_leaf_hash = get_leaf_hash(right_bytes);

    // Combine the left and right leaf hashes with node prefix
    let mut combined_bytes = Bytes::new();
    combined_bytes.push(NODE_PREFIX.try_as_u8().unwrap()); // Add prefix 0x01 for node

    let left_bytes = Bytes::from(left_hash);
    let mut i = 0;
    while i < 32 {
        combined_bytes.push(left_bytes.get(i).unwrap());
        i += 1;
    }
    // Add right leaf hash bytes
    let right_bytes = Bytes::from(right_leaf_hash);
    i = 0;
    while i < 32 {
        combined_bytes.push(right_bytes.get(i).unwrap());
        i += 1;
    }

    // Calculate and return root hash
    let root = sha256_digest(combined_bytes);
    get_predi_addr_from_root(root)
}


pub fn get_leaf_hash(data: Bytes) -> b256 {

    let mut j = 0;

    let mut leafbytes = Bytes::new();
    leafbytes.push(LEAF_PREFIX.try_as_u8().unwrap());
    j = 0;
    let data_len = data.len();
    while j < (data_len) {
        leafbytes.push(data.get(j).unwrap());
        j += 1;
    }
    let chunk_hash = sha256_digest(leafbytes);

    chunk_hash
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



//-------------------------------------------------------------------------

pub fn get_v2master_addr_leaf_hash_and_bytes(
    ref mut leaf_hashes: [b256; 8],
    num_leaves: u64,
    ref mut final_leaf_bytes: Bytes,
    final_leaf_position: u64,
    swap_value: b256,
    swap_position: u64,
) -> b256 {

    // Add left leaf hash bytes
    //REVIEW - This is the left leaf hash for a debug build of Master.
    // let left_hash: b256 = 0x59fae45635d0f7f560d4fbfe02899305e2d5e7d16e864eb5e506c46b85dd3223;

    //REVIEW - OG - This is the left leaf hash for a release build of Master.
    // let left_hash: b256 = 0x03c0ca1ee820cc8d85c0082e4a7b1b091b1ec6a06ad5bdcb4153d9b0d5c0e78d;
    // let swap_position = 3576u64;        // Position to swap at - release


    //REVIEW - This is the left leaf hash for a release build of Master.
    // let left_hash: b256 = 0x887f618e0e5af1cc4ff0269243f7ce0dc8f0a8e2d240a62027fd2be36e805110;
    // let swap_position = 3600u64;        // Position to swap at - release


    // First perform the swap in the OWNER PUBKEY bytes
    let swap_success = swap_bytes_at_position(
        final_leaf_bytes,
        swap_position,
        swap_value
    );

    // Return zero hash if swap failed
    if !swap_success {
        return b256::min();
    }

    // Calculate the right leaf hash with the swapped OWNER PUBKEY bytes
    let final_leaf_hash = get_leaf_hash(final_leaf_bytes);
    let final_leaf_hash: b256 = 0xe85ee99f4887c5ea53be14a833bbe383059b0a1af80f159b517e1983e178f220;

    // place the final leaf hash into its position
    leaf_hashes[final_leaf_position] = final_leaf_hash;

    //------------------------------------
    //NOTE - DEBUG
    let mut i = 0u64;
    while i < 8 {
        log(u256_to_hex(asm(r1: (0, 0, 0, i)) { r1: u256 }));
        log(b256_to_hex(leaf_hashes[i]));
        i += 1;
    }
    //------------------------------------


    // Calculate and return root hash
    let root = get_merkle_root_from_leaf_hashes(leaf_hashes, num_leaves);

    get_predi_addr_from_root(root)
}

/// restricted to 8 lots of LEAF_SIZE,
pub fn get_merkle_root_from_leaf_hashes(leaf_hashes: [b256; 8], num_leaves: u64) -> b256 {
    let mut tree_hashes = leaf_hashes;
    let mut tree_size = num_leaves;

    // Build the Merkle tree
    while tree_size > 1 {
        let mut next_tree_size = 0u64;
        let mut j = 0u64;

        // Process pairs of hashes
        while j < tree_size - 1 {
            let left_hash = tree_hashes[j];
            let right_hash = tree_hashes[(j + 1)];

            // Combine hashes with NODE_PREFIX
            let mut combined_bytes = Bytes::new();
            combined_bytes.push(NODE_PREFIX.try_as_u8().unwrap());

            // Add left hash bytes
            let left_bytes = left_hash.to_be_bytes();
            let mut k = 0;
            while k < 32 {
                combined_bytes.push(left_bytes.get(k).unwrap());
                k += 1;
            }

            // Add right hash bytes
            let right_bytes = right_hash.to_be_bytes();
            k = 0;
            while k < 32 {
                combined_bytes.push(right_bytes.get(k).unwrap());
                k += 1;
            }

            // Compute the parent hash
            tree_hashes[next_tree_size] = sha256_digest(combined_bytes);
            next_tree_size += 1;
            j += 2;
        }

        // If there's an odd number of hashes, carry over the last one
        if tree_size % 2 != 0 {
            tree_hashes[next_tree_size] = tree_hashes[(tree_size - 1)];
            next_tree_size += 1;
        }

        // Update tree_size for the next level
        tree_size = next_tree_size;
    }

    // The Merkle root is the first element in tree_hashes
    tree_hashes[0]
}



//FIXME - move to helpers or use Hash
fn sha256_digest(bytes_to_hash: Bytes) -> b256 {
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

fn swap_bytes_at_position(ref mut data: Bytes, position: u64, new_bytes: b256) -> bool {
    // Check if position is valid (there must be 32 bytes after position)
    if position + 32 > data.len() {
        return false;
    }

    // Convert b256 to Bytes to get the new bytes
    let swap_bytes = Bytes::from(new_bytes);

    // We know swap_bytes is exactly 32 bytes since it comes from b256
    let mut i = 0;
    while i < 32 {
        let curr_pos = position + i;
        // Get current byte
        let temp = data.get(curr_pos).unwrap();
        // Set new byte
        data.set(curr_pos, swap_bytes.get(i).unwrap());
        i += 1;
    }

    true
}


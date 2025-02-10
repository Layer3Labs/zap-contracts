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

use zapwallet_consts::wallet_consts::{V1_SWAP_POSITION, V1_LEFT_LEAF_HASH};
use ::rlp_helpers::*;

// const LEAF_SIZE: u64 = 16 * 1024;
// const PADDING_BYTE: u8 = 0u8;
// const MULTIPLE: u64 = 8;
const LEAF_PREFIX: u64 = 0;
const NODE_PREFIX: u64 = 1;


/// Struct representing a V1 ZapWallet predicate
pub struct V1Predicate { }

/// Struct representing a V2 ZapWallet predicate with up to 8 leaves
pub struct V2Predicate {
    leaf_hashes: [b256; 8],
    num_leaves: u64,
    swap_position: u64,
}

impl V1Predicate {

    /// Creates a new V1Predicate with the given parameters
    ///
    /// # Arguments
    ///
    /// * `left_leaf_hash` - The hash of the left leaf
    /// * `swap_position` - The position where EVM address should be swapped
    ///
    // pub fn new(left_leaf_hash: b256, swap_position: u64) -> Self {
    //     Self {
    //         left_leaf_hash,
    //         swap_position,
    //     }
    // }
    pub fn new() -> Self {
        Self {}
    }
}

impl V2Predicate {

    /// Creates a new V2Predicate with the given parameters
    ///
    /// # Arguments
    ///
    /// * `leaf_hashes` - Array of initial leaf hashes
    /// * `num_leaves` - Total number of leaves
    /// * `swap_position` - Position for EVM address swap
    ///
    pub fn new(leaf_hashes: [b256; 8], num_leaves: u64, swap_position: u64) -> Self {
        Self {
            leaf_hashes,
            num_leaves,
            swap_position,
        }
    }

}

/// Trait for merkle tree utility functions
pub trait MerkleUtils {

    /// Calculate predicate address from bytecode and EVM address
    fn calculate_predicate_address(
        self,
        receiver_code: Bytes,
        receiver_evm_addr: b256,
    ) -> b256;

}

impl MerkleUtils for V1Predicate {

    /// Calculates the predicate address for a V1 ZapWallet using a two-leaf merkle tree,
    /// where the left leaf is fixed and the right leaf bytcode is variable and contains the
    /// owner's EVM address and any ZapWallet related configurables.
    ///
    /// # Arguments
    ///
    /// * `v1_code` - The bytecode for the right leaf that will be modified with owner's address
    /// * `owner_evm_addr` - The owner's EVM address to be swapped into the right leaf
    ///
    /// # Returns
    ///
    /// * [b256] - The calculated predicate address, or b256::min() if the swap operation fails
    ///
    /// # Details
    ///
    /// The function:
    /// 1. Takes the right leaf's bytecode and swaps in the owner's EVM address at V1_SWAP_POSITION
    /// 2. Hashes the modified right leaf using SHA-256 with a leaf prefix
    /// 3. Combines the fixed left leaf hash (V1_LEFT_LEAF_HASH) and modified right leaf hash into a two-leaf merkle tree
    /// 4. Computes the final predicate address by adding a contract ID seed to the merkle root
    ///
    fn calculate_predicate_address(
        self,
        v1_code: Bytes,
        owner_evm_addr: b256,
    ) -> b256 {
        // Create mutable copy of input data
        let mut right_bytes = v1_code;
        // Calculate v1 master address with specific right leaf data.
        let calcualted_v1master_addr = get_v1master_addr_with_right_leaf_bytes(
            right_bytes,
            owner_evm_addr,
        );

        calcualted_v1master_addr
    }
}

impl MerkleUtils for V2Predicate {

    /// Calculates the predicate address for a V2 ZapWallet by constructing a merkle tree
    /// from the stored leaf hashes and a final leaf containing the owner's EVM address.
    ///
    /// # Arguments
    ///
    /// * `final_leaf_bytes` - The bytecode for the final leaf that will be modified with owner's address
    /// * `owner_evm_addr` - The owner's EVM address to be inserted into the final leaf
    ///
    /// # Returns
    ///
    /// * [b256] - The calculated predicate address, or b256::zero() if the swap operation fails
    ///
    /// # Details
    ///
    /// The function:
    /// 1. Takes the final leaf's bytecode and swaps in the owner's EVM address at self.swap_position
    /// 2. Hashes the modified final leaf using SHA-256 with a leaf prefix
    /// 3. Places this hash in the last position of the merkle tree (at self.num_leaves - 1)
    /// 4. Constructs a merkle tree using all leaf hashes (up to 8 leaves max)
    /// 5. Computes the final predicate address by adding a contract ID seed to the merkle root
    ///
    fn calculate_predicate_address(
        self,
        final_leaf_bytes: Bytes,
        owner_evm_addr: b256,
    ) -> b256 {
        // Create mutable copy of input data
        let mut leaf_hashes = self.leaf_hashes;
        let mut final_bytes = final_leaf_bytes;
        // final leaf position is always last
        let final_leaf_position = self.num_leaves - 1;

        // Perform the swap in of the OWNER PUBKEY bytes
        let swap_success = swap_bytes_at_position(
            final_bytes,
            self.swap_position,
            owner_evm_addr
        );

        // Return zero hash if swap failed
        if !swap_success {
            return b256::zero();
        }

        // Calculate the right leaf hash with the swapped OWNER PUBKEY bytes
        let final_leaf_hash = calculate_leaf_hash(final_bytes);

        // Place the final leaf hash into its position
        leaf_hashes[final_leaf_position] = final_leaf_hash;

        // Calculate and return root hash
        let root = get_merkle_root_from_leaf_hashes(leaf_hashes, self.num_leaves);
        calculate_predi_addr_from_root(root)
    }

}

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

/// Swaps 32 bytes at a specified position in a byte array with new bytes.
///
/// # Arguments
///
/// * `data` - The bytes to modify.
/// * `position` - The starting position for the swap.
/// * `new_bytes` - The new 32 bytes to insert.
///
/// # Returns
///
/// * [bool] - True if swap was successful, false if position is invalid
///
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
        // let temp = data.get(curr_pos).unwrap();
        // Set new byte
        data.set(curr_pos, swap_bytes.get(i).unwrap());
        i += 1;
    }

    true
}

/// Calculates the Merkle root from an array of leaf hashes.
/// Limited to 8 leaves maximum.
///
/// # Arguments
///
/// * `leaf_hashes` - Array of leaf hashes (maximum 8).
/// * `num_leaves` - Number of active leaves in the array.
///
/// # Returns
///
/// * [b256] - The calculated Merkle root.
///
/// # Additional Information
///
/// Restricted to a maximumof 8 leaves.
///
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
            tree_hashes[next_tree_size] = hash_bytes_sha256(combined_bytes);
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

/// Calculates a V1 ZapWallet master address using a right leaf's bytes and a swap value.
///
/// # Arguments
///
/// * `right_bytes` - The right leaf bytecode that will be modified.
/// * `swap_value` - The pubkey to be swapped into the bytes at a predefined position.
///
/// # Returns
///
/// * [b256] - The calculated master address, or zero if swap operation fails.
///
pub fn get_v1master_addr_with_right_leaf_bytes(
    ref mut right_bytes: Bytes,
    swap_value: b256,
) -> b256 {

    // The left leaf hash and position at which to swap for a release build of Master.
    let left_hash: b256 = V1_LEFT_LEAF_HASH;
    let swap_position = V1_SWAP_POSITION;

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
    let right_leaf_hash = calculate_leaf_hash(right_bytes);

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
    let root = hash_bytes_sha256(combined_bytes);

    calculate_predi_addr_from_root(root)
}

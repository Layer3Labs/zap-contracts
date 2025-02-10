// Authorship and attribution:
// The original rlp decoding for an EIP-1559 transaction was written by the authors of the
// the repository found at:
// https://github.com/kmonn64/RefuelWallet/blob/main/predicate/refuel-predicate/src/rlp_utils.sw
//
// This file buids upon the work of the original authors.


library;

use std::{
    b512::B512,
    bytes::Bytes,
    math::*,
    option::Option,
    string::String,
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};


// RLP encoding constants
//0x00-0x7f: it's own byte (transaction type identifier)
//0x80-0xb7: string identifier and how many bytes long it is [0-55]
//0xb7-0xbf: string identifier and how many next bytes represent it's length
//0xc0-0xf7: payload identifier and how many bytes long it is [0-55]
//0xf7-0xff: payload identifier and how many next bytes represent it's length
pub const RLP_SINGLE_BYTE_MAX = 0x7fu64;
pub const RLP_ITEM_IDENTIFIER_IMMEDIATE_START = 0x80u64;
pub const RLP_ITEM_IDENTIFIER_IMMEDIATE_MAX = 0xb7u64;
pub const RLP_ITEM_IDENTIFIER_BYTES_START = 0xb7u64;
pub const RLP_ITEM_IDENTIFIER_BYTES_MAX = 0xbfu64;
pub const RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START = 0xc0u64;
pub const RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_MAX = 0xf7u64;
pub const RLP_PAYLOAD_IDENTIFIER_BYTES_START = 0xf7u64;
pub const RLP_PAYLOAD_IDENTIFIER_BYTES_MAX = 0xffu64;


// RLP Utils:

/// Calculates the length of a transaction segment in RLP encoded data.
///
/// # Arguments
///
/// * `_data`: [Bytes] - The RLP encoded data
/// * `ptr_start`: [u64] - Start pointer of segment
/// * `ptr_end`: [u64] - End pointer of segment
///
/// # Returns
///
/// * [u64] - Length of the segment
///
pub fn length_to_digest(_data: Bytes, ptr_start: u64, ptr_end: u64) -> u64 {

    let len = ptr_end - ptr_start;

    len
}

/// Decodes an RLP payload prefix, returning the data position and length.
///
/// # Arguments
///
/// * `data`: [Bytes] - The RLP encoded data
/// * `ptr`: [u64] - Position of the payload prefix
///
/// # Returns
///
/// * `Option<(u64, u64)>` - Tuple of (data start position, length) if valid
///
pub fn rlp_decode_payload(data: Bytes, ptr: u64) -> Option<(u64, u64)> {
    // let payload_identifier = data.get(ptr).unwrap();
    let payload_identifier = convert_u8_u64(data.get(ptr).unwrap());

    if payload_identifier >= RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START && payload_identifier <= RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_MAX {
        //immediate length
        let length: u64 = payload_identifier - RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START;
        return Some((ptr + 1, length));
    } else if payload_identifier >= RLP_PAYLOAD_IDENTIFIER_BYTES_START && payload_identifier <= RLP_PAYLOAD_IDENTIFIER_BYTES_MAX {
        //get number of bytes to read to figure out the length
        let num_bytes: u64 = payload_identifier - RLP_PAYLOAD_IDENTIFIER_BYTES_START;
        let length = rlp_read_u64(data, ptr + 1, num_bytes);
        return Some((ptr + 1 + num_bytes, length));
    }

    None
}

/// Decodes an RLP item prefix, returning the data position and length.
///
/// # Arguments
///
/// * `data`: [Bytes] - The RLP encoded data
/// * `ptr`: [u64] - Position of the item prefix
///
/// # Returns
///
/// * `(u64, u64)` - Tuple of (data start position, length)
///
pub fn rlp_decode_item(data: Bytes, ptr: u64) -> (u64, u64) {
    // let item_identifier = data.get(ptr).unwrap();
    let item_identifier = convert_u8_u64(data.get(ptr).unwrap());

    if item_identifier <= RLP_SINGLE_BYTE_MAX {
        //immediate
        return (ptr, 1);
    } else if item_identifier >= RLP_ITEM_IDENTIFIER_IMMEDIATE_START && item_identifier <= RLP_ITEM_IDENTIFIER_IMMEDIATE_MAX {
        //immediate length
        let length: u64 = item_identifier - RLP_ITEM_IDENTIFIER_IMMEDIATE_START;
        return (ptr + 1, length);
    } else if item_identifier >= RLP_ITEM_IDENTIFIER_BYTES_START && item_identifier <= RLP_ITEM_IDENTIFIER_BYTES_MAX {
        //get number of bytes to read to figure out the length
        let num_bytes: u64 = item_identifier - RLP_ITEM_IDENTIFIER_BYTES_START;
        let length = rlp_read_u64(data, ptr + 1, num_bytes);
        return (ptr + 1 + num_bytes, length);
    }

    //TODO - adjust this function to return Option, return None if here.
    (ptr, 0)
}

/// Reads a u64 value from RLP encoded bytes.
///
/// # Arguments
///
/// * `data`: [Bytes] - Source bytes
/// * `ptr`: [u64] - Start position
/// * `num_bytes`: [u64] - Number of bytes to read (max 8)
///
/// # Returns
///
/// * [u64] - Decoded integer value
///
/// # Reverts
///
/// * When num_bytes > 8
///
pub fn rlp_read_u64(data: Bytes, ptr: u64, num_bytes: u64) -> u64 {
    if num_bytes > 8 {
        revert(0);
    }
    if num_bytes == 0 {
        return 0;
    }
    //REVIEW - there's got to be a more efficiet way to do this
    let mut value: (u64, u64) = (0, 0);
    let dst = __addr_of(value).add_uint_offset(16 - num_bytes);
    let src = data.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };

    value.1
}

/// Reads a b256 value from RLP encoded bytes.
///
/// # Arguments
///
/// * `data`: [Bytes] - Source bytes
/// * `ptr`: [u64] - Start position
/// * `num_bytes`: [u64] - Number of bytes to read (max 32)
///
/// # Returns
///
/// * [b256] - Decoded 256-bit value
///
/// # Reverts
///
/// * When num_bytes > 32
///
pub fn rlp_read_b256(data: Bytes, ptr: u64, num_bytes: u64) -> b256 {
    if num_bytes > 32 {
        revert(0);
    }
    if num_bytes == 0 {
        return b256::zero();
    }

    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value).add_uint_offset(32 - num_bytes);
    let src = data.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };

    asm(r1: __addr_of(value)) { r1: b256 }
    // to_b256(value)
}

/// Reads RLP encoded bytes into a u256 value.
///
/// # Method
///
/// Reads `num_bytes` from `data` starting at the position specified by `ptr`,
/// converts those bytes into a `u256`, and returns the `u256` value along with
/// the updated pointer position.
///
/// # Arguments
///
/// * `data` - The byte array containing the data to be read.
/// * `ptr` - The starting position of the bytes to be read.
/// * `num_bytes` - The number of bytes to be read (must be less than or equal to 32).
///
/// # Returns
///
/// * `Some((u256, u64))` - If the operation is successful, returns a tuple containing:
///   - The extracted bytes as a `u256` value.
///   - The updated pointer position after reading the bytes.
/// * `None` - If `num_bytes` is greater than 32, indicating that the operation cannot be performed.
///
pub fn rlp_read_bytes_to_u256(data: Bytes, ptr: u64, num_bytes: u64) -> Option<(u256, u64)> {
    if num_bytes > 32 {
        return None;
    }
    if num_bytes == 0 {
        return Some((u256::zero(), ptr));
    }

    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value).add_uint_offset(32 - num_bytes);
    let src = data.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };
    let result = asm(r1: __addr_of(value)) { r1: u256 };
    let new_ptr = ptr + num_bytes;

    Some((result, new_ptr))
}

/// Decodes ERC20 transfer function data from RLP encoded bytes.
///
/// # Arguments
///
/// * `data`: [Bytes] - The RLP encoded data
/// * `ptr`: [u64] - Start position of function data
/// * `num_bytes`: [u64] - Length of function data
///
/// # Returns
///
/// * `(b256, b256)` - Tuple of (recipient address, amount)
///
pub fn rlp_decode_transfer_bytes(data: Bytes, ptr: u64, num_bytes: u64) -> (b256, b256) {

    if num_bytes == 0 {
        return (b256::zero(), b256::zero());
    }

    let ptr_to_addr_start = ptr + 4;
    let ptr_to_amnt_start = ptr + 4 + 32;
    let ct_to = rlp_read_b256(data, ptr_to_addr_start, 32);
    let ct_amnt = rlp_read_b256(data, ptr_to_amnt_start, 32);

    (ct_to, ct_amnt)
}


// Signature related:

/// Normalizes an Ethereum signature recovery ID.
///
/// # Arguments
///
/// * `v`: [u64] - Recovery ID value to normalize
///
/// # Returns
///
/// * [u8] - Normalized recovery ID (0, 1, or 4 for invalid)
///
pub fn normalize_recovery_id(v: u64) -> u8 {
    match v {
        0 => return(0u8),
        1 => return(1u8),
        27 => return(0u8),
        28 => return(1u8),
        _ => {
            if v >= 35 {
                let x = ((v - 1) % 2);
                return(x.try_as_u8().unwrap());
            } else {
                return(4u8);
            }
        },
        // _ => 4,
    }
}

/// Creates a compact signature from r, s components and recovery ID.
///
/// # Arguments
///
/// * `r`: [b256] - R component of signature
/// * `s`: [b256] - S component of signature
/// * `v`: [u64] - Recovery ID
///
/// # Returns
///
/// * [B512] - Compact signature with recovery bit in s
///
pub fn compact_signature_normalize(r: b256, s: b256, v: u64) -> B512 {
    // get the value for the normalized recovery id
    let x = normalize_recovery_id(v);
    // convert to tuple
    let mut s_v = asm(r1: __addr_of(s)) { r1: (u64, u64, u64, u64) };
    if x > 0 {
        s_v.0 = (s_v.0 | (1 << 63));
    }
    // let s_v = to_b256(s_v);
    let s_v = asm(r1: __addr_of(s_v)) { r1: b256 };

    B512::from((r, s_v))
}

//TODO - remove use of this function and use std lib conversions instead.
pub fn convert_u8_u64(a: u8) -> u64 {
    asm(input: a) {
        input: u64
    }
}



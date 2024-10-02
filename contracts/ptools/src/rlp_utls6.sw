// Authorship and attribution:
// The original rlp decoding for an EIP-1559 transaction was written by the authors of the
// the repository found at:
// https://github.com/kmonn64/RefuelWallet/blob/main/predicate/refuel-predicate/src/rlp_utils.sw
// This file has been modified, while ensuring appropriate attribution to the original authors.

//  development version: 0.0.6


library;

use std::{
    b512::B512,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    bytes::Bytes,
    math::*,
    option::Option,
    string::String,
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use helpers::general_helpers::{
    hex_string_to_bytes,
    char_to_hex,
};




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

// returns pointers to start and end of the tx part of the tx data bytes:
pub fn length_to_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> u64 {
    // let txtype = 2;
    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    // let dst = __addr_of(value);
    // let src = data.buf.ptr().add_uint_offset(ptr_start);
    let src = data.ptr().add_uint_offset(ptr_start);

    let len = ptr_end - ptr_start;
    len
}

/// Returns the ptr index of where the payload begins and byte length of the payload
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

/*
//TODO - needs work.
fn rlp_decode_legacy_payload_len(data: Bytes, ptr: u64) -> (u64, u64) {

    let payload_identifier = convert_u8_u64(data.get(ptr).unwrap());


    revert(0);
    (ptr, 0)
}
*/

/// Returns the ptr index of where the item data begins and byte length of the item
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

    revert(0);
    (ptr, 0)
}

/// Returns the u64 representation of the bytes starting from the pointer to num_bytes
pub fn rlp_read_u64(data: Bytes, ptr: u64, num_bytes: u64) -> u64 {
    if num_bytes > 8 {
        revert(0);
    }
    if num_bytes == 0 {
        return 0;
    }

    //TODO: there's got to be a more efficiet way to do this
    let mut value: (u64, u64) = (0, 0);
    let dst = __addr_of(value).add_uint_offset(16 - num_bytes);
    // let src = data.buf.ptr().add_uint_offset(ptr);
    let src = data.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };

    value.1
}

/// Returns the b256 representation of the bytes starting from the pointer to num_bytes
pub fn rlp_read_b256(data: Bytes, ptr: u64, num_bytes: u64) -> b256 {
    if num_bytes > 32 {
        revert(0);
    }
    if num_bytes == 0 {
        return b256::zero();
    }

    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value).add_uint_offset(32 - num_bytes);
    //let src = data.buf.ptr().add_uint_offset(ptr);
    let src = data.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };

    to_b256(value)
}

/// Returns the recipient and amount of the erc20 transfer function.
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

fn normalize_recovery_id(v: u64) -> u8 {
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

pub fn compact_signature_normalize(r: b256, s: b256, v: u64) -> B512 {
    let x = normalize_recovery_id(v); // get the value for the normalized recovery id
    let mut s_v = to_tuple(s);
    if x > 0 {
        s_v.0 = (s_v.0 | (1 << 63));
    }
    let s_v = to_b256(s_v);
    B512::from((r, s_v))
}


// Utils:

/// Converts given tuple of words to a b256
//TODO: for some reason, the output of functions has to be wrapped like this or the compiler fails
fn to_b256(words: (u64, u64, u64, u64)) -> b256 {
    asm(r1: __addr_of(words)) { r1: b256 }
}

/// Converts given b256 to a tuple of words
fn to_tuple(bits: b256) -> (u64, u64, u64, u64) {
    asm(r1: __addr_of(bits)) { r1: (u64, u64, u64, u64) }
}

pub fn convert_u8_u64(a: u8) -> u64 {
    asm(input: a) {
        input: u64
    }
}



// Tests:

// Tests for normalization of sig v value.
#[test]
fn tests_normalize_v() {
    use std::assert::*;

    let var1 = 1243059u64;
    let var2 = 1243060u64;
    let var3 = 27u64;
    let var4 = 28u64;
    let var5 = 0u64;
    let var6 = 1u64;

    assert(normalize_recovery_id(var1) == 0u8 );
    assert(normalize_recovery_id(var2) == 1u8 );
    assert(normalize_recovery_id(var3) == 0u8 );
    assert(normalize_recovery_id(var4) == 1u8 );
    assert(normalize_recovery_id(var5) == 0u8 );
    assert(normalize_recovery_id(var6) == 1u8 );

}

// Tests for signature recovery from known digests, signatures combos for sig v values.
#[test]
fn test_signature_spec(){
    let expected: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;

    // DEBUG06.md
    // type 02 transaction built with MM
    let t1_r: b256 = 0xcafc2b2a1e474859ed2fde107d6de5ad020d7e4f1f0c1838e6ae1f95aa65f7f1;
    let t1_s: b256 = 0x7a5ee832672368630df1fc9ab62f247f4260a03477c7354ef8765c4b40d78b7a;
    let t1_v: u64 = 1;
    let t1_digest: b256 = 0xd1cd6fd19dfec18c42f18dcbc896116d4eafb77c8d397e5b94555bc6b0dba21c;

    let t1_sig = compact_signature_normalize(t1_r, t1_s, t1_v);
    let t1_from: b256 = ec_recover_evm_address(t1_sig, t1_digest).unwrap().into();
    assert(t1_from == expected);

    // DEBUG06.md
    // type 02 transaction built with ethers
    let t2_r: b256 = 0x219e0df36f00e5511d9279bdda0ef317996c9017c4ea4c06eca82d73a690bc2d;
    let t2_s: b256 = 0x0e994a03f0904c932b7b480b5a5b0a53738e01eb6b0513a185e99723914ed641;
    let t2_v: u64 = 0;
    let t2_digest: b256 = 0xb6314e2de6ae205ddfb247a7f977e5e8363a27381e838bd26075a4d37eae6111;

    let t2_sig = compact_signature_normalize(t2_r, t2_s, t2_v);
    let t2_from: b256 = ec_recover_evm_address(t2_sig, t2_digest).unwrap().into();
    assert(t2_from == expected);

    // DEBUG02.md
    // legacy tx, created with coinbase wallet
    let t3_r: b256 = 0x542fae74e0157dead597483a999016ab81ba9e4d046e47379235a287fb8844a9;
    let t3_s: b256 = 0x3c7c632e5c6f5bd33b240a0a009e4155ab97c16a17c04346f2b2a223e4dd7a60;
    let t3_v: u64 = 1243059;
    let t3_digest: b256 = 0xd4c4b53f1f000f4781aa9c62f4f5183c501d8f3ae576e16d9f923d3d8bbec2e3;

    let t3_sig = compact_signature_normalize(t3_r, t3_s, t3_v);
    let t3_from: b256 = ec_recover_evm_address(t3_sig, t3_digest).unwrap().into();
    assert(t3_from == expected);

    // DEBUG04.md
    // legacy tx, created with coinbase wallet
    let t4_r: b256 = 0x5fc787c5a651732383e5125d7828b1b009bfd7c507a2ebfaeed093e2149ccd3a;
    let t4_s: b256 = 0x5bdfe3215a8e0be4bd5ab8f993dba8d8ec5cc60caef507de3a623e62f2e9ab72;
    let t4_v: u64 = 1243060;
    let t4_digest: b256 = 0x608b0486d8daacfdc00b8309591c50c0af6cd0cad1001f9c4c17eefe5de08da3;

    let t4_sig = compact_signature_normalize(t4_r, t4_s, t4_v);
    let t4_from: b256 = ec_recover_evm_address(t4_sig, t4_digest).unwrap().into();
    assert(t4_from == expected);

    // DEBUG07.md
    // legacy tx, created with ethers
    let t5_r: b256 = 0x774a132dfae4d36975109ecb0bfa17ae4894ae81ab66822d0c14c5aca84a1364;
    let t5_s: b256 = 0x682bb55353d9d7ce526c965b19bdd49fe1677d905fcd00d02eeff33e0bba9292;
    let t5_v: u64 = 1243059;
    let t5_digest: b256 = 0xed026390545fe0d348f05e19791cc7d7bb4bb862cc74c9f3d70d37ee060d9917;

    let t5_sig = compact_signature_normalize(t5_r, t5_s, t5_v);
    let t5_from: b256 = ec_recover_evm_address(t5_sig, t5_digest).unwrap().into();
    assert(t5_from == expected);

}









#[test()]
fn test_char_to_hex() {


    let mut hex_string = String::from_ascii_str("020fa2ffa3");
    // let slice_1 = asm(ptr: (hex_string.ptr(), 10)) {
    //     ptr: raw_slice
    // };
    // let mut s_bytes = Bytes::from(slice_1);

    // let bytes = hex_to_bytes(hex_string).unwrap();

    // let a = char_to_hex(s_bytes.get(0).unwrap());
    // let b = char_to_hex(s_bytes.get(1).unwrap());

    // assert(a == Some(0x00u8));
    // assert(b == Some(0x02u8));

    // assert(a == Some(0x00u8));
    // assert(b == Some(0x0fu8));

    // assert(s_bytes.get(1).unwrap() == 50)

    let g = hex_string_to_bytes(hex_string).unwrap();
    assert(g.get(0).unwrap() == 0x02);
    assert(g.get(1).unwrap() == 0x0f);
    assert(g.get(2).unwrap() == 0xa2);
    assert(g.get(3).unwrap() == 0xff);
    assert(g.get(4).unwrap() == 0xa3);

    // assert(g.get(0).unwrap() == 0x0fu8);


    // assert(bytes.len() == 4);
    // assert(bytes.get(0).unwrap() == 0x02);

    // assert(char_to_hex(rlp_bytes.get(0).unwrap()).unwrap() == 0x02);
}

// Tests hex string convert to bytes
#[test()]
fn test_hex_string(){

    let mut hex_string = String::from_ascii_str("020fa2ffa3");
    let hex_string_len = hex_string.capacity();

    // log(hex_string_len);


    // let slice_1 = asm(ptr: (hex_string.ptr(), 10)) {
    //     ptr: raw_slice
    // };
    // let mut rlp_hex_str_as_bytes = Bytes::from(slice_1);
    // let rlp_bytes = hex_string_to_bytes(rlp_hex_str_as_bytes).unwrap();

    let rlp_bytes = hex_string_to_bytes(hex_string).unwrap();

}



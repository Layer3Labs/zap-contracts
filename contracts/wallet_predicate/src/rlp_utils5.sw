// Authorship and attribution:
// The original rlp decoding for an EIP-1559 transaction was written by the authors of the
// the repository found at:
// https://github.com/kmonn64/RefuelWallet/blob/main/predicate/refuel-predicate/src/rlp_utils.sw
// This file has been modified, while ensuring appropriate attribution to the original authors.

//  development version: 0.0.5

library;

use std::{bytes::Bytes, constants::ZERO_B256, math::*, option::Option, u256::U256};
use std::{
    b512::B512,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
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
const RLP_SINGLE_BYTE_MAX = 0x7fu64;
const RLP_ITEM_IDENTIFIER_IMMEDIATE_START = 0x80u64;
const RLP_ITEM_IDENTIFIER_IMMEDIATE_MAX = 0xb7u64;
const RLP_ITEM_IDENTIFIER_BYTES_START = 0xb7u64;
const RLP_ITEM_IDENTIFIER_BYTES_MAX = 0xbfu64;
const RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START = 0xc0u64;
const RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_MAX = 0xf7u64;
const RLP_PAYLOAD_IDENTIFIER_BYTES_START = 0xf7u64;
const RLP_PAYLOAD_IDENTIFIER_BYTES_MAX = 0xffu64;


//------------------------------------------------------------------------------------------------------------------
// Decodes a signed EVM transaction of type(s):
// EIP-1559 (0x02), Legacy (0x00),
// returns transaction details.
pub fn decode_signed_tx_digest_sig(signed_tx: Bytes)
    -> (
        u64,    // type_identifier
        u64,    // chain_id
        u64,    // nonce
        u64,    // maxFeePerGas
        u64,    // gasLimit
        u64,    // value
        b256,   // to
        b256,   // asset_id
        b256,   // digest
        u64,    // length
        u64,    // tx_data_start
        u64,    // tx_data_end
        B512,   // signature
        b256,   // from
    )
    {
    let type_identifier = convert_u8_u64(signed_tx.get(0).unwrap());

    match type_identifier {
        1u64 => {
            // EIP-2930 (0x01) - Unsupported transaction type
            let b512zero = B512::new();
            (0, 0, 0, 0, 0, 0, ZERO_B256, ZERO_B256,
            ZERO_B256, 0, 0, 0,
            b512zero, ZERO_B256)
        }
        2u64 => {
            // EIP-1559 (0x02) - Type 2 style transaction
            let ptr: u64 = 1;

            //---------------------------------------------------------------
            // decode the payload opening
            let (ptr, _) = rlp_decode_payload(signed_tx, ptr);
            let ptr_tx_data_start = ptr;

            //---------------------------------------------------------------
            // first item is the chain id
            let (ptr, len) = rlp_decode_item(signed_tx, ptr);
            let chain_id = rlp_read_u64(signed_tx, ptr, len);

            //---------------------------------------------------------------
            //second item is the nonce
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let nonce = rlp_read_u64(signed_tx, ptr, len);

            //---------------------------------------------------------------
            // third item is the maxPriorityFeePerGas (ignore)
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);

            //---------------------------------------------------------------
            //fourth item is the maxFeePerGas
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let maxFeePerGas = rlp_read_u64(signed_tx, ptr, len);

            //---------------------------------------------------------------
            // fifth item is the gasLimit
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let gasLimit = rlp_read_u64(signed_tx, ptr, len);

            //---------------------------------------------------------------
            //sixth item is the to field
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let to = rlp_read_b256(signed_tx, ptr, len);

            //---------------------------------------------------------------
            // seventh item is the value
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let value = rlp_read_u64(signed_tx, ptr, len);

            //---------------------------------------------------------------
            // eigth item is the data
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            //TODO: analyze this data to determine what tokens are being transferred
            let asset_id = ZERO_B256;

            //---------------------------------------------------------------
            // ninth item is the accessList
            let (ptr, len) = rlp_decode_payload(signed_tx, ptr + len);
            let ptr_tx_data_end = ptr + len;

            //---------------------------------------------------------------
            // remaining three items are v, r, s
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let v = rlp_read_u64(signed_tx, ptr, len);
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let r = rlp_read_b256(signed_tx, ptr, len);
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let s = rlp_read_b256(signed_tx, ptr, len);

            //---------------------------------------------------------------
            // payload and digest calculation.
            let len = length_to_digest(signed_tx, ptr_tx_data_start, ptr_tx_data_end);
            //log(len);

            // compute the digest that the sender signs
            let digest = tx_type2_digest(signed_tx, ptr_tx_data_start, ptr_tx_data_end);
            //log(digest);

            // use signature to get the "from" public key
            // let sig = compact_signature(r, s, v);
            let sig = compact_signature_normalize(r, s, v);
            let from: b256 = ec_recover_evm_address(sig, digest).unwrap().into();

            return (type_identifier, chain_id, nonce, maxFeePerGas, gasLimit, value, to, asset_id,
            digest, len, ptr_tx_data_start, ptr_tx_data_end,
            sig, from)
        },
        _ => {
            // Legacy (0x00) - legacy style transaction.
            // note: must include chain id.
            let ptr: u64 = 1;

            //---------------------------------------------------------------
            // decode the payload opening
            // let (ptr, _) = rlp_decode_payload(signed_tx, ptr);
            let ptr_tx_data_start = 2;
            //log(ptr_tx_data_start);

            //---------------------------------------------------------------
            // 1st item is the nonce
            let ptr = ptr + 1;
            let (ptr, len) = rlp_decode_item(signed_tx, ptr);
            let nonce = rlp_read_u64(signed_tx, ptr, len);
            //log(nonce);

            //---------------------------------------------------------------
            // 2nd item is the gas_price
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let gas_price = rlp_read_u64(signed_tx, ptr, len);
            //log(gas_price);

            //---------------------------------------------------------------
            // 3rd item is the gas
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let gas = rlp_read_u64(signed_tx, ptr, len);
            //log(gas);

            //---------------------------------------------------------------
            // 4th item is the to field
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let to = rlp_read_b256(signed_tx, ptr, len);
            //log(to);

            //---------------------------------------------------------------
            // 5th item is the value
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let value = rlp_read_u64(signed_tx, ptr, len);
            //log(value);

            //---------------------------------------------------------------
            // 6th item is the chain id w.r.t EIP-155
            // https://eips.ethereum.org/EIPS/eip-155
            // this is also the v of signature.

            let ptr = ptr + len + 1;
            let (ptr, len) = rlp_decode_item(signed_tx, ptr);

            let v_chain_id = rlp_read_u64(signed_tx, ptr, len);
            //log(v_chain_id);    // u64

            // convert chain id w.r.t EIP-155
            let mut chain_id = 0;
            if v_chain_id >= 35 {
                chain_id = ((v_chain_id - 35) >> 1);
            }
            //log(chain_id);  // u64

            // the ptr value below is pointing to the first byte of v_chian_id,
            // the last byte of the payload is: ptr_payload_end - 2
            // i.e. ptr includs the rlp prefix for the chainid data.
            let ptr_payload_end = ptr;
            //log(ptr_payload_end);

            //FIXME - the v_chain_id bytes length, may not be the same length as the bytes calcualted below.
            // todo(): get the ptr, reverse it one byte, work out how many bytes long the original cahinid data is.
            // its probably likley that this does not exceed the rlp encoding byte limit. so if it was
            // for example  1 - 10 bytes it should be ok. Either way, need constrain this.

            //---------------------------------------------------------------
            // for total payload length add ptr_payload_end to length repr bytes of chain_id
            // convert u64 to bytes and get length

            let chain_id_bytes_temp = chain_id.to_be_bytes();
            //log(chain_id_bytes_temp.len());

            // get the bytes in BE fashion. MSbyte first
            let mut chain_id_bytes: Vec<u8> = Vec::new();
            let mut j = 0;
            while j < chain_id_bytes_temp.len() {
                let t = chain_id_bytes_temp.get(j).unwrap();
                if t != 0x00 {
                    chain_id_bytes.push(t);
                }
                j += 1;
            }
            //TODO - do a check here to make sure byte lengh is reasonable.

            //---------------------------------------------------------------
            //7th & 8th item is r, s
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let r = rlp_read_b256(signed_tx, ptr, len);
            let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
            let s = rlp_read_b256(signed_tx, ptr, len);
            //log(r);
            //log(s);

            //---------------------------------------------------------------
            // Calculate encoded payload prefix.
            let encoded_payload_prefix = RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + ptr_payload_end + chain_id_bytes.len();
            //log(encoded_payload_prefix);        // is u64

            // Construct the rllp encoded payload and get the keccak-256 hash of it.
            let digest = tx_type_legacy_digest(
                    encoded_payload_prefix,
                    signed_tx,
                    ptr_tx_data_start,
                    ptr_payload_end,
                    chain_id_bytes,
                );
            //log(digest);

            //---------------------------------------------------------------
            // Construct the Signature from (r, s, v) and get the "from" public key
            // let sig = B512::from((r, s));
            let sig = compact_signature_normalize(r, s, v_chain_id);
            let from: b256 = ec_recover_evm_address(sig, digest).unwrap().into();
            //log(from);
            //log(sig);

            let asset_id = ZERO_B256;
            return (
                0, chain_id, nonce, gas_price, gas, value, to, asset_id,
            digest, 0, 0, 0,
            sig, from)
        }
    }
}

//------------------------------------------------------------------------------------------------------------------
// Routines to construct tx payload and obtain digest for each evm tx type:

/// Returns the digest of a signed type 2 tx (the thing the signer signed)
fn tx_type2_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> b256 {
    let txtype = 2;
    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value);
    let src = data.buf.ptr().add_uint_offset(ptr_start);

    let len = (ptr_end ) - (ptr_start );
    let len_b0 = len.to_le_bytes();

    //log(ptr_start);
    //log(ptr_end);
    //log(len);       // ptr_end - ptr_start, as a u64

    let mut result_buffer = b256::min();

    if len <= 55 { // For buffer length < 55 :

        let a_prefix = RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + len; // 0xC0 + len , i.e., deciaml 192 + len (both a u64's)
        //log(a_prefix);     // this us u64

        let data_len = len_b0.get(0).unwrap();

        let prefix = 0xc0u8 + data_len;    // this is 0xC0 + length. RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + len

        //log(data_len);  // this is u8
        //log(prefix);  // this is u8

        let size = data_len + 3;        // size in bytes of the memory on heap to create.
                                        // (Not sure why it has to be 3 here and not 2. 2 causes memoryOwnership Err)
        let buflen = size - 1;          // length on memory bytes on heap to hash.

        //log(size);      // this is u8
        //log(buflen);    // this is u8

        //-------------------------------
        let a_size = len + 3;
        let a_buflen = a_size - 1;
        //log(a_size);    // this is u64
        //log(a_buflen);  // this is u64

        asm(hash: result_buffer, ptrdata: src, length: len, txtype: txtype, prefix: a_prefix, size: a_size, buflen: a_buflen, memptr) {
            aloc size;                              // allocate memory to the stack
            sb hp txtype i1;                        // set the type identifier
            sb hp prefix i2;                        // set the payload prefix
            addi memptr hp i3;                      // increase memory pointer for copying payload items
            mcp  memptr ptrdata length;             // copy
            addi memptr hp i1;                      // move memory pointer back to the beginning
            k256 hash memptr buflen;
            hash: b256
        };
        return(result_buffer);
    }
    if len <= 256 {

        let a_prefix = RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + len; // 0xC0 + len , i.e., deciaml 192 + 1 (both a u64's)
        //log(a_prefix);     // this us u64

        let a_size = len + 4;
        let a_buflen = a_size - 1;
        //log(a_size);    // this is u64
        //log(a_buflen);  // this is u64

        let len0 = len;
        //log(len0);

        asm(hash: result_buffer, ptrdata: src, length: len, size: a_size, txtype: txtype, prefix: a_prefix, len0: len0, buflen: a_buflen, memptr) {
            aloc size;                              // allocate memory to the stack
            sb hp txtype i1;                        // set the type identifier
            sb hp prefix i2;                        // set the payload prefix
            sb hp len0 i3;                          // set the payload prefix
            addi memptr hp i4;                      // increase memory pointer for copying payload items
            mcp  memptr ptrdata length;             // copy
            addi memptr hp i1;                      // move memory pointer back to the beginning
            k256 hash memptr buflen;
            hash: b256
        };
        return(result_buffer);
    }

    revert(0);
    ZERO_B256
}


// Get the hash of the rlp encoded payload:chainid for a legacy tx.
// Setup payload to encoded payload to hash.
// <xx>: single byte place keeper for: 0xc0 + length of payload (everything before the sig, not including the first byte )
// <rlp payload>: as seen in tx, everything up to the v_chain_id.
// <chain_id_bytes>: w.r.t EIP-155 the converted chain id value. (v - 35) >> 1
// end with two rlp encoded zeros.
// <xx> <rlp payload> <chain_id_bytes> <8080>
//
fn tx_type_legacy_digest(
    encoded_payload_prefix: u64,
    signed_tx: Bytes,
    payload_ptr_start: u64,
    payload_ptr_end: u64,
    chain_id_bytes: Vec<u8>,
    ) -> b256 {
        let mut result_buffer = b256::min();
        let chain_id_bytes_len = chain_id_bytes.len();

        // the <rlp payload> length itself:
        let p_ems = (payload_ptr_end - payload_ptr_start);
        //log(p_ems); // u8

        //----------------
        // start constructing the cytes to hash:
        let mut payloadbytes = Bytes::new();
        // add prefix byte <xx>:
        payloadbytes.push(encoded_payload_prefix.try_as_u8().unwrap());

        // add the tx data bytes <rlp payload>:
        let mut j = payload_ptr_start;
        while j < (payload_ptr_end - 0x02) {
            payloadbytes.push(signed_tx.get(j).unwrap());
            j += 1;
        }

        //----------------
        // add the rlp encoded chain_id bytes <chain_id_bytes>:
        let rlp_chain_id_bytes = RLP_ITEM_IDENTIFIER_IMMEDIATE_START + chain_id_bytes_len;
        payloadbytes.push(RLP_ITEM_IDENTIFIER_IMMEDIATE_START.try_as_u8().unwrap());     // add 0x80
        payloadbytes.push(rlp_chain_id_bytes.try_as_u8().unwrap());                      // add 0x80 + chain_id bytes length.

        j = 0;
        while j < chain_id_bytes_len {
            payloadbytes.push(chain_id_bytes.get(j).unwrap());
            j += 1;
        }
        //----------------
        // add the end with two rlp encoded zeros <8080>:
        j = 0;
        while j < 2 {
            payloadbytes.push(0x80);
            j += 1;
        }
        let len = payloadbytes.len();

        //----------------------------------------
        // debug:
        // j = 0;
        // while j < len {
        //     log(payloadbytes.get(j).unwrap());
        //     j += 1;
        // }
        //----------------------------------------

        let a_size = len + 1;
        let a_buflen = a_size - 1;
        //log(a_size);    // this is u64
        //log(a_buflen);  // this is u64
        let x_src = payloadbytes.buf.ptr();
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
            k256 hash memptr buflen;
            hash: b256
        };
        return(result_buffer);
}


//------------------------------------------------------------------------------------------------------------------
// RLP Utils

// returns pointers to start and end of the tx part of the tx data bytes:
fn length_to_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> u64 {
    let txtype = 2;
    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value);
    let src = data.buf.ptr().add_uint_offset(ptr_start);

    let len = ptr_end - ptr_start;
    len
}

/// Returns the ptr index of where the payload begins and byte length of the payload
fn rlp_decode_payload(data: Bytes, ptr: u64) -> (u64, u64) {
    // let payload_identifier = data.get(ptr).unwrap();
    let payload_identifier = convert_u8_u64(data.get(ptr).unwrap());

    if payload_identifier >= RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START && payload_identifier <= RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_MAX {
        //immediate length
        let length: u64 = payload_identifier - RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START;
        return (ptr + 1, length);
    } else if payload_identifier >= RLP_PAYLOAD_IDENTIFIER_BYTES_START && payload_identifier <= RLP_PAYLOAD_IDENTIFIER_BYTES_MAX {
        //get number of bytes to read to figure out the length
        let num_bytes: u64 = payload_identifier - RLP_PAYLOAD_IDENTIFIER_BYTES_START;
        let length = rlp_read_u64(data, ptr + 1, num_bytes);
        return (ptr + 1 + num_bytes, length);
    }

    revert(0);
    (ptr, 0)
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
fn rlp_decode_item(data: Bytes, ptr: u64) -> (u64, u64) {
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
fn rlp_read_u64(data: Bytes, ptr: u64, num_bytes: u64) -> u64 {
    if num_bytes > 8 {
        revert(0);
    }
    if num_bytes == 0 {
        return 0;
    }

    //TODO: there's got to be a more efficiet way to do this
    let mut value: (u64, u64) = (0, 0);
    let dst = __addr_of(value).add_uint_offset(16 - num_bytes);
    let src = data.buf.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };

    value.1
}

/// Returns the b256 representation of the bytes starting from the pointer to num_bytes
fn rlp_read_b256(data: Bytes, ptr: u64, num_bytes: u64) -> b256 {
    if num_bytes > 32 {
        revert(0);
    }
    if num_bytes == 0 {
        return ZERO_B256;
    }

    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value).add_uint_offset(32 - num_bytes);
    let src = data.buf.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };

    to_b256(value)
}

//------------------------------------------------------------------------------------------------------------------
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

fn compact_signature_normalize(r: b256, s: b256, v: u64) -> B512 {
    let x = normalize_recovery_id(v); // get the value for the normalized recovery id
    let mut s_v = to_tuple(s);
    if x > 0 {
        s_v.0 = (s_v.0 | (1 << 63));
    }
    let s_v = to_b256(s_v);
    B512::from((r, s_v))
}

//------------------------------------------------------------------------------------------------------------------
// Utils

/// Converts given tuple of words to a b256
//TODO: for some reason, the output of functions has to be wrapped like this or the compiler fails
fn to_b256(words: (u64, u64, u64, u64)) -> b256 {
    asm(r1: __addr_of(words)) { r1: b256 }
}

/// Converts given b256 to a tuple of words
fn to_tuple(bits: b256) -> (u64, u64, u64, u64) {
    asm(r1: __addr_of(bits)) { r1: (u64, u64, u64, u64) }
}

/// Converts given tuple of words to a b256
// fn compact_signature(r: b256, s: b256, v: u64) -> B512 {
//     let mut s_v = to_tuple(s);
//     if v > 0 {
//         s_v.0 = (s_v.0 | (1 << 63));
//     }
//     let s_v = to_b256(s_v);
//     B512::from((r, s_v))
// }

pub fn convert_u8_u64(a: u8) -> u64 {
    asm(input: a) {
        input: u64
    }
}



//------------------------------------------------------------------------------------------------------------------
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

// Tests for signature recovery from known digeests, signatures combos for sig v values.
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
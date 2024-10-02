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

use ::rlp_utls6::{
    convert_u8_u64,
    rlp_decode_payload,
    length_to_digest,
    rlp_decode_item,
    rlp_read_u64,
    rlp_read_b256,
    compact_signature_normalize,
    RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START,
};



/// Decodes an EVM signed TypedTransaction, EIP-1559 (0x02).
///
/// # Arguements
///
/// # Returns
///
/// * transaction detials as below.
///
pub fn decode_signed_typedtx_1559(signed_tx: Bytes)
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
    ) {

    let type_identifier = convert_u8_u64(signed_tx.get(0).unwrap());

    // EIP-1559 (0x02) - Type 2 style transaction
    let ptr: u64 = 1;

    //---------------------------------------------------------------
    // decode the payload opening
    let ptr_tx_data_start: u64 = 0;

    // let (ptr, _) = rlp_decode_payload(signed_tx, ptr);
    // match rlp_decode_payload(signed_tx, ptr).ok_or(0) {
    //     Result::Ok(inner) => ptr_tx_data_start,
    //     Result::Err => revert(0),
    // }
    // let ptr_tx_data_start = ptr;

    let ptr: u64 = match rlp_decode_payload(signed_tx, ptr) {
        Some((new_ptr, _)) => new_ptr,
        None => revert(0),
    };
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
    // for the rlp decode, base asset only.
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let asset_id = b256::zero();

    //---------------------------------------------------------------
    // ninth item is the accessList
    // let (ptr, len) = rlp_decode_payload(signed_tx, ptr + len);
    // let ptr_tx_data_end = ptr + len;
    let (ptr, len) = match rlp_decode_payload(signed_tx, ptr) {
        Some((new_ptr, new_len)) => (new_ptr, new_len),
        None => revert(0),
    };
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
}


/// Returns the digest of a signed TypedTransaction EIP-1559.
///
fn tx_type2_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> b256 {
    let txtype = 2;
    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value);

    // let src = data.buf.ptr().add_uint_offset(ptr_start);

    // let src: raw_ptr = data.ptr().add_uint_offset(ptr_start);
    // let src: raw_ptr = data.ptr().add_uint_offset(ptr_start);
    let src = data.ptr().add_uint_offset(ptr_start);


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

        let _ = asm(hash: result_buffer, ptrdata: src, length: len, txtype: txtype, prefix: a_prefix, size: a_size, buflen: a_buflen, memptr) {
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

        let _ = asm(hash: result_buffer, ptrdata: src, length: len, size: a_size, txtype: txtype, prefix: a_prefix, len0: len0, buflen: a_buflen, memptr) {
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
    b256::zero()
}

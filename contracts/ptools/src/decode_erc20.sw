library;

// mod rlp_utls6;

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

use ::rlp_utls6::{
    convert_u8_u64,
    rlp_decode_payload,
    length_to_digest,
    rlp_decode_item,
    rlp_read_u64,
    rlp_read_b256,
    rlp_decode_transfer_bytes,
    compact_signature_normalize,
};




pub fn decode_signed_typedtx_erc20(signed_tx: Bytes) -> (
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
    // let (ptr, _) = rlp_decode_payload(signed_tx, ptr);
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

    // log(chain_id);

    //---------------------------------------------------------------
    //second item is the nonce
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let nonce = rlp_read_u64(signed_tx, ptr, len);

    // log(nonce);

    //---------------------------------------------------------------
    // third item is the maxPriorityFeePerGas (ignore)
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);

    //---------------------------------------------------------------
    //fourth item is the maxFeePerGas
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let maxFeePerGas = rlp_read_u64(signed_tx, ptr, len);

    // log(maxFeePerGas);

    //---------------------------------------------------------------
    // fifth item is the gasLimit
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let gasLimit = rlp_read_u64(signed_tx, ptr, len);

    //---------------------------------------------------------------
    // sixth item is the to field
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let to = rlp_read_b256(signed_tx, ptr, len);

    // log(to);

    //---------------------------------------------------------------
    // seventh item is the value
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let value = rlp_read_u64(signed_tx, ptr, len);

    // log(value);

    //---------------------------------------------------------------
    // eigth item is the data
    // b8xx: This prefix is for the data field
    // where xx is the number of bytes.
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    //TODO: analyze this data to determine what tokens are being transferred

    // log(len);

    // ct_to: contract transfer() to address (the recipient).
    // ct_amount: contract transfer() token amount.
    let (ct_to, ct_amount) = rlp_decode_transfer_bytes(signed_tx, ptr, len);
    // log(ct_to);
    // log(ct_amount);


    let asset_id = b256::zero();

    //---------------------------------------------------------------
    // ninth item is the accessList
    // let (ptr, len) = rlp_decode_payload(signed_tx, ptr + len);
    // let ptr_tx_data_end = ptr + len;
    let (ptr, len) = match rlp_decode_payload(signed_tx, ptr + len) {
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

    // log(v);
    // log(r);
    // log(s);

    //---------------------------------------------------------------
    // payload and digest calculation.
    let len = length_to_digest(signed_tx, ptr_tx_data_start, ptr_tx_data_end);
    // log(len);

    // compute the digest that the sender signs
    let digest = tx_erc20_digest(signed_tx, ptr_tx_data_start, ptr_tx_data_end);
    // log(digest);

    // use signature to get the "from" public key
    // let sig = compact_signature(r, s, v);
    let sig = compact_signature_normalize(r, s, v);
    let from: b256 = ec_recover_evm_address(sig, digest).unwrap().into();

    return (type_identifier, chain_id, nonce, maxFeePerGas, gasLimit, value, to, asset_id,
    digest, len, ptr_tx_data_start, ptr_tx_data_end,
    sig, from)

}




//
pub fn tx_erc20_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> b256 {

    let txtype = 2;
    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value);
    let src = data.ptr().add_uint_offset(ptr_start);


    let len = (ptr_end ) - (ptr_start );
    let len_b0 = len.to_le_bytes();

    // log(ptr_start);
    // log(ptr_end);
    // log(len);       // ptr_end - ptr_start, as a u64

    let mut result_buffer = b256::min();

    if len <= 55 { // will it ever be less than 56 for a transfer? no.
        return(b256::zero());
    }
    if len <= 256 {

        let a_prefix = 0xf8u64;
        // log(a_prefix);     // this us u64

        let a_size = len + 4;
        let a_buflen = a_size - 1;
        // log(a_size);    // this is u64
        // log(a_buflen);  // this is u64

        let len0 = len;

        let _ = asm(hash: result_buffer,
            ptrdata: src,
            length: len,
            size: a_size,
            txtype: txtype,
            prefix: a_prefix,
            len0: len0,
            buflen: a_buflen,
            memptr
            ) {
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

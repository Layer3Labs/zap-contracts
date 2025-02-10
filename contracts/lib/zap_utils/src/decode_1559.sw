library;

use std::{
    b512::B512,
    hash::*,
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
    rlp_read_bytes_to_u256,
    compact_signature_normalize,
    RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START,
};

pub enum DecodeType02RLPResult {
    Success: (
        u64,    // type_identifier
        u64,    // chain_id
        u64,    // nonce
        u64,    // maxFeePerGas
        u64,    // gasLimit
        u256,   // value
        b256,   // to
        b256,   // asset_id
        b256,   // digest
        u64,    // length
        u64,    // tx_data_start
        u64,    // tx_data_end
        B512,   // signature
        b256,   // from
    ),
    Fail: (u64),
}

/// Decodes an EVM signed TypedTransaction, EIP-1559 (0x02).
///
/// This function takes a signed EIP-1559 transaction as rlp encoded bytes and decodes it into
/// its constituent fields. It returns a tuple containing the decoded fields of the transaction.
///
/// # Arguments
///
/// * `signed_tx` - The signed EIP-1559 transaction as rlp encoded bytes.
///
/// # Returns
///
/// A DecodeType02RLPResult::Success containing the following fields:
///
/// * `type_identifier` - The transaction type identifier (u64).
/// * `chain_id` - The chain ID (u64).
/// * `nonce` - The transaction nonce (u64).
/// * `maxFeePerGas` - The maximum fee per gas (u64).
/// * `gasLimit` - The gas limit (u64).
/// * `value` - The transaction value (u256).
/// * `to` - The recipient address (b256).
/// * `asset_id` - The asset ID (b256).
/// * `digest` - The transaction digest (b256).
/// * `length` - The length of the transaction data (u64).
/// * `tx_data_start` - The start index of the transaction data (u64).
/// * `tx_data_end` - The end index of the transaction data (u64).
/// * `signature` - The transaction signature (B512).
/// * `from` - The sender address (b256).
///
/// # Errors
///
/// This function will return DecodeType02RLPResult::Fail with a specific error code if:
/// - The RLP decoding of the payload fails.
/// - The RLP decoding of the access list fails.
/// - The conversion of the transaction value to u256 fails.
///
pub fn decode_signed_typedtx_1559(signed_tx: Bytes) -> DecodeType02RLPResult {

    // EIP-1559 (0x02) - Type 2 style transaction
    let type_identifier = convert_u8_u64(signed_tx.get(0).unwrap());
    if type_identifier != 2 {
        // incorrect transaction type.
        return DecodeType02RLPResult::Fail(2999u64);
    }

    let ptr: u64 = 1;

    // decode the payload opening
    // let ptr_tx_data_start: u64 = 0;
    let ptr: u64 = match rlp_decode_payload(signed_tx, ptr) {
        Some((new_ptr, _)) => new_ptr,
        None => return DecodeType02RLPResult::Fail(2998u64),
    };
    let ptr_tx_data_start = ptr;

    // first item is the chain id
    let (ptr, len) = rlp_decode_item(signed_tx, ptr);
    let chain_id = rlp_read_u64(signed_tx, ptr, len);

    //second item is the nonce
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let nonce = rlp_read_u64(signed_tx, ptr, len);

    // third item is the maxPriorityFeePerGas (ignore)
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);

    //fourth item is the maxFeePerGas
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let maxFeePerGas = rlp_read_u64(signed_tx, ptr, len);

    // fifth item is the gasLimit
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let gasLimit = rlp_read_u64(signed_tx, ptr, len);

    // sixth item is the to field
    // this is bytes but can be up to U256.
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let to = rlp_read_b256(signed_tx, ptr, len);

    // seventh item is the value
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);

    let (value, _) = match rlp_read_bytes_to_u256(signed_tx, ptr, len) {
        Some((result, new_ptr)) => {
            (result, new_ptr)
        }
        None => {
            // (u256::zero(), 0x00)
            return DecodeType02RLPResult::Fail(2007u64);
        }
    };

    // eigth item is the data
    // for the rlp decode, base asset only.
    let (ptr, _len) = rlp_decode_item(signed_tx, ptr + len);
    let asset_id = b256::zero();

    // ninth item is the accessList
    // let (ptr, len) = rlp_decode_payload(signed_tx, ptr + len);
    // let ptr_tx_data_end = ptr + len;
    let (ptr, len) = match rlp_decode_payload(signed_tx, ptr) {
        Some((new_ptr, new_len)) => (new_ptr, new_len),
        None => return DecodeType02RLPResult::Fail(2009u64),
    };
    let ptr_tx_data_end = ptr + len;

    // remaining three items are v, r, s
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let v = rlp_read_u64(signed_tx, ptr, len);
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let r = rlp_read_b256(signed_tx, ptr, len);
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let s = rlp_read_b256(signed_tx, ptr, len);

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

    DecodeType02RLPResult::Success((
        type_identifier,
        chain_id,
        nonce,
        maxFeePerGas,
        gasLimit,
        value,
        to,
        asset_id,
        digest,
        len,
        ptr_tx_data_start,
        ptr_tx_data_end,
        sig,
        from,
    ))
}

/// Computes the digest of a signed TypedTransaction EIP-1559 (type 2).
///
/// Takes the transaction data as bytes and the start and end pointers of the
/// transaction payload, and computes the digest of the signed EIP-1559 transaction.
/// The digest is calculated by RLP encoding the transaction payload and hashing it using the
/// Keccak-256 algorithm.
///
/// # Arguments
///
/// * `data` - The transaction data as bytes.
/// * `ptr_start` - The start pointer of the transaction payload.
/// * `ptr_end` - The end pointer of the transaction payload.
///
/// # Returns
///
/// The computed digest of the signed EIP-1559 transaction as a `b256`.
///
/// # Errors
///
/// This function will revert with an error code of 0 if the payload length is greater than 256 bytes.
///
/// # Examples
///
/// ```sway
/// let tx_data = Bytes::from([<rlp tx data>]);
/// let ptr_start = 10;
/// let ptr_end = 100;
/// let digest = tx_type2_digest(tx_data, ptr_start, ptr_end);
/// ```
///
/// # Note
///
/// The function uses inline assembly to allocate memory, copy the transaction payload,
/// and compute the Keccak-256 hash of the RLP encoded payload.
///
/// The RLP encoding scheme used in this function follows the EIP-1559 specification:
/// - If the payload length is less than or equal to 55 bytes, the RLP encoding consists of a single byte
///   with value `0xc0 + length`, followed by the payload bytes.
/// - If the payload length is greater than 55 bytes but less than or equal to 256 bytes, the RLP encoding
///   consists of two bytes: the first byte with value `0xf7 + length of the length`, and the second byte
///   with the actual length, followed by the payload bytes.
///
fn tx_type2_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> b256 {

    let txtype = 2;
    // let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let src = data.ptr().add_uint_offset(ptr_start);
    let len = (ptr_end ) - (ptr_start );
    let mut result_buffer = b256::min();

    if len <= 55 { // For buffer length < 55 :

        // 0xC0 + len , i.e., deciaml 192 + len (both a u64's)
        let a_prefix = RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + len;

        // this is 0xC0 + length. RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + len
        let a_size = len + 3;           // size in bytes of the memory on heap to create.
        let a_buflen = a_size - 1;      // length on memory bytes on heap to hash.

        // Obtain the keccak256 rlp data payload
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

        // 0xC0 + len , i.e., deciaml 192 + 1 (both a u64's)
        let a_prefix = RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START + len;
        let a_size = len + 4;
        let a_buflen = a_size - 1;
        let len0 = len;

        // Obtain the keccak256 rlp data payload
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

    b256::zero()
}

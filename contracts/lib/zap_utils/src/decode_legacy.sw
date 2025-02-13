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
use std::primitive_conversions::{u8::*, u16::*, u32::*, u64::*};

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
    RLP_ITEM_IDENTIFIER_IMMEDIATE_START,
};


pub enum DecodeLegacyRLPResult {
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

/// Decodes a signed EVM Legacy transaction
///
/// Takes a signed Legacy EVM transaction as RLP encoded bytes and decodes it into
/// its constituent fields. Handles chain ID calculation according to EIP-155.
///
/// # Arguments
///
/// * `signed_tx` - The signed Legacy transaction as RLP encoded bytes
///
/// # Returns
///
/// A DecodeLegacyRLPResult containing either:
/// * Success variant with decoded transaction fields
/// * Fail variant with error code if decoding fails
///
/// # Notes
///
/// - Processes legacy transactions which must include chain ID per EIP-155
/// - Calculates chain ID from v value: chain_id = (v - 35) >> 1
/// - Recovers sender address from signature and calculated digest
///
pub fn decode_signed_legacy_tx(signed_tx: Bytes) -> DecodeLegacyRLPResult {

    // Legacy (0x00) - legacy style transaction.

    // note: must include chain id.
    let type_identifier = convert_u8_u64(signed_tx.get(0).unwrap());
    // this would just be the start of the rlp encoding. something like f8
    // if type_identifier != 2 {
    //     // incorrect transaction type.
    //     return DecodeLegacyRLPResult::Fail(1999u64);
    // }

    let ptr: u64 = 1;

    // Assign the payload opening
    let ptr_tx_data_start = 2;

    // 1st item is the nonce
    let ptr = ptr + 1;
    let (ptr, len) = rlp_decode_item(signed_tx, ptr);
    let nonce = rlp_read_u64(signed_tx, ptr, len);

    // 2nd item is the gas_price
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let gas_price = rlp_read_u64(signed_tx, ptr, len);

    // 3rd item is the gas_limit
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let gas_limit = rlp_read_u64(signed_tx, ptr, len);

    // 4th item is the to field
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let to = rlp_read_b256(signed_tx, ptr, len);

    // 5th item is the value
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let (value, _) = match rlp_read_bytes_to_u256(signed_tx, ptr, len) {
        Some((result, new_ptr)) => {
            (result, new_ptr)
        }
        None => {
            return DecodeLegacyRLPResult::Fail(1005u64);
        }
    };

    // 6th item is the chain id w.r.t EIP-155
    // https://eips.ethereum.org/EIPS/eip-155
    // this is also the v of signature.
    let ptr = ptr + len + 1;
    let (ptr, len) = rlp_decode_item(signed_tx, ptr);

    let v_chain_id = rlp_read_u64(signed_tx, ptr, len);

    // convert chain id w.r.t EIP-155
    let mut chain_id = 0;
    if v_chain_id >= 35 {
        chain_id = ((v_chain_id - 35) >> 1);
    }

    // The ptr value below is pointing to the first byte of v_chian_id,
    // the last byte of the payload is: ptr_payload_end - 2
    // i.e. ptr includs the rlp prefix for the chainid data.
    let ptr_payload_end = ptr;

    //REVIEW - the v_chain_id bytes length, may not be the same length as the bytes calcualted below.
    //TODO - get the ptr, reverse it one byte, work out how many bytes long the original cahinid data is.
    // its probably likley that this does not exceed the rlp encoding byte limit. so if it was
    // for example  1 - 10 bytes it should be ok. Either way, need constrain this.

    // For total payload length add ptr_payload_end to length repr bytes
    // of chain_id convert u64 to bytes and get length

    let chain_id_bytes_temp = chain_id.to_be_bytes();

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

    //7th & 8th item is r, s
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let r = rlp_read_b256(signed_tx, ptr, len);
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let s = rlp_read_b256(signed_tx, ptr, len);

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

    // Construct the Signature from (r, s, v) and get the "from" public key
    let sig = compact_signature_normalize(r, s, v_chain_id);
    let from: b256 = ec_recover_evm_address(sig, digest).unwrap().into();

    let asset_id = b256::zero();

    DecodeLegacyRLPResult::Success(( type_identifier, chain_id, nonce, gas_price, gas_limit, value, to, asset_id, digest, 0, 0, 0, sig, from ))
}

/// Computes the digest of a signed Legacy transaction
///
/// Takes the transaction data and chain ID information to construct and hash
/// the RLP encoded payload according to EIP-155 specification.
///
/// # Arguments
///
/// * `encoded_payload_prefix` - The RLP prefix byte for the entire payload
/// * `signed_tx` - The original signed transaction bytes
/// * `payload_ptr_start` - Start pointer of the payload data
/// * `payload_ptr_end` - End pointer of the payload data
/// * `chain_id_bytes` - The chain ID bytes derived from v value
///
/// # Returns
///
/// The Keccak-256 hash of the constructed RLP payload as b256
///
/// # Notes
///
/// Constructs payload in format:
/// <prefix_byte> <rlp_payload> <chain_id_bytes> <0x80 0x80>
/// Where:
/// - prefix_byte: 0xc0 + length of following data
/// - rlp_payload: Original transaction data up to v
/// - chain_id_bytes: RLP encoded chain ID
/// - 0x80 0x80: Two RLP encoded zeros per EIP-155
///
fn tx_type_legacy_digest( encoded_payload_prefix: u64, signed_tx: Bytes, payload_ptr_start: u64, payload_ptr_end: u64, chain_id_bytes: Vec<u8> ) -> b256 {
        let mut result_buffer = b256::min();
        let chain_id_bytes_len = chain_id_bytes.len();

        // The <rlp payload> length itself:
        let _p_ems = (payload_ptr_end - payload_ptr_start);

        // start constructing the cytes to hash:
        let mut payloadbytes = Bytes::new();

        // add prefix byte <xx>:
        payloadbytes.push(encoded_payload_prefix.try_as_u8().unwrap());

        // Add the tx data bytes <rlp payload>:
        let mut j = payload_ptr_start;
        while j < (payload_ptr_end - 0x02) {
            payloadbytes.push(signed_tx.get(j).unwrap());
            j += 1;
        }

        // Add the rlp encoded chain_id bytes <chain_id_bytes>:
        let rlp_chain_id_bytes = RLP_ITEM_IDENTIFIER_IMMEDIATE_START + chain_id_bytes_len;
        payloadbytes.push(RLP_ITEM_IDENTIFIER_IMMEDIATE_START.try_as_u8().unwrap());     // add 0x80
        payloadbytes.push(rlp_chain_id_bytes.try_as_u8().unwrap());                      // add 0x80 + chain_id bytes length.

        j = 0;
        while j < chain_id_bytes_len {
            payloadbytes.push(chain_id_bytes.get(j).unwrap());
            j += 1;
        }

        // append with two rlp encoded zeros <8080>:
        j = 0;
        while j < 2 {
            payloadbytes.push(0x80);
            j += 1;
        }
        let len = payloadbytes.len();
        let a_size = len + 1;
        let a_buflen = a_size - 1;
        let x_src = payloadbytes.ptr();

        let _ = asm( hash: result_buffer, ptrdata: x_src, length: a_buflen,  size: a_size, buflen: a_buflen, memptr  ) {
            aloc size;                              // allocate memory to the stack
            addi memptr hp i1;                      // increase memory pointer for copying payload items
            mcp  memptr ptrdata length;             // copy
            addi memptr hp i1;                      // move memory pointer back to the beginning
            k256 hash memptr buflen;
            hash: b256
        };
        return(result_buffer);
}

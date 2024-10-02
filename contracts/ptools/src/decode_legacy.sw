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
    compact_signature_normalize,
    RLP_PAYLOAD_IDENTIFIER_IMMEDIATE_START,
    RLP_ITEM_IDENTIFIER_IMMEDIATE_START,
};



/// Decodes an EVM signed Legacy Transaction,.
///
/// # Arguements
///
/// * the rlp encoded bytes of a signed legacy format evm transaction.
///
/// # Returns
///
/// * transaction detials as below.
///
pub fn decode_signed_legacy_tx(signed_tx: Bytes)
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
    let sig = compact_signature_normalize(r, s, v_chain_id);
    let from: b256 = ec_recover_evm_address(sig, digest).unwrap().into();
    //log(from);
    //log(sig);

    let asset_id = b256::zero();
    return (
        0, chain_id, nonce, gas_price, gas, value, to, asset_id,
    digest, 0, 0, 0,
    sig, from)

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

        //let x_src = payloadbytes.buf.ptr();
        let x_src = payloadbytes.ptr();

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

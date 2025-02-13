library;

use std::{ b512::B512, vm::evm::{ ecr::ec_recover_evm_address, evm_address::EvmAddress }, bytes::Bytes, math::*, option::Option, string::String,};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use ::rlp_utls6::{ convert_u8_u64, rlp_decode_payload, length_to_digest, rlp_decode_item, rlp_read_u64, rlp_read_b256, rlp_decode_transfer_bytes, compact_signature_normalize };


pub enum DecodeERC20RLPResult {
    Success: (
        u64,    // type_identifier
        u64,    // chain_id
        u64,    // nonce
        u64,    // maxFeePerGas
        u64,    // gasLimit
        u64,    // value
        b256,   // to (is the erc20 ContractId)
        b256,   // asset_id
        b256,   // digest
        u64,    // length
        u64,    // tx_data_start
        u64,    // tx_data_end
        B512,   // signature
        b256,   // from
        b256,   // erc20 contract transfer; to (the evm address receiver)
        b256,   // erc20 contract transfer; amount in wei (U256)
    ),
    Fail: (u64),
}

/// Decodes an EVM signed TypedTransaction EIP-1559 (0x02) containing an ERC20 transfer.
///
/// This function takes a signed EIP-1559 transaction containing an ERC20 transfer function call
/// as RLP encoded bytes and decodes it into its constituent fields. It returns a tuple containing
/// both the transaction fields and the decoded ERC20 transfer parameters.
///
/// # Arguments
///
/// * `signed_tx` - The signed EIP-1559 transaction as RLP encoded bytes.
///
/// # Returns
///
/// A DecodeERC20RLPResult::Success containing the following fields:
///
/// * `type_identifier` - The transaction type identifier (u64)
/// * `chain_id` - The chain ID (u64)
/// * `nonce` - The transaction nonce (u64)
/// * `maxFeePerGas` - The maximum fee per gas (u64)
/// * `gasLimit` - The gas limit (u64)
/// * `value` - The transaction value (u64)
/// * `to` - The ERC20 contract address (b256)
/// * `asset_id` - The asset ID (b256)
/// * `digest` - The transaction digest (b256)
/// * `length` - The length of the transaction data (u64)
/// * `tx_data_start` - The start index of the transaction data (u64)
/// * `tx_data_end` - The end index of the transaction data (u64)
/// * `signature` - The transaction signature (B512)
/// * `from` - The sender address (b256)
/// * `ct_to` - The recipient address for the ERC20 transfer (b256)
/// * `ct_amount` - The amount of tokens to transfer (b256)
///
/// # Errors
///
/// This function will return DecodeERC20RLPResult::Fail with error code:
/// - 3999: If the transaction is not an EIP-1559 (type 2) transaction
/// - Will revert(0) if RLP payload decoding fails
///
/// # Additional Notes
///
/// - The function specifically handles ERC20 transfer function calls encoded in the transaction data
/// - The `to` field represents the ERC20 contract address being called
/// - The `ct_to` and `ct_amount` fields are extracted from the decoded transfer function call data
/// - Unlike regular ETH transfers, the `value` field should be 0 as value is sent via the ERC20 transfer
/// - The function uses RLP decoding utilities from the rlp_utls6 module
///
pub fn decode_signed_typedtx_erc20(signed_tx: Bytes) -> DecodeERC20RLPResult {

    let type_identifier = convert_u8_u64(signed_tx.get(0).unwrap());
    if type_identifier != 2 {
        // incorrect transaction type.
        return DecodeERC20RLPResult::Fail(3999u64);
    }

    // EIP-1559 (0x02) - Type 2 style transaction
    let ptr: u64 = 1;

    // Decode the payload opening
    // let (ptr, _) = rlp_decode_payload(signed_tx, ptr);
    // let ptr_tx_data_start = ptr;
    let ptr: u64 = match rlp_decode_payload(signed_tx, ptr) {
        Some((new_ptr, _)) => new_ptr,
        None => revert(0),
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
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let to = rlp_read_b256(signed_tx, ptr, len);

    // seventh item is the value
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    let value = rlp_read_u64(signed_tx, ptr, len);

    // eigth item is the data
    // b8xx: This prefix is for the data field
    // where xx is the number of bytes.
    let (ptr, len) = rlp_decode_item(signed_tx, ptr + len);
    //TODO: analyze this data to determine what tokens are being transferred

    // ct_to: contract transfer() to address (the recipient) and token amount.
    // the `ct_to` filed is the ERC20 contract address (aka the token id)
    let (ct_to, ct_amount) = rlp_decode_transfer_bytes(signed_tx, ptr, len);

    // The asset id is zerod
    let asset_id = b256::zero();

    // ninth item is the accessList
    // let (ptr, len) = rlp_decode_payload(signed_tx, ptr + len);
    // let ptr_tx_data_end = ptr + len;
    let (ptr, len) = match rlp_decode_payload(signed_tx, ptr + len) {
        Some((new_ptr, new_len)) => (new_ptr, new_len),
        None => revert(0),
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

    // compute the digest that the sender signs
    let digest = tx_erc20_digest(signed_tx, ptr_tx_data_start, ptr_tx_data_end);
    // log(digest);

    // use signature to get the "from" public key
    let sig = compact_signature_normalize(r, s, v);
    let from: b256 = ec_recover_evm_address(sig, digest).unwrap().into();

    DecodeERC20RLPResult::Success(( type_identifier, chain_id, nonce, maxFeePerGas, gasLimit, value, to, asset_id, digest, len, ptr_tx_data_start, ptr_tx_data_end, sig, from, ct_to, ct_amount ))
}

/// Computes the digest of a signed TypedTransaction EIP-1559 (type 2) containing an ERC20 transfer.
///
/// Takes the transaction data as bytes and the start and end pointers of the
/// transaction payload, and computes the digest of the signed EIP-1559 transaction.
/// The digest is calculated by RLP encoding the transaction payload and hashing it using
/// the Keccak-256 algorithm.
///
/// # Arguments
///
/// * `data` - The transaction data as bytes
/// * `ptr_start` - The start pointer of the transaction payload
/// * `ptr_end` - The end pointer of the transaction payload
///
/// # Returns
///
/// The computed digest of the signed EIP-1559 transaction as a `b256`.
///
/// # Notes
///
/// - The function assumes the payload length will be > 55 bytes due to ERC20 transfer data
/// - Handles payloads up to 256 bytes in length
/// - Uses inline assembly for memory allocation, copying and hashing
/// - Returns zero for payloads ≤ 55 bytes or > 256 bytes
/// - The RLP encoding follows EIP-1559 specification with 0xf8 prefix for lengths > 55 bytes
///
fn tx_erc20_digest(data: Bytes, ptr_start: u64, ptr_end: u64) -> b256 {

    let txtype = 2;
    let src = data.ptr().add_uint_offset(ptr_start);
    let len = (ptr_end ) - (ptr_start );
    let mut result_buffer = b256::min();

    if len <= 55 {
        // will it ever be less than 56 for a transfer? no.
        return(b256::zero());
    }
    if len <= 256 {
        let a_prefix = 0xf8u64;
        let a_size = len + 4;
        let a_buflen = a_size - 1;
        let len0 = len;
        let _ = asm(hash: result_buffer, ptrdata: src, length: len, size: a_size, txtype: txtype, prefix: a_prefix, len0: len0, buflen: a_buflen, memptr ) {
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

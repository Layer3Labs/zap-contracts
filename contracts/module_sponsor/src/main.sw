predicate;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    tx::{
        tx_id,
        tx_witness_data,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::{
        input_coin_owner,
        input_asset_id,
        input_amount,
        Input,
    },
    outputs::{
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
    },
    hash::Hasher,
};
use std::*;
use std::bytes_conversions::{b256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use helpers::general_helpers::{
    hex_string_to_bytes,
    char_to_hex,
};

use ptools::{
    transaction_utls::{
        verify_input_coin,
        verify_output_change,
        verify_output_coin,
        input_txn_hash,
        input_coin_asset_id,
    },
    personal_sign::personal_sign_hash,
};



configurable {
    OWNER: b256 = b256::zero(),
    INDEX: u64 = 1,
}

/// Verify that the input at index is coin and the default asset.
/// Returns the utxo_txid and the owner of the utxo at index.
fn verify_input_coin_gas(index: u64) -> (Option<Bytes>, Option<Address>) {
    let mut bytes = Bytes::new();

    if verify_input_coin(index) && (input_coin_asset_id(index) == b256::zero()) {
        let txn_hash = input_txn_hash(index);
        let mut txn_hash_bytes = txn_hash.to_be_bytes();
        bytes.append(txn_hash_bytes);
        let inp_coin_owner = input_coin_owner(index);
        // return the bytes of the utxo_txid coin input at index, and the owner as an Address.
        return (Some(bytes), inp_coin_owner);
    } else {
        return (None, None);
    }
}


/// Validates a transaction by verifying:
/// 1. The base asset input UTXO at index 0
/// 2. The owner's signature at witness index 1
///
/// The signature is expected to be over SHA256(gas_input_utxo_id || this_tx_id),
/// where '||' denotes concatenation.
///
/// Returns true if the signature is valid and matches the expected owner.
fn main() -> bool {

    let ( op_inp_gas_utxoid, op_owner_addr ) = verify_input_coin_gas(INDEX);
    let inp_gas_utxoid = op_inp_gas_utxoid.unwrap();
    let owner_addr = op_owner_addr.unwrap();

    let txid: Bytes = tx_id().to_be_bytes();
    // log(txid);        // log the txid. Bytes

    let mut payload = Bytes::new();
    payload.append(inp_gas_utxoid);
    payload.append(txid);
    let mut hasher = Hasher::new();
    hasher.write(payload);
    let payload_hash = hasher.sha256();
    // log(payload_hash);  // log the sha256(inp_gas_utxoid:thistxid), b256

    let witness_index = 1u64;
    let signature: B512 = tx_witness_data(witness_index).unwrap();
    let result_signer = ec_recover_evm_address(signature, personal_sign_hash(payload_hash)).unwrap();
    // log(result_signer);

    OWNER == result_signer.bits()
}

predicate;

use std::{
    b512::B512,
    bytes::Bytes,
    constants::*,
    tx::{
        tx_id,
        tx_witness_data,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
    },
    inputs::{
        input_count,
    },
};

use ptools::{
    personal_sign::personal_sign_hash,
    transaction_utls::{
        input_coin_asset_id,
        verify_input_coin,
    },
};

configurable {
    OWNER: b256 = b256::zero(),
    MODULE_KEY01_ASSETID: b256 = b256::zero(),
    MODULE_KEY02_ASSETID: b256 = b256::zero(),
    MODULE_KEY03_ASSETID: b256 = b256::zero(),
    MODULE_KEY04_ASSETID: b256 = b256::zero(),
    MODULE_KEYFF_ASSETID: b256 = b256::zero(),
}

/// This predicate verifies that a transaction id has been signed by a specific Ethereum address.
/// It uses EIP-191 personal sign format for signature verification.
///
/// # Arguments
///
/// * `witness_index`: u64 - The index of the witness data containing the signature.
///
/// # Returns
///
/// * `bool` - True if the signature is valid and matches the configured signer, false otherwise.
///
/// # Behavior
///
/// 1. Retrieves the signature from the transaction's witness data.
/// 2. Computes the personal sign hash of the txid.
/// 3. Attempts to recover the EVM signers (padded) pubkey from the signature and hash.
/// 4. Compares the recovered address with the configured owner address.
/// 5. Returns true if they match, false otherwise.
///
/// # References:
/// see: https://github.com/FuelLabs/fuel-connectors/blob/main/packages/evm-predicates/predicate/src/main.sw
///
fn main(witness_index: u64) -> bool {

    if check_input_no_modules() {
        return false;
    }

    let signature: B512 = tx_witness_data(witness_index).unwrap();
    let result = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));
    if result.is_ok() {
        if OWNER == result.unwrap().into() {
            return true;
        }
    }
    false
}

fn check_input_no_modules() -> bool {
    let in_count: u64 = input_count().into();
    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let coin_asset_id = input_coin_asset_id(i);
            if (coin_asset_id == MODULE_KEY01_ASSETID ||
                coin_asset_id == MODULE_KEY02_ASSETID ||
                coin_asset_id == MODULE_KEY03_ASSETID ||
                coin_asset_id == MODULE_KEY04_ASSETID ||
                coin_asset_id == MODULE_KEYFF_ASSETID) {

                return true;
            }
        }
        i += 1;
    }
    return false;
}
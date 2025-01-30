library;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    hash::*,
    vm::evm::ecr::ec_recover_evm_address,
    inputs::{
        input_coin_owner,
        input_count,
        input_asset_id,
        input_amount,
        Input,
    },
    outputs::{
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
        Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use ptools::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_input_coin,
        output_count,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        verify_output_change,
        verify_output_coin,
        input_txn_hash,
    },
};
use ::evmtx_io_utils::InpOut;





/// Finds the first occurrence of the given `assetid` in the inputs and returns its `utxoid`.
///
/// # Arguments
///
/// * `assetid` - The asset ID to search for in the inputs.
///
/// # Returns
///
/// * `Option<b256>` - Returns `Some(utxoid)` if the asset is found in the inputs, otherwise `None`.
///
/// # Behavior
///
/// - Iterates through all inputs and checks if the `assetid` matches.
/// - If a match is found, it retrieves the `utxoid` using `input_txn_hash(i)` and returns it.
/// - If no match is found, it returns `None`.
///
/// # Example
///
/// ```sway
/// let assetid = b256::from_hex("0x123...");
/// match find_utxoid_by_asset(assetid) {
///     Some(utxoid) => {
///         // Handle the found utxoid
///     },
///     None => {
///         // Handle the case where the asset is not found
///     }
/// }
/// ```
pub fn find_utxoid_by_asset(assetid: b256) -> Option<b256> {
    let in_count: u64 = input_count().as_u64();

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let input_asset = input_coin_asset_id(i);
            if input_asset == assetid {
                // Found the asset, return the utxoid
                return Some(input_txn_hash(i));
            }
        }
        i += 1;
    }

    // Asset not found in inputs
    None
}





/// for Success:
/// - asset inputor output owner address.
/// for Fail:
/// - error_code
pub enum CheckAssetResult {
    Success: (Address),
    Fail: (u64),
}

/// Obtains that an input or output asset exists within the vector of InpOut.
///
/// Iterates over the input assets and looks for an asset that matches the specified
/// `nonce_assetid`. If found, it returns the owner.
///
/// # Arguments
///
/// * `tx_inputs` - A vector of InpOut structures representing the input assets.
/// * `nonce_assetid` - The asset ID of the nonce asset to look for.
///
/// # Returns
///
/// * `NonceCheckUpgradeResult::Success` - If the nonce check is successful, returns the owner
///   address of the nonce asset (Address).
/// * `NonceCheckUpgradeResult::Fail` - If the nonce check fails, returns an error code (u64):
///   - `0070`: No valid amount provided for the nonce asset.
///   - `0071`: The correct nonce asset/value combination was not found.
///
pub fn check_asset_exists(
    tx_inputs: Vec<InpOut>,
    nonce_assetid: b256,
) -> CheckAssetResult {
    let mut nonce_ok = false;
    let mut nonce_idx = 0u64;
    let mut i = 0;
    while i < tx_inputs.len() {
        let input = tx_inputs.get(i).unwrap();
        let asset = input.assetid;
        let amount = input.amount;

        // if the i'th assetid is not the same as the nonce assetid, skip it.
        if asset != nonce_assetid {
            i += 1;
            continue;
        }

        match input.amount {
            Some(val) => {
                // Dontneed to check the value here, just return the owner.
                nonce_ok = true;
                nonce_idx = i;
            },
            None => {
                // No valid amount provided for nonce
                return CheckAssetResult::Fail(0070u64);
            },
        };
        i += 1;
    }
    if nonce_ok {
        // Return the nonce owner
        let nonce_input = tx_inputs.get(nonce_idx).unwrap();
        return CheckAssetResult::Success((
            nonce_input.owner.unwrap()
        ));
    }
    CheckAssetResult::Fail(0071u64) // Correct nonce asset not found.
}


//
pub fn collect_inputs_outputs_change() -> (Vec<InpOut>, Vec<InpOut>, Vec<InpOut>) {

    // Collect inputs and outputs:
    let in_count: u64 = input_count().as_u64();
    let out_count: u64 = output_count();

    let mut tx_inputs : Vec<InpOut> = Vec::new();
    let mut tx_outputs : Vec<InpOut> = Vec::new();
    let mut tx_change: Vec<InpOut> = Vec::new();

    let mut i = 0;
    while i < in_count {
        // collect all the input coins.
        if verify_input_coin(i) {

            let inp = InpOut::new(
                input_coin_asset_id(i),
                Some(input_coin_amount(i)),
                input_coin_owner(i)
            );

            //NOTE - DEBUG
            // let inp = InpOut::new(
            //     b256::zero(),
            //     Some(input_coin_amount(i)),
            //     input_coin_owner(i)
            // );

            tx_inputs.push(inp);
        }
        i += 1;
    }
    let mut j = 0;
    while j < out_count {
        // collect all the output coins.
        if verify_output_coin(j) {
            let outp = InpOut::new(
                output_coin_asset_id(j).unwrap(),
                Some(output_amount(j).unwrap()),
                Some(output_asset_to(j).unwrap()),
            );
            tx_outputs.push(outp);
        }
        // collect all the change outputs assetid's and receivers.
        match verify_output_change(j) {
            Some(is_change) => {
                if is_change {
                    // add change details: assetid, to,
                    tx_change.push(
                        InpOut::new(
                            output_asset_id(j).unwrap().into(),
                            None,
                            Some(output_asset_to(j).unwrap()),
                        )
                    );
                }
            },
            _ => {},
        }
        j += 1;
    }

    (tx_inputs, tx_outputs, tx_change)
}
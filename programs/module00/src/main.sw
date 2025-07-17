predicate;

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
use io_utils::io::{
    InpOut,
    CheckAssetResult, check_asset_exists,
    find_utxoid_and_owner_by_asset,
    collect_inputs_outputs_change,
};
use module00_utils::ack_message::WalletUpgradeAcknowledgment;
use zap_utils::personal_sign_string::*;


configurable {
    /// The address of the ZapWallet master owner.
    OWNER_ADDRESS: b256 = b256::zero(),
    /// The nonce native assetid ascoiated with the owners ZapWallet.
    NONCE_ASSETID: b256 = b256::zero(),
    /// This modules assetid as a b256.
    MODULE_KEY00_ASSETID: b256 = b256::zero(),
    /// The address of the ZapManager V1 contract.
    ZAPMANAGER_V1: b256 = b256::zero(),
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
}


/// ZapWallet Module 00.
///
/// This module verifies the upgrade acknowledgement message parameters and signature for the that upgrade
/// a ZapWallet from V1 to V2.
///
/// # Arguments
///
/// * `compact_signature`: [B512] - The compact signature of the upgrade acknowledgment message
/// * `v2_version`: [String] - The version string of V2 ZapWallet in format "X.Y.Z"
///
/// # Returns
///
/// * [bool] - Returns true if the upgrade acknowledgement is valid and signed by the owner, false otherwise
///
/// # Additional Information
///
/// This predicate ensures:
/// - The module00 asset is properly sent to ZapManager V1 Contract.
/// - The nonce asset ownership is verified in both inputs and outputs
/// - The upgrade acknowledgment message is properly signed by the ZapWallet owner
///
fn main(
    compact_signature: B512,
    v2_version: String,
) -> bool {

    // Collect inputs and outputs:
    let (tx_inputs, tx_outputs, _tx_change) = collect_inputs_outputs_change();

    // The only function thats payable at the ZapManager V1 is the upgrade function.
    // Check if module00 asset is sent to ZapManager. Otherwise fail.
    if !verify_module00_output(
        tx_outputs,
        MODULE_KEY00_ASSETID,
        Address::from(ZAPMANAGER_V1),
    ) {
        return false;
    }

    // Get the owner of the nonce asset, this should be the owners ZapWallet
    let from_address: b256 = match check_asset_exists(tx_inputs, NONCE_ASSETID ) {
        CheckAssetResult::Success(nonce_owner_from) => {
            nonce_owner_from.into()
        },
        CheckAssetResult::Fail(_error_code) => {
            // fail if there was an error matching an input to the nonce asset.
            return false;
        },
    };

    // Obtain the receiving master address from the nonce asset output to
    let to_address: b256 = match check_asset_exists(tx_outputs, NONCE_ASSETID ) {
        CheckAssetResult::Success(nonce_to) => {
            nonce_to.into()
        },
        CheckAssetResult::Fail(_error_code) => {
            // return Err(error_code);
            //NOTE - should probably just fail it here
            b256::zero()
        },
    };

    // Get the utxo id of the upgrade module
    let (utxo_id, _module00_owner) = match find_utxoid_and_owner_by_asset(MODULE_KEY00_ASSETID) {
        Some((utxoid, owner)) => {
            // utxo module00 asset is found
            (utxoid, owner)
        },
        None => {
            // Handle the case where the asset is not found
            (b256::zero(), Address::zero())
        }
    };

    // The final version of V1 ZapWallet will always be tagged 1.0.0
    let current_version = String::from_ascii_str("1.0.0");

    // Build the Acknowledgment message using the V2 version is passed in by the tx builder.
    let acknowledgment = WalletUpgradeAcknowledgment::new(
        from_address,
        to_address,
        current_version,
        v2_version,
        utxo_id,
    );
    // Build the acknowledgment message
    let message = acknowledgment.get_message();

    // Obtain the hash of the acknowledgment message
    let eip191_message_hash = personal_sign_string(message);

    // Recover the signer and compare
    let result = ec_recover_evm_address(compact_signature, eip191_message_hash);
    if result.is_ok() {
        if OWNER_ADDRESS == result.unwrap().into() {
            return true;
        }
    }

    return false;
}

/// Verifies if there exists a coin output that sends the module00 asset to the ZapManager V1 contract.
///
/// # Arguments
///
/// * `tx_outputs` - A vector of InpOut structures representing transaction outputs
/// * `module00_assetid` - The asset ID of the module00 asset
/// * `zapmanagerv1` - The address of the ZapManager V1 contract
///
/// # Returns
///
/// * `bool` - Returns true if there exists an output that matches the module00 asset
///           and is sent to the ZapManager V1 contract address
///
pub fn verify_module00_output(
    tx_outputs: Vec<InpOut>,
    module00_assetid: b256,
    zapmanagerv1: Address,
) -> bool {
    let mut i = 0;
    while i < tx_outputs.len() {
        let output = tx_outputs.get(i).unwrap();

        // Check if this output's asset matches module00_assetid
        if output.assetid == module00_assetid {
            // Check if the output is sent to ZapManager V1
            match output.owner {
                Some(owner) => {
                    if owner == zapmanagerv1 {
                        return true;
                    }
                },
                None => {},
            }
        }
        i += 1;
    }

    false
}

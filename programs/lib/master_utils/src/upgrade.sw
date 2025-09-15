library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    hash::*,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    tx::tx_witness_data,
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use ::types::*;
use ::tools::*;
use zap_utils::personal_sign_string::*;
use io_utils::io::{
    // InpOut,
    // CheckAssetResult, check_asset_exists,
    find_utxoid_and_owner_by_asset,
    collect_inputs_outputs_change,
};
use walletop_upgrade::{
    io_verify::*,
    ack_message::WalletUpgradeAcknowledgment,
};



/// Verifies a wallet upgrade operation.
///
/// # Arguments
///
/// * `op`: [WalletOp] - The wallet operation containing upgrade details
/// * `owner_address`: [b256] - The owner's address for signature verification
/// * `tx_outputs`: [Vec<InpOut>] - Transaction outputs to verify
///
/// # Returns
///
/// * [bool] - True if upgrade is valid, false otherwise
///
pub fn verify_wallet_upgrade(
    op: WalletOp,
    owner_address: b256,
    v1_manager_id: b256,
) -> bool {

    // Calculate the v1 nonce asset id from the configs
    let v1_nonce_assetid = get_nonce_assetid(owner_address, v1_manager_id);

    // Extract and validate nonce from transaction inputs
    let (_nonce_amount, from_address) = match extract_nonce_from_inputs(v1_nonce_assetid) {
        NonceExtractionResult::Success((amount, owner)) => {
            (amount, owner)
        },
        NonceExtractionResult::NotFound => {
            (0, Address::zero()) // Won't reach here
        },
        NonceExtractionResult::Invalid => {
            (0, Address::zero()) // Won't reach here
        }
    };

    // Get the utxo id of the v1 nonce input
    let (nonce_utxo_id, _nonce_owner) = match find_utxoid_and_owner_by_asset(v1_nonce_assetid) {
        Some((utxoid, owner)) => {
            // nonce asset utxo is found
            (utxoid, owner)
        },
        None => {
            // Handle the case where the asset is not found
            (b256::zero(), Address::zero())
        }
    };

    // Obtain the v2 master address from the outputs and verify at the same time.
    let v2_master_address = match verify_outputs_same_destination(
        Address::from(v1_manager_id),
        v1_nonce_assetid
    ) {
        OutputValidationResult::Success(dest) => {
            // Found v2_master address from outputs
            dest  // This IS the v2_master address!
        },
        OutputValidationResult::MixedDestinations => {
            // Outputs go to different destinations, all outputs must go to same v2_master
            Address::zero()
        },
        OutputValidationResult::NoOutputs => {
            // No outputs found for v2_master
            Address::zero()
        }
    };

    // The final version of V1 ZapWallet will always be tagged 1.0.0
    let current_version = String::from_ascii_str("1.0.0");

    // The final version of V2 ZapWallet will always be tagged 2.0.0
    let latest_version = String::from_ascii_str("2.0.0");

    // Build the Acknowledgment message using the V2 version is passed in by the tx builder.
    let acknowledgment = WalletUpgradeAcknowledgment::new(
        from_address.into(),
        v2_master_address.into(),
        current_version,
        latest_version,
        nonce_utxo_id,
    );
    // Build the acknowledgment message
    let message = acknowledgment.get_message();

    // Obtain the hash of the acknowledgment message
    let eip191_message_hash = personal_sign_string(message);

    let witness_index = op.override_witness_index.unwrap_or(0);

    let compact_signature: B512 = tx_witness_data(witness_index).unwrap();

    // Recover the signer and compare
    match ec_recover_evm_address(compact_signature, eip191_message_hash) {
        Ok(recovered_address) => owner_address == recovered_address.into(),
        Err(_) => false,
    }
}
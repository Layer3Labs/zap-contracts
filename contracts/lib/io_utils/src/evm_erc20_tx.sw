library;

use std::bytes::Bytes;
use std::bytes_conversions::{u64::*, b256::*};
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use zap_utils::wei_to_eth::wei_to_eth;
use ::io::InpOut;
use ::evmtx_io_utils::{
    NonceCheckResult, nonce_check,
    verify_change_output, verify_receiver,
};


/// Compares a b256 values, checking if the last 20 bytes of x match the first 20 bytes of y
/// x: partial assetId (12 zero bytes + 20 bytes at end)
/// y: full 32 byte value where first 20 bytes should match
/// Returns true if the last 20 bytes of x match the first 20 bytes of y
///
pub fn compare_asset_ids(x: b256, y: b256) -> bool {
    // Convert both b256 values to bytes for easier comparison
    let x_bytes = x.to_be_bytes();
    let y_bytes = y.to_be_bytes();

    // Compare last 20 bytes of x (starting at index 12)
    // with first 20 bytes of y (starting at index 0)
    let mut i = 0;
    while i < 20 {
        // For x, we look at position 12+i (last 20 bytes)
        // For y, we look at position i (first 20 bytes)
        if x_bytes.get(12 + i).unwrap() != y_bytes.get(i).unwrap() {
            return false;
        }
        i += 1;
    }

    true
}

/// Verifies if an asset is one of the allowed types
///
/// Valid types: src20_asset, FUEL_BASE_ASSET, nonce_asset, module03_asset.
///
/// Returns true if the asset is valid (one of the allowed types)
/// Returns false if the asset is not an allowed type
///
fn is_valid_asset_type( asset: b256, src20_asset: b256, nonce_asset: b256, module03_asset: b256 ) -> bool {
    //REVIEW - match statementh use here compiles to nonsensical warning.
    if asset == FUEL_BASE_ASSET { return true; }
    if asset == nonce_asset { return true; }
    if asset == module03_asset { return true; }
    if compare_asset_ids(src20_asset, asset) { return true; }

    false
}

/// Represents successful aggregation results for Module 03 transaction assets
///
pub struct AggSuccess {
    // Total accumulated gas amount (as u256)
    agg_gas_amount: u256,
    // Total accumulated SRC20 token amount (as u256)
    agg_src20_amount: u256,
    // The asset ID of the SRC20 token being transferred
    src20_assetid: b256,
    // Address of the sender/owner of the SRC20 input
    sender_addr: Address,
    // Boolean indicating if all relevant assets belong to the same owner
    assets_same_owner: bool,
}

/// Result type for asset aggregation operations
///
/// # Variants
/// * `Success(AggSuccess)` - Contains aggregated transaction data in an AggSuccess struct
/// * `Fail(u64)` - Contains an error code indicating why the aggregation failed
///
pub enum AggregateResult { Success: (AggSuccess), Fail: (u64),}

/// Aggregates assets and their amounts from a vector of InpOut structures.
///
/// This function iterates over the input assets, ignoring the specified nonce asset,
/// and checks if all the remaining assets are of type FUEL_BASE_ASSET or SRC20. It accumulates
/// the amounts for FUEL_BASE_ASSET inputs and checks if all input owners are the same
/// and match the provided nonce_owner.
///
/// # Arguments
///
/// * tx_inputs - A vector of InpOut structures containing asset IDs, amounts, and owners.
/// * nonce_asset - The asset ID of the nonce asset to be ignored during aggregation.
/// * nonce_owner - The expected owner address for all input assets.
///
/// # Returns
///
/// * AggregateResult::Success - If the aggregation is successful, returns a populated AggSuccess struct:
///   - The total aggregated amount in FuelEth (u256).
///   - The owner address of all input assets (Address).
///   - A boolean indicating whether all input assets are of type FUEL_BASE_ASSET and have the same owner.
/// * AggregateResult::Fail - If the aggregation fails, returns an error code (u64).
///
pub fn aggregate_multiple_assets( tx_inputs: Vec<InpOut>, src20_asset: b256, nonce_asset: b256, nonce_owner: Address, modulexx_asset: b256,) -> AggregateResult {
    let mut aggregated_gas_amount = u256::zero();
    let mut aggregated_src20_amount = u256::zero();
    let mut src20_assetid = b256::zero();
    let mut assets_same_owner = true;   // the src20 owner is the same as the nonce asset.
    let mut owner_address = Address::zero();

    let mut i = 0;
    while i < tx_inputs.len() {
        let input = tx_inputs.get(i).unwrap();
        let asset = input.assetid;
        let owner = input.owner;

        // Verify this is a valid asset type
        if !is_valid_asset_type(asset, src20_asset, nonce_asset, modulexx_asset) {
            // assets_correct = false; //REVIEW - do we need to set this if we just Fail right after.
            return AggregateResult::Fail(6668u64);
        }

        // Ignore the nonce asset and module02 asset
        if (asset == nonce_asset) || (asset == modulexx_asset) {
            i += 1;
            continue;
        }

        // Accumulate the amounts for FUEL_BASE_ASSET & SRC20 asset
        if asset == FUEL_BASE_ASSET {

            match input.amount {
                Some(val) => {
                    let amount = asm(r1: (0, 0, 0, val)) { r1: u256 };
                    aggregated_gas_amount = aggregated_gas_amount + amount;
                },
                None => {
                    return AggregateResult::Fail(6666u64); // No valid amount provided
                },
            };
        }
        if compare_asset_ids(src20_asset, asset) {
            src20_assetid = asset;
            // Check if all input owners are the same and match the nonce_owner
            owner_address = owner.unwrap_or(Address::zero());
            if owner_address != nonce_owner {
                assets_same_owner = false;
            }
            match input.amount {
                Some(val) => {
                    let amount = asm(r1: (0, 0, 0, val)) { r1: u256 };
                    aggregated_src20_amount = aggregated_src20_amount + amount;
                },
                None => {
                    // No valid amount provided
                    return AggregateResult::Fail(6667u64);
                },
            };
        }

        i += 1;
    }

    AggregateResult::Success( AggSuccess { agg_gas_amount: aggregated_gas_amount, agg_src20_amount: aggregated_src20_amount, src20_assetid: src20_assetid, sender_addr: owner_address,  assets_same_owner: assets_same_owner, } )
}

/// Result structure containing processed SRC20 input asset information
///
struct SRC20InputProcessingResult {
    // The asset ID of the SRC20 token being transferred
    src20_assetid: b256,
    // Maximum cost in Fuel ETH units for RPC tip validation
    max_cost_fueleth: u256,
    // The address of the sender/owner of the input assets
    sender_addr: Address,
}

/// Processes and validates SRC20 input assets in a Zap module 03 transaction
///
/// Validates input assets including nonce, gas (base asset), and SRC20 tokens.
/// Ensures proper asset ownership and sufficient amounts for the transfer.
///
/// # Arguments
/// * `tx_input_assets` - Vector of transaction input assets to process
/// * `expected_src20_asset` - Expected SRC20 asset ID (20-bytes) from the RLP transaction
/// * `expected_src20_amount` - Expected SRC20 transfer amount from EVM transaction data
/// * `max_cost_wei` - Maximum cost in Wei from the transaction
/// * `nonce_assetid` - Asset ID of the nonce asset
/// * `expected_nonce_val` - Expected nonce value
/// * `modulexx_assetid` - Module-specific asset ID to ignore during processing
///
/// # Returns
/// * `Ok(SRC20InputProcessingResult)` - Processing succeeded with asset details
/// * `Err(u64)` - Error code indicating specific validation failure:
///   - 3003: Insufficient SRC20 input amount
///   - 3004: Insufficient gas amount
///   - 3005: Input assets have different owners
///   - Other codes from nonce check or asset aggregation failures
///
pub fn process_src20_input_assets( tx_input_assets: Vec<InpOut>, expected_src20_asset: b256, expected_src20_amount: u256, max_cost_wei: u256,  nonce_assetid: b256, expected_nonce_val: u64, modulexx_assetid: b256, ) -> Result<SRC20InputProcessingResult, u64> {

    let mut nonce_owner_addr = Address::zero();

    // covert the e18 value to the fueleth value, return as u256
    let fuel_eth_max_cost = match wei_to_eth(max_cost_wei){
        Some(result) => { result.0 }
        None => { u256::zero() }
    };

    // Check the nonce assetid and value
    match nonce_check( tx_input_assets, nonce_assetid, expected_nonce_val ) {
        NonceCheckResult::Success((_nonce_val_at_inp, nonce_owner)) => {
            nonce_owner_addr = nonce_owner;
        },
        NonceCheckResult::Fail(error_code) => {
            return Err(error_code);
        },
    }

    match aggregate_multiple_assets( tx_input_assets, expected_src20_asset, nonce_assetid, nonce_owner_addr, modulexx_assetid, ) {
        AggregateResult::Success(agg_res) => {

            // Verify the native asset transfer total amount
            if !(agg_res.agg_src20_amount >= expected_src20_amount) {
                // inputs src20/other_native asset amount incorrect
                return Err(3003u64);
            }

            // Verify there is enough gas
            if !(agg_res.agg_gas_amount >= fuel_eth_max_cost) { return Err(3004u64); }

            // The input assets are not from the same owner.
            if !agg_res.assets_same_owner { return Err(3005u64); }

            // agg_res.sender_addr has been checked and is the same as nonce owner address
            Ok(SRC20InputProcessingResult { src20_assetid: agg_res.src20_assetid, max_cost_fueleth: fuel_eth_max_cost, sender_addr: agg_res.sender_addr, })
        },
        AggregateResult::Fail(error_code) => Err(error_code),
    }

}

/// Processes and validates SRC20 output assets in a Zap module 03 transaction
///
/// Validates output assets including the receiver's SRC20 amount, builder tip,
/// nonce return, and change outputs back to the sender.
///
/// # Arguments
/// * `tx_output_assets` - Vector of transaction output assets to process
/// * `tx_change_assets` - Vector of change outputs to validate
/// * `ip_result` - Input processing result containing validated input information
/// * `receiver_src20_amount` - Amount of SRC20 tokens to be received
/// * `nonce_assetid` - Asset ID of the nonce asset
/// * `nonce_target_val` - Expected nonce value after transaction
/// * `tx_receiver` - Address of the intended receiver
/// * `receiver_code` - Bytecode of the receiver's wallet for validation
///
/// # Returns
/// * `Ok(bool)` - True if all output validations pass
/// * `Err(u64)` - Error code indicating specific validation failure:
///   - 3070: Invalid SRC20 receiver or missing SRC20 change output
///   - 3071: Invalid builder tip amount or missing base asset change
///   - 3073: Missing builder tip amount
///   - 3074: Invalid nonce output value
///   - 3075: Invalid nonce output receiver
///   - 3076: Missing nonce output owner
///   - 3077: Missing nonce output amount
///
pub fn process_src20_output_assets( tx_output_assets: Vec<InpOut>, tx_change_assets: Vec<InpOut>, ip_result: SRC20InputProcessingResult, receiver_src20_amount: u256, nonce_assetid: b256, nonce_target_val: u64, tx_receiver: b256, ref mut receiver_code: Bytes,) -> Result<bool, u64> {

    // Ensure sure there is an src20 output for the receiver that is enough to
    // cover receiver src20 amount (u256)
    for output in tx_output_assets.iter() {
        if output.assetid == ip_result.src20_assetid {
            match output.amount {
                Some(amount) => {
                    // receiver_src20_amount is u256 value from rlp_tx
                    let mut out_amt = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                    if out_amt == receiver_src20_amount {
                        // verify that the output for the src20 asset is to the receiver.
                        if !verify_receiver( receiver_code,tx_receiver, output.owner.unwrap().into(), ) { return Err(3070u64); }
                    }
                }
                None => { continue; }
            }
        }

        // verify that there was a builder tip that does not exceed max_cost.
        if output.assetid == FUEL_BASE_ASSET {
            match output.amount {
                Some(amount) => {
                    let mut out_amt = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                    if !(out_amt <= ip_result.max_cost_fueleth) {
                        // Some base asset output was found that "should" be the builder
                        // tip and is leq the rlp transaction max_cost.
                        // Note: that this tip should be less than max_cost minus the actual
                        // network fee, or the tx will fail.
                        return Err(3071u64);
                    }
                }
                None => {
                    // If the amount is None, fail. At minimum it can be zero.
                    return Err(3073u64);
                }
            }
        }

        // Verify the Nonce asset output
        if output.assetid == nonce_assetid {
            match output.amount {
                Some(amount) => {
                    if amount != nonce_target_val {
                        // nonce output value was ok
                        return Err(3074u64);
                    }
                    match output.owner {
                        Some(owner) => {
                            if owner != ip_result.sender_addr {
                                // nonce output receiver is not the owner
                                return Err(3075u64);
                            }
                        },
                        None => {
                            // None output owner not found
                            return Err(3076u64);
                        }
                    }
                }
                None => {
                    // This output must have a value.
                    return Err(3077u64);
                }
            }
        }
    }

    // Ensure SRC20 change gets sent back to owner:
    if !verify_change_output(
        tx_change_assets,
        ip_result.src20_assetid,
        Address::from(ip_result.sender_addr)
    ) {
        // if there is no src20 asset change output to the owner then fail.
        return Err(3070u64);
    }

    // Ensure Base Asset change gets sent back to owner:
    if !verify_change_output( tx_change_assets, FUEL_BASE_ASSET, Address::from(ip_result.sender_addr) ) {
        // if there is no base asset change output to the owner then fail.
        return Err(3071u64);
    }

    // If we get here, all checks have passed for outputs:
    Ok(true)
}

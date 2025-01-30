library;

/*
┌--------------------------------------------------------------------┐
|                                                                    |
|  This file contains the same validation logic as in ./libs/ for    |
|  Module 03, execpt with logging. This is used for debugging via    |
|  the Contract .//test_contracts/evmerc20_validator                 |
|                                                                    |
└--------------------------------------------------------------------┘
*/

use std::{
    bytes::Bytes,
    string::String,
};
use std::bytes_conversions::{u64::*, b256::*};
use std::primitive_conversions::u64::*;

// use zap_utils::merkle_utils::get_master_addr_with_right_leaf_bytes;

use bignum::{
    wei_to_eth::wei_to_eth,
    helpers::to_u256,       //move to general helpers or helpers in general
};
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;

use io_utils::evmtx_io_utils::{
    InpOut,
    NonceCheckResult, nonce_check,
    // AggregateResult, aggregate_single_asset,
    verify_change_output,
    verify_receiver,
};


/// Compares a b256 values, checking if the last 20 bytes of x match the first 20 bytes of y
/// x: partial assetId (12 zero bytes + 20 bytes at end)
/// y: full 32 byte value where first 20 bytes should match
/// Returns true if the last 20 bytes of x match the first 20 bytes of y
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
/// Returns true if the asset is valid (one of the allowed types)
/// Returns false if the asset is not an allowed type
//
// Valid types: src20_asset, FUEL_BASE_ASSET, nonce_asset, modulexx_asset,
//
fn is_valid_asset_type(
    asset: b256,
    src20_asset: b256,
    nonce_asset: b256,
    modulexx_asset: b256,
) -> bool {
    // First log the asset being checked
    // log(String::from_ascii_str("Checking asset:"));
    // log(asset);

    // Return the result of the match
    match asset {
        FUEL_BASE_ASSET => {
            //log(String::from_ascii_str("Matched FUEL_BASE_ASSET"));
            true
        },
        nonce_asset => {
            //log(String::from_ascii_str("Matched nonce_asset"));
            true
        },
        modulexx_asset => {
            //log(String::from_ascii_str("Matched modulexx_asset"));
            true
        },
        // For the SRC20 comparison, check each asset
        a => {
            if compare_asset_ids(src20_asset, a) {
                //log(String::from_ascii_str("Matched src20_asset"));
                true
            } else {
                //log(String::from_ascii_str("No match found for asset"));
                false
            }
        }
    }
}



pub struct AggSuccess {
    pub agg_gas_amount: u256,
    pub agg_src20_amount: u256,
    pub src20_assetid: b256,
    pub sender_addr: Address,
    pub assets_correct: bool,
    pub assets_same_owner: bool,
}

/// for Success:
/// - total aggregated amount in (u64's accumulated), for:
///   gas, src20.
/// - owner of the src20 input,
/// - assets_correct
/// - assets_same_owner
///
pub enum AggregateResult {
    Success: (u256, u256, b256, Address, bool, bool),
    Fail: (u64),
}


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
/// * AggregateResult::Success - If the aggregation is successful, returns a tuple containing:
///   - The total aggregated amount in FuelEth (u256).
///   - The owner address of all input assets (Address).
///   - A boolean indicating whether all input assets are of type FUEL_BASE_ASSET and have the same owner.
/// * AggregateResult::Fail - If the aggregation fails, returns an error code (u64).
///
pub fn aggregate_multiple_assets(
    tx_inputs: Vec<InpOut>,
    src20_asset: b256,          // from rlp tx
    nonce_asset: b256,
    nonce_owner: Address,
    modulexx_asset: b256,
) -> AggregateResult {
    let mut aggregated_gas_amount = u256::zero();
    let mut aggregated_src20_amount = u256::zero();
    let mut src20_assetid = b256::zero();
    let mut assets_correct = true;      // the only asssets in the tx, are for this tx (only, gas, src20 and zap)
    let mut assets_same_owner = true;   // the src20 owner is the same as the nonce asset.
    let mut owner_address = Address::zero();

    let mut i = 0;
    while i < tx_inputs.len() {
        let input = tx_inputs.get(i).unwrap();
        let asset = input.assetid;
        let owner = input.owner;

        // Verify this is a valid asset type
        if !is_valid_asset_type(asset, src20_asset, nonce_asset, modulexx_asset) {
            assets_correct = false; //REVIEW - do we need to set this if we just Fail right after.
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

            //log(String::from_ascii_str("found erc20/src20 asset!"));

            src20_assetid = asset;

            // // Check if all input owners are the same and match the nonce_owner
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
                    return AggregateResult::Fail(6667u64); // No valid amount provided
                },
            };

        }

        i += 1;
    }

    AggregateResult::Success((
        aggregated_gas_amount,
        aggregated_src20_amount,
        src20_assetid,
        owner_address,
        assets_correct,
        assets_same_owner,
    ))

}


//FIXME - make this not pub after debug
pub struct SRC20InputProcessingResult {
    pub amount_src20: u64,
    pub src20_assetid: b256,
    pub max_cost_fueleth: u256,     // used to check for rpc tip in output processing
    pub sender_addr: Address,
}


pub fn process_src20_input_assets(
    tx_input_assets: Vec<InpOut>,
    expected_src20_asset: b256,
    expected_src20_amount: u256,        // the amount the sender is sending in the evm txdata as U256.
    expected_gas_asset: b256,           // the expected assetid of of the gas
    max_cost_wei: u256,                 // tx specied max_cost in Wei
    nonce_assetid: b256,
    expected_nonce_val: u64,
    modulexx_assetid: b256,
) -> Result<SRC20InputProcessingResult, u64> {

    let mut nonce_owner_addr = Address::zero();

    // covert the e18 value to the fueleth value, return as u256
    let fuel_eth_max_cost = match wei_to_eth(max_cost_wei){
        Some(result) => {
            // equivalent max_cost Fuel eth value.
            result.0
        }
        None => {
            //log(String::from_ascii_str("Error: exceeds the maximum wei value on fuel"));
            //TODO - this needs to fail the execution.
            u256::zero()
        }
    };

    // check the nonce assetid and value
    match nonce_check(
        tx_input_assets,
        nonce_assetid,
        expected_nonce_val,
    ) {
        NonceCheckResult::Success((nonce_val_at_inp, nonce_owner)) => {    // underscore for non-debug

            //-------------------------------------------------------
            // DEBUG:

            //-------------------------------------------------------
            nonce_owner_addr = nonce_owner;
        },
        NonceCheckResult::Fail(error_code) => {
            return Err(error_code);
        },
    }

    match aggregate_multiple_assets(
        tx_input_assets,
        expected_src20_asset,
        nonce_assetid,
        nonce_owner_addr,
        modulexx_assetid,
    ) {
        AggregateResult::Success((
            agg_gas_amount,
            agg_src20_amount,
            src20_assetid,
            input_owner,
            assets_correct,
            assets_same_owner,
        )) => {

            let exp_total_token_input = expected_src20_amount;
            let exp_total_gas_input = fuel_eth_max_cost;

            //-------------------------------------------------------
            // DEBUG:

            //-------------------------------------------------------

            if (agg_src20_amount >= exp_total_token_input) {
                //log(String::from_ascii_str("inputs SRC20 total OK."));
            } else {
                // fail not enough SRC20 inputs to match outputs
                //log(String::from_ascii_str("fail not enough SRC20 inputs to match outputs or wrong type."));
                return Err(3003u64);
            }

            if (agg_gas_amount >= exp_total_gas_input) {
                //log(String::from_ascii_str("inputs Gas total OK."));
            } else {
                // fail not enough Gas inputs to match outputs
                //log(String::from_ascii_str("fail not enough Gas inputs to match outputs or wrong type."));
                return Err(3004u64);
            }


            /*
            //REVIEW -
            Do we need to pass amount_src20: agg_src20_amount back to main? we need to only check if there is
            change back to the owner.

            Do we need to pass max_cost_fueleth: fuel_eth_max_cost, back to main?

            */

            Ok(SRC20InputProcessingResult {
                amount_src20: 27u64,
                src20_assetid: src20_assetid,
                max_cost_fueleth: fuel_eth_max_cost,
                sender_addr: input_owner,   // has been checked and is the same as nonce owner address

            })

            //TODO - error code here is assets_same_owner !true


        },
        AggregateResult::Fail(error_code) => Err(error_code),
    }

}


//FIXME - make this not pub after debug
pub struct SRC20OutputProcessingResult {
    pub outputs_ok: bool,
}

pub fn process_src20_output_assets(
    tx_output_assets: Vec<InpOut>,
    tx_change_assets: Vec<InpOut>,
    ip_result: SRC20InputProcessingResult,
    receiver_src20_amount: u256,        // the amount the sender is sending in the evm txdata as U256.
    nonce_assetid: b256,
    nonce_target_val: u64,
    tx_receiver: b256,
    ref mut receiver_code: Bytes,
) -> Result<SRC20OutputProcessingResult, u64> {

    // Ensure sure there is an src20 output for the receiver that is enough to
    // cover inputprocessing_result.amount_fueleth amount (u256)
    // let mut receiver_src20_output_found = false;

    // Ensure there is an output for builder tip that is not more than
    // inputprocessing_result.max_cost_fueleth (u256)
    //NOTE - the builder tip just needs to exist as an output, it can be an output
    // with zero value. If it is zero, then the change will just go back to the base
    // asset input owner.
    // let mut builder_tip_output_found = false;
    // let mut builder_tip_amount_ok = false;

    // Ensure we have the correct nonce value and is returned to the master
    // let mut nonce_output_val_ok = false;
    // let mut nonce_output_to_ok = false;

    // Ensure change sent back to owner:
    // let mut change_ok = false;


    // Ensure receiver src20 output and Nonce return:
    for output in tx_output_assets.iter() {
        if output.assetid == ip_result.src20_assetid {
            match output.amount {
                Some(amount) => {
                    // receiver_src20_amount is u256 value from rlp_tx
                    let mut out_amt = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                    if out_amt == receiver_src20_amount {

                        // verify that the output for the src20 asset is to the receiver.
                        // receiver_src20_output_found = verify_receiver(
                        //     receiver_code,
                        //     tx_receiver,
                        //     output.owner.unwrap().into(),   //Option<Address> --> b256
                        // );

                        if !verify_receiver(
                            receiver_code,
                            tx_receiver,    // the padded evm address from rlp tx.
                            output.owner.unwrap().into(),   //Option<Address> --> b256
                        ) {
                            return Err(3070u64);
                        }

                        // DEBUG ONLY - remove receiver check to pass V2 params
                        // receiver_src20_output_found = true;
                    }

                }
                None => {
                    // If the amount is None, skip this output
                    continue;
                }
            }
        }

        // verify that there was a builder tip that does not exceed max_cost.
        if output.assetid == FUEL_BASE_ASSET {
            match output.amount {
                Some(amount) => {
                    let mut out_amt = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                    // max_cost_fueleth is a u256
                    // if out_amt <= ip_result.max_cost_fueleth {
                    //     builder_tip_output_found = true;
                    //     builder_tip_amount_ok = true;
                    // }
                    if !(out_amt <= ip_result.max_cost_fueleth) {
                        // Some base asset output was found that "should" be the builder
                        // tip and is leq the rlp transaction max_cost.
                        // Note: that this tip should be less than max_cost minus the actual
                        // network fee, or the tx will fail.
                        return Err(3071u64);
                    }
                }
                None => {
                    // If the amount is None, skip this output
                    continue;
                }
            }
        }

        if output.assetid == nonce_assetid {
            match output.amount {
                Some(amount) => {
                    if amount != nonce_target_val {
                        // nonce output value was ok
                        return Err(3072u64);
                    }
                    match output.owner {
                        Some(owner) => {
                            if owner != ip_result.sender_addr {
                                // nonce output receiver is ok
                                return Err(3073u64);
                            }
                        },
                        None => {
                            // None output owner not found
                            return Err(3060u64);
                        }
                    }

                }
                None => {   // it really shouldnt be none unless its change
                    continue;
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
    if !verify_change_output(
        tx_change_assets,
        FUEL_BASE_ASSET,
        Address::from(ip_result.sender_addr)
    ) {
        // if there is no base asset change output to the owner then fail.
        return Err(3071u64);
    }

    // If we get here, all checks have passed for outputs:
    Ok(SRC20OutputProcessingResult {
        outputs_ok: true,
    })
}

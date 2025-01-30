library;

use std::{
    bytes::Bytes,
};
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use bignum::wei_to_eth::wei_to_eth;
// use zap_utils::merkle_utils::get_master_addr_with_right_leaf_bytes;
use io_utils::evmtx_io_utils::{
    InpOut,
    NonceCheckResult, nonce_check,
    AggregateResult, aggregate_single_asset,
    verify_change_output,
    verify_receiver,
};



struct InputProcessingResult {
    pub amounts_i_ok: bool,
    pub amount_fueleth: u256,
    pub max_cost_fueleth: u256,
    pub sender_addr: Address,
    pub nonce_i_ok: bool,
    pub nonce_owner: Address,
}

/// Processes the input assets of a transaction.
///
/// This function performs various checks on the input assets of a transaction, including:
/// - Verifying the nonce asset and value.
/// - Aggregating the amounts of non-nonce and non-module02 assets.
/// - Checking if all input owners match the nonce owner (the ZapWallet master).
/// - Comparing the aggregated amount with the expected total input amount.
///
/// # Arguments
///
/// * `tx_input_assets` - A vector of InpOut structures representing the input assets.
/// * `expected_in_asset` - The expected input asset type.
/// * `expected_out_amount` - The expected output amount in Wei.
/// * `max_cost_wei` - The evm tx max_cost in Wei.
/// * `nonce_assetid` - The asset ID of the nonce asset.
/// * `expected_nonce_val` - The expected nonce value.
/// * `module02_assetid` - The asset ID of the module02 asset.
///
/// # Returns
///
/// * `Ok(InputProcessingResult)` - If the input processing is successful, returns an `InputProcessingResult` containing:
///   - `amounts_i_ok`: A boolean indicating whether the aggregated input amounts are sufficient.
///   - `amount_fueleth`: The amount to the receiver in FuelEth (u256).
///   - `max_cost_fueleth`: The maximum cost in FuelEth (u256).
///   - `sender_addr`: The address of the input owner.
///   - `nonce_i_ok`: A boolean indicating whether the nonce asset and value are correct.
///   - `nonce_owner`: The address of the nonce owner.
/// * `Err(error_code)` - If the input processing fails, returns an error code (u64).
pub fn process_input_assets(
    tx_input_assets: Vec<InpOut>,
    expected_in_asset: b256,
    expected_out_amount: u256,          // the amount the sender is sending in the evm txdata as Wei.
    max_cost_wei: u256,                 // tx specied max_cost in Wei
    nonce_assetid: b256,
    expected_nonce_val: u64,
    module02_assetid: b256,
) -> Result<InputProcessingResult, u64> {

    let mut inp_amounts_ok = false;
    let mut imp_nonce_ok = false;
    let mut nonce_owner_addr = Address::zero();

    // The variable `expected_out_amount` is the amount in Ethereum Wei obtained from
    // the 'value', decoded from evm tx (u256). The is amount the sender is sending.
    //
    // the minimum amount minus max_cost, that all the inputs should add up to in this tx.

    // Covert Ethereum Wei value (1 ETH = 1e18) to Fuel ETH (1 ETH = 1e9).
    // Note: This loses 1e9 of precision from the original Wei value.

    let fuel_eth_to_receiver = match wei_to_eth(expected_out_amount){
        Some(result) => {
            // evm tx equivalent Fuel eth value
            result.0
        }
        None => {
            // Error: exceeds the maximum wei value on fuel
            //TODO - this needs to fail the execution.
            u256::zero()
        }
    };

    let fuel_eth_max_cost = match wei_to_eth(max_cost_wei){
        Some(result) => {
            // equivalent max_cost Fuel eth value
            result.0
        }
        None => {
            // Error: exceeds the maximum wei value on fuel
            //TODO - this needs to fail the execution.
            //FIXME -
            u256::zero()
        }
    };

    // check the nonce assetid and value
    match nonce_check(
        tx_input_assets,
        nonce_assetid,
        expected_nonce_val,
    ) {
        NonceCheckResult::Success((nonce_val_at_inp, nonce_owner)) => {
            nonce_owner_addr = nonce_owner;
            imp_nonce_ok = true;
        },
        NonceCheckResult::Fail(error_code) => {
            return Err(error_code);
        },
    }

    match aggregate_single_asset(tx_input_assets, nonce_assetid, nonce_owner_addr, module02_assetid) {
    // match aggregate_assets(tx_input_assets, nonce_assetid, nonce_owner_addr, module02_assetid) {
        AggregateResult::Success((agg_amount, input_owner, all_same_type)) => {

            let exp_total_input = fuel_eth_max_cost + fuel_eth_to_receiver;

            if (agg_amount >= exp_total_input) && all_same_type {
                // evm tx total signed amount is leq aggregated inputs total.
                inp_amounts_ok = true;
            } else {
                // fail not enough inputs to match outputs or wrong type
                return Err(2023u64);
            }

            Ok(InputProcessingResult {
                amounts_i_ok: inp_amounts_ok,               // agg input amounts >= total tx eth signed.
                amount_fueleth: fuel_eth_to_receiver,       // amount to receiver as fueleth in u256.
                max_cost_fueleth: fuel_eth_max_cost,        // max cost as fueleth in u256.
                sender_addr: input_owner,                   // input(s) owner address. ---------------------|
                nonce_i_ok: imp_nonce_ok,                   // the correct nonce value/assetid was found    | --> these should be the same.
                nonce_owner: nonce_owner_addr,              // the nonce owner address (the master) --------|
            })

        },
        AggregateResult::Fail(error_code) => Err(error_code),
    }

}

/*
/// Verifies that a receiving address matches the master address of a ZapWallet,
/// by calculating the master address from the receiver's bytecode and given EVM address.
///
/// # Arguments
///
/// * `receiver_code` - The bytecode of the receiver's ZapWallet as mutable Bytes
/// * `receiver_evm_addr` - The EVM address (as b256) from the EVM transaction data
/// * `receiving_addr` - The receiving address (as b256) from the Fuel transaction
///
/// # Returns
///
/// * `bool` - Returns `true` if the receiving address matches the calculated master address
///           of the ZapWallet, `false` otherwise
///
/// The function works by:
/// 1. Swapping in the EVM address at a specific position in the bytecode.
/// 2. Calculating the master address from the modified bytecode.
/// 3. Comparing the calculated master address with the receiving address.
///
pub fn verify_receiver(
    ref mut receiver_code: Bytes,
    receiver_evm_addr: b256,
    receiving_addr: b256,
) -> bool {

    let swap_position = 8208u64;        // Position to swap at

    let receiver_master_addr = get_master_addr_with_right_leaf_bytes(
        receiver_code,
        receiver_evm_addr,
        swap_position
    );

    if receiving_addr == receiver_master_addr {
        return true;
    }
    return false;
}
*/

struct OutputProcessingResult {
    pub outputs_ok: bool,
}

/// Processes the output assets of a transaction.
///
/// This function performs various checks on the output assets of a transaction, including:
/// - Ensuring there is an output for the receiver with the correct amount.
/// - Ensuring there is an output for the builder tip that does not exceed the maximum cost.
/// - Verifying the nonce output value and owner.
///
/// # Arguments
///
/// * `tx_output_assets` - A vector of InpOut structures representing the output assets.
/// * `tx_change_assets` - A vector of InpOut structures representing the change assets.
/// * `ip_result` - The `InputProcessingResult` obtained from processing the input assets.
/// * `nonce_assetid` - The asset ID of the nonce asset.
/// * `nonce_target_val` - The target value for the nonce output.
/// * `tx_receiver` - The transaction base asse receiver from the evm rlp data.
/// * `receiver_code` - The receiver zapwallet master bytecode (see addition information).
///
/// # Returns
///
/// * `Ok(OutputProcessingResult)` - If the output processing is successful, returns an
///   `OutputProcessingResult` containing:
///   - `outputs_ok`: A boolean indicating whether the output amounts are correct.
/// * `Err(error_code)` - If the output processing fails, returns an error code (u64).
///
/// # Additional Information
///
/// The `receiver_code` should be only the 2nd leaf in from the master predicate bytecode, populated
/// with the configurables specific to the receiver.
///
pub fn process_output_assets(
    tx_output_assets: Vec<InpOut>,
    tx_change_assets: Vec<InpOut>,
    ip_result: InputProcessingResult,
    nonce_assetid: b256,
    nonce_target_val: u64,
    tx_receiver: b256,
    ref mut receiver_code: Bytes,
) -> Result<OutputProcessingResult, u64> {

    // Ensure sure there is an output for the receiver that is enough to
    // cover inputprocessing_result.amount_fueleth amount (u256)
    //NOTE - we can not enforce the receiver address from the evm tx data
    // no EVM address <--> ZapWallet address mapping available here.
    // unfortunately we have to trust the transaction builder.
    let mut receiver_output_found = false;
    let mut receiver_amount_ok = false;     //REVIEW - can remove

    // Ensure there is an output for builder tip that is not more than
    // inputprocessing_result.max_cost_fueleth (u256)
    //NOTE - the builder tip just needs to exist as an output, it can be an output
    // with zero value. If it is zero, then the change will just go back to the base
    // asset input owner.
    let mut builder_tip_output_found = false;
    let mut builder_tip_amount_ok = false;

    // Ensure we have the correct nonce value and is returned to the master
    let mut nonce_output_val_ok = false;
    let mut nonce_output_to_ok = false;

    // Ensure change sent back to owner:
    let mut change_ok = false;


    // Ensure receiver output and Nonce return:
    for output in tx_output_assets.iter() {
        if output.assetid == FUEL_BASE_ASSET {
            match output.amount {
                Some(amount) => {
                    let mut out_amt = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                    if out_amt == ip_result.amount_fueleth {

                        receiver_output_found = verify_receiver(
                            receiver_code,
                            tx_receiver,
                            output.owner.unwrap().into(),   //Option<Address> --> b256
                        );
                        // receiver_output_found = true;
                    }
                    if out_amt <= ip_result.max_cost_fueleth {
                        builder_tip_output_found = true;
                        builder_tip_amount_ok = true;
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
                    if amount == nonce_target_val {
                        nonce_output_val_ok = true;
                    }
                    match output.owner {
                        Some(owner) => {
                            if owner == ip_result.nonce_owner {
                                nonce_output_to_ok = true;
                            }
                        },
                        None => {
                            // None output owner not found
                            return Err(2060u64);
                        }
                    }
                    // if output.owner.unwrap() == ip_result.nonce_owner {
                    //     nonce_output_to_ok = true;
                    // }
                }
                None => {   // it really shouldnt be none unless its change
                    continue;
                }
            }
        }

    }

    // Ensure change gets sent back to owner:
    change_ok = verify_change_output(
        tx_change_assets,
        FUEL_BASE_ASSET,
        Address::from(ip_result.nonce_owner)
    );

    //FIXME - this is ugly, rework.
    match (
        receiver_output_found,                              // Receiver output.
        builder_tip_output_found, builder_tip_amount_ok,    // Builder tip (max_cost - exe/network cost).
        nonce_output_val_ok, nonce_output_to_ok,            // Nonce
        change_ok                                           // Change output
    ) {
        (false, _, _, _, _, _) => Err(8052u64), // Receiver output not found
        (_, false, _, _, _, _) => Err(8053u64), // Builder tip output not found
        (_, _, false, _, _, _) => Err(8054u64), // Builder tip amount exceeds the maximum allowed
        (_, _, _, false, _, _) => Err(8055u64), // Nonce output value does not match the target value
        (_, _, _, _, false, _) => Err(8056u64), // Nonce output owner does not match the expected owner
        (_, _, _, _, _, false) => Err(8057u64), // Change output not found or owner does not match the expected owner
        (true, true, true, true, true, true) => Ok(OutputProcessingResult {
                                                    outputs_ok: true,
                                                }),
        _ => Err(8058u64),  // should not get here.
    }

    // Ok(OutputProcessingResult {
    //     outputs_ok: true,
    // })
}



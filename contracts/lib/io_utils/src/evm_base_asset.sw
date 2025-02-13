library;

use std::bytes::Bytes;
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use zap_utils::wei_to_eth::wei_to_eth;
use ::io::InpOut;
use ::evmtx_io_utils::{
    NonceCheckResult, nonce_check,
    AggregateResult, aggregate_single_asset,
    verify_change_output,
    verify_receiver,
};


/// Results from processing transaction input assets for a Zap Module 02 transaction.
///
/// # Additional Information
///
/// This struct holds validation results and key information extracted from transaction inputs,
/// including amount verification, fuel-eth conversions, sender details, and nonce validation.
///
pub struct InputProcessingResult {
    /// Indicates whether the aggregated input amounts are sufficient to cover the transaction.
    pub amounts_i_ok: bool,
    /// The amount being sent to the receiver, converted from Wei to Fuel ETH units.
    pub amount_fueleth: u256,
    /// The maximum transaction cost, converted from Wei to Fuel ETH units.
    pub max_cost_fueleth: u256,
    /// The address of the input assets owner ZapWallet master).
    pub sender_addr: Address,
    /// Indicates whether the nonce asset and its value are valid.
    pub nonce_i_ok: bool,
    /// The address of the nonce owner (ZapWallet master).
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
///
pub fn process_input_assets( tx_input_assets: Vec<InpOut>, expected_out_amount: u256, max_cost_wei: u256, nonce_assetid: b256, expected_nonce_val: u64, module02_assetid: b256, ) -> Result<InputProcessingResult, u64> {

    let mut inp_amounts_ok = false;
    let mut imp_nonce_ok = false;
    let mut nonce_owner_addr = Address::zero();

    // The variable `expected_out_amount` is the amount in Ethereum Wei obtained from
    // the 'value', decoded from evm tx (u256). This is amount the sender is sending which
    // is the minimum amount minus max_cost, that all the inputs should add up to in this tx.

    // Convert transaction value Wei to Fuel units
    let fuel_eth_to_receiver = match wei_to_eth(expected_out_amount){
        Some(result) => {
            // evm tx equivalent Fuel eth value
            result.0
        }
        None => {
            // Signed rlp transaction value exceeds the maximum wei value on fuel
            return Err(2010);
        }
    };

    // Convert the max_cost Wei to Fuel units
    let fuel_eth_max_cost = match wei_to_eth(max_cost_wei){
        Some(result) => { result.0 }
        None => { return Err(2011); }
    };

    // check the nonce assetid and value
    match nonce_check( tx_input_assets, nonce_assetid, expected_nonce_val, ) {
        NonceCheckResult::Success((_nonce_val_at_inp, nonce_owner)) => {
            nonce_owner_addr = nonce_owner;
            imp_nonce_ok = true;
        },
        NonceCheckResult::Fail(error_code) => {
            return Err(error_code);
        },
    }

    match aggregate_single_asset(tx_input_assets, nonce_assetid, nonce_owner_addr, module02_assetid) {
        AggregateResult::Success((agg_amount, input_owner, all_same_type)) => {

            let exp_total_input = fuel_eth_max_cost + fuel_eth_to_receiver;

            if (agg_amount >= exp_total_input) && all_same_type {
                // evm tx total signed amount is leq aggregated inputs total.
                inp_amounts_ok = true;
            } else {
                // fail not enough inputs to match outputs or wrong type
                return Err(2023u64);
            }

            Ok(InputProcessingResult { amounts_i_ok: inp_amounts_ok, amount_fueleth: fuel_eth_to_receiver, max_cost_fueleth: fuel_eth_max_cost, sender_addr: input_owner, nonce_i_ok: imp_nonce_ok, nonce_owner: nonce_owner_addr, })
        },
        AggregateResult::Fail(error_code) => Err(error_code),
    }

}

/// Results from processing transaction output assets for a Zap Module 02 transaction.
///
/// # Additional Information
///
/// This struct holds the validation result of transaction outputs, ensuring that:
/// - The receiver output exists with correct amount
/// - The builder tip output exists within max cost bounds
/// - The nonce output is returned to the correct owner
/// - Change outputs are properly handled
///
pub struct OutputProcessingResult {
    /// Indicates whether all output validations have passed successfully.
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
pub fn process_output_assets( tx_output_assets: Vec<InpOut>, tx_change_assets: Vec<InpOut>, ip_result: InputProcessingResult, nonce_assetid: b256, nonce_target_val: u64, tx_receiver: b256, ref mut receiver_code: Bytes ) -> Result<OutputProcessingResult, u64> {

    // Ensure sure there is an output for the receiver that is enough to cover the amount
    // specified in the signed transaction bytes.
    let mut receiver_output_found = false;

    // Ensure there is an output for builder tip that is not more than the max_cost_fueleth
    // amount in the signed transaction bytes.
    // Note: The builder tip just needs to exist as an output, it can be an output with zero
    // value. If it is zero, then the change will just go back to the base asset input owner.
    let mut builder_tip_output_found = false;

    // Ensure we have the correct nonce value and is returned to the master
    let mut nonce_output_found = false;

    // Ensure receiver output and Nonce return:
    for output in tx_output_assets.iter() {
        if output.assetid == FUEL_BASE_ASSET {
            match output.amount {
                Some(amount) => {
                    let mut out_amt = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                    if out_amt == ip_result.amount_fueleth {
                        // Verify that the base asset receiving address is the ZapWallet
                        // receiver mapped to the receiving evm address in the signed rlp bytes.
                        receiver_output_found = verify_receiver( receiver_code, tx_receiver, output.owner.unwrap().into() );
                    }
                    if out_amt <= ip_result.max_cost_fueleth {
                        builder_tip_output_found = true;
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
                        // The nonce value at the output is correct
                        match output.owner {
                            Some(owner) => {
                                if owner == ip_result.nonce_owner {
                                    nonce_output_found = true;
                                }
                            },
                            None => {
                                // Nonce output owner not found
                                return Err(2060u64);
                            }
                        }
                    }
                }
                None => {
                    // There should be an explicit amount attached to this asset output.
                    return Err(2061u64);
                }
            }
        }

    }

    // Ensure Base Asset change gets sent back to owner.
    if !verify_change_output(
        tx_change_assets,
        FUEL_BASE_ASSET,
        Address::from(ip_result.sender_addr)
    ) {
        // if there is no base asset change output to the owner then fail.
        return Err(2071u64);
    }

    // Final check.
    if (receiver_output_found && builder_tip_output_found && nonce_output_found) {
        return Ok(
            OutputProcessingResult {
                outputs_ok: true,
            }
        );
    }

    // Return error if transaction outputs are not satisfield.
    return Err(2058u64)
}



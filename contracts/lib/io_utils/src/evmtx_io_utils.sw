library;

use std::bytes::Bytes;
use zapwallet_consts::wallet_consts::{
    FUEL_BASE_ASSET, V1_SWAP_POSITION, V1_LEFT_LEAF_HASH,
};
use ::io::InpOut;
use zap_utils::{
    merkle_utils::{MerkleUtils, V1Predicate},
    wei_to_eth::wei_to_eth,
};


/// Result type for Nonce validation checks
///
/// # Variants
/// * `Success(u64, Address)` - Nonce check succeeded, contains:
///   - The nonce value found in the input (u64)
///   - The owner address of the nonce asset (Address)
/// * `Fail(u64)` - Contains an error code indicating why the nonce check failed:
///   - 2070: No valid amount provided for nonce asset
///   - 2071: Correct nonce asset/value combination not found
///
pub enum NonceCheckResult {
    Success: (u64, Address),
    Fail: (u64),
}

/// Checks the nonce asset and value in the input assets.
///
/// Iterates over the input assets and looks for an asset that matches the specified
/// `nonce_assetid`. If found, it compares the asset's amount with the `expected_nonce_val`.
///
/// # Arguments
///
/// * `tx_inputs` - A vector of InpOut structures representing the input assets.
/// * `nonce_assetid` - The asset ID of the nonce asset to look for.
/// * `expected_nonce_val` - The expected value of the nonce asset.
///
/// # Returns
///
/// * `NonceCheckResult::Success` - If the nonce check is successful, returns a tuple containing:
///   - The nonce value found in the input assets (u64).
///   - The owner address of the nonce asset (Address).
/// * `NonceCheckResult::Fail` - If the nonce check fails, returns an error code (u64):
///   - `2070`: No valid amount provided for the nonce asset.
///   - `2071`: The correct nonce asset/value combination was not found.
///
pub fn nonce_check(
    tx_inputs: Vec<InpOut>,
    nonce_assetid: b256,
    expected_nonce_val: u64,
) -> NonceCheckResult {
    let mut nonce_ok = false;
    let mut nonce_idx = 0u64;
    let mut i = 0;
    while i < tx_inputs.len() {
        let input = tx_inputs.get(i).unwrap();
        let asset = input.assetid;
        // let amount = input.amount;

        // if the i'th assetid is not the same as the nonce assetid, skip it.
        if asset != nonce_assetid {
            i += 1;
            continue;
        }

        match input.amount {
            Some(val) => {
                if val == expected_nonce_val {
                    nonce_ok = true;
                    nonce_idx = i;
                }
            },
            None => {
                // No valid amount provided for nonce
                return NonceCheckResult::Fail(2070u64);
            },
        };
        i += 1;
    }
    if nonce_ok {
        // pass back the value of the nonce and owner
        let nonce_input = tx_inputs.get(nonce_idx).unwrap();
        return NonceCheckResult::Success((
            nonce_input.amount.unwrap(), nonce_input.owner.unwrap()
        ));
    }
    NonceCheckResult::Fail(2071u64) // Correct nonce asset/value not found.
}

/// Result type for asset aggregation of a FUEL_BASE_ASSET asset
///
/// # Variants
/// * `Success(u256, Address, bool)` - Aggregation succeeded, contains:
///   - Total aggregated amount in Fuel ETH (u256)
///   - Owner address of the input assets (Address)
///   - Boolean indicating if all inputs are FUEL_BASE_ASSET and have same owner
/// * `Fail(u64)` - Contains an error code indicating why aggregation failed:
///   - 2066: No valid amount provided for FUEL_BASE_ASSET input
///
pub enum AggregateResult {
    Success: (u256, Address, bool),
    Fail: (u64),
}

/// Aggregates a single asset and their amounts from a vector of InpOut structures.
///
/// This function iterates over the input assets, ignoring the specified nonce asset,
/// and the Zap module asset id being used in this transaction.
/// The routine checks if all the remaining assets are of type FUEL_BASE_ASSET. It accumulates
/// the amounts for FUEL_BASE_ASSET inputs and checks if all input owners are the same
/// and match the provided nonce_owner.
///
/// # Arguments
///
/// * tx_inputs - A vector of InpOut structures containing asset IDs, amounts, and owners.
/// * nonce_asset - The asset ID of the nonce asset to be ignored during aggregation.
/// * nonce_owner - The expected owner address for all input assets.
/// * module_asset - The Zap Module AssetId being used in this transactions.
///
/// # Returns
///
/// * AggregateResult::Success - If the aggregation is successful, returns a tuple containing:
///   - The total aggregated amount in FuelEth (u256).
///   - The owner address of all input assets (Address).
///   - A boolean indicating whether all input assets are of type FUEL_BASE_ASSET and have the same owner.
/// * AggregateResult::Fail - If the aggregation fails, returns an error code (u64).
///
pub fn aggregate_single_asset(
    tx_inputs: Vec<InpOut>,
    nonce_asset: b256,
    nonce_owner: Address,
    module_asset: b256,
) -> AggregateResult {
    let mut aggregated_amount = u256::zero();
    let mut all_same_type = true;
    let mut all_same_owner = true;
    let mut owner_address = Address::zero();

    let mut i = 0;
    while i < tx_inputs.len() {
        let input = tx_inputs.get(i).unwrap();
        let asset = input.assetid;
        let owner = input.owner;

        // Ignore the nonce asset and module asset
        if (asset == nonce_asset) || (asset == module_asset) {
            i += 1;
            continue;
        }

        if asset != FUEL_BASE_ASSET {
            all_same_type = false;
        }
        // Check if all other inputs are of type FUEL_BASE_ASSET
        // Accumulate the amount if it's a FUEL_BASE_ASSET
        if asset == FUEL_BASE_ASSET {

            // Check if all input owners are the same and match the nonce_owner
            owner_address = owner.unwrap_or(Address::zero());
            if owner_address != nonce_owner {
                all_same_owner = false;
            }

            match input.amount {
                Some(val) => {
                    let amount = asm(r1: (0, 0, 0, val)) { r1: u256 };
                    aggregated_amount = aggregated_amount + amount;
                },
                None => {
                    // No valid amount provided
                    return AggregateResult::Fail(2066u64);
                },
            };
        }
        i += 1;
    }

    if all_same_type && all_same_owner {
        AggregateResult::Success((aggregated_amount, owner_address, true))
    } else {
        AggregateResult::Success((aggregated_amount, owner_address, false))
    }
}

/// Verifies that there exists a change output for the exptected asset that is addressed to a receiver.
///
/// # Arguments
///
/// * `tx_change_assets`: A Vec of InpOut structs representing the change output assets.
/// * `expected_change_asset`: A b256 value representing the expected change asset ID.
/// * `expected_change_receiver`: An Address value representing the expected receiver's address.
///
/// # Returns
///
/// * `bool`: Returns `true` if a matching change output is found for the asset/receiver, `false` otherwise.
///
pub fn verify_change_output(
    tx_change_assets: Vec<InpOut>,
    expected_change_asset: b256,
    expected_change_receiver: Address,
) -> bool {
    // Check each InpOut struct for matching asset and receiver
    for change in tx_change_assets.iter() {
        if change.assetid == expected_change_asset {
            match change.owner {
                Some(owner) => {
                    if owner == expected_change_receiver {
                        return true;
                    }
                },
                None => {},
            }
        }
    }

    false
}

/// Verifies that a receiving address matches the master address of a V1 ZapWallet,
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

    // Calculate the v1 predicate address
    let v1_predicate = V1Predicate::new();
    let v1_wallet_addr = v1_predicate.calculate_predicate_address(
        receiver_code,
        receiver_evm_addr
    );

    if receiving_addr == v1_wallet_addr {
        return true;
    }
    return false;

    //NOTE - DEBUG:
    // return true;
}


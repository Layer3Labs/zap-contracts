library;

use std::{
    inputs::{input_coin_owner, input_count},
    outputs::{output_asset_id, output_asset_to, output_amount},
};
use zap_utils::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_input_coin,
        output_count,
        output_coin_asset_id,
        verify_output_change,
        verify_output_coin,
        input_txn_hash,
    },
};


/// Result of nonce asset extraction from transaction inputs
pub enum NonceExtractionResult {
    /// Successfully found nonce with amount and owner
    Success: (u64, Address),
    /// Failed to find nonce asset in inputs
    NotFound: (),
    /// Found nonce but invalid (no amount or owner)
    Invalid: (),
}

/// Result of ownership validation
pub enum OwnershipValidationResult {
    /// All assets from same owner
    Success: Address,
    /// Mixed ownership detected
    MixedOwners: (),
    /// No valid inputs found
    NoInputs: (),
}

/// Result of output destination validation
pub enum OutputValidationResult {
    /// All outputs go to same destination
    Success: Address,
    /// Outputs go to different destinations
    MixedDestinations: (),
    /// No valid outputs found
    NoOutputs: (),
}

/// Finds the nonce asset in transaction inputs and extracts its amount and owner.
///
/// # Arguments
///
/// * `nonce_assetid` - The asset ID of the nonce to find
///
/// # Returns
///
/// * `NonceExtractionResult::Success` - Contains (amount, owner) of the nonce
/// * `NonceExtractionResult::NotFound` - Nonce asset not found in any input
/// * `NonceExtractionResult::Invalid` - Found but missing amount or owner
///
pub fn extract_nonce_from_inputs(nonce_assetid: b256) -> NonceExtractionResult {
    let in_count: u64 = input_count().as_u64();

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let asset_id = input_coin_asset_id(i);

            if asset_id == nonce_assetid {
                // Found the nonce asset
                let amount = input_coin_amount(i);
                let owner = input_coin_owner(i);

                // Validate we have both amount and owner
                match owner {
                    Some(addr) => {
                        if amount > 0 {
                            return NonceExtractionResult::Success((amount, addr));
                        } else {
                            return NonceExtractionResult::Invalid;
                        }
                    },
                    None => {
                        return NonceExtractionResult::Invalid;
                    }
                }
            }
        }
        i += 1;
    }

    NonceExtractionResult::NotFound
}

/// Verifies all non-nonce coin inputs come from the same owner address.
///
/// # Arguments
///
/// * `nonce_assetid` - The nonce asset ID to exclude from validation
///
/// # Returns
///
/// * `OwnershipValidationResult::Success` - All non-nonce inputs from same owner
/// * `OwnershipValidationResult::MixedOwners` - Different owners detected
/// * `OwnershipValidationResult::NoInputs` - No non-nonce inputs found
///
pub fn verify_non_nonce_inputs_same_owner(nonce_assetid: b256) -> OwnershipValidationResult {
    let in_count: u64 = input_count().as_u64();
    let mut common_owner: Option<Address> = None;
    let mut found_non_nonce = false;

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let asset_id = input_coin_asset_id(i);

            // Skip nonce assets
            if asset_id == nonce_assetid {
                i += 1;
                continue;
            }

            // Check owner of non-nonce asset
            match input_coin_owner(i) {
                Some(owner) => {
                    found_non_nonce = true;

                    match common_owner {
                        Some(expected_owner) => {
                            // Verify this owner matches the expected one
                            if owner != expected_owner {
                                return OwnershipValidationResult::MixedOwners;
                            }
                        },
                        None => {
                            // First non-nonce input, set as expected owner
                            common_owner = Some(owner);
                        }
                    }
                },
                None => {
                    // Input without owner is invalid
                    return OwnershipValidationResult::MixedOwners;
                }
            }
        }
        i += 1;
    }

    match common_owner {
        Some(owner) => OwnershipValidationResult::Success(owner),
        None => OwnershipValidationResult::NoInputs,
    }
}

/// Verifies that all transaction outputs (except excluded burn outputs) are directed to the same destination address.
///
/// # Purpose
///
/// During an upgrade transaction, this function ensures that all assets being transferred
/// (except those being burned) go to a single destination. This prevents fragmentation
/// of assets and ensures atomic upgrade semantics.
///
/// # Arguments
///
/// * `v1_manager_addr` - The address of the v1_manager contract that will burn v1_nonce tokens.
///                       Outputs sending v1_nonce to this address are excluded from validation.
/// * `v1_nonce_assetid` - The asset ID of v1_nonce tokens that will be burned during upgrade.
///                        Used to identify which outputs should be excluded.
///
/// # Returns
///
/// * `OutputValidationResult::Success(Address)` - All non-excluded outputs (both coin and change)
///                                                go to the same destination. Returns that destination.
/// * `OutputValidationResult::MixedDestinations` - Outputs are split between different destinations,
///                                                 indicating an invalid upgrade transaction.
/// * `OutputValidationResult::NoOutputs` - No valid outputs found after excluding burn outputs.
///                                         This is an error condition.
///
/// # Validation Logic
///
/// The function examines all transaction outputs and:
/// 1. **Excludes** coin outputs where v1_nonce tokens are sent to v1_manager (these will be burned)
/// 2. **Validates** all other coin outputs go to the same destination
/// 3. **Validates** all change outputs go to that same destination
/// 4. **Ensures** at least one non-excluded output exists
///
/// # Transaction Structure Expected
///
/// ```
/// Outputs:
///   - Coin(v1_nonce → v1_manager)     [EXCLUDED from validation]
///   - Coin(other_asset → destination) [VALIDATED]
///   - Change(asset → destination)     [VALIDATED]
///   - Contract outputs                [IGNORED]
///   - Variable outputs                [IGNORED]
/// ```
///
/// # Edge Cases
///
/// - If only v1_nonce burn output exists → returns `NoOutputs`
/// - If no outputs exist at all → returns `NoOutputs`
/// - Empty change outputs are validated if they have a destination
/// - Contract/Variable outputs are completely ignored
///
/// # Security Considerations
///
/// This function is critical for upgrade security as it ensures:
/// - Assets cannot be redirected to unintended recipients during upgrade
/// - The upgrade is atomic (all assets go to new owner or none do)
/// - Burn operations are properly isolated from transfers
///
pub fn verify_outputs_same_destination(
    v1_manager_addr: Address,
    v1_nonce_assetid: b256
) -> OutputValidationResult {
    let out_count: u64 = output_count();
    let mut common_destination: Option<Address> = None;
    let mut validated_output_count = 0u64;
    let mut excluded_count = 0u64;

    let mut j = 0;
    while j < out_count {
        // Check if it's a coin output
        if verify_output_coin(j) {
            let output_asset = match output_coin_asset_id(j) {
                Some(asset) => asset,
                None => {
                    j += 1;
                    continue;
                }
            };

            let output_dest = match output_asset_to(j) {
                Some(dest) => dest,
                None => {
                    return OutputValidationResult::MixedDestinations;
                }
            };

            // Check if this should be excluded
            if output_asset == v1_nonce_assetid && output_dest == v1_manager_addr {
                excluded_count += 1;
                j += 1;
                continue;
            }

            // Validate this coin output
            validated_output_count += 1;

            match common_destination {
                Some(expected_dest) => {
                    if output_dest != expected_dest {
                        return OutputValidationResult::MixedDestinations;
                    }
                },
                None => {
                    common_destination = Some(output_dest);
                }
            }
        }
        // check if it's a change output
        else if let Some(true) = verify_output_change(j) {
            // Change outputs should also go to the same destination
            let change_dest = match output_asset_to(j) {
                Some(dest) => dest,
                None => {
                    j += 1;
                    continue;
                }
            };
            validated_output_count += 1;

            match common_destination {
                Some(expected_dest) => {
                    if change_dest != expected_dest {
                        // log("Change output goes to different destination!");
                        // log("Expected:");
                        // log(expected_dest);
                        // log("Found:");
                        // log(change_dest);
                        return OutputValidationResult::MixedDestinations;
                    }
                },
                None => {
                    common_destination = Some(change_dest);
                }
            }
        }

        j += 1;
    }

    // Check if we validated any outputs
    if validated_output_count == 0 {
        return OutputValidationResult::NoOutputs;
    }

    match common_destination {
        Some(dest) => {
            OutputValidationResult::Success(dest)
        },
        None => {
            OutputValidationResult::NoOutputs
        }
    }
}



/// Upgrade transaction validation result
pub struct UpgradeValidation {
    pub nonce_amount: u64,
    pub nonce_owner: Address,
    pub input_owner: Address,
    pub output_destination: Address,
    pub is_valid: bool,
}

/// Performs complete validation of an upgrade transaction.
///
/// # Arguments
///
/// * `nonce_assetid` - The nonce asset ID to validate
/// * `v1_manager_addr` - The v1_manager contract address (for exclusion)
///
/// # Returns
///
/// * `Option<UpgradeValidation>` - Complete validation results if successful, None if failed
///
pub fn validate_upgrade_transaction(
    nonce_assetid: b256,
    v1_manager_addr: Address
) -> Option<UpgradeValidation> {
    // Extract nonce information
    let (nonce_amount, nonce_owner) = match extract_nonce_from_inputs(nonce_assetid) {
        NonceExtractionResult::Success((amount, owner)) => (amount, owner),
        _ => return None,
    };

    // Verify non-nonce inputs
    let input_owner = match verify_non_nonce_inputs_same_owner(nonce_assetid) {
        OwnershipValidationResult::Success(owner) => owner,
        OwnershipValidationResult::NoInputs => nonce_owner, // Use nonce owner if no other inputs
        _ => return None,
    };

    // Verify outputs (excluding v1_nonce to v1_manager)
    let output_destination = match verify_outputs_same_destination(v1_manager_addr, nonce_assetid) {
        OutputValidationResult::Success(dest) => dest,
        _ => return None,
    };

    // Consistency check: nonce owner should match other input owners
    let is_valid = nonce_owner == input_owner;

    Some(UpgradeValidation {
        nonce_amount,
        nonce_owner,
        input_owner,
        output_destination,
        is_valid,
    })
}

/// Counts the number of inputs with a specific asset ID.
///
/// # Arguments
///
/// * `target_assetid` - The asset ID to count
///
/// # Returns
///
/// * `u64` - Number of inputs with the specified asset ID
///
pub fn count_inputs_by_asset(target_assetid: b256) -> u64 {
    let in_count: u64 = input_count().as_u64();
    let mut count = 0u64;

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            if input_coin_asset_id(i) == target_assetid {
                count += 1;
            }
        }
        i += 1;
    }

    count
}

/// Gets the total amount of a specific asset across all inputs.
///
/// # Arguments
///
/// * `target_assetid` - The asset ID to sum
///
/// # Returns
///
/// * `u64` - Total amount of the asset across all inputs
///
pub fn sum_input_amounts_by_asset(target_assetid: b256) -> u64 {
    let in_count: u64 = input_count().as_u64();
    let mut total = 0u64;

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            if input_coin_asset_id(i) == target_assetid {
                total += input_coin_amount(i);
            }
        }
        i += 1;
    }

    total
}

/// Verifies that change outputs match expected pattern for upgrade.
///
/// # Arguments
///
/// * `expected_recipient` - The address that should receive change
/// * `expected_assets` - Vector of asset IDs that should have change outputs
///
/// # Returns
///
/// * `bool` - True if all expected change outputs are present and correct
///
pub fn verify_change_outputs(
    expected_recipient: Address,
    expected_assets: Vec<b256>
) -> bool {
    let out_count: u64 = output_count();
    let mut found_assets: Vec<b256> = Vec::new();

    let mut j = 0;
    while j < out_count {
        match verify_output_change(j) {
            Some(is_change) => {
                if is_change {
                    // Verify recipient
                    match output_asset_to(j) {
                        Some(recipient) => {
                            if recipient != expected_recipient {
                                return false;
                            }
                        },
                        None => return false,
                    }

                    // Track asset
                    match output_asset_id(j) {
                        Some(asset) => {
                            found_assets.push(asset.into());
                        },
                        None => return false,
                    }
                }
            },
            _ => {},
        }
        j += 1;
    }

    // Verify all expected assets have change outputs
    let mut k = 0;
    while k < expected_assets.len() {
        let expected = expected_assets.get(k).unwrap();
        let mut found = false;

        let mut l = 0;
        while l < found_assets.len() {
            if found_assets.get(l).unwrap() == expected {
                found = true;
                break;
            }
            l += 1;
        }

        if !found {
            return false;
        }
        k += 1;
    }

    true
}

/// Gets the first input owner that isn't the nonce asset.
///
/// Useful for determining the original owner in upgrade transactions.
///
/// # Arguments
///
/// * `nonce_assetid` - The nonce asset to exclude
///
/// # Returns
///
/// * `Option<Address>` - The first non-nonce input owner, if any
///
pub fn get_first_non_nonce_owner(nonce_assetid: b256) -> Option<Address> {
    let in_count: u64 = input_count().as_u64();

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            if input_coin_asset_id(i) != nonce_assetid {
                return input_coin_owner(i);
            }
        }
        i += 1;
    }

    None
}

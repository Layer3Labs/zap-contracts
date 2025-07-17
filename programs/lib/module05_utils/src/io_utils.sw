library;

use std::bytes::Bytes;
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use io_utils::{
    io::{InpOut, collect_inputs_outputs_change},
    evmtx_io_utils::verify_change_output,
};


/// Verifies that there exists a output Coin for the exptected asset that is addressed to a receiver.
///
/// # Arguments
///
/// * `output_assets`: A Vec of InpOut structs representing the collected output assets.
/// * `expected_c_asset`: A b256 value representing the expected coin asset ID.
/// * `expected_c_receiver`: An Address value representing the expected receiver's address.
/// * `expected_c_amount`: An value representing the expected coin outout amount.
///
/// # Returns
///
/// * `bool`: Returns `true` if a matching output is found for the asset/receiver, `false` otherwise.
///
pub fn verify_coin_output(
    output_assets: Vec<InpOut>,
    expected_c_asset: b256,
    expected_c_receiver: Address,
    expected_c_amount: u64,
) -> bool {
    // Check each InpOut struct for matching asset and receiver
    for coin in output_assets.iter() {
        if coin.assetid == expected_c_asset {
            match coin.owner {
                Some(owner) => {
                    if owner == expected_c_receiver && coin.amount.unwrap_or(0) == expected_c_amount {
                        return true;
                    }
                },
                None => {},
            }
        }
    }

    false
}

// verify a ModuleXX output, can either be a Change OR a Coin
pub fn verify_module_output(
    coin_assets: Vec<InpOut>,
    change_assets: Vec<InpOut>,
    expected_assetid: b256,
    expected_receiver: Address,
) -> bool {
    let a = verify_change_output(change_assets, expected_assetid, expected_receiver);
    let b = verify_coin_output(coin_assets, expected_assetid, expected_receiver, 1u64);

    // (a || b) && !(a && b)
    (a || b)
}


pub enum TransferAssetResult {
    /// The asset was found and contains the owner's address.
    Success: (Address, u64),
    /// The asset check failed with a specific error code.
    ///
    /// Error codes:
    /// - 3170: No valid amount provided for the asset
    /// - 3171: The correct asset was not found
    Fail: (u64),
}

/// Obtains that an input or output asset exists within the vector of InpOut.
///
/// Iterates over the input assets and looks for an asset that matches the specified
/// `find_assetid`. If found, it returns the FIRST matching owner that is not in the ignore list.
///
/// # Arguments
///
/// * `tx_io` - A vector of InpOut structures representing the input assets.
/// * `find_assetid` - The asset ID of the asset to look for.
/// * `ignore_owner` - A vector of owner addresses that we don't care about.
///
/// # Returns
///
/// * `TransferAssetResult::Success` - If the check is successful, returns the owner
///   address of the asset and amount (Address, u64).
/// * `TransferAssetResult::Fail` - If the nonce check fails, returns an error code (u64):
///   - `3170`: No valid amount provided for the nonce asset.
///   - `3171`: The correct asset/value combination was not found.
///   - `3173`: No valid owner.
///
pub fn check_asset_exists(
    tx_io: Vec<InpOut>,
    find_assetid: b256,
    ignore_owner: Vec<Address>,
) -> TransferAssetResult {
    let mut i = 0;

    while i < tx_io.len() {
        let io = tx_io.get(i).unwrap();
        let asset = io.assetid;

        // if the i'th assetid is not the same as the assetid we want, skip it.
        if asset != find_assetid {
            i += 1;
            continue;
        }

        match io.owner {
            Some(owner) => {
                // check if this owner is in the ignore list
                let mut should_ignore = false;
                let mut j = 0;
                while j < ignore_owner.len() {
                    if ignore_owner.get(j).unwrap() == owner {
                        should_ignore = true;
                        break;
                    }
                    j += 1;
                }

                if !should_ignore {
                    match io.amount {
                        Some(amount) => {
                            // Found the first valid match - return immediately
                            return TransferAssetResult::Success((owner, amount));
                        },
                        None => {
                            // No valid amount provided for asset with correct assetID
                            return TransferAssetResult::Fail(3170u64);
                        },
                    };
                }
            },
            None => {
                // No valid owner
                return TransferAssetResult::Fail(3173u64);
            },
        };

        i += 1;
    }

    // No matching asset found after checking all
    TransferAssetResult::Fail(3171u64)
}

library;

use std::{
    bytes::Bytes,
};

use io_utils::evmtx_io_utils::{
    InpOut,
};

/// for Success:
/// - nonce amount at input and owner address.
/// for Fail:
/// - error_code
pub enum NonceCheckUpgradeResult {
    Success: (Address),
    Fail: (u64),
}

/// Obtains the nonce asset owner if it exists from the input assets.
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
pub fn nonce_check_upgrade(
    tx_inputs: Vec<InpOut>,
    nonce_assetid: b256,
) -> NonceCheckUpgradeResult {
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
                // if val == expected_nonce_val {
                //     nonce_ok = true;
                //     nonce_idx = i;
                // }
                //
                nonce_ok = true;
                nonce_idx = i;
            },
            None => {
                // No valid amount provided for nonce
                return NonceCheckUpgradeResult::Fail(0070u64);
            },
        };
        i += 1;
    }
    if nonce_ok {
        // pass back the nonce and owner
        let nonce_input = tx_inputs.get(nonce_idx).unwrap();
        return NonceCheckUpgradeResult::Success((
            nonce_input.owner.unwrap()
        ));
    }
    NonceCheckUpgradeResult::Fail(0071u64) // Correct nonce asset not found.
}
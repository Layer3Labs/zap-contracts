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


/// A universal input/output container that holds input/output/change information.
///
pub struct InpOut {
    /// The unique identifier of the asset ID.
    pub assetid: b256,
    /// The quantity of the asset, if applicable. None for change outputs where amount isn't needed.
    pub amount: Option<u64>,
    /// The address that owns or will own this asset. None if ownership is not relevant.
    pub owner: Option<Address>,
}

impl InpOut {
    pub fn new(
        assetid: b256,
        amountu64: Option<u64>,
        owner: Option<Address>,
    ) -> InpOut {
        InpOut {
            assetid: assetid,
            amount: amountu64,
            owner: owner,
        }
    }
}

/// Verifies that no inputs consume the nonce asset associated with this ZapWallet.
///
/// # Arguments
///
/// * `nonce_assetid` - The asset ID to search for in the inputs.
///
/// # Returns
///
/// * [bool] - False if a nonce asset input is found, true otherwise.
///
/// # Additional Information
///
/// This validation ensures that nonce assets can only be consumed through
/// the use of other Zap modules specifically designed to handle nonce inputs
/// and outputs. This preventing unauthorized spending of nonce assets even
/// with a valid signature.
///
pub fn verify_no_nonce_assets(nonce_assetid: b256) -> bool {
    let in_count: u64 = input_count().into();
    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let coin_asset_id = input_coin_asset_id(i);
            if (coin_asset_id == nonce_assetid) {
                return false;
            }
        }
        i += 1;
    }

    return true;
}

/// Collects and categorizes all inputs, outputs, and change outputs from the current transaction.
///
/// # Additional Information
///
/// This function processes the transaction context to gather three distinct categories of UTXOs:
/// - Input coins being spent
/// - Output coins being created
/// - Change outputs being returned to input owners
///
/// Each category is collected into a separate vector of InpOut structures for further processing
/// and validation.
///
/// # Returns
///
/// * [Vec<InpOut>] - All valid input coins from the transaction
/// * [Vec<InpOut>] - All valid output coins from the transaction
/// * [Vec<InpOut>] - All change outputs, with only assetid and owner information (no amounts)
///
/// # Number of Storage Accesses
///
/// * Reads: None (operates only on transaction context)
///
/// # Examples
///
/// ```sway
/// let (inputs, outputs, change) = collect_inputs_outputs_change();
/// let input_count = inputs.len();
/// let output_count = outputs.len();
/// let change_count = change.len();
/// ```
///
pub fn collect_inputs_outputs_change() -> (Vec<InpOut>, Vec<InpOut>, Vec<InpOut>) {

    // Collect inputs and outputs:
    let in_count: u64 = input_count().as_u64();
    let out_count: u64 = output_count();

    let mut tx_inputs : Vec<InpOut> = Vec::new();
    let mut tx_outputs : Vec<InpOut> = Vec::new();
    let mut tx_change: Vec<InpOut> = Vec::new();

    let mut i = 0;
    while i < in_count {
        // collect all the input coins.
        if verify_input_coin(i) {

            let inp = InpOut::new(
                input_coin_asset_id(i),
                Some(input_coin_amount(i)),
                input_coin_owner(i)
            );

            tx_inputs.push(inp);
        }
        i += 1;
    }
    let mut j = 0;
    while j < out_count {
        // collect all the output coins.
        if verify_output_coin(j) {
            let outp = InpOut::new(
                output_coin_asset_id(j).unwrap(),
                Some(output_amount(j).unwrap()),
                Some(output_asset_to(j).unwrap()),
            );
            tx_outputs.push(outp);
        }
        // collect all the change outputs assetid's and receivers.
        match verify_output_change(j) {
            Some(is_change) => {
                if is_change {
                    // add change details: assetid, to,
                    tx_change.push(
                        InpOut::new(
                            output_asset_id(j).unwrap().into(),
                            None,
                            Some(output_asset_to(j).unwrap()),
                        )
                    );
                }
            },
            _ => {},
        }
        j += 1;
    }

    (tx_inputs, tx_outputs, tx_change)
}

/// Finds the first occurrence of the given `assetid` in the inputs and returns its `utxoid` and owner.
///
/// # Arguments
///
/// * `assetid` - The asset ID to search for in the inputs.
///
/// # Returns
///
/// * `Option<(b256, Address)>` - Returns `Some((utxoid, owner))` if the asset is found in the inputs,
///   otherwise `None`. The tuple contains the UTXO ID and the owner's address.
///
/// # Behavior
///
/// - Iterates through all inputs and checks if the `assetid` matches.
/// - If a match is found, returns both the `utxoid` and the owner's address.
/// - If no match is found, or if the input is not a coin, returns `None`.
///
/// # Example
///
/// ```sway
/// let assetid: b256 = 0x1234...8ef7;
/// match find_utxoid_and_owner_by_asset(assetid) {
///     Some((utxoid, owner)) => {
///         // Handle the found utxoid and owner
///     },
///     None => {
///         // Handle the case where the asset is not found
///     }
/// }
/// ```
pub fn find_utxoid_and_owner_by_asset(assetid: b256) -> Option<(b256, Address)> {
    let in_count: u64 = input_count().as_u64();

    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let input_asset = input_coin_asset_id(i);
            if input_asset == assetid {
                // Get the owner of this input coin
                if let Some(owner) = input_coin_owner(i) {
                    // Found the asset, return both utxoid and owner
                    return Some((input_txn_hash(i), owner));
                }
            }
        }
        i += 1;
    }

    // Asset not found in inputs
    None
}

/// Result of asset existence verification in a transaction's inputs or outputs.
///
/// # Additional Information
///
/// Used primarily for validating asset presence and ownership during transaction
/// processing, especially for nonce assets in Zap Related transctions.
///
pub enum CheckAssetResult {
    /// The asset was found and contains the owner's address.
    Success: (Address),
    /// The asset check failed with a specific error code.
    ///
    /// Error codes:
    /// - 0070: No valid amount provided for the asset
    /// - 0071: The correct asset was not found
    Fail: (u64),
}

/// Obtains that an input or output asset exists within the vector of InpOut.
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
pub fn check_asset_exists(
    tx_inputs: Vec<InpOut>,
    nonce_assetid: b256,
) -> CheckAssetResult {
    let mut nonce_ok = false;
    let mut nonce_idx = 0u64;
    let mut i = 0;
    while i < tx_inputs.len() {
        let input = tx_inputs.get(i).unwrap();
        let asset = input.assetid;

        // if the i'th assetid is not the same as the nonce assetid, skip it.
        if asset != nonce_assetid {
            i += 1;
            continue;
        }

        match input.amount {
            Some(_val) => {
                // Dont need to check the value here, just return the owner.
                nonce_ok = true;
                nonce_idx = i;
            },
            None => {
                // No valid amount provided for nonce
                return CheckAssetResult::Fail(0070u64);
            },
        };
        i += 1;
    }
    if nonce_ok {
        // Return the nonce owner
        let nonce_input = tx_inputs.get(nonce_idx).unwrap();
        return CheckAssetResult::Success((
            nonce_input.owner.unwrap()
        ));
    }

    // Correct nonce asset not found.
    CheckAssetResult::Fail(0071u64)
}


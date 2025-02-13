library;

use std::string::String;

use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use ::gas_sponsor_tools::*;
use ::overflow::*;


/// General struct with either input or output details from
/// transaction data.
///
pub struct InpOut {
    /// Asset identifier
    pub assetid: b256,
    /// Optional amount for the asset
    pub amount: Option<u64>,
    /// Optional UTXO identifier
    pub uxtoid: Option<b256>,
    /// Optional owner address
    pub owner: Option<Address>,
}

impl InpOut {
    pub fn new( assetid: b256, amountu64: Option<u64>, uxtoid: Option<b256>, owner: Option<Address> ) -> InpOut { InpOut { assetid: assetid, amount: amountu64, uxtoid: uxtoid, owner: owner, } }
}

/// Checks if an asset ID is present in `tx_inputs`. If found, returns
/// the owner address of the first occurrence of this input.
///
/// # Arguments
///
/// * `tx_inputs`: [Vec<InpOut>] - A vector of `InpOut` structs representing the transaction inputs.
/// * `target_asset`: [b256] - The asset ID to search for in the transaction inputs.
///
/// # Returns
///
/// * [bool] - Indicates whether the target asset was found in the transaction inputs.
/// * [Address] - The address of the input owner if the target asset is found.
/// * [b256] - The UTXO ID of the gas input.
///
pub fn get_gas_utxo( tx_inputs: Vec<InpOut>, target_asset: b256,) -> (bool, Address, b256) {
    let mut utxo_found = false;
    let mut utxo_owner = Address::zero();
    let mut utxoid = b256::zero();

    // Check all inputs to see if the asset ID matches the target asset
    for asset in tx_inputs.iter() {
        if asset.assetid == target_asset {
            utxo_found = true;
            //REVIEW - this should not be a None in any case
            utxo_owner = asset.owner.unwrap_or(Address::zero());
            utxoid = asset.uxtoid.unwrap_or(b256::zero());
            break;
        }
    }

    (utxo_found, utxo_owner, utxoid)
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
pub fn verify_change_output( tx_change_assets: Vec<InpOut>, expected_change_asset: b256, expected_change_receiver: Address, ) -> bool {
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

/// Calcualte acceptable tolerance bounds for amount and determine if
/// actual amount is within expteced range.
///
/// Tolerance in basis points (1 bps = 0.01%, 10000 bps = 100%)
/// Do any calculations for tolerance in bn, using U256 arithmetic.
///
pub fn calcualte_asset_within_tolerance( actual_amount: u64, expected_amount: u64, tolerance: u256, ) -> bool {

    let actual_amount_bn = asm(r1: (0, 0, 0, actual_amount)) { r1: u256 };

    let expected_amount_bn = asm(r1: (0, 0, 0, expected_amount)) { r1: u256 };
    let tolerance_amount_bn = (expected_amount_bn * tolerance) / asm(r1: (0, 0, 0, 10000)) { r1: u256 };
    let upper_bound_bn = expected_amount_bn + tolerance_amount_bn;
    let lower_bound_bn = if expected_amount_bn > tolerance_amount_bn { expected_amount_bn - tolerance_amount_bn } else { 0 };
    let upperb_ovf = is_overflow_u64(upper_bound_bn);

    if actual_amount_bn < lower_bound_bn || actual_amount_bn > upper_bound_bn {
        return false;
    }
    return true;
}

/// Process outputs for the "sponsor" command, validating gas returns and asset exchange.
///
/// # Arguments
///
/// * `tx_output_assets`: [Vec<InpOut>] - Vector of transaction output assets
/// * `tx_change_assets`: [Vec<InpOut>] - Vector of transaction change outputs
/// * `expected_other_asset`: [b256] - Asset ID expected to be received by sponsor
/// * `expected_other_amount`: [u256] - Amount of other asset expected
/// * `tolerance_bps_u256`: [u256] - Tolerance in basis points for asset amount
/// * `sponsor_addr`: [b256] - Address of the gas sponsor
/// * `expected_gas_return_amount`: [u256] - Amount of gas to return to sponsor
/// * `gas_utxo_in`: [b256] - Input gas UTXO identifier
///
/// # Returns
///
/// * [Result<GasSponsor, u64>] - Rebuilt GasSponsor struct or error code
///
/// # Reverts
///
/// * When gas return output owner is missing (7060)
/// * When other asset output owner is missing (7061)
/// * When other asset amount is outside tolerance (7062)
/// * When gas change output is invalid (7063)
///
pub fn process_output_assets_command_sponsor( tx_output_assets: Vec<InpOut>, tx_change_assets: Vec<InpOut>, expected_other_asset: b256, expected_other_amount: u256, tolerance_bps_u256: u256, sponsor_addr: b256, _expected_gas_return_amount: u256, gas_utxo_in: b256,) -> Result<GasSponsor, u64> {

    // let mut sponsor_gas_output_found = true;
    let mut actual_gas_output_amount = asm(r1: (0, 0, 0, 0)) { r1: u256 };

    // Find output for other_asset, and is send towards the sponsor.
    // save other_asset_amount to be used below in tolerance calculation.
    let mut actual_other_amount = 0u64;

    for output in tx_output_assets.iter() {
        // Ensure there is an explicit output for gas back to sponsor:
        if output.assetid == FUEL_BASE_ASSET {
            match output.amount {
                Some(amount) => {
                    // We dont bother checking if the amount is the exptected amount,
                    // `expected_gas_return_amount`, instead let the GasSponsor struct
                    // check if the output amount was what was signed by the sponsor.
                    // check if the owner is correct before assigning the value.
                    match output.owner {
                        Some(owner) => {
                            if owner == Address::from(sponsor_addr) {
                                actual_gas_output_amount = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                            }
                        },
                        None => {
                            // Gas Return output owner not found
                            return Err(7060u64);
                        }
                    }
                }
                None => {
                    // If the amount is None, skip this output
                    continue;
                }
            }
        }
        // match other_asset, if its _to the sponsor, then get amount.
        if output.assetid == expected_other_asset {
            match output.amount {
                Some(amount) => {
                    match output.owner {
                        Some(owner) => {
                            if owner == Address::from(sponsor_addr) { actual_other_amount = amount; }
                        },
                        None => {
                            // other_asset output owner not found
                            return Err(7061u64);
                        }
                    }
                }
                None => {   // it really shouldnt be none unless its change
                    continue;
                }
            }
        }
    }

    // extract lowest u64 amount from expected other amount from inputs data.
    let (_, _, _, expected_amount): (u64, u64, u64, u64) = asm(r1: expected_other_amount) { r1: (u64, u64, u64, u64) };

    // Ensure other_asset output amount is within tolerance
    if !calcualte_asset_within_tolerance( actual_other_amount, expected_amount, tolerance_bps_u256 ) { return Err(7062u64); }

    // Ensure gas output change for is directed to sponsor address
    if !verify_change_output( tx_change_assets, FUEL_BASE_ASSET, Address::from(sponsor_addr) ) { return Err(7063u64); }

    Ok(GasSponsor::new( String::from_ascii_str("sponsor"), sponsor_addr, gas_utxo_in, actual_gas_output_amount, expected_other_asset, expected_other_amount, tolerance_bps_u256 ))
}

/// Process outputs for the "gaspass" command, validating only gas returns.
///
/// # Arguments
///
/// * `tx_output_assets`: [Vec<InpOut>] - Vector of transaction output assets
/// * `tx_change_assets`: [Vec<InpOut>] - Vector of transaction change outputs
/// * `sponsor_addr`: [b256] - Address of the gas sponsor
/// * `expected_gas_return_amount`: [u256] - Amount of gas to return to sponsor
/// * `gas_utxo_in`: [b256] - Input gas UTXO identifier
///
/// # Returns
///
/// * [Result<GasSponsor, u64>] - Rebuilt GasSponsor struct or error code
///
/// # Reverts
///
/// * When gas return output owner is missing (7060)
/// * When gas change output is invalid (7063)
///
pub fn process_output_assets_command_gaspass(
    tx_output_assets: Vec<InpOut>,
    tx_change_assets: Vec<InpOut>,
    sponsor_addr: b256,                     // propagated from get_gas_utxo()
    _expected_gas_return_amount: u256,
    gas_utxo_in: b256,
) -> Result<GasSponsor, u64> {

    // let mut sponsor_gas_output_found = true;
    let mut actual_gas_output_amount = asm(r1: (0, 0, 0, 0)) { r1: u256 };

    for output in tx_output_assets.iter() {
        // Ensure there is an explicit output for gas back to sponsor:
        if output.assetid == FUEL_BASE_ASSET {
            match output.amount {
                Some(amount) => {
                    match output.owner {
                        Some(owner) => {
                            // dont need to check `expected_gas_return_amount` as
                            // actual_gas_output_amount is fd into the verifying
                            // stuct.
                            if owner == Address::from(sponsor_addr) {
                                actual_gas_output_amount = asm(r1: (0, 0, 0, amount)) { r1: u256 };
                            }
                        },
                        None => {
                            // Gas Return output owner not found
                            return Err(7060u64);
                        }
                    }
                }
                None => {
                    // If the amount is None, skip this output
                    continue;
                }
            }
        }
    }

    // Ensure gas output change for is directed to sponsor address
    let gas_change_ok = verify_change_output(
        tx_change_assets,
        FUEL_BASE_ASSET,
        Address::from(sponsor_addr)
    );

    // If the no gas change then fail
    if !gas_change_ok {
        return Err(7063u64);
    }

    Ok(GasSponsor::new(
        String::from_ascii_str("gaspass"),
        sponsor_addr,
        gas_utxo_in,
        actual_gas_output_amount,
        b256::zero(),
        u256::zero(),
        u256::zero(),
    ))
}

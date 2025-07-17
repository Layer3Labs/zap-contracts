library;

use std::{
    bytes::Bytes,
    math::*,
    option::Option,
};


/// Converts Ethereum Wei amounts to Fuel ETH amounts by performing a division by 1e9.
///
/// # Additional Information
///
/// This function handles the denomination conversion between Ethereum and Fuel:
/// - Ethereum uses 18 decimal places (1 ETH = 1e18 Wei)
/// - Fuel uses 9 decimal places (1 ETH = 1e9 base units)
///
/// The conversion results in a loss of precision due to the different decimal places:
/// - Maximum value supported: 18446744073.709551615 ETH
/// - Precision loss: 9 decimal places (1e9)
///
/// # Arguments
///
/// * `wei_amount`: [u256] - The amount in Ethereum Wei to convert to Fuel ETH units
///
/// # Returns
///
/// * `Option<(u256, u256)>` - If successful:
///   * First u256: The amount in Fuel ETH units (quotient)
///   * Second u256: The remainder in Wei
///   Returns `None` if the input amount exceeds the maximum supported value
///
pub fn wei_to_eth(wei_amount: u256) -> Option<(u256, u256)> {

    // Check if wei_amount is not larger than the maximum allowed value
    // 18446744073.709551615 ETH max on Fuel in a single utxo
    let max_amount = asm(r1: (0, 0, 0x3B9AC9FF, 0xFFFFFFFFC4653600)) { r1: u256 };
    if wei_amount > max_amount {
        return None; // Number too large to process
    }

    let divisor = asm(r1: (0, 0, 0, 1_000_000_000)) { r1: u256 };

    let quo = wei_amount / divisor;
    let rem = wei_amount % divisor;

    Some((quo, rem))
}


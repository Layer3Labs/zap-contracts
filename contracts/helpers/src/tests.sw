library;

use std::{
    bytes::Bytes,
    math::*,
    option::Option,
    string::String,
};
use std::*;
use std::bytes_conversions::{b256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use ::numeric_utils::*;
use :: hex::b256_to_hex;


//----------------------------------------------------------------------------------
// TEST psudo-bignum operations

// forc test test_u64_add_overflow --logs
// test
#[test]
fn test_u64_add_overflow() {

    let ovf = check_u64_addition_overflow(0xFFFFFFFFFFFFFFFE, 0x01);
    log(ovf);   // should be true
    assert(ovf == true);

    let ovf = check_u64_addition_overflow(0xFFFFFFFFFFFFFFFE, 0x02);
    log(ovf);   // should be false
    assert(ovf == false);
}

// forc test test_b256_operations --logs
#[test]
fn test_b256_operations() {

    // Simple addition:
    // 520000000 --> 1EFE9200
    // 1000000000 --> 3B9ACA00
    // 1520000000 --> 5A995C00
    let a: b256 = 0x000000000000000000000000000000000000000000000000000000001EFE9200;
    let b: b256 = 0x000000000000000000000000000000000000000000000000000000003B9ACA00;
    let c: b256 = 0x000000000000000000000000000000000000000000000000000000005a995c00;
    let result = add_b256(a, b).unwrap();
    // log(result);
    assert(result == c);

    // add 0 to 200 decimal.
    let a: b256 = 0x00000000000000000000000000000000000000000000000000000000000000C8; // decimal 200
    let b: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let c: b256 = 0x00000000000000000000000000000000000000000000000000000000000000C8;
    let result = add_b256(a, b).unwrap();
    // log(result);
    assert(result == c);

    // test u64 max
    let max_u64 = to_b256((0, 0, 0, 0xFFFFFFFFFFFFFFFE));
    let one = to_b256((0, 0, 0, 0x01));
    let result = add_b256(max_u64, one);
    // assert(result.is_none());
    match result {
        Some(v) => assert(v == to_b256((0, 0, 0, 0xFFFFFFFFFFFFFFFF))),
        None => revert(2335u64),
    }

    // test u64 overflow
    let max_u64 = to_b256((0, 0, 0, 0xFFFFFFFFFFFFFFFF));
    let one = to_b256((0, 0, 0, 0x01));
    let result = add_b256(max_u64, one);
    // assert(result.is_none());
    let mut r = b256::zero();
    match result {
        Some(v) => {
            r = v;
        },
        None => {
            r = to_b256((0, 0, 0, 0xaa)); // should handle the None case, revert or return Error.
        },
    }
    assert(r == to_b256((0, 0, 0, 0xaa)))

}

// forc test test_b256_to_u64 --logs
#[test]
fn test_b256_to_u64() {
    // let x: b256 = 0x00000000000000000000000000000000000000000000000000000000000000fa;
    let x: b256 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF; // u64 max
    let y = b256_to_u64(x);
    log(y);
    assert(y == 0xFFFFFFFFFFFFFFFFu64);
}

// forc test test_b256_sub --logs
#[test]
fn test_b256_sub() {
    let x: b256 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF; // u64 max
    let y: b256 = 0x00000000000000000000000000000000000000000000000000000000000000fa; // 250 decimal
    let z = sub_b256_packed_u64(x, y);
    log(z); // should be Some(18446744073709551365)
    assert(z == Some(18446744073709551365));

    let x: b256 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF; // u64 max
    let y: b256 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF; // u64 max
    let z = sub_b256_packed_u64(x, y);
    log(z); // should be Some(0)
    assert(z == Some(0));

    // return None, y > x
    let x: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001; // 1 decimal
    let y: b256 = 0x000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF; // u64 max
    let z = sub_b256_packed_u64(x, y);
    log(z); // should be None
    assert(z == None);
}



/// Divides a b256 number by 1E9 (1_000_000_000) to convert from Wei to Fuel ETH
/// Returns None if the input is invalid or result would overflow
pub fn xx_wei_to_eth(wei_amount: b256) -> Option<b256> {
    let (w1, w2, w3, w4) = to_tuple(wei_amount);

    // Convert to a larger representation for division
    // Since we're dividing by 1E9, we need to handle the full number
    let mut total: u64 = 0;

    // Process each word, shifting and adding
    if w1 != 0 || w2 != 0 {
        return None; // Number too large to process
    }

    // Handle w3 and w4 carefully
    let mut remainder: u64 = 0;
    if w3 != 0 {
        remainder = w3 % 1_000_000_000;
        total += (w3 / 1_000_000_000) << 32;
    }

    // Add the contribution from w4 with any remainder from w3
    let combined = w4 + (remainder << 32);
    total += combined / 1_000_000_000;

    Some(to_b256((0, 0, 0, total)))
}

/// Divides a b256 number by 1E9 (1_000_000_000) to convert from Wei to Fuel ETH
/// Returns None if the input is invalid or result would overflow
pub fn yy_wei_to_eth(wei_amount: b256) -> Option<b256> {
    let (w1, w2, w3, w4) = to_tuple(wei_amount);

    // Convert to a larger representation for division
    let mut total: u64 = 0;

    // Process each word, shifting and adding
    if w1 != 0 || w2 != 0 {
        return None; // Number too large to process
    }

    // Handle w3 (middle word)
    if w3 != 0 {
        let high_part = w3 * (1u64 << 32);
        total += high_part / 1_000_000_000;
    }

    // Add the contribution from w4 (lowest word)
    total += w4 / 1_000_000_000;

    Some(to_b256((0, 0, 0, total)))
}

/// Divides a b256 number by 1E9 (1_000_000_000) to convert from Wei to Fuel ETH
pub fn zz_wei_to_eth(wei_amount: b256) -> Option<b256> {
    let (w1, w2, w3, w4) = to_tuple(wei_amount);

    if w1 != 0 || w2 != 0 {
        return None; // Number too large to process
    }

    // Handle the full 128 bits between w3 and w4
    let high = w3 * (1u64 << 32); // Shift w3 left by 32 bits
    let total_low = high + w4;     // Combine with w4

    // Calculate division by 1_000_000_000 (1e9)
    let quotient = total_low / 1_000_000_000;

    // Handle any remainder to ensure rounding
    let remainder = total_low % 1_000_000_000;
    let final_result = if remainder >= 500_000_000 {
        quotient + 1
    } else {
        quotient
    };

    Some(to_b256((0, 0, 0, final_result)))
}





/// For testing and debugging
pub fn log_b256(val: b256) {
    let (w1, w2, w3, w4) = to_tuple(val);
    // Log each word
    log(w1);
    log(w2);
    log(w3);
    log(w4);
}

// forc test test_wei_to_eth --logs
#[test]
fn test_wei_to_eth() {
    // Test 1 ETH in Wei (1e18) -> 1e9 Fuel ETH
    // dec 1000000000000000000 --> hex DE0B6B3 A7640000
    let one_eth_wei = to_b256((0, 0, 0x0DE0B6B3, 0xA7640000)); // 1e18
    let result = xx_wei_to_eth(one_eth_wei);

    log(result.unwrap());
    log(b256_to_hex(result.unwrap()));

    assert(result.unwrap() == to_b256((0, 0, 0, 1_000_000_000))); // 1e9


    // // Test your specific value: 1245500000000000000 Wei
    // let test_amount = to_b256((0, 0, 0x11_48E7, 0xA6ABBFC000));
    // let result = wei_to_eth(test_amount);
    // assert(result.unwrap() == to_b256((0, 0, 0, 1_245_500_000))); // 1245.5 Fuel ETH
}

// forc test test_xx_wei_to_eth --logs
#[test]
fn test_xx_wei_to_eth() {
    // Test with your specific value: 1245500000000000000 Wei
    // dec 1245500000000000000 --> hex 1148E7A6 ABBFC000
    let wei_amount = to_b256((0, 0, 0x1148E7A6, 0xABBFC000));

    let result = yy_wei_to_eth(wei_amount);
    let expected = to_b256((0, 0, 0, 1_245_500_000));

    log(b256_to_hex(result.unwrap()));
    log(b256_to_hex(expected));


    log_b256(result.unwrap());
    log_b256(expected);


    log(String::from_ascii_str("------------------"));

    // assert(result.is_some());
    // assert(result.unwrap() == expected);


    let result = yy_wei_to_eth(wei_amount);
    // assert(result.is_some());

    let expected = to_b256((0, 0, 0, 1_245_500_000));
    let (a1, b1, c1, actual) = toa_tuple(result.unwrap());
    let (a2, b2, c2, exp) = toa_tuple(expected);

    log(actual);
    log(exp);

    // assert(actual == exp);

    log(String::from_ascii_str("------------------"));

    // Test case 1: 1245500000000000000000 Wei (1245.5 ETH)
    // 43 84C8E30EE5060000
    let wei_amount = to_b256((0, 0, 0x1148E7A6, 0xABBFC000));
    let result = zz_wei_to_eth(wei_amount);
    let expected = to_b256((0, 0, 0, 1_245_500_000));

    let (_, _, _, actual) = toa_tuple(result.unwrap());
    let (_, _, _, exp) = toa_tuple(expected);

    log(actual);
    log(exp);

    assert(actual == exp);

    // Test case 2: 1 ETH (1000000000000000000 Wei)
    // DE0B6B3A7640000
    let one_eth = to_b256((0, 0, 0x0DE0B6B3, 0xA7640000));
    let result = zz_wei_to_eth(one_eth);


    // assert(result.unwrap() == to_b256((0, 0, 0, 1_000_000_000))




}


/// Converts given b256 to a tuple of words
pub fn toa_tuple(bits: b256) -> (u64, u64, u64, u64) {
    asm(r1: __addr_of(bits)) { r1: (u64, u64, u64, u64) }
}
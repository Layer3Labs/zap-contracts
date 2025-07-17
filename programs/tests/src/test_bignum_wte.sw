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

use zap_utils::wei_to_eth::*;
use zap_utils::hex::*;


// forc test test_202_wei_to_eth --logs
#[test]
fn test_202_1_wei_to_eth() {
    // Test case 2: 1 ETH (1000000000000000000 Wei)
    // DE0B6B3A7640000
    let one_eth = asm(r1: (0, 0, 0, 0x0DE0B6B3A7640000)) { r1: u256 };

    log(String::from_ascii_str("------------------ 1"));

    let result = wei_to_eth(one_eth);
    let expected = asm(r1: (0, 0, 0, 1_000_000_000)) { r1: u256 };

    log(u256_to_hex(result.unwrap().0));
    log(u256_to_hex(expected));

    assert(result.unwrap().0 == expected);
}

// forc test test_202_2_wei_to_eth --logs
#[test]
fn test_202_2_wei_to_eth() {
    // 1.000000000900000001 ETH
    // 1000000000900000001 Wei
    let a = asm(r1: (0, 0, 0, 0x0DE0B6B3DD08E901)) { r1: u256 };

    log(String::from_ascii_str("------------------ 1"));

    let result = wei_to_eth(a);
    let expected = asm(r1: (0, 0, 0, 1_000_000_000)) { r1: u256 };

    log(u256_to_hex(result.unwrap().0));
    log(u256_to_hex(result.unwrap().1));
    log(u256_to_hex(expected));


}

// forc test test_202_3_wei_to_eth --logs
#[test]
fn test_202_3_wei_to_eth() {

    // 1.000000005000000001 ETH
    // 1000000005000000001 Wei
    let a = asm(r1: (0, 0, 0, 0xDE0B6B4D169F201)) { r1: u256 };

    let result = wei_to_eth(a);
    let expected_q = asm(r1: (0, 0, 0, 1_000_000_005)) { r1: u256 };
    let expected_r = asm(r1: (0, 0, 0, 1)) { r1: u256 };

    log(u256_to_hex(result.unwrap().0));
    log(u256_to_hex(expected_q));
    assert(result.unwrap().0 == expected_q);
    log(u256_to_hex(result.unwrap().1));
    log(u256_to_hex(expected_r));
    assert(result.unwrap().1 == expected_r);
}

// forc test test_204_wei_to_eth --logs
#[test]
fn test_204_wei_to_eth() {

    // 0xffffffffffffffff / 0x3B9ACA00 =
    // max amount of ETH on Fuel can be =
    // 18446744073709551615 / 1000000000 = 18446744073.709551615 ETH max on Fuel.
    // 18446744073 141910323/200000000
    // 1.8446744073709551615 × 10^10 ETH

    // 18446744073.709551615 * 1E18 = Wei equivalent on Ethereum
    // 18446744073709551615000000000 Wei (on ETH)
    //
    // 3B9AC9FF FFFFFFFFC4653600
    let v6 = asm(r1: (0, 0, 0x3B9AC9FF, 0xFFFFFFFFC4653600)) { r1: u256 };

    // let v6 = asm(r1: (0, 0, 0x3b9ac9ff, 0xffffffffc4653600)) { r1: u256 };

    log(String::from_ascii_str("------------------ "));

    let result = wei_to_eth(v6);
    let expected = asm(r1: (0, 0, 0, 0xffffffffffffffff)) { r1: u256 };

    log(u256_to_hex(result.unwrap().0));
    log(u256_to_hex(expected));

    // 1844674407370955161500000000000
}

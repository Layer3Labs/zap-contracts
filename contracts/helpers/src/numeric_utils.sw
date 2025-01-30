library;

use std::{
    b512::B512,
    bytes::Bytes,
    math::*,
    option::Option,
    string::String,
};
use std::*;
use std::bytes_conversions::{b256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};



pub fn check_u64_addition_overflow(a: u64, b: u64) -> bool {

    let a_in = to_b256((0, 0, 0, a));
    let b_in = to_b256((0, 0, 0, b));
    let result = add_b256(a_in, b_in);
    match result {
        Some(_) => true,
        None => false,
    }
}

/// add two u64's packed in a b256, return None if overflow.
pub fn add_b256(a: b256, b: b256) -> Option<b256> {
    let a_bytes = a.to_be_bytes();
    let b_bytes = b.to_be_bytes();
    let mut result = Bytes::with_capacity(32);
    let mut carry = 0u8;

    let mut i = 0;
    while i < 32 {
        let index = 31 - i;  // Start from least significant byte
        let byte_a = a_bytes.get(index).unwrap();
        let byte_b = b_bytes.get(index).unwrap();

        let sum = byte_a.as_u64() + byte_b.as_u64() + carry.as_u64();
        // log(sum);

        if i == 7 {
            if sum > 0xffu64 {
                return None;
            }
        }

        let y: u64 = sum & 0xFF_u64;
        // log(y);

        let u: Bytes = y.to_le_bytes();
        result.push(u.get(0).unwrap());
        // log(u.get(0).unwrap());

        let carry_bytes: Bytes = (sum >> 8).to_le_bytes();
        carry = carry_bytes.get(0).unwrap();
        //log(carry);


        i += 1;
    }

    reverse(result);  // Reverse to get big-endian order
    // log(b256::from_be_bytes(result));
    Some(b256::from_be_bytes(result))
}

pub fn reverse(ref mut bytes: Bytes) {
    let length = bytes.len();
    let mut i = 0;
    while i < length / 2 {
        bytes.swap(i, length - 1 - i);
        i += 1;
    }
}

/// subtracts a u64 from another u64 number packed
/// a u64 packed in a b256, in big-endian
pub fn sub_b256_packed_u64(a: b256, b: b256) -> Option<u64> {
    let ax = b256_to_u64(a);
    let bx = b256_to_u64(b);

    if bx > ax {
        return None;
    }
    let result = ax - bx;
    Some(result)
}

//TODO - return a Option, as this is lossy
pub fn b256_to_u64(a: b256) -> u64 {
    let mut ax = Bytes::new();
    let a_bytes: Bytes = a.to_le_bytes();
    let mut i = 0;
    while i < 8 {
        ax.push(a_bytes.get(i).unwrap());
        i += 1;
    }
    let a64 = u64::from_le_bytes(ax);
    a64
}

/// Converts given tuple of words to a b256
pub fn to_b256(words: (u64, u64, u64, u64)) -> b256 {
    asm(r1: __addr_of(words)) { r1: b256 }
}

/// Converts given b256 to a tuple of words
pub fn to_tuple(bits: b256) -> (u64, u64, u64, u64) {
    asm(r1: __addr_of(bits)) { r1: (u64, u64, u64, u64) }
}

pub fn convert_u8_u64(a: u8) -> u64 {
    asm(input: a) {
        input: u64
    }
}


//-------------------------------------------

/// Divides a b256 number by 1E9 (1_000_000_000) to convert from Wei to Fuel ETH
/// Returns None if the input is invalid or result would overflow
pub fn wei_to_eth(wei_amount: b256) -> Option<b256> {
    let divisor: b256 = to_b256((0, 0, 0, 1_000_000_000));
    divide_b256(wei_amount, divisor)
}

/// Divides two b256 numbers
/// Returns None if division by zero or overflow
pub fn divide_b256(dividend: b256, divisor: b256) -> Option<b256> {
    if divisor == to_b256((0, 0, 0, 0)) {
        return None;
    }

    let dividend_bytes = dividend.to_be_bytes();
    let divisor_bytes = divisor.to_be_bytes();

    // Convert to u64 values for division
    let mut dividend_u64 = 0u64;
    let mut divisor_u64 = 0u64;

    // Read first 8 bytes for both numbers
    let mut i = 24; // Start from most significant byte that matters
    while i < 32 {
        dividend_u64 = (dividend_u64 << 8) | dividend_bytes.get(i).unwrap().as_u64();
        divisor_u64 = (divisor_u64 << 8) | divisor_bytes.get(i).unwrap().as_u64();
        i += 1;
    }

    // Check if divisor is 0
    if divisor_u64 == 0 {
        return None;
    }

    // Perform division
    let result = dividend_u64 / divisor_u64;

    // Convert result back to b256
    Some(to_b256((0, 0, 0, result)))
}
library;

use std::{
    bytes::Bytes,
    string::String,
    bytes_conversions::{b256::*, u64::*, u256::* },
};


/// Converts a byte (0-255) into its hex representation as ASCII bytes
///
/// # Arguments
///
/// * `byte` - A byte value between 0 and 255.
///
/// # Returns
///
/// * [Bytes] - Two ASCII bytes representing the hex characters
pub fn byte_to_hex_ascii(byte: u8) -> Bytes {
    let mut result = Bytes::new();

    // Convert high nibble to ASCII
    let high = byte >> 4;
    match high {
        0 => result.push(48),
        1 => result.push(49),
        2 => result.push(50),
        3 => result.push(51),
        4 => result.push(52),
        5 => result.push(53),
        6 => result.push(54),
        7 => result.push(55),
        8 => result.push(56),
        9 => result.push(57),
        10 => result.push(97),
        11 => result.push(98),
        12 => result.push(99),
        13 => result.push(100),
        14 => result.push(101),
        15 => result.push(102),
        _ => revert(0), // Should never happen
    }

    // Convert low nibble to ASCII
    let low = byte & 0x0f;
    match low {
        0 => result.push(48),
        1 => result.push(49),
        2 => result.push(50),
        3 => result.push(51),
        4 => result.push(52),
        5 => result.push(53),
        6 => result.push(54),
        7 => result.push(55),
        8 => result.push(56),
        9 => result.push(57),
        10 => result.push(97),
        11 => result.push(98),
        12 => result.push(99),
        13 => result.push(100),
        14 => result.push(101),
        15 => result.push(102),
        _ => revert(0), // Should never happen
    }

    result
}

pub fn bytes_to_hex_string(bytes: Bytes) -> String {
    let mut result = Bytes::new();
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes.get(i).unwrap();
        let hex_ascii = byte_to_hex_ascii(byte);
        result.push(hex_ascii.get(0).unwrap());
        result.push(hex_ascii.get(1).unwrap());
        i += 1;
    }

    String::from_ascii(result)
}

/// Convert a b256 to a hex encoded string.
pub fn b256_to_hex(a: b256) -> String {
    let b256_bytes = Bytes::from(a);
    bytes_to_hex_string(b256_bytes)
}

/// Convert a u256 to a hex encoded string.
pub fn u256_to_hex(a: u256) -> String {
    let u256_bytes = a.to_be_bytes();
    bytes_to_hex_string(u256_bytes)
}



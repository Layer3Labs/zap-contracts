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



// forc test test_hex_conversions --logs
#[test]
fn test_hex_conversions() {

    // Test case 1: Single byte conversion
    let mut test_byte = 0xff;
    let hex_bytes = byte_to_hex_ascii(test_byte);
    log(hex_bytes);
    let hex_string_01 = String::from_ascii(hex_bytes);
    assert(hex_string_01 == String::from_ascii_str("ff") );
    log(hex_string_01);

    // Test case 2: Multiple bytes
    let mut bytes = Bytes::new();
    bytes.push(0xde);
    bytes.push(0xad);
    bytes.push(0xbe);
    bytes.push(0xef);
    let hex_string_02 = bytes_to_hex_string(bytes);
    log(hex_string_02);

    // Test case 3: Zeros
    let mut bytes = Bytes::new();
    bytes.push(0x00);
    bytes.push(0x00);
    let hex_string_03 = bytes_to_hex_string(bytes);
    log(hex_string_03);
    assert(hex_string_03 == String::from_ascii_str("0000") );

    // Test case 4: Mixed values
    let mut bytes = Bytes::new();
    bytes.push(0x12);
    bytes.push(0x34);
    bytes.push(0xab);
    bytes.push(0xcd);
    let hex_string_04 = bytes_to_hex_string(bytes);
    log(hex_string_04);
    assert(hex_string_04 == String::from_ascii_str("1234abcd") );

    // Test case 5: Empty bytes
    let bytes = Bytes::new();
    let hex_string_05 = bytes_to_hex_string(bytes);
    log(hex_string_05);
    assert(hex_string_05 == String::from_ascii_str(""));

    // Test case 6: Values that need zero padding
    let mut bytes = Bytes::new();
    bytes.push(0x01);  // Should become "01" not "1"
    bytes.push(0x0a);  // Should become "0a" not "a"
    let hex_string_06 = bytes_to_hex_string(bytes);
    log(hex_string_06);
    assert(hex_string_06 == String::from_ascii_str("010a"));


}

// forc test test_b256_to_hex_string_conversion --logs
#[test]
fn test_b256_to_hex_string_conversion() {
    let test_asset_id: b256 = 0x2ed3afa6f5cc276b75779b5b5a95a0fe06eaa3f504a5ed4ceb75c502b9bc7936;

    let b256_bytes = Bytes::from(test_asset_id);
    let hex_string_07 = bytes_to_hex_string(b256_bytes);
    log(hex_string_07);
    assert(hex_string_07 == String::from_ascii_str("2ed3afa6f5cc276b75779b5b5a95a0fe06eaa3f504a5ed4ceb75c502b9bc7936"));

}
library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
};


/// Converts a hex-encoded string into `Bytes`.
///
/// # Arguments
///
/// * `hex_string` - A string slice containing the hex-encoded characters.
///
/// # Returns
///
/// * [Option<Bytes>] - A `Bytes` containing the decoded bytes if the input is valid hex, otherwise `None`.
///
/// # Examples
///
/// ```sway
/// use std::string::String;
///
/// fn foo() {
///     let hex_string = String::from_ascii_str("01ffabef");
///     let bytes_option = hex_to_bytes(hex_string);
///     assert(bytes_option.is_some());
///     let bytes = bytes_option.unwrap();
///     assert(bytes.len() == 4);
///     assert(bytes.get(0).unwrap() == 1u8);
///     assert(bytes.get(1).unwrap() == 255u8);
///     assert(bytes.get(2).unwrap() == 171u8);
///     assert(bytes.get(3).unwrap() == 239u8);
/// }
/// ```
pub fn hex_string_to_bytes(hex_string: String) -> Option<Bytes> {

    let slice_1 = asm(ptr: (hex_string.ptr(), hex_string.capacity())) {
        ptr: raw_slice
    };
    let mut hex_bytes = Bytes::from(slice_1);

    // Check if the string has an even number of characters
    if (hex_bytes.len() % 2).neq(0) {
        return None;
    }
    let mut bytes = Bytes::new();
    let mut i = 0;
    while i < hex_bytes.len() {
        let high_nibble = char_to_hex(hex_bytes.get(i).unwrap());
        let low_nibble = char_to_hex(hex_bytes.get(i + 1).unwrap());

        match (high_nibble, low_nibble) {
            (Some(high), Some(low)) => {
                bytes.push((high << 4) | low);
            },
            _ => return None, // Return None if any character is not a valid hex digit
        }
        i += 2;
    }
    Some(bytes)
}

/// Converts a hex character to its corresponding value.
///
/// # Arguments
///
/// * `c` - A byte representing a hex character.
///
/// # Returns
///
/// * [Option<u8>] - The value of the hex character if valid, otherwise `None`.
pub fn char_to_hex(c: u8) -> Option<u8> {
    match c {
        // ASCII values for '0' to '9'
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 => Some(c - 48),
        // ASCII values for 'a' to 'f'
        97 | 98 | 99 | 100 | 101 | 102 => Some(c - 97 + 10),
        // ASCII values for 'A' to 'F'
        65 | 66 | 67 | 68 | 69 | 70 => Some(c - 65 + 10),
        _ => None,
    }
}



pub fn string_to_bytes(input_string: String) -> Option<Bytes> {

    // Copy the input bytes
    let input_slice = asm(ptr: (input_string.ptr(), input_string.capacity())) {
        ptr: raw_slice
    };
    let input_bytes = Bytes::from(input_slice);

    Some(input_bytes)
}

/// //FIXME -  uses for this can be replaced with Sway append()
pub fn extend(ref mut bytes: Bytes, src: Bytes, length: u64) {
    let mut i: u64 = 0;
    while i < length {
        bytes.push(src.get(i).unwrap());
        i += 1;
    }
}

library;

use std::{bytes::Bytes, string::String};
use helpers::{
    hex::*,
    general_helpers::*,
};


/// The start of the Ethereum signed message prefix "\x19Ethereum Signed Message:\n"
/// Note: We don't include the length suffix as it will be dynamic
const ETHEREUM_PREFIX: b256 = 0x19457468657265756d205369676e6564204d6573736167653a0a000000000000;


pub fn personal_sign_string(message: String) -> b256 {
    // Create empty buffer
    let mut combined = Bytes::new();

    // Step 1: Add exactly 26 bytes of the prefix
    let prefix_bytes = ETHEREUM_PREFIX.to_be_bytes();
    let prefix_len = 26u64;
    let mut i = 0;
    while i < prefix_len {
        combined.push(prefix_bytes.get(i).unwrap());
        i += 1;
    }

    let message_bytes = string_to_bytes(message).unwrap();

    // Step 2: Add length as ASCII characters
    //FIXME -
    //NOTE - once the acknowledge is fixed, we can set the length and not have to calcualte it.
    //
    let message_len = message_bytes.len();  // Will be 23 for "UPGRADE ACKNOWLEDGMENT:"
    let len_str = u64_to_ascii(message_len); // Should give us "23" in ASCII (0x3231)
    combined.append(len_str);

    // let mut len_str = Bytes::new();
    // len_str.push(0x32);
    // len_str.push(0x33);
    // combined.append(len_str);

    // Step 3: Add the actual message bytes
    combined.append(message_bytes);

    /*
    //----------------------------------------------------
    // Log each step
    log("STEP 1 - Prefix:");
    log(bytes_to_hex_string(ETHEREUM_PREFIX.to_be_bytes()));

    log("STEP 2 - Length:");
    log(bytes_to_hex_string(len_str));

    log("STEP 3 - Message:");
    log(bytes_to_hex_string(message_bytes));

    log("Combined result:");
    log(bytes_to_hex_string(combined));
    //----------------------------------------------------
    */

    // Hash the combined buffer
    hash_bytes(combined)
}

// Helper function to convert number to ASCII bytes
fn u64_to_ascii(num: u64) -> Bytes {
    let mut result = Bytes::new();

    // Handle zero case
    if num == 0 {
        let zero_ascii = 48u8;
        result.push(zero_ascii);
        return result;
    }

    let mut n = num;
    let mut digits = Bytes::new();

    // Convert to ASCII one digit at a time
    while n > 0 {
        // Get rightmost digit
        let remainder = n % 10;

        // Convert to ASCII by adding 48 (ASCII '0')
        // Use explicit conversion since we know remainder is 0-9
        match u8::try_from(remainder + 48) {
            Some(ascii_val) => digits.push(ascii_val),
            None => revert(0), // Should never happen as remainder + 48 is always < 255
        };

        n = n / 10;
    }

    // Reverse the digits
    let mut i = digits.len();
    while i > 0 {
        i = i - 1;
        result.push(digits.get(i).unwrap());
    }

    result
}

// forc test test_personal_sign --logs
#[test]
fn test_personal_sign() {
    let message = String::from_ascii_str("UPGRADE ACKNOWLEDGMENT:");
    let hash = personal_sign_string(message);

    // Print the final hash
    log(String::from_ascii_str("Final hash:"));
    log(b256_to_hex(hash));
}


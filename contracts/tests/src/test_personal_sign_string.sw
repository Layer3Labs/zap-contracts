library;

use std::{
    bytes::Bytes,
    string::String,
};
use std::*;

use zap_utils::*;

// forc test test_personal_sign_string --logs
#[test]
fn test_personal_sign_string() {
    let message = String::from_ascii_str("UPGRADE ACKNOWLEDGMENT:");
    let hash = personal_sign_string(message);

    // Print the final hash
    log(String::from_ascii_str("Final hash:"));
    log(b256_to_hex(hash));
}

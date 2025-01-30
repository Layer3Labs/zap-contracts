predicate;

use std::{
    bytes::Bytes,
    string::String,
};

use helpers::general_helpers::{
    hex_string_to_bytes,
    char_to_hex,
};

fn main() -> bool {
    // Dummy code for unique predicate root/addr.
    let mut bytes = Bytes::new();
    bytes.push(0x6d); // m
    bytes.push(0x6f); // o
    bytes.push(0x64); // d
    bytes.push(0x75); // u
    bytes.push(0x6c); // l
    bytes.push(0x65); // e
    bytes.push(0x30); // 0
    bytes.push(0x38); // 8

    let mut ascii_hex_string = String::from_ascii_str("6d6f64756c653038"); // "module08"
    let namebytes = hex_string_to_bytes(ascii_hex_string).unwrap();

    let mut j = 0;
    while j < namebytes.capacity() {
        if (bytes.get(j) != namebytes.get(j)) {
            return false;
        }
        j += 1;
    }
    return true;
}
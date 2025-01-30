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
    bytes.push(0x35); // 5
    bytes.push(0x5f); // _
    bytes.push(0x65); // e
    bytes.push(0x69); // i
    bytes.push(0x70); // p
    bytes.push(0x37); // 7
    bytes.push(0x31); // 1
    bytes.push(0x32); // 2
    bytes.push(0x5f); // _
    bytes.push(0x73); // s
    bytes.push(0x69); // i
    bytes.push(0x6d); // m
    bytes.push(0x70); // p
    bytes.push(0x6c); // l
    bytes.push(0x65); // e

    let mut ascii_hex_string = String::from_ascii_str("6d6f64756c6530355f6569703731325f73696d706c65"); // "module05_eip712_simple"
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
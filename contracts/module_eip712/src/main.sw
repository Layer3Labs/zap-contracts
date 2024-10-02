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
    bytes.push(0x6d);
    bytes.push(0x6f);
    bytes.push(0x64);
    bytes.push(0x75);
    bytes.push(0x6c);
    bytes.push(0x65);
    bytes.push(0x5f);
    bytes.push(0x65);
    bytes.push(0x69);
    bytes.push(0x70);
    bytes.push(0x37);
    bytes.push(0x31);
    bytes.push(0x32);

    let mut ascii_hex_string = String::from_ascii_str("6d6f64756c656970373132"); // "module_eip712"
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
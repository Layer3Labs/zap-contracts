



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
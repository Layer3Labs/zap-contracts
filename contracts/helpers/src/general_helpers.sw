library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    vm::evm::evm_address::EvmAddress,
};



pub fn calc_asset_id(
    evm_addr: EvmAddress,
    dummy_sub_id: b256,
    contract_id: ContractId,
) -> b256 {

    let mut result_buffer_1 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(n_id: result_buffer_1, ptr: (evm_addr, dummy_sub_id), bytes: 64) {
        s256 n_id ptr bytes;
    };

    // log(result_buffer_1);

    // let contract_id = asm() { fp: b256 };
    let mut result_buffer_2 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(asset_id: result_buffer_2, ptr: (contract_id, result_buffer_1), bytes: 64) {
        s256 asset_id ptr bytes;
    };

    // log(result_buffer_2);

    return(result_buffer_2);

}


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

    let input_capacity = input_string.capacity();
    let mut padded_bytes = Bytes::new();
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

/// calculate keccak256 of arbitary length Bytes.
pub fn hash_bytes(payloadbytes: Bytes) -> b256 {

    let len = payloadbytes.len();
    let a_size = len + 1;
    let a_buflen = a_size - 1;
    let x_src = payloadbytes.ptr();
    let mut result_buffer = b256::zero();
    let _ = asm(
        hash: result_buffer,            // result buffer.
        ptrdata: x_src,                 // the payload data bytes.
        length: a_buflen,               // the length of the payload data.
        size: a_size,                   // the size of the buffer to alloc on stack.
        buflen: a_buflen,               // the size of the buffer to hash.
        memptr                          //
        ) {
        aloc size;                      // allocate memory to the stack
        addi memptr hp i1;              // increase memory pointer for copying payload items
        mcp  memptr ptrdata length;     // copy
        addi memptr hp i1;              // move memory pointer back to the beginning
        k256 hash memptr buflen;
        hash: b256
    };
    return(result_buffer);
}

/// calculate sha256 of arbitary length Bytes.
pub fn hash_bytes_sha256(payloadbytes: Bytes) -> b256 {

    let len = payloadbytes.len();
    let a_size = len + 1;
    let a_buflen = a_size - 1;
    let x_src = payloadbytes.ptr();
    let mut result_buffer = b256::zero();
    let _ = asm(
        hash: result_buffer,            // result buffer.
        ptrdata: x_src,                 // the payload data bytes.
        length: a_buflen,               // the length of the payload data.
        size: a_size,                   // the size of the buffer to alloc on stack.
        buflen: a_buflen,               // the size of the buffer to hash.
        memptr                          //
        ) {
        aloc size;                      // allocate memory to the stack
        addi memptr hp i1;              // increase memory pointer for copying payload items
        mcp  memptr ptrdata length;     // copy
        addi memptr hp i1;              // move memory pointer back to the beginning
        s256 hash memptr buflen;
        hash: b256
    };
    return(result_buffer);
}

/// Returns the b256 representation of the bytes starting from the pointer to num_bytes
/// and the new pointer value.
pub fn bytes_read_b256(data: Bytes, ptr: u64, num_bytes: u64) -> (b256, u64) {
    if num_bytes > 32 {
        return (b256::zero(), ptr);
    }
    if num_bytes == 0 {
        return (b256::zero(), ptr);
    }
    let mut value: (u64, u64, u64, u64) = (0, 0, 0, 0);
    let dst = __addr_of(value).add_uint_offset(32 - num_bytes);
    let src = data.ptr().add_uint_offset(ptr);
    asm(dst: dst, src: src, len: num_bytes) {
        mcp  dst src len;
    };
    let newptr = ptr + num_bytes;
    (to_b256(value), newptr)
}

pub fn to_b256(words: (u64, u64, u64, u64)) -> b256 {
    asm(r1: __addr_of(words)) { r1: b256 }
}
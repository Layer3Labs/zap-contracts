library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    vm::evm::evm_address::EvmAddress,
};


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


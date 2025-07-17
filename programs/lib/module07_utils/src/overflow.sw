library;

use std::math::*;
use std::*;
use std::bytes_conversions::{b256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};


pub fn is_overflow_u64(x: u256) -> bool {

    let u64_max_bn = asm(r1: (0, 0, 0, 0xFFFFFFFFFFFFFFFF)) { r1: u256 };
    if x > u64_max_bn {
        return true;
    }
    false
}
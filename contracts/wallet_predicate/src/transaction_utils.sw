library;

use std::constants::{ZERO_B256, BASE_ASSET_ID};
use std::{
    inputs::{
        GTF_INPUT_COIN_AMOUNT,
        GTF_INPUT_COIN_ASSET_ID,
    },
    inputs::Input,
    outputs::{
        GTF_OUTPUT_TYPE,
        GTF_OUTPUT_COIN_AMOUNT,
    },
    tx::{
        GTF_SCRIPT_GAS_LIMIT,
        GTF_POLICY_GAS_PRICE,       //GTF_SCRIPT_GAS_PRICE,
        GTF_SCRIPT_INPUTS_COUNT,
        GTF_SCRIPT_OUTPUTS_COUNT,
    },
};

// TODO: replace GTF consts with direct references to tx.sw, inputs.sw, and outputs.sw from std lib
const GTF_INPUT_TYPE = 0x101;
const GTF_OUTPUT_COIN_ASSET_ID = 0x204;
const GTF_OUTPUT_COIN_TO = 0x202;

const OUTPUT_TYPE_COIN = 0u64;
const OUTPUT_TYPE_CHANGE = 3u64;

const INPUT_TYPE_COIN = 0u64;
const INPUT_TYPE_CONTRACT = 1u64;

/// Get the transaction gas price
pub fn tx_gas_price() -> u64 {
    // __gtf::<u64>(0, GTF_SCRIPT_GAS_PRICE)
    __gtf::<u64>(0, GTF_POLICY_GAS_PRICE)
}

/// Get the transaction gas price
pub fn tx_gas_limit() -> u64 {
    __gtf::<u64>(0, GTF_SCRIPT_GAS_LIMIT)
}

/// Get the transaction inputs count
pub fn input_count() -> u64 {
    __gtf::<u64>(0, GTF_SCRIPT_INPUTS_COUNT)
}

/// Verifies an input at the given index is a coin input
pub fn verify_input_coin(index: u64) -> bool {
    __gtf::<u64>(index, GTF_INPUT_TYPE) == INPUT_TYPE_COIN
}

/// Get the asset ID of a coin input
pub fn input_coin_asset_id(index: u64) -> b256 {
    __gtf::<b256>(index, GTF_INPUT_COIN_ASSET_ID)
}

/// Get the amount of a coin input
pub fn input_coin_amount(index: u64) -> u64 {
    __gtf::<u64>(index, GTF_INPUT_COIN_AMOUNT)
}

/// Get the transaction outputs count
pub fn output_count() -> u64 {
    __gtf::<u64>(0, GTF_SCRIPT_OUTPUTS_COUNT)
}

/// Verifies an output at the given index is a contract output
pub fn verify_output_coin(index: u64) -> bool {
    __gtf::<u64>(index, GTF_OUTPUT_TYPE) == OUTPUT_TYPE_COIN
}

/// Verifies an output at the given index is a change output
pub fn verify_output_change(index: u64) -> bool {
    __gtf::<u64>(index, GTF_OUTPUT_TYPE) == OUTPUT_TYPE_CHANGE
}

/// Get the asset ID of a coin input
pub fn output_coin_asset_id(index: u64) -> b256 {
    __gtf::<b256>(index, GTF_OUTPUT_COIN_ASSET_ID)
}

/// Get the amount of a coin input
pub fn output_coin_amount(index: u64) -> u64 {
    __gtf::<u64>(index, GTF_OUTPUT_COIN_AMOUNT)
}

/// Get the receiver of a coin input
pub fn output_coin_to(index: u64) -> b256 {
    __gtf::<b256>(index, GTF_OUTPUT_COIN_TO)
}


//--------------------------------------------------------

pub fn input_asset_id(index: u64) -> Option<AssetId> {
    match input_type(index) {
        Input::Coin => Some(AssetId::from(__gtf::<b256>(index, GTF_INPUT_COIN_ASSET_ID))),  // Input::Coin => Some(__gtf::<b256>(index, GTF_INPUT_COIN_ASSET_ID)),
        Input::Message => Some(BASE_ASSET_ID),
        Input::Contract => None,
    }
}

pub fn input_type(index: u64) -> Input {
    match __gtf::<u8>(index, GTF_INPUT_TYPE) {
        0u8 => Input::Coin,
        1u8 => Input::Contract,
        2u8 => Input::Message,
        _ => revert(0),
    }
}
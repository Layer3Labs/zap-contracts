library;

use std::{
    inputs::{
        GTF_INPUT_COIN_AMOUNT,
        GTF_INPUT_COIN_ASSET_ID,
        input_type,
        Input,
    },
    outputs::{
        GTF_OUTPUT_TYPE,
        GTF_OUTPUT_COIN_AMOUNT,
        // output_pointer, moved to private in 0.63.1
        output_type,
    },
    tx::{
        GTF_SCRIPT_GAS_LIMIT,
        GTF_POLICY_TYPES,
        GTF_POLICY_TIP,
        GTF_SCRIPT_INPUTS_COUNT,
        GTF_SCRIPT_OUTPUTS_COUNT,
        GTF_CREATE_OUTPUT_AT_INDEX,
        GTF_SCRIPT_OUTPUT_AT_INDEX,
        Transaction,
        tx_type,
    },
};

// TODO: replace GTF consts with direct references to tx.sw, inputs.sw, and outputs.sw from std lib
const GTF_INPUT_TYPE = 0x101;
const GTF_OUTPUT_COIN_ASSET_ID = 0x204;
const GTF_OUTPUT_COIN_TO = 0x202;

const GTF_INPUT_COIN_TX_ID = 0x201;

const OUTPUT_TYPE_COIN = 0u64;
const OUTPUT_TYPE_CHANGE = 3u64;

const INPUT_TYPE_COIN = 0u64;
const INPUT_TYPE_CONTRACT = 1u64;

/// Get the transaction gas price
// pub fn tx_gas_price() -> u64 {
//     // __gtf::<u64>(0, GTF_SCRIPT_GAS_PRICE)
//     __gtf::<u64>(0, GTF_POLICY_GAS_PRICE)
// }

fn policies() -> u32 {
    __gtf::<u32>(0, GTF_POLICY_TYPES)
}

// changed to policy_tip in sway 0.60.0
const TIP_POLICY: u32 = 1u32 << 0;

pub fn tx_tip() -> Option<u64> {
    let bits = policies();
    if bits & TIP_POLICY > 0 {
        Some(__gtf::<u64>(0, GTF_POLICY_TIP))
    } else {
        None
    }
}

/// Get the transaction gas price
pub fn tx_gas_limit() -> u64 {
    __gtf::<u64>(0, GTF_SCRIPT_GAS_LIMIT)
}

/// Get the transaction inputs count
pub fn input_count() -> u64 {
    __gtf::<u64>(0, GTF_SCRIPT_INPUTS_COUNT)
}

/// Verifies an input at the given index is a Coin input
pub fn verify_input_coin(index: u64) -> bool {
    match input_type(index) {
        Some(Input::Coin) => return true,
        _ => false,
    }
}
/// Verifies an input at the given index is a Contract input
pub fn verify_input_contract(index: u64) -> bool {
    match input_type(index) {
        Some(Input::Contract) => true,
        _ => false,
    }
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

//REVIEW - this is already in inputs.sw 0.63.1, just include it.
pub fn input_asset_id(index: u64) -> Option<AssetId> {
    match input_type(index) {
        Some(Input::Coin) => Some(AssetId::from(__gtf::<b256>(index, GTF_INPUT_COIN_ASSET_ID))),
        Some(Input::Message) => Some(AssetId::base()),
        _ => None,
    }
}

// taken from outputs.sw in std, this is a private function.
fn output_pointer(index: u64) -> Option<raw_ptr> {
    if output_type(index).is_none() {
        return None
    }
    match tx_type() {
        Transaction::Script => Some(__gtf::<raw_ptr>(index, GTF_SCRIPT_OUTPUT_AT_INDEX)),
        Transaction::Create => Some(__gtf::<raw_ptr>(index, GTF_CREATE_OUTPUT_AT_INDEX)),
    }
}

pub fn output_amount_at_index(index: u64) -> u64 {
    let ptr = output_pointer(index);
    asm(r1, r2, r3: ptr) {
        addi r2 r3 i40;
        lw r1 r2 i0;
        r1: u64
    }
}

/// return the utxo id from the coin input at index.
pub fn input_txn_hash(index: u64) -> b256 {
     __gtf::<b256>(index, GTF_INPUT_COIN_TX_ID)
}
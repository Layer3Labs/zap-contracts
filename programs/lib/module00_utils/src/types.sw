library;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    hash::*,
    vm::evm::ecr::ec_recover_evm_address,
};
use zap_utils::{
    hex::b256_to_hex,
    rlp_helpers::{
        hash_bytes, bytes_read_b256,
    },
    string_helpers::*,
    personal_sign_string::*,
};



pub struct Intent {
    /// Defines the type and parameters of the intent
    pub io: IntentType,

    /// Custom witness index for signature verification (defaults to 0 if None)
    pub override_witness_index: Option<u64>,
}

pub enum IntentType {
    /// Token swap intent
    Swap: SwapIntent,

    /// Cancel a pending intent
    Cancel: CancelIntent,
}


pub struct SwapIntent {
    /// Asset to sell
    pub sell_asset: AssetId,

    /// Amount to sell
    pub sell_amount: u64,

    /// Asset to buy
    pub buy_asset: AssetId,

    /// Minimum amount to receive
    pub min_buy_amount: u64,

    /// Slippage tolerance in basis points
    pub slippage_bps: u64,
}

pub struct CancelIntent {
    /// UTXO ID that the current intent is validated against
    pub module_utxo_id: b256,
}

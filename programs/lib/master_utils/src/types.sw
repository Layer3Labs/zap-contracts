library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    hash::*,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::input_coin_owner,
    outputs::{
        output_asset_id,
        output_asset_to,
        // Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};



/// A ZapWallet master operation.
pub struct WalletOp {
    /// The b256 hash of the command string to execute
    pub command: b256,
    /// Custom witness index for signature verification (defaults to 0 if None)
    pub override_witness_index: Option<u64>,
}

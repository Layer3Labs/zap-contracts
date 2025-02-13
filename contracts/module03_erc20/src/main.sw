predicate;

use std::{ b512::B512, bytes::Bytes, string::String,
    inputs::{ input_coin_owner, input_count, input_asset_id, input_amount, Input },
    outputs::{ output_type, output_asset_id, output_asset_to, output_amount, Output },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use zap_utils::{
    decode_erc20::{DecodeERC20RLPResult, decode_signed_typedtx_erc20},
    transaction_utls::{ input_coin_amount, input_coin_asset_id, verify_input_coin, output_count, output_coin_asset_id, output_coin_amount, output_coin_to, tx_gas_limit, verify_output_change, verify_output_coin } };
use io_utils::{ evm_erc20_tx::*, io::{InpOut, collect_inputs_outputs_change} };
use zapwallet_consts::wallet_consts::{ FUEL_CHAINID, NONCE_MAX };


configurable {
    /// The address of the ZapWallet master owner.
    OWNER_ADDRESS: b256 = b256::zero(),
    /// The nonce native assetid ascoiated with the owners ZapWallet.
    NONCE_ASSETID: b256 = b256::zero(),
    /// This modules assetid as a b256.
    MODULE_KEY03_ASSETID: b256 = b256::zero(),
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
}


/// ZapWallet Module 03.
///
/// Takes a signed EIP-1559 EVM ERC20 transfer transaction as input and performs various checks
/// to ensure the Fuel transaction that has been built satisfies the parameters defined within the
/// signed EVM transaction and against any constraints set out by the architecture of
/// the ZapWallet.
///
/// # Arguments
///
/// * `signed_evm_tx` - The signed RLP encoded EVM ERC20 transfer transaction as a byte array.
/// * `receiver_wallet_bytecode` - The Zap Wallet master bytecode (see additional information).
///
/// # Returns
///
/// * `true` - If the transaction passes all checks and validations.
/// * `false` - If the transaction fails any of the checks or validations.
///
/// # Description
///
/// The main function performs the following steps:
///
/// 1. Decodes the signed EVM ERC20 transfer transaction using the `decode_signed_typedtx_erc20()` function.
///    - If the decoding fails, returns `false`.
///
/// 2. Checks if the transaction was signed by the owner and has the correct chain ID.
///    - If either condition is not met, returns `false`.
///
/// 3. Calculates the expected nonce input value based on the transaction nonce.
///
/// 4. Calculates the maximum cost signed by the owner using the gas limit and maximum fee per gas.
///
/// 5. Collects the input and output coins of the transaction.
///    - Iterates over the input coins and adds them to the `tx_inputs` vector.
///    - Iterates over the output coins and adds them to the `tx_outputs` vector.
///    - Collects the change outputs and adds them to the `tx_change` vector.
///
/// 6. Processes the input assets using the `process_src20_input_assets()` function.
///    - If the input processing fails, returns `false`.
///
/// 7. Processes the output assets using the `process_src20_output_assets()` function.
///    - If the output processing fails, returns `false`.
///
/// 8. If all checks and validations pass, returns `true`.
///
/// # Additional Information
///
/// - The function assumes that the signed EVM ERC20 transfer transaction is of type EIP-1559 (type 2) and
///   uses the `decode_signed_typedtx_erc20()` function to decode it.
///
/// - The Contract Id in the EVM ERC20 transfer transaction is ascoiated with the SRC20 AssetId on the
///   Fuel network. The variable `tx_to` returned from decode_signed_typedtx_erc20() is the "short" partial
///   (20-byte) Fuel native Asset ID of the asset being transferred from the sender to receiver.
///
/// - The `receiver_wallet_bytecode` should be only the 2nd leaf in from the master predicate bytecode,
///   populated with the configurables specific to the receiver.
///
/// - The function uses the `configurable` block to define the owner's public key, nonce asset ID,
///   and module03 asset ID, which can be set within the predicate bytecode.
///
/// - The function uses various utility functions and constants from the `io_utils` and `zapwallet_consts`
///   modules to perform specific tasks and validations.
///
/// - This program can only be used to transfer any native asset other than the BASE_ASSET on Fuel.
///
fn main( signed_evm_tx: Bytes, receiver_wallet_bytecode: Bytes ) -> bool {

    // Decode signed evm erc20 transfer tx rlp into its constituent fields:
    let ( _, tx_chain_id, tx_nonce, tx_max_fee_per_gas, tx_gas_limit, _, tx_to, _, _, _, _, _, _, tx_from, tx_ct_to, tx_ct_amount ) = match decode_signed_typedtx_erc20(signed_evm_tx) {
        DecodeERC20RLPResult::Success(result) => { result },
        DecodeERC20RLPResult::Fail(_error_code) => { return false; },
    };

    // Ensure evm tx was signed by the owner & correct chain_id in evm tx:
    if !(tx_chain_id == FUEL_CHAINID && tx_from == OWNER_ADDRESS) { return false; }

    // Calculate the expected nonce input value.
    let exp_nonce_inp_val = NONCE_MAX - tx_nonce;

    // Calculate max cost signed by owner:
    let max_cost_bn = asm(r1: (0, 0, 0, (tx_gas_limit * tx_max_fee_per_gas))) { r1: u256 };

    // Copy the receiver bytecode bytes to mutable variable.
    let mut receiver_bytecode = receiver_wallet_bytecode;

    // Collect transaction inputs, outputs and change:
    let (tx_inputs, tx_outputs, tx_change) = collect_inputs_outputs_change();

    // Process the inputs:
    let ip_result = match process_src20_input_assets( tx_inputs, tx_to, tx_ct_amount.into(), max_cost_bn, NONCE_ASSETID, exp_nonce_inp_val, MODULE_KEY03_ASSETID ) {
        Ok(result) => { result },
        Err(_error_code) => { return false; },
    };

    // Process the outputs:
    let final_result = match process_src20_output_assets( tx_outputs, tx_change, ip_result, tx_ct_amount.into(), NONCE_ASSETID, (exp_nonce_inp_val - 1), tx_ct_to, receiver_bytecode ) {
        Ok(result) => { result },
        Err(_error_code) => { false },
    };

    final_result
}

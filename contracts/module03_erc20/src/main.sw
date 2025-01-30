predicate;

mod constants;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    inputs::{
        input_coin_owner,
        input_count,
        input_asset_id,
        input_amount,
        Input,
    },
    outputs::{
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
        Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use ptools::{
    decode_erc20::{DecodeERC20RLPResult, decode_signed_typedtx_erc20},
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_input_coin,
        output_count,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        verify_output_change,
        verify_output_coin,
    },
};

use io_utils::evmtx_io_utils::InpOut;

use module03_utils::{
    erc20tx_io_utils::*,
};
use ::constants::VERSION;
use zapwallet_consts::wallet_consts::{
    FUEL_CHAINID, NONCE_MAX, FUEL_BASE_ASSET,
};

configurable {
    OWNER_PUBKEY: b256 = b256::zero(),
    NONCE_KEY00_ASSETID: b256 = b256::zero(),
    MODULE_KEY03_ASSETID: b256 = b256::zero(),
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
fn main(
    signed_evm_tx: Bytes,
    receiver_wallet_bytecode: Bytes,
) -> bool {

    // Compile version identifier into bytecode.
    let version = VERSION;

    // Decode signed evm erc20 transfer tx rlp into its constituent fields:
    let (
        tx_type_identifier,
        tx_chain_id,
        tx_nonce,
        tx_max_fee_per_gas,
        tx_gas_limit,
        tx_value,
        tx_to,
        tx_asset_id,
        _tx_digest,
        _tx_length,
        _tx_data_start,
        _tx_data_end,
        _tx_signature,
        tx_from,
        tx_ct_to,
        tx_ct_amount,
    ) = match decode_signed_typedtx_erc20(signed_evm_tx) {
        DecodeERC20RLPResult::Success(result) => { result },
        DecodeERC20RLPResult::Fail(error_code) => {
            // rlp decoding failed with error code.
            return false;
        },
    };

    // Ensure evm tx was signed by the owner & correct chain_id in evm tx:
    if !(tx_chain_id == FUEL_CHAINID && tx_from == OWNER_PUBKEY) {
        return false;
    }

    // calculate the expected nonce input value.
    let exp_nonce_inp_val = NONCE_MAX - tx_nonce;

    // Calculate max cost signed by owner:
    let max_cost_bn = asm(r1: (0, 0, 0, (tx_gas_limit * tx_max_fee_per_gas))) { r1: u256 };

    // copy the receiver bytecode bytes to mutable variable.
    let mut receiver_bytecode = receiver_wallet_bytecode;

    // Collect inputs and outputs:
    let in_count: u64 = input_count().as_u64();
    let out_count: u64 = output_count();

    let mut tx_inputs : Vec<InpOut> = Vec::new();
    let mut tx_outputs : Vec<InpOut> = Vec::new();
    let mut tx_change: Vec<InpOut> = Vec::new();

    let mut i = 0;
    while i < in_count {
        // collect all the input coins
        if verify_input_coin(i) {
            let inp = InpOut::new(
                input_coin_asset_id(i),
                Some(input_coin_amount(i)),
                input_coin_owner(i)
            );
            tx_inputs.push(inp);

        }
        i += 1;
    }
    let mut j = 0;
    while j < out_count {
        // collect all the output coins
        if verify_output_coin(j) {

            let outp = InpOut::new(
                output_coin_asset_id(j).unwrap(),   // from tx_utls, return Option<b256>
                Some(output_amount(j).unwrap()),
                Some(output_asset_to(j).unwrap()),
            );
            tx_outputs.push(outp);
        }
        // collect all the change outputs assetid's and receivers.
        match verify_output_change(j) {
            Some(is_change) => {
                if is_change {
                    tx_change.push(
                        InpOut::new(
                            output_asset_id(j).unwrap().into(), // whats the assetid of the change.
                            None,
                            Some(output_asset_to(j).unwrap()),  // who is the change going to
                        )
                    );
                }
            },
            _ => {},
        }
        j += 1;
    }

    // process the inputs:
    let ip_result = match process_src20_input_assets(
        tx_inputs,
        tx_to,                  // this is the rlp tx EVM "ContractId", which is the short (20-byte) Fuel AssetId here.
        tx_ct_amount.into(),
        FUEL_BASE_ASSET,
        max_cost_bn,
        NONCE_KEY00_ASSETID,
        exp_nonce_inp_val,
        MODULE_KEY03_ASSETID,
    ) {
        Ok(result) => { result },
        Err(error_code) => {
            // input processing failed with error code"
            return false;
        },
    };

    // process the outputs:
    let final_result = match process_src20_output_assets(
        tx_outputs,
        tx_change,
        ip_result,
        tx_ct_amount.into(),
        NONCE_KEY00_ASSETID,
        (exp_nonce_inp_val - 1),
        tx_ct_to,
        receiver_bytecode,
    ) {
        Ok(result) => { result.outputs_ok },
        Err(error_code) => {
            // output processing failed with error code
            false
        },
    };

    final_result



    // true
}

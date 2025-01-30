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
    decode_1559::{DecodeType02RLPResult, decode_signed_typedtx_1559},
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

use module02_utils::{
    evmtx_io_utils::*,
};
use ::constants::VERSION;
use zapwallet_consts::wallet_consts::{
    FUEL_CHAINID, NONCE_MAX, FUEL_BASE_ASSET,
};

configurable {
    OWNER_PUBKEY: b256 = b256::zero(),
    NONCE_KEY00_ASSETID: b256 = b256::zero(),
    MODULE_KEY02_ASSETID: b256 = b256::zero(),
}


/// ZapWallet Module 02.
///
/// Takes a signed EIP-1559 EVM transaction as input and performs various checks to ensure
/// the Fuel transaction that has been built satisfies the parameters defined within the
/// signed EVM transaction and against any constraints set out by the architecture of
/// the ZapWallet.
///
/// # Arguments
///
/// * `signed_evm_tx` - The signed RLP encoded EVM transaction as a byte array.
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
/// 1. Decodes the signed EVM transaction using the `decode_signed_typedtx_1559()` function.
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
/// 6. Processes the input assets using the `process_input_assets()` function.
///    - If the input processing fails, returns `false`.
///
/// 7. Processes the output assets using the `process_output_assets()` function.
///    - If the output processing fails, returns `false`.
///
/// 8. If all checks and validations pass, returns `true`.
///
/// # Additional Information
///
/// - The `receiver_wallet_bytecode` should be only the 2nd leaf in from the master predicate bytecode,
///   populated with the configurables specific to the receiver.
///
/// - The function uses the `configurable` block to define the owner's public key, nonce asset ID,
///   and module02 asset ID, which can be set within the predicate bytecode.
///
/// - The function uses various utility functions and constants from the `io_utils` and `zapwallet_consts`
///   modules to perform specific tasks and validations.
///
/// - The function assumes that the signed EVM transaction is of type EIP-1559 (type 2) and uses the
///   `decode_signed_typedtx_1559()` function to decode it.
///
/// - This program can only be used to transfer the BASE_ASSET on Fuel.
///
fn main(
    signed_evm_tx: Bytes,
    receiver_wallet_bytecode: Bytes,
) -> bool {

    // Compile version identifier into bytecode.
    let version = VERSION;

    // Decode signed_evm_tx rlp into its constituent fields:
    let (
        type_identifier,
        chain_id,
        tx_nonce,
        max_fee_per_gas,
        gas_limit,
        value_wei,
        tx_to,
        asset_id,
        digest,
        txlengeth,
        tx_data_start,
        tx_data_end,
        signature,
        tx_from
    ) = match decode_signed_typedtx_1559(signed_evm_tx) {
        DecodeType02RLPResult::Success(result) => { result },
        DecodeType02RLPResult::Fail(error_code) => {
            // rlp decoding failed with error code.
            return false;
        },
    };

    // Ensure evm tx was signed by the owner & has the correct chain_id:
    if !(chain_id == FUEL_CHAINID && tx_from == OWNER_PUBKEY) {
        return false;
    }

    // Specific bytecode bytes from receivers zapwallet master.
    let mut receiver_bytecode = receiver_wallet_bytecode;

    // Calculate the expected nonce input value:
    let exp_nonce_inp_val = NONCE_MAX - tx_nonce;

    // Calculate max cost signed by owner:
    let max_cost_bn = asm(r1: (0, 0, 0, (gas_limit * max_fee_per_gas))) { r1: u256 };

    // Collect inputs and outputs:
    let in_count: u64 = input_count().as_u64();
    let out_count: u64 = output_count();

    let mut tx_inputs : Vec<InpOut> = Vec::new();
    let mut tx_outputs : Vec<InpOut> = Vec::new();
    let mut tx_change: Vec<InpOut> = Vec::new();

    let mut i = 0;
    while i < in_count {
        // collect all the input coins.
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
        // collect all the output coins.
        if verify_output_coin(j) {
            let outp = InpOut::new(
                output_coin_asset_id(j).unwrap(),
                Some(output_amount(j).unwrap()),
                Some(output_asset_to(j).unwrap()),
            );
            tx_outputs.push(outp);
        }
        // collect all the change outputs assetid's and receivers.
        match verify_output_change(j) {
            Some(is_change) => {
                if is_change {
                    // add change details: assetid, to,
                    tx_change.push(
                        InpOut::new(
                            output_asset_id(j).unwrap().into(),
                            None,
                            Some(output_asset_to(j).unwrap()),
                        )
                    );
                }
            },
            _ => {},
        }
        j += 1;
    }

    // Process the inputs:
    let ip_result = match process_input_assets(
        tx_inputs,
        FUEL_BASE_ASSET,
        value_wei,
        max_cost_bn,
        NONCE_KEY00_ASSETID,
        exp_nonce_inp_val,
        MODULE_KEY02_ASSETID,
    ) {
        Ok(result) => { result },
        Err(error_code) => {
            // input processing failed with error code.
            return false;
        },
    };

    // Process the outputs while consuming input_processing_result:
    let final_result = match process_output_assets(
        tx_outputs,
        tx_change,
        ip_result,
        NONCE_KEY00_ASSETID,
        (exp_nonce_inp_val - 1),
        tx_to,
        receiver_bytecode,
    ) {
        Ok(result) => { result.outputs_ok },
        Err(error_code) => {
            // output processing failed with error code.
            false
        },
    };

    final_result
}

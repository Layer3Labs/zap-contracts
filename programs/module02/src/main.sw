predicate;

use std::bytes::Bytes;
use zap_utils::{
    blob_utils::*,
    decode_1559::{DecodeType02RLPResult, decode_signed_typedtx_1559},
};
use io_utils::{
    evm_base_asset::*,
    io::{InpOut, collect_inputs_outputs_change},
};
use zapwallet_consts::wallet_consts::*;


configurable {
    /// The address of the ZapWallet master owner.
    OWNER_ADDRESS: b256 = b256::zero(),
    /// The nonce native assetid ascoiated with the owners ZapWallet.
    NONCE_ASSETID: b256 = b256::zero(),
    /// This modules assetid as a b256.
    MODULE_KEY02_ASSETID: b256 = b256::zero(),
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
    /// Module Blob ID's as b256 values.
    M00_BLOB_ID: b256 = b256::zero(), M01_BLOB_ID: b256 = b256::zero(),
    M02_BLOB_ID: b256 = b256::zero(), M03_BLOB_ID: b256 = b256::zero(),
    M04_BLOB_ID: b256 = b256::zero(), M05_BLOB_ID: b256 = b256::zero(),
    M06_BLOB_ID: b256 = b256::zero(), M07_BLOB_ID: b256 = b256::zero(),
    M08_BLOB_ID: b256 = b256::zero(),
    /// Master Blob ID as a b256.
    MASTER_BLOB_ID: b256 = b256::zero(),
    /// V1 Zap Manager contract id as a b256
    V1_MANAGER_CID: b256 = b256::zero(),
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
/// * `precomputed_modules` - Optional pre-calculated module asset IDs and addresses for the receiver's
///   ZapWallet. When provided, skips expensive module calculations for faster verification.
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
/// - This program can only be used to transfer the BASE_ASSET on Fuel.
///
fn main(
    signed_evm_tx: Bytes,
    precomputed_modules: Option<MasterConfigs>,
) -> bool {

    // Decode signed_evm_tx rlp into its constituent fields.
    let (
        _tx_type_identifier,
        tx_chain_id,
        tx_nonce,
        tx_max_fee_per_gas,
        tx_gas_limit,
        tx_value_wei,
        tx_to,
        _tx_asset_id,
        _tx_digest,
        _tx_txlengeth,
        _tx_data_start,
        _tx_data_end,
        _tx_signature,
        tx_from
    ) = match decode_signed_typedtx_1559(signed_evm_tx) {
        DecodeType02RLPResult::Success(result) => { result },
        DecodeType02RLPResult::Fail(_error_code) => {
            // rlp decoding failed with error code.
            return false;
        },
    };

    // Ensure evm tx was signed by the owner & has the correct chain_id.
    if !(tx_chain_id == FUEL_CHAINID && tx_from == OWNER_ADDRESS) {
        return false;
    }

    let loader_cfgs = [
        LoaderConfig::new(M00_BLOB_ID, M00_SEC_LEN),
        LoaderConfig::new(M01_BLOB_ID, M01_SEC_LEN),
        LoaderConfig::new(M02_BLOB_ID, M02_SEC_LEN),
        LoaderConfig::new(M03_BLOB_ID, M03_SEC_LEN),
        LoaderConfig::new(M04_BLOB_ID, M04_SEC_LEN),
        LoaderConfig::new(M05_BLOB_ID, M05_SEC_LEN),
        LoaderConfig::new(M06_BLOB_ID, M06_SEC_LEN),
        LoaderConfig::new(M07_BLOB_ID, M07_SEC_LEN),
        LoaderConfig::new(M08_BLOB_ID, M08_SEC_LEN),
        LoaderConfig::new(MASTER_BLOB_ID, MASTER_SEC_LEN),
    ];

    // Create receiver context
    let receiver_zapwallet_ctx = WalletContext::new(tx_to, V1_MANAGER_CID, loader_cfgs);

    // Calculate the expected nonce input value.
    let exp_nonce_inp_val = NONCE_MAX - tx_nonce;

    // Calculate max cost signed by owner.
    let max_cost_bn = asm(r1: (0, 0, 0, (tx_gas_limit * tx_max_fee_per_gas))) { r1: u256 };

    // Collect transaction inputs, outputs and change.
    let (tx_inputs, tx_outputs, tx_change) = collect_inputs_outputs_change();

    // Process the inputs.
    let ip_result = match process_input_assets(
        tx_inputs,
        tx_value_wei,
        max_cost_bn,
        NONCE_ASSETID,
        exp_nonce_inp_val,
        MODULE_KEY02_ASSETID,
    ) {
        Ok(result) => { result },
        Err(_error_code) => {
            // Input processing failed with error code, return fail.
            return false;
        },
    };

    // Process the outputs while consuming input_processing_result.
    let final_result = match process_output_assets(
        tx_outputs,
        tx_change,
        ip_result,
        NONCE_ASSETID,
        (exp_nonce_inp_val - 1),
        receiver_zapwallet_ctx,
        precomputed_modules,
    ) {
        Ok(result) => { result.outputs_ok },
        Err(_error_code) => {
            // Output processing failed with error code, return fail.
            false
        },
    };

    final_result
}

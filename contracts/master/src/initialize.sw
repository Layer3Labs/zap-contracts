library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    tx::{
        tx_id,
        tx_witness_data,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::{
        input_coin_owner,
        input_predicate_length,
        input_predicate,
        input_type,
        input_count,
        Input,
    },
    outputs::{
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
        output_count,
        Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use zapwallet_consts::{
    wallet_consts::{
        DUMMY_1_OWNER_EVM_ADDR,
        VERSION, NUM_MODULES, FUEL_BASE_ASSET,
    },
};
use ptools::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        tx_tip,
        verify_input_coin,
        verify_input_contract,
        verify_output_change,
        input_txn_hash,
    },
    personal_sign::personal_sign_hash,
    initialize_tools::{WalletOp, Initialization, EIP712Domain, Eip712},
    // module_check::*,
};
use helpers::general_helpers::bytes_read_b256;


/// Validation logic for the master predicate funding the initialization tx.
///
pub fn verify_init_struct(in_count: u64, out_count: u64, op: WalletOp, owner_pubkey: b256) -> bool {

    // check there is only two inputs, one for contract, and one for gas
    // check address of contract call --> cant do.
    // check there exists an output change of base asset and no other
    // base asset outputs.
    let (inpok, utxoid, change_to) = check_inputs(in_count);
    let chgok = check_change(out_count, change_to);
    if inpok && chgok {

        let mut ptr: u64 = 0;
        let (cs_lhs, ptr) = bytes_read_b256(op.compsig, ptr, 32);
        let (cs_rhs, _ptr) = bytes_read_b256(op.compsig, ptr, 32);
        let compactsig = B512::from((cs_lhs, cs_rhs));

        let payload = (
            EIP712Domain::new(),
            Initialization::new(
                String::from_ascii_str("ZapWalletInitialize"),
                op.evm_addr,
                utxoid,
            )
        );
        let encoded_hash = match payload.encode_eip712() {
            Some(hash) => hash,
            None => { return false; },
        };
        let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();

        return (recovered_signer == owner_pubkey);
    } else {
        return false;
    }
}

/// Verifies transaction inputs and returns relevant information.
/// Requirements:
/// 1. Exactly two inputs
/// 2. One Coin input with FUEL_BASE_ASSET
/// 3. One Contract input
///
/// # Arguments
/// * `in_count`: Number of inputs in the transaction
///
/// # Returns
/// * `(bool, b256, b256)`: (valid inputs, coin input UTXO ID, coin owner)
pub fn check_inputs(in_count: u64) -> (bool, b256, b256) {
    // Early return if not exactly 2 inputs
    if in_count != 2 {
        return (false, b256::zero(), b256::zero());
    }

    let mut coin_found = false;
    let mut contract_found = false;
    let mut utxo_id = b256::zero();
    let mut owner = b256::zero();

    let mut i = 0;
    while i < 2 {
        // Check for coin input
        if verify_input_coin(i) {
            // Return false if we already found a coin input or asset isn't FUEL_BASE_ASSET
            if coin_found || input_coin_asset_id(i) != FUEL_BASE_ASSET {
                return (false, b256::zero(), b256::zero());
            }
            coin_found = true;
            utxo_id = input_txn_hash(i);
            owner = input_coin_owner(i).unwrap().into();
        }
        // Check for contract input
        else if verify_input_contract(i) {
            // Return false if we already found a contract input
            if contract_found {
                return (false, b256::zero(), b256::zero());
            }
            contract_found = true;
        }
        i += 1;
    }

    // Return true only if we found exactly one coin and one contract
    (coin_found && contract_found, utxo_id, owner)
}

/// Checks if the transaction has valid change output configuration
/// Returns true only if:
/// 1. Exactly one change output exists
/// 2. Change asset is FUEL_BASE_ASSET
/// 3. Change recipient matches change_to address
pub fn check_change(out_count: u64, change_to: b256) -> bool {
    let mut found_valid_change = false;

    // Early return if no outputs
    if out_count == 0 {
        return false;
    }

    let mut i = 0;
    while i < out_count {
        // Check if this output is marked as change
        if let Some(true) = verify_output_change(i) {
            // If we already found a valid change output, this is a second one - fail
            if found_valid_change {
                return false;
            }

            // Get asset ID and recipient for this change output
            let asset_id: b256 = match output_asset_id(i) {
                Some(id) => id.into(),
                None => return false,
            };

            let recipient: b256 = match output_asset_to(i) {
                Some(addr) => addr.into(),
                None => return false,
            };

            // Check if this change output meets all criteria
            if asset_id == FUEL_BASE_ASSET && recipient == change_to {
                found_valid_change = true;
            } else {
                return false;
            }
        }
        i += 1;
    }

    found_valid_change
}
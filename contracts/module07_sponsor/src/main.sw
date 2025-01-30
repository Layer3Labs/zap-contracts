predicate;

mod constants;

use std::{
    b512::*,
    bytes::Bytes,
    string::String,
    hash::*,
    bytes_conversions::u64::*,
    primitive_conversions::{u16::*, u32::*, u64::*},
    tx::{
        tx_id,
        tx_witness_data,
        tx_witnesses_count, tx_witness_data_length,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::{
        input_coin_owner,
        input_predicate_length,
        input_count,
        input_predicate,
        input_asset_id,
        input_amount,
        Input,
    },
    outputs::{
        output_count,
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
        Output,
    },
};

use ptools::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_input_coin,
        output_coin_asset_id,
        // output_coin_amount,
        // output_coin_to,
        // tx_gas_limit,
        // tx_tip,
        verify_output_change,
        verify_output_coin,
        input_txn_hash,
    },
};
use module07_utils::{
    gas_sponsor_tools_v3::{
        SponsorOp, GasSponsor, get_domain_separator,
    },
    gas_sponsor_io_utils::*,
};
use standards::src16::SRC16Payload;
use ::constants::VERSION;
use zapwallet_consts::wallet_consts::{
    FUEL_BASE_ASSET,
};


/// Constant sha256() of the gas sponsor commands as UTF-8 encoded bytes.
///
/// # Additional Information
///
/// sha256("sponsor")
/// sha256("gasspass")
/// sha256("cancel")
///
const COMMAND_SPONSOR_HASH: b256 = 0x13d853006f71ed7b6b092b7ec45dbdddcba22fbec5d04e0fb2b5fdb5b2704ce7;
const COMMAND_GASPASS_HASH: b256 = 0x560f523e31e13dd71e8cc973a7d4de271dbb87d084b9fcad9c68dd7e0b384520;
const COMMAND_CANCEL_HASH: b256 = 0x2374d91794b79f4fb4ec9587d2cf00aecc4f9953fab3ed1dd12ab147a0b721f9;


configurable {
    /// The public key of the ZapWallet Master Owner, that
    /// must sign all gas sponsorship operations
    OWNER_PUBKEY: b256 = b256::zero(),
}


/// ZapWallet Module07 "Gas Sponsor".
///
/// This module validates if a transaction follows the sponsor's signed intent for gas UTXO usage.
/// The sponsor is considered the ZapWallet owner and the gas UTXO is of AssetId Base Asset.
///
/// # Additional Information
///
/// This module supports three types of gas sponsorship mechanisms:
/// - "sponsor": Exchange gas for another asset with tolerance bounds
/// - "gaspass": Allow gas usage without asset exchange
/// - "cancel": Simple gas UTXO movement, used to remove a utxo.
///
/// # Arguments
///
/// * `op`: [SponsorOp] - Operation details including witness data and sponsorship parameters
///
/// # Returns
///
/// * [bool] - True if the transaction matches the signed sponsor intent, false otherwise
///
fn main(op: SponsorOp) -> bool {

    // Get the gas sponsor witness attached to the tx
    let compactsig: B512 = tx_witness_data(op.witnss_idx).unwrap();

    // Collect inptus and outputs:
    let in_count: u64 = input_count().as_u64();
    let out_count: u64 = output_count().as_u64();

    let mut tx_inputs : Vec<InpOut> = Vec::new();
    let mut tx_outputs : Vec<InpOut> = Vec::new();
    let mut tx_change: Vec<InpOut> = Vec::new();

    // Collect Coin Inputs:
    let mut i = 0;
    while i < in_count {
        // collect all the input coins
        if verify_input_coin(i) {
            let inp = InpOut::new(
                input_coin_asset_id(i),
                Some(input_coin_amount(i)),
                Some(input_txn_hash(i)),
                // None,
                input_coin_owner(i)
            );
            tx_inputs.push(inp);
        }
        i += 1;
    }
    // Collect Coin and Change Outputs:
    let mut j = 0;
    while j < out_count {
        // collect all the output coins
        if verify_output_coin(j) {

            let outp = InpOut::new(
                output_coin_asset_id(j).unwrap(),
                Some(output_amount(j).unwrap()),
                None,
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

    // Find gas utxo:
    let (gas_found, gas_owner_addr, gas_utxo) = get_gas_utxo(tx_inputs, FUEL_BASE_ASSET);
    if !gas_found {
        // revert(7021u64);
        return false;
    }

    // Check command and process as required:
    let rebuilt_gassponsor = match sha256(op.sponsor_details.command) {
        COMMAND_SPONSOR_HASH => {   // run command: "sponsor"
            // Process "sponsor" outputs:
            let rebuilt_sponsor = match process_output_assets_command_sponsor(
                tx_outputs,
                tx_change,
                op.sponsor_details.expectedoutputasset,     // other_asset id
                op.sponsor_details.expectedoutputamount,    // other_asset amount
                op.sponsor_details.tolerance,
                gas_owner_addr.into(),                      // gas return addr
                op.sponsor_details.expectedgasoutputamount, // gas amount to return
                gas_utxo,
            ) {
                Ok(gassponsor) => gassponsor,
                Err(_error_code) => {
                    // output processing of command "sponsor" failed with error code.
                    // revert(error_code);
                    return false;
                },
            };

            rebuilt_sponsor
        },
        COMMAND_GASPASS_HASH => {   // run command: "gaspass"
            // Process "gaspass" outputs:
            let rebuilt_gaspass = match process_output_assets_command_gaspass(
                tx_outputs,
                tx_change,
                gas_owner_addr.into(),                      // gas return addr
                op.sponsor_details.expectedgasoutputamount, // gas amount to return
                gas_utxo,
            ) {
                Ok(gassponsor) => gassponsor,
                Err(_error_code) => {
                    // output processing of command "gaspass" failed with error code.
                    // revert(error_code);
                    return false;
                },
            };

            rebuilt_gaspass
        },
        COMMAND_CANCEL_HASH => { // run command: "cancel"
            // Nothing to process, just make sure the builder specifies which utxo.
            // This constraint verifies that only this gas utxo will be moved.
            GasSponsor::new(
                String::from_ascii_str("cancel"),
                b256::zero(),
                gas_utxo,
                u256::zero(),
                b256::zero(),
                u256::zero(),
                u256::zero()
            )
        },
        _ => {
            // revert(73322u64);
            return false;
        }
    };

    // Encode and hash rebuilt GasSponsor struct and recover signer:
    let payload = SRC16Payload {
        domain: get_domain_separator(),
        data_hash: rebuilt_gassponsor.struct_hash(),
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => {return false;},
    };
    let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();
    //TODO - handle error.
    if recovered_signer == OWNER_PUBKEY {
        return true;
    }

    return false;
}
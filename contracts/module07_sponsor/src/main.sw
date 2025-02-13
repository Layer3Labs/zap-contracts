predicate;

use std::{
    b512::*,
    bytes::Bytes,
    string::String,
    hash::*,
    bytes_conversions::u64::*,
    primitive_conversions::{u16::*, u32::*, u64::*},
    tx::tx_witness_data,
    vm::evm::{ ecr::ec_recover_evm_address, evm_address::EvmAddress },
    inputs::{ input_coin_owner, input_count, input_asset_id, input_amount, Input },
    outputs::{ output_count, output_asset_id, output_asset_to, output_amount, Output },
};
use zap_utils::{
    transaction_utls::{ input_coin_amount, input_coin_asset_id, verify_input_coin, output_coin_asset_id, verify_output_change, verify_output_coin, input_txn_hash },
};
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use module07_utils::{
    gas_sponsor_tools::{
        SponsorOp, GasSponsor, get_domain_separator,
    },
    gas_sponsor_io_utils::*,
};
use standards::src16::SRC16Payload;


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
    /// The address of the ZapWallet master owner.
    OWNER_ADDRESS: b256 = b256::zero(),
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
}


/// ZapWallet Module 07.
///
/// Validates gas sponsorship operations by verifying signatures and enforcing exchange rules
/// for gas UTXO usage from the owners ZapWallet.
///
/// # Additional Information
///
/// This predicate implements the core validation logic for ZapWallet gas sponsorship.
/// It supports three operation modes:
/// - "sponsor": Trade gas for another asset with configurable tolerance bounds
/// - "gaspass": Allow free gas usage with guaranteed return amounts
/// - "cancel": Move a gas UTXO without requiring exchange
///
/// # Description
///
/// The main function performs the following alidation flow:
///
/// 1. Extracts EIP-712 signature from witness data
/// 2. Collects and categorizes all transaction inputs/outputs
/// 3. Validates the specific gas UTXO being used
/// 4. Processes outputs according to command type:
///    - sponsor: Verifies asset exchange and return amounts
///    - gaspass: Verifies gas return amount
///    - cancel: Validates gas UTXO movement
/// 5. Rebuilds and verifies EIP-712 signature against owner's pubkey
///
/// # Arguments
///
/// * `op`: [SponsorOp] - The sponsorship operation containing:
///   * witnss_idx: Index to the sponsor's EIP-712 signature
///   * sponsor_details: Gas sponsorship parameters and constraints
///
/// # Returns
///
/// * [bool] - True if transaction matches sponsor intent and:
///   * Gas UTXO is found and valid
///   * All outputs match command requirements
///   * Signature verification succeeds
///   * Change outputs are properly handled
///   Returns false if any validation fails
///
/// # Fails
///
///   * Gas UTXO not found in inputs
///   * Invalid command type specified
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
            let inp = InpOut::new( input_coin_asset_id(i), Some(input_coin_amount(i)), Some(input_txn_hash(i)), input_coin_owner(i) );
            tx_inputs.push(inp);
        }
        i += 1;
    }
    // Collect Coin and Change Outputs:
    let mut j = 0;
    while j < out_count {
        // collect all the output coins
        if verify_output_coin(j) {

            let outp = InpOut::new( output_coin_asset_id(j).unwrap(), Some(output_amount(j).unwrap()), None, Some(output_asset_to(j).unwrap()) );
            tx_outputs.push(outp);
        }
        // collect all the change outputs assetid's and receivers.
        match verify_output_change(j) {
            Some(is_change) => {
                if is_change {
                    tx_change.push( InpOut::new( output_asset_id(j).unwrap().into(), None, None, Some(output_asset_to(j).unwrap()) ) );
                }
            },
            _ => {},
        }
        j += 1;
    }

    // Find gas utxo:
    let (gas_found, gas_owner_addr, gas_utxo) = get_gas_utxo(tx_inputs, FUEL_BASE_ASSET);
    if !gas_found {
        // fail if no gas utxo was found.
        return false;
    }

    // Check command and process as required:
    let rebuilt_gassponsor = match sha256(op.sponsor_details.command) {
        COMMAND_SPONSOR_HASH => {   // run command: "sponsor"
            // Process "sponsor" outputs:
            let rebuilt_sponsor = match process_output_assets_command_sponsor( tx_outputs, tx_change, op.sponsor_details.expectedoutputasset, op.sponsor_details.expectedoutputamount, op.sponsor_details.tolerance, gas_owner_addr.into(), op.sponsor_details.expectedgasoutputamount, gas_utxo,
            ) {
                Ok(gassponsor) => gassponsor,
                Err(_error_code) => {
                    // output processing of command "sponsor" failed with error code.
                    return false;
                },
            };

            rebuilt_sponsor
        },
        COMMAND_GASPASS_HASH => {   // run command: "gaspass"
            // Process "gaspass" outputs:
            let rebuilt_gaspass = match process_output_assets_command_gaspass( tx_outputs, tx_change, gas_owner_addr.into(), op.sponsor_details.expectedgasoutputamount, gas_utxo,
            ) {
                Ok(gassponsor) => gassponsor,
                Err(_error_code) => {
                    // output processing of command "gaspass" failed with error code.
                    return false;
                },
            };

            rebuilt_gaspass
        },
        COMMAND_CANCEL_HASH => { // run command: "cancel"
            // Nothing to process, just make sure the builder specifies which utxo.
            // This constraint verifies that only this gas utxo will be moved.
            GasSponsor::new( String::from_ascii_str("cancel"), b256::zero(), gas_utxo, u256::zero(), b256::zero(), u256::zero(), u256::zero())
        },
        _ => { return false; }
    };

    // Encode and hash rebuilt GasSponsor struct and recover signer:
    let payload = SRC16Payload { domain: get_domain_separator(), data_hash: rebuilt_gassponsor.struct_hash() };
    let encoded_hash = match payload.encode_hash() { Some(hash) => hash, None => {return false;} };
    let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();
    //TODO - handle error.
    if recovered_signer == OWNER_ADDRESS { return true; }

    return false;
}
predicate;

mod initialize;
mod module;
mod module_check;
mod static_debug;

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
        verify_output_coin,
        input_txn_hash,
    },
    initialize_tools::WalletOp,
};
use ::initialize::*;
use ::module::*;
use ::module_check::*;


configurable {
    ASSET_KEY00: b256 = b256::zero(), MODULE00_ADDR: Address = Address::zero(),
    ASSET_KEY01: b256 = b256::zero(), MODULE01_ADDR: Address = Address::zero(),
    ASSET_KEY02: b256 = b256::zero(), MODULE02_ADDR: Address = Address::zero(),
    ASSET_KEY03: b256 = b256::zero(), MODULE03_ADDR: Address = Address::zero(),
    ASSET_KEY04: b256 = b256::zero(), MODULE04_ADDR: Address = Address::zero(),
    ASSET_KEY05: b256 = b256::zero(), MODULE05_ADDR: Address = Address::zero(),
    ASSET_KEY06: b256 = b256::zero(), MODULE06_ADDR: Address = Address::zero(),
    ASSET_KEY07: b256 = b256::zero(), MODULE07_ADDR: Address = Address::zero(),
    ASSET_KEY08: b256 = b256::zero(), MODULE08_ADDR: Address = Address::zero(),
    OWNER_PUBKEY: b256 = b256::zero(),
}



fn main( op: Option<WalletOp> ) -> bool {

    // make version into compiled bytecode
    let version: Bytes = Bytes::from(VERSION);

    // precalculated modules assetid's:
    let walletmodules = setup_walletmodues(
        ASSET_KEY00, MODULE00_ADDR,
        ASSET_KEY01, MODULE01_ADDR,
        ASSET_KEY02, MODULE02_ADDR,
        ASSET_KEY03, MODULE03_ADDR,
        ASSET_KEY04, MODULE04_ADDR,
        ASSET_KEY05, MODULE05_ADDR,
        ASSET_KEY06, MODULE06_ADDR,
        ASSET_KEY07, MODULE07_ADDR,
        ASSET_KEY08, MODULE08_ADDR,
    );

    // Critial bools for validation success:
    let mut all_checks: bool = false;
    let mut module_checks: bool = false;
    let mut init_check: bool = false;

    // Includes upgrade module.
    let mut found_modules: Vec<bool> = Vec::with_capacity(NUM_MODULES);
    let mut k = 0;
    while k < NUM_MODULES {
        // found_modules.set(k, false);
        found_modules.push(false);
        k += 1;
    }

    // Collect Inputs:
    let in_count: u64 = input_count().into();
    let mut i = 0;
    while i < in_count {

        if verify_input_coin(i) {

            let coin_asset_id = input_coin_asset_id(i);     // as a b256
            let coin_owner = input_coin_owner(i).unwrap();  // as an Address

            let potentialmodule = Module {
                assetid: coin_asset_id,
                address: coin_owner,
            };

            if let Some(index) = match_module(potentialmodule, walletmodules) {
                assert(found_modules.get(index).unwrap() != true);
                found_modules.set(index, true);
            }

        }
        i += 1;
    }

    // Collect Outputs:
    let mut tx_outputs: Vec<InpOut> = Vec::new();
    let out_count: u64 = output_count().into();
    let mut j = 0;
    while j < out_count {
        // collect all the output coins
        if verify_output_coin(j) {

            let outp = InpOut {
                assetid: output_coin_asset_id(j).unwrap(),   // from tx_utls, return Option<b256>
                amount: output_amount(j),
                owner_to: output_asset_to(j),
            };
            tx_outputs.push(outp);
        }

        j += 1;
    }

    // Do module checks or init.
    match module_check_controller(found_modules) {
        ModuleCheckResult::Init => {
            // log("do Init");
            if op.is_some() {
                init_check = verify_init_struct(in_count, out_count, op.unwrap(), OWNER_PUBKEY);
                // init_check = false;   // DEBUG
                // init_check = true;   // DEBUG
            }
        },
        ModuleCheckResult::Module(pos) => {

            // Ensure that there is a suitable output that returns
            // the Module asset to the Module address:
            let modulex = match pos {
                1 => walletmodules.module01,
                2 => walletmodules.module02,
                3 => walletmodules.module03,
                4 => walletmodules.module04,
                5 => walletmodules.module05,
                6 => walletmodules.module06,
                7 => walletmodules.module07,
                8 => walletmodules.module08,
                _ => Module::new(),
            };
            module_checks = check_output_module(tx_outputs, modulex);

            //NOTE - See Note 0.
            // module_checks = true;    // DEBUG
        },
        ModuleCheckResult::Upgrade => {

            let module_upgrade = walletmodules.module00;
            // let output_module_check = check_output_module(tx_outputs, module_upgrade);
            //TODO - what checks?
            // check module00 asset output to ZapManager contract

            module_checks = true;
        },
        ModuleCheckResult::ShouldRevert => { return false; },
        _ => { return false; },
    }

    //----------------------------------------------------------------------------------------------------------------
    /*
    //NOTE - Developer Notes

    Note 0:
        If the found module is a module that makes use of the nonce asset, then do what? NOTING
        Why:
        because the module itself handles the nonce accounting.

    Note 1:
        In a transaction including only the nonce token as an input (from the master), results in a PredicateVerificationFailed(Panic(PredicateReturnedNonOne))
        Is this correct behavious? YES.
        why:
        becuase the master predicate has not found either an Init WalletOp or an input asset that matches a module.

    */
    //----------------------------------------------------------------------------------------------------------------


    all_checks = (module_checks || init_check) && !(module_checks && init_check);
    return all_checks;

    //NOTE - DEBUG
    // return true;    // DEBUG

}


predicate;

use std::{
    // b512::B512,
    // bytes::Bytes,
    inputs::{
        input_coin_owner,
        input_count,
        Input,
    },
    outputs::{
        output_asset_to,
        output_amount,
        output_count,
        Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use zapwallet_consts::wallet_consts::{NUM_MODULES, FUEL_BASE_ASSET};
use zap_utils::{
    transaction_utls::{
        input_coin_asset_id,
        output_coin_asset_id,
        verify_input_coin,
        verify_output_coin,
    },
};
use master_utils::initialize::*;
use master_utils::module::*;
use master_utils::module_check::*;


configurable {
    /// Precalculated module asset ID's and module addresses for this ZapWallet.
    ASSET_KEY00: b256 = b256::zero(), MODULE00_ADDR: Address = Address::zero(),
    ASSET_KEY01: b256 = b256::zero(), MODULE01_ADDR: Address = Address::zero(),
    ASSET_KEY02: b256 = b256::zero(), MODULE02_ADDR: Address = Address::zero(),
    ASSET_KEY03: b256 = b256::zero(), MODULE03_ADDR: Address = Address::zero(),
    ASSET_KEY04: b256 = b256::zero(), MODULE04_ADDR: Address = Address::zero(),
    ASSET_KEY05: b256 = b256::zero(), MODULE05_ADDR: Address = Address::zero(),
    ASSET_KEY06: b256 = b256::zero(), MODULE06_ADDR: Address = Address::zero(),
    ASSET_KEY07: b256 = b256::zero(), MODULE07_ADDR: Address = Address::zero(),
    ASSET_KEY08: b256 = b256::zero(), MODULE08_ADDR: Address = Address::zero(),
    /// The address of the owner (example value for testing).
    OWNER_ADDRESS: b256 = 0xff00ff01ff02ff03ff04ff05ff06ff07ff08ff09ff0aff0bff0cff0dff0eff0f,
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
}


/// ZapWallet Master.
///
/// The "master" is the asset holding predicate for the ZapWallet which validates all wallet
/// operations.
///
/// # Additional Information
///
/// The master predicate serves as the central validation point for all ZapWallet operations.
/// It handles three primary transaction types:
/// - Wallet initialization
/// - Module operations
/// - Wallet upgrades
///
/// The master predicate ensures that module assets are properly handled and maintains the
/// wallet's operational integrity.
///
/// # Arguments
///
/// * `op`: [Option<WalletOp>] - Optional wallet operation data, required for initialization
///
/// # Returns
///
/// * [bool] - True if the transaction is valid, false otherwise
///
/// # Fails
///
/// * When a module is found multiple times in inputs
/// * When transaction validation fails
///
fn main( op: Option<WalletOp> ) -> bool {

    // Setup wallet module from precalculated modules details.
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

    // Critial bools for validation success.
    let mut all_checks: bool = false;
    let mut module_checks: bool = false;
    let mut init_check: bool = false;

    // Sets up a clean vector for module finding.
    let mut found_modules: Vec<bool> = Vec::with_capacity(NUM_MODULES);
    let mut k = 0;
    while k < NUM_MODULES {
        found_modules.push(false);
        k += 1;
    }

    // Collect Inputs:
    let in_count: u64 = input_count().into();
    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let coin_asset_id = input_coin_asset_id(i);
            let coin_owner = input_coin_owner(i).unwrap();
            // Copy the assetid and owner and attempt to match to a
            // known module
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
                assetid: output_coin_asset_id(j).unwrap(),
                amount: output_amount(j),
                owner_to: output_asset_to(j),
            };
            tx_outputs.push(outp);
        }
        j += 1;
    }

    // Checks if we should process an initialization fo other module.
    match module_check_controller(found_modules) {
        ModuleCheckResult::Init => {
            // Validate initialization
            if op.is_some() {
                init_check = verify_init_struct(in_count, out_count, op.unwrap(), OWNER_ADDRESS);
            }
        },
        ModuleCheckResult::Module(pos) => {
            // Determine which module was found and ensure that
            // there is a suitable output that returns the module
            // asset to the module address:
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
        },
        ModuleCheckResult::Upgrade => {
            // The upgrade module was found, we dont need to return its asset
            module_checks = true;
        },
        ModuleCheckResult::ShouldRevert => { return false; },
    }

    // Ensure that exactly one of `module_checks` or `init_check` is true.
    all_checks = (module_checks || init_check) && !(module_checks && init_check);

    return all_checks;
}


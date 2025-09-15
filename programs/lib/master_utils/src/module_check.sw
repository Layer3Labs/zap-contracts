library;

use std::hash::*;
use zapwallet_consts::wallet_consts::NUM_MODULES;
use ::types::*;


/// Constant sha256() of the WalletOp commands as UTF-8 encoded bytes.
///
/// # Additional Information
///
/// sha256("ZapWalletInitialize")
/// sha256("ZapWalletUpgrade")
/// sha256("ZapWalletContractCall")
/// sha256("ZapWalletEIP191PersonalSignTXID")
///
pub const COMMAND_INIT_HASH: b256 = 0xb9a6c70c35bf95bf4fda23f711739a44f7f3d98dca100e07255a2ba0976c0c28;
pub const COMMAND_UPGRADE_HASH: b256 = 0xff8bb25aea6726a4178bb8c4e8d09b564036fc9bd9a53872a2bf2b5fcca36106;
pub const COMMAND_CONTRACT_CALL_HASH: b256 = 0x757312115e025ba19d2f50a26f92700e097d94e9c18da886e69c24c5742b256a;
pub const COMMAND_EIP191_PERSONAL_SIGN_TXID_HASH: b256 = 0x228d75424bdec6e5f50dd0e7294199c7288f913a4fd5c841fc671cf3a4f9cba7;


// Updated enum - keeping all module positions 0-8
pub enum ModuleCheckResult {
    /// WalletOp initialization operation
    WalletInit: (),
    /// WalletOp upgrade operation
    WalletUpgrade: (),
    /// WalletOp contract call operation
    WalletContractCall: (),
    /// WalletOp witness transaction ID operation
    WalletWitnessTxID: (),
    /// Contains the position of the single active module (0-8)
    Module: u64,
    /// Indicates an invalid module combination or unknown command
    ShouldRevert: (),
}

/// Controls the logic flow for validating module presence and operation type in transactions.
///
/// # Arguments
///
/// * `values`: [Vec<bool>] - Boolean vector indicating presence of each module (0-8)
/// * `op`: [Option<WalletOp>] - Optional wallet operation containing command to execute
///
/// # Returns
///
/// * [ModuleCheckResult] - The determined transaction type and validity
///
/// # Additional Information
///
/// This function determines whether a transaction is:
/// - A wallet initialization (no modules, init command)
/// - A wallet upgrade (no modules, upgrade command)
/// - A contract call (no modules, contract call command)
/// - A regular module operation (exactly one module from 0-8)
/// - Invalid (any other combination or unknown command)
///
pub fn module_check_controller(values: Vec<bool>, op: Option<WalletOp>) -> ModuleCheckResult {

    // Check if no modules are present
    if any_check(values) {
        // No modules found - this is a wallet operation
        // Need to check the command to determine which type
        match op {
            Some(wallet_op) => {
                // Check command hash to determine operation type
                match wallet_op.command {
                    COMMAND_INIT_HASH => {
                        // "ZapWalletInitialize"
                        return ModuleCheckResult::WalletInit;
                    },
                    COMMAND_UPGRADE_HASH => {
                        // "ZapWalletUpgrade"
                        return ModuleCheckResult::WalletUpgrade;
                    },
                    COMMAND_CONTRACT_CALL_HASH => {
                        // "ZapWalletContractCall"
                        return ModuleCheckResult::WalletContractCall;
                    },
                    COMMAND_EIP191_PERSONAL_SIGN_TXID_HASH => {
                        // "ZapWalletEIP191PersonalSignTXID"
                        return ModuleCheckResult::WalletWitnessTxID;
                    },
                    _ => {
                        // Unknown command
                        return ModuleCheckResult::ShouldRevert;
                    }
                }
            },
            None => {
                // No modules and no WalletOp provided - invalid
                return ModuleCheckResult::ShouldRevert;
            }
        }
    }

    // Check if exactly one module is present
    if xor_check(values) {
        let position = check_position(values).unwrap();
        return ModuleCheckResult::Module(position);
    }

    // Invalid combination of modules
    ModuleCheckResult::ShouldRevert
}

/// Checks if no modules are present in the transaction.
///
/// # Arguments
///
/// * `values`: [Vec<bool>] - Boolean vector indicating presence of each module
///
/// # Returns
///
/// * [bool] - True if no modules are present, false if any are found
///
pub fn any_check(values: Vec<bool>) -> bool {
    for value in values.iter() {
        if value {
            return false;
        }
    }

    true
}

/// Verifies if exactly one module is present.
///
/// # Arguments
///
/// * `values`: [Vec<bool>] - Boolean vector indicating presence of each module
///
/// # Returns
///
/// * [bool] - True if exactly one module is present, false otherwise
///
pub fn xor_check(values: Vec<bool>) -> bool {
    let mut true_count: u64 = 0;
    for value in values.iter() {
        if value {
            true_count += 1;
        }
    }

    true_count == 1
}

/// Finds the position of the single active module.
///
/// # Arguments
///
/// * `values`: [Vec<bool>] - Boolean vector indicating presence of each module
///
/// # Returns
///
/// * [Option<u64>] - The index of the single true value, or None if not exactly one true value
///
pub fn check_position(values: Vec<bool>) -> Option<u64> {
    let mut true_count: u64 = 0;
    let mut true_position: u64 = 0;
    let mut current_position: u64 = 0;

    // Iterate through the vector to find the position of the true value
    for value in values.iter() {
        if value {
            true_count += 1;
            true_position = current_position;
        }
        current_position += 1;
    }

    // Return the position only if exactly one true value was found
    if true_count == 1 {
        Some(true_position)
    } else {
        None
    }
}


library;

use zapwallet_consts::wallet_consts::NUM_MODULES;


/// This enum determines the type of transaction being processed and its validity
/// based on which modules are present in the inputs.
pub enum ModuleCheckResult {
    /// Indicates no modules are present, transaction should proceed to initialization
    Init: (),
    /// Contains the position of the single active module
    Module: u64,
    /// Indicates an upgrade operation with only module00 present
    Upgrade: (),
    /// Indicates an invalid module combination
    ShouldRevert: (),
}

/// Controls the logic flow for validating module presence in transactions.
///
/// # Arguments
///
/// * `values`: [Vec<bool>] - Boolean vector indicating presence of each module
///
/// # Returns
///
/// * [ModuleCheckResult] - The determined transaction type and validity
///
/// # Additional Information
///
/// This function determines whether a transaction is:
/// - An initialization (no modules)
/// - A regular module operation (exactly one module)
/// - An upgrade operation (only module00)
/// - Invalid (any other combination)
///
pub fn module_check_controller(values: Vec<bool>) -> ModuleCheckResult {

    if any_check(values) { return ModuleCheckResult::Init; }

    if check_upgrade_case(values) { return ModuleCheckResult::Upgrade; }

    if xor_check(values) {
        let position = check_position(values).unwrap();
        return ModuleCheckResult::Module(position);
    }

   ModuleCheckResult::ShouldRevert
}

/// Verifies if the transaction is a valid upgrade case.
///
/// # Arguments
///
/// * `values`: [Vec<bool>] - Boolean vector indicating presence of each module
///
/// # Returns
///
/// * [bool] - True if only module00 is present, false otherwise
///
pub fn check_upgrade_case(values: Vec<bool>) -> bool {
    // First check if module00 is present
    if !values.get(0).unwrap() {
        return false;
    }
    // Then ensure NO other modules are present
    let mut i = 1;
    while i < NUM_MODULES {
        if values.get(i).unwrap() { // If any other module is true, fail
            return false;
        }
        i += 1;
    }

    true
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


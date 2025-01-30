library;

use zapwallet_consts::wallet_consts::NUM_MODULES;


pub enum ModuleCheckResult {
    Init: (),           // All values were false, should go to init
    Module: u64,        // Exactly one true was found, contains its position
    Upgrade: (),        // All modules true (upgrade case)
    ShouldRevert: (),   // Invalid state
}

/// Logic flow controller for module checks
/// Returns ModuleCheckResult:
/// - Init if all modules are false
/// - Module(position) if exactly one true is found
/// Reverts in all other cases
pub fn module_check_controller(values: Vec<bool>) -> ModuleCheckResult {

    // Clone vector as we need it multiple times
    //FIXME - fix this sloppy
    let values_clone1 = values;
    let values_clone2 = values;
    let values_clone3 = values;

    if any_check(values_clone1) {
        return ModuleCheckResult::Init;
    }

    if check_upgrade_case(values_clone2) {
        return ModuleCheckResult::Upgrade;
    }

    if xor_check(values_clone3) {
        let position = check_position(values).unwrap();
        return ModuleCheckResult::Module(position);
    }

   ModuleCheckResult::ShouldRevert
}


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

/// Takes a vector of booleans and returns false if any value is true (NOR)
/// Return true only if no true values were found
pub fn any_check(values: Vec<bool>) -> bool {
    for value in values.iter() {
        if value {
            return false;  // Return false immediately if any true is found
        }
    }

    true
}


/// Takes a vector of booleans and returns true if exactly one value is true
/// Return true if exactly one value was true
pub fn xor_check(values: Vec<bool>) -> bool {
    // Keep track of how many true values we've seen
    let mut true_count: u64 = 0;
    // Iterate through the vector and count true values
    for value in values.iter() {
        if value {
            true_count += 1;
        }
    }

    true_count == 1
}

/// Takes a vector of booleans and returns the index of the true value
/// Returns None if there isn't exactly one true value
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


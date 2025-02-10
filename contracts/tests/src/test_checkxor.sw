library;

use ptools::module_check::*;


// 01. TXTYPE1 MODULE:          00
// 02. TXTYPE2 MODULE:          01
// 03. ERC20 MODULE:            02
// 04. EIP-712 MODULE:          03
// 05. TXID WITNESS MODULE:     04
// FF. UPDRADE CRITERIA:        05




// forc test test_anymodules_check --logs
#[test]
fn test_anymodules_check() {
    // Test with all false - should return true
    let mut vec1 = Vec::new();
    vec1.push(false);
    vec1.push(false);
    vec1.push(false);
    vec1.push(false);
    vec1.push(false);
    assert(any_check(vec1) == true);

    // Test with one true - should return false
    let mut vec2 = Vec::new();
    vec2.push(false);
    vec2.push(true);
    vec2.push(false);
    vec2.push(false);
    vec2.push(false);
    assert(any_check(vec2) == false);

    // Test with multiple true - should return false
    let mut vec3 = Vec::new();
    vec3.push(true);
    vec3.push(true);
    vec3.push(false);
    vec3.push(false);
    vec3.push(false);
    assert(any_check(vec3) == false);

    // Test with all true - should return false
    let mut vec4 = Vec::new();
    vec4.push(true);
    vec4.push(true);
    vec4.push(true);
    vec4.push(true);
    vec4.push(true);
    assert(any_check(vec4) == false);

}

// forc test test_xor_check --logs
#[test]
fn test_xor_check() {
    // Test case 1: no modules
    let mut checks1: Vec<bool> = Vec::with_capacity(5);
    checks1.push(false);
    checks1.push(false);
    checks1.push(false);
    checks1.push(false);
    checks1.push(false);
    let result1 = xor_check(checks1);
    log(result1);
    assert(result1 == false);  // XOR should be false
    // no modules

    // Test case 2: One module only
    let mut checks2: Vec<bool> = Vec::with_capacity(5);
    checks2.push(false);
    checks2.push(false);
    checks2.push(false);
    checks2.push(true);
    checks2.push(false);
    let result2 = xor_check(checks2);
    assert(result2 == true);  // XOR should be true
    // single module found.

    // Test case 3: Multiple modules
    let mut checks3: Vec<bool> = Vec::with_capacity(5);
    checks3.push(true);
    checks3.push(true);
    checks3.push(false);
    checks3.push(false);
    checks3.push(false);
    let result3 = xor_check(checks3);
    assert(result3 == false);  // XOR should be false
    //

}


// forc test test_xnor_and_pos_check --logs
#[test]
fn test_xnor_and_pos_check() {

    // Test case 2: One module only
    let mut checks2: Vec<bool> = Vec::with_capacity(5);
    checks2.push(false);
    checks2.push(false);
    checks2.push(false);
    checks2.push(true);
    checks2.push(false);

    // Check if exactly one value is true
    let xnor_res = xor_check(checks2);
    log(xnor_res);
    if xnor_res {

        let position = check_position(checks2);
        match position {
            Some(pos) => {
                // Position 0 indicates TXTYPE1 MODULE
                // Position 1 indicates TXTYPE2 MODULE
                // etc...
                log(pos);
            },
            None => {
                // Either no true values or multiple true values found
                log("Invalid number of true values");
            }
        }

    } else {
        revert(548);
    }

}

// forc test test_module_check_controller --logs
#[test]
fn test_module_check_controller() {
    // Test case 1: All false - should return Init
    let mut vec1 = Vec::new();
    vec1.push(false);
    vec1.push(false);
    vec1.push(false);
    match module_check_controller(vec1) {
        ModuleCheckResult::Init => assert(true),
        _ => assert(false), // Wrong variant returned
    }

    // Test case 2: One true - should return Module(position)
    let mut vec2 = Vec::new();
    vec2.push(false);
    vec2.push(true);
    vec2.push(false);
    match module_check_controller(vec2) {
        ModuleCheckResult::Module(pos) => assert(pos == 1),
        _ => assert(false), // Wrong variant returned
    }

    // Test case 3: Multiple true - should revert
    let mut vec3 = Vec::new();
    vec3.push(true);
    vec3.push(true);
    vec3.push(false);
    // This should revert
    match module_check_controller(vec3) {
        ModuleCheckResult::ShouldRevert => assert(true),
        _ => assert(false), // Wrong variant returned
    }



}


// forc test test_ff_module_check_controller --logs
#[test]
fn test_ff_module_check_controller() {

    let mut checks2: Vec<bool> = Vec::with_capacity(5);
    checks2.push(false);
    checks2.push(false);
    checks2.push(false);
    checks2.push(true);
    checks2.push(false);

    match module_check_controller(checks2) {
        ModuleCheckResult::Init => {
            log("do Init");
        },
        ModuleCheckResult::Module(pos) => {
            log("do Module x");
            log(pos);
        },
        ModuleCheckResult::ShouldRevert => {
            log("do Revert");
        },
        _ => (), // Wrong variant returned
    }



}
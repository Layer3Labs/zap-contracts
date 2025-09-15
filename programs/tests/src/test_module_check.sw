library;

use master_utils::{
    types::*,
    module_check::*,
};



// Test module_check_controller with various WalletOp commands
// forc test test_module_check_controller_wallet_ops --logs
#[test]
fn test_module_check_controller_wallet_ops() {
    // Test WalletInit command
    let mut no_modules = Vec::new();
    no_modules.push(false);
    no_modules.push(false);
    no_modules.push(false);

    let init_op = WalletOp {
        command: COMMAND_INIT_HASH,
        override_witness_index: None,
    };

    match module_check_controller(no_modules, Some(init_op)) {
        ModuleCheckResult::WalletInit => assert(true),
        _ => assert(false), // Wrong variant
    }

    // Test WalletUpgrade command
    let mut no_modules2 = Vec::new();
    no_modules2.push(false);
    no_modules2.push(false);
    no_modules2.push(false);

    let upgrade_op = WalletOp {
        command: COMMAND_UPGRADE_HASH,
        override_witness_index: None,
    };

    match module_check_controller(no_modules2, Some(upgrade_op)) {
        ModuleCheckResult::WalletUpgrade => assert(true),
        _ => assert(false), // Wrong variant
    }

    // Test WalletContractCall command
    let mut no_modules3 = Vec::new();
    no_modules3.push(false);
    no_modules3.push(false);
    no_modules3.push(false);

    let contract_call_op = WalletOp {
        command: COMMAND_CONTRACT_CALL_HASH,
        override_witness_index: None,
    };

    match module_check_controller(no_modules3, Some(contract_call_op)) {
        ModuleCheckResult::WalletContractCall => assert(true),
        _ => assert(false), // Wrong variant
    }

    // Test WalletWitnessTxID command
    let mut no_modules4 = Vec::new();
    no_modules4.push(false);
    no_modules4.push(false);
    no_modules4.push(false);

    let witness_op = WalletOp {
        command: COMMAND_EIP191_PERSONAL_SIGN_TXID_HASH,
        override_witness_index: None,
    };

    match module_check_controller(no_modules4, Some(witness_op)) {
        ModuleCheckResult::WalletWitnessTxID => assert(true),
        _ => assert(false), // Wrong variant
    }
}

// Test module operations (single module active)
// forc test test_module_check_controller_single_module --logs
#[test]
fn test_module_check_controller_single_module() {
    // Test module at position 0
    let mut vec_pos0 = Vec::new();
    vec_pos0.push(true);
    vec_pos0.push(false);
    vec_pos0.push(false);
    vec_pos0.push(false);
    vec_pos0.push(false);

    match module_check_controller(vec_pos0, None) {
        ModuleCheckResult::Module(pos) => assert(pos == 0),
        _ => assert(false), // Wrong variant
    }

    // Test module at position 3
    let mut vec_pos3 = Vec::new();
    vec_pos3.push(false);
    vec_pos3.push(false);
    vec_pos3.push(false);
    vec_pos3.push(true);
    vec_pos3.push(false);
    vec_pos3.push(false);

    match module_check_controller(vec_pos3, None) {
        ModuleCheckResult::Module(pos) => assert(pos == 3),
        _ => assert(false), // Wrong variant
    }

    // Test module at position 8 (last position)
    let mut vec_pos8 = Vec::new();
    let mut i = 0;
    while i < 8 {
        vec_pos8.push(false);
        i += 1;
    }
    vec_pos8.push(true);

    match module_check_controller(vec_pos8, None) {
        ModuleCheckResult::Module(pos) => assert(pos == 8),
        _ => assert(false), // Wrong variant
    }
}

// Test invalid cases that should revert
// forc test test_module_check_controller_should_revert --logs
#[test]
fn test_module_check_controller_should_revert() {
    // Test: No modules, no WalletOp
    let mut no_modules = Vec::new();
    no_modules.push(false);
    no_modules.push(false);
    no_modules.push(false);

    match module_check_controller(no_modules, None) {
        ModuleCheckResult::ShouldRevert => assert(true),
        _ => assert(false), // Should have reverted
    }

    // Test: No modules, unknown command
    let mut no_modules2 = Vec::new();
    no_modules2.push(false);
    no_modules2.push(false);
    no_modules2.push(false);

    let unknown_op = WalletOp {
        command: 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,
        override_witness_index: None,
    };

    match module_check_controller(no_modules2, Some(unknown_op)) {
        ModuleCheckResult::ShouldRevert => assert(true),
        _ => assert(false), // Should have reverted
    }

    // Test: Multiple modules active (XOR fails)
    let mut multi_modules = Vec::new();
    multi_modules.push(true);
    multi_modules.push(true);
    multi_modules.push(false);
    multi_modules.push(false);

    match module_check_controller(multi_modules, None) {
        ModuleCheckResult::ShouldRevert => assert(true),
        _ => assert(false), // Should have reverted
    }

    // Test: All modules active
    let mut all_modules = Vec::new();
    let mut j = 0;
    while j < 9 {
        all_modules.push(true);
        j += 1;
    }

    match module_check_controller(all_modules, None) {
        ModuleCheckResult::ShouldRevert => assert(true),
        _ => assert(false), // Should have reverted
    }
}

// Test edge case: WalletOp provided when modules are active
// forc test test_module_check_controller_mixed_edge_cases --logs
#[test]
fn test_module_check_controller_mixed_edge_cases() {
    // Single module active, but WalletOp also provided
    // Should return Module (WalletOp ignored when modules present)
    let mut single_module = Vec::new();
    single_module.push(false);
    single_module.push(true);
    single_module.push(false);

    let init_op = WalletOp {
        command: COMMAND_INIT_HASH,
        override_witness_index: None,
    };

    // WalletOp should be ignored since a module is active
    match module_check_controller(single_module, Some(init_op)) {
        ModuleCheckResult::Module(pos) => assert(pos == 1),
        _ => assert(false), // Should return Module, not WalletInit
    }
}
library;

use std::{
    b512::B512,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    bytes::Bytes,
    math::*,
    vec::Vec,
    option::Option,
    string::String,
    revert::revert,
    bytes_conversions::{b256::*, u256::*, u64::*},
    primitive_conversions::{u16::*, u32::*, u64::*}
};
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use zap_utils::{
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
};
use io_utils::io::*;
use module05_utils::{
    native_transfer_v1::{
        NativeTransfer,
    },
    io_utils::{verify_module_output, check_asset_exists, TransferAssetResult},
};

// Constants for test addresses
const OWNER1: Address = Address::from(0x1111111111111111111111111111111111111111111111111111111111111111);
const OWNER2: Address = Address::from(0x2222222222222222222222222222222222222222222222222222222222222222);
const OWNER3: Address = Address::from(0x3333333333333333333333333333333333333333333333333333333333333333);
const RECEIVER: Address = Address::from(0x2891970ee5132e3523f80b2bde241b75285715359fc4209728812eed35e61fa8);

// Test asset IDs
const OTHER_ASSET_ID: b256 = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

// forc test test_500_check_asset_exists --logs
#[test]
fn test_500_check_asset_exists() {
    use std::vec::Vec;

    // Test Case 1: Asset found with valid owner not in ignore list
    // The function returns the FIRST valid match
    let mut tx_io1: Vec<InpOut> = Vec::new();
    tx_io1.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), Some(OWNER1)));
    tx_io1.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(OWNER2)));
    tx_io1.push(InpOut::new(FUEL_BASE_ASSET, Some(300u64), Some(OWNER3)));

    let mut ignore_list1: Vec<Address> = Vec::new();
    ignore_list1.push(OWNER2); // Only ignore owner2

    let result1 = check_asset_exists(tx_io1, FUEL_BASE_ASSET, ignore_list1);

    match result1 {
        TransferAssetResult::Success((found_owner, found_amount)) => {
            // Log values first to debug
            log(String::from_ascii_str("Test 500 - found_owner:"));
            log(b256_to_hex(found_owner.into()));
            log(String::from_ascii_str("expected owner1:"));
            log(b256_to_hex(OWNER1.into()));

            log(String::from_ascii_str("found_amount:"));
            log(found_amount);
            log(String::from_ascii_str("expected amount:"));
            log(100u64);

            assert(found_owner == OWNER1);  // expecting OWNER1 (first match)
            assert(found_amount == 100u64);
        },
        TransferAssetResult::Fail(error_code) => {
            log(String::from_ascii_str("Test failed with error code:"));
            log(error_code);
            revert(0); // Should not fail
        }
    }
}

// forc test test_501_check_asset_exists --logs
#[test]
fn test_501_check_asset_exists() {
    use std::vec::Vec;

    // Test Case 2: Asset found with specific receiver
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(RECEIVER)));

    let mut ignore_list: Vec<Address> = Vec::new();
    ignore_list.push(OWNER1); // Only ignore owner1

    let result1 = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result1 {
        TransferAssetResult::Success((found_receiver, found_amount)) => {
            assert(found_receiver == RECEIVER);
            assert(found_amount == 200u64);

            log(String::from_ascii_str("Test 501 - found_receiver:"));
            log(b256_to_hex(found_receiver.into()));
            log(String::from_ascii_str("found_amount:"));
            log(found_amount);
        },
        TransferAssetResult::Fail(_) => {
            revert(0); // Should not fail
        }
    }
}

// forc test test_502_asset_no_amount --logs
#[test]
fn test_502_asset_no_amount() {
    use std::vec::Vec;

    // Test Case 3: Error 3170 - Asset with no amount
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, None, Some(OWNER1))); // No amount

    let ignore_list: Vec<Address> = Vec::new();

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success(_) => {
            revert(0); // Should fail
        },
        TransferAssetResult::Fail(error_code) => {
            assert(error_code == 3170u64);
            log(String::from_ascii_str("Test 502 - Expected error 3170:"));
            log(error_code);
        }
    }
}

// forc test test_503_asset_not_found --logs
#[test]
fn test_503_asset_not_found() {
    use std::vec::Vec;

    // Test Case 4: Error 3171 - Asset not found
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), Some(OWNER1)));
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(OWNER2)));

    let ignore_list: Vec<Address> = Vec::new();

    // Search for OTHER_ASSET_ID which doesn't exist
    let result = check_asset_exists(tx_io, OTHER_ASSET_ID, ignore_list);

    match result {
        TransferAssetResult::Success(_) => {
            revert(0); // Should fail
        },
        TransferAssetResult::Fail(error_code) => {
            assert(error_code == 3171u64);
            log(String::from_ascii_str("Test 503 - Expected error 3171:"));
            log(error_code);
        }
    }
}

// forc test test_504_all_owners_ignored --logs
#[test]
fn test_504_all_owners_ignored() {
    use std::vec::Vec;

    // Test Case 5: Error 3171 - All matching assets have ignored owners
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), Some(OWNER1)));
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(OWNER2)));

    let mut ignore_list: Vec<Address> = Vec::new();
    ignore_list.push(OWNER1);
    ignore_list.push(OWNER2); // Ignore all owners

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success(_) => {
            revert(0); // Should fail
        },
        TransferAssetResult::Fail(error_code) => {
            assert(error_code == 3171u64);
            log(String::from_ascii_str("Test 504 - Expected error 3171:"));
            log(error_code);
        }
    }
}

// forc test test_505_asset_no_owner --logs
#[test]
fn test_505_asset_no_owner() {
    use std::vec::Vec;

    // Test Case 6: Error 3173 - Asset with no owner
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), None)); // No owner

    let ignore_list: Vec<Address> = Vec::new();

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success(_) => {
            revert(0); // Should fail
        },
        TransferAssetResult::Fail(error_code) => {
            assert(error_code == 3173u64);
            log(String::from_ascii_str("Test 505 - Expected error 3173:"));
            log(error_code);
        }
    }
}

// forc test test_506_empty_vector --logs
#[test]
fn test_506_empty_vector() {
    use std::vec::Vec;

    // Test Case 7: Empty tx_io vector
    let tx_io: Vec<InpOut> = Vec::new();
    let ignore_list: Vec<Address> = Vec::new();

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success(_) => {
            revert(0); // Should fail
        },
        TransferAssetResult::Fail(error_code) => {
            assert(error_code == 3171u64);
            log(String::from_ascii_str("Test 506 - Expected error 3171:"));
            log(error_code);
        }
    }
}

// forc test test_507_multiple_matching_returns_first --logs
#[test]
fn test_507_multiple_matching_returns_first() {
    use std::vec::Vec;

    // Test Case 8: Multiple matching assets, returns FIRST valid
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), Some(OWNER1))); // Ignored
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(OWNER2))); // Should find this (first valid)
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(300u64), Some(OWNER3))); // Not reached

    let mut ignore_list: Vec<Address> = Vec::new();
    ignore_list.push(OWNER1); // Ignore first owner

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success((found_owner, found_amount)) => {
            assert(found_owner == OWNER2);  // Returns FIRST valid
            assert(found_amount == 200u64);
            log(String::from_ascii_str("Test 507 - found first non-ignored:"));
            log(found_amount);
        },
        TransferAssetResult::Fail(_) => {
            revert(0); // Should not fail
        }
    }
}

// forc test test_508_mixed_asset_ids --logs
#[test]
fn test_508_mixed_asset_ids() {
    use std::vec::Vec;

    // Test Case 9: Different asset IDs mixed
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(OTHER_ASSET_ID, Some(50u64), Some(OWNER1)));
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), Some(OWNER2)));
    tx_io.push(InpOut::new(OTHER_ASSET_ID, Some(150u64), Some(OWNER3)));
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(OWNER1)));

    let ignore_list: Vec<Address> = Vec::new();

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success((found_owner, found_amount)) => {
            assert(found_owner == OWNER2);  // First matching asset in the list
            assert(found_amount == 100u64);
            log(String::from_ascii_str("Test 508 - found correct asset:"));
            log(found_amount);
        },
        TransferAssetResult::Fail(_) => {
            revert(0); // Should not fail
        }
    }
}

// forc test test_509_complex_ignore_scenario --logs
#[test]
fn test_509_complex_ignore_scenario() {
    use std::vec::Vec;

    // Test Case 10: Complex scenario with multiple assets and partial ignore list
    let mut tx_io: Vec<InpOut> = Vec::new();
    tx_io.push(InpOut::new(OTHER_ASSET_ID, Some(50u64), Some(OWNER1)));
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(100u64), Some(OWNER1))); // Ignored
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(200u64), Some(OWNER2))); // Ignored
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(300u64), Some(OWNER3))); // Should find this
    tx_io.push(InpOut::new(FUEL_BASE_ASSET, Some(400u64), Some(RECEIVER)));

    let mut ignore_list: Vec<Address> = Vec::new();
    ignore_list.push(OWNER1);
    ignore_list.push(OWNER2);

    let result = check_asset_exists(tx_io, FUEL_BASE_ASSET, ignore_list);

    match result {
        TransferAssetResult::Success((found_owner, found_amount)) => {
            assert(found_owner == OWNER3);
            assert(found_amount == 300u64);
            log(String::from_ascii_str("Test 509 - found first non-ignored:"));
            log(b256_to_hex(found_owner.into()));
        },
        TransferAssetResult::Fail(_) => {
            revert(0); // Should not fail
        }
    }
}

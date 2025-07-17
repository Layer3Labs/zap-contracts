library;

use std::{
    bytes::Bytes,
    string::String,
    vm::evm::evm_address::EvmAddress,
    result::Result::*,
};

use io_utils::evmtx_io_utils::verify_receiver;
use zap_utils::{
    merkle_utils::{calculate_leaf_hash, calculate_predi_addr_from_root},
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
    blob_utils::*,
};

use zapwallet_consts::wallet_consts::*;


// Blob IDs
const M00_BLOB_ID: b256 = 0x68b8ae305bbb264872c6c0957eee37059c274b0c680a3a4160ef167b1f88f6da;
const M01_BLOB_ID: b256 = 0x57b28d6b9df8bde2fd0cdd22fbcf14b95aee20de62010f83803551fa6e1699f2;
const M02_BLOB_ID: b256 = 0xc1e247bad1f300b84e3d54dea83604031a96c3dac4313233b508bd03b116c32d;
const M03_BLOB_ID: b256 = 0xb67126bcfb377d4ebeb042e33dd481e17bdc7f1d10aeb7b957a94789cda19883;
const M04_BLOB_ID: b256 = 0xb66a7d206c4623f24af1932ec9a7a1312d5f26d198506220f170e2a1baa01c90;
const M05_BLOB_ID: b256 = 0x76b10385edb26a217d13817efb6d81b686577beea7a0be3bf747b2550e3042be;
const M06_BLOB_ID: b256 = 0xf8c2b3282ba4711c93d8a801d2e4e3bdb7996a3d6711a38360e7a4a6392150d7;
const M07_BLOB_ID: b256 = 0x0fc1f076ffb99827792711c75144a65f8113d102f2024f3782d9b7b0d7c2786f;
const M08_BLOB_ID: b256 = 0xf8c2b3282ba4711c93d8a801d2e4e3bdb7996a3d6711a38360e7a4a6392150d7;
const MASTER_BLOB_ID: b256 = 0xaf1a84a4b754c8077db3dc319abcde9099d6f9c9e5d55b4ab59af592445463ac;
// V1 ZapManager CID
const V1_MANAGER_CID: b256 = 0xbe2d6330b95da19fc7c0e779d0c5f159711066b5424b0b6fbd100c757ad693a0;


// forc test test_100_zapwallet_ctx_builder_pattern --logs
#[test()]
fn test_100_zapwallet_ctx_builder_pattern() {
    let owner_pubkey: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

    let loader_cfgs = [
        LoaderConfig::new(M00_BLOB_ID, M00_SEC_LEN),
        LoaderConfig::new(M01_BLOB_ID, M01_SEC_LEN),
        LoaderConfig::new(M02_BLOB_ID, M02_SEC_LEN),
        LoaderConfig::new(M03_BLOB_ID, M03_SEC_LEN),
        LoaderConfig::new(M04_BLOB_ID, M04_SEC_LEN),
        LoaderConfig::new(M05_BLOB_ID, M05_SEC_LEN),
        LoaderConfig::new(M06_BLOB_ID, M06_SEC_LEN),
        LoaderConfig::new(M07_BLOB_ID, M07_SEC_LEN),
        LoaderConfig::new(M08_BLOB_ID, M08_SEC_LEN),
        LoaderConfig::new(MASTER_BLOB_ID, MASTER_SEC_LEN),
    ];

    // Create the context
    let ctx = WalletContext::new(owner_pubkey, V1_MANAGER_CID, loader_cfgs);

    // Calculate all module addresses and asset IDs
    let result = ZapWalletBuilderV1::calculate_all_module_addresses(ctx);

    let (module_asset_ids, module_addrs) = match result {
        Result::Ok((ids, addrs)) => (ids, addrs),
        Result::Err(_) => {
            log(String::from_ascii_str("Failed to calculate module addresses"));
            revert(0);
        }
    };

    // Calculate master address
    let master_addr = match ZapWalletBuilderV1::calculate_master_details(
        ctx,
        module_asset_ids,
        module_addrs,
    ) {
        Result::Ok(addr) => addr,
        Result::Err(_) => {
            log(String::from_ascii_str("Failed to calculate master address"));
            revert(0);
        }
    };

    // Log results
    log(String::from_ascii_str("nonce_asset_id:"));
    log(b256_to_hex(ctx.nonce_asset_id));

    // Log each module
    let module_names = [
        String::from_ascii_str("M00"),
        String::from_ascii_str("M01"),
        String::from_ascii_str("M02"),
        String::from_ascii_str("M03"),
        String::from_ascii_str("M04"),
        String::from_ascii_str("M05"),
        String::from_ascii_str("M06"),
        String::from_ascii_str("M07"),
        String::from_ascii_str("M08"),
    ];
    let mut i = 0;
    while i < 9 {
        log(module_names[i]);
        log(String::from_ascii_str("asset_id:"));
        log(b256_to_hex(module_asset_ids[i]));
        log(String::from_ascii_str("addr:"));
        log(b256_to_hex(module_addrs[i]));
        i += 1;
    }
    // Log master
    log(String::from_ascii_str("Master:"));
    log(String::from_ascii_str("master_addr:"));
    log(b256_to_hex(master_addr));
}

// forc test test_101_full_wallet_details --logs
#[test()]
fn test_101_full_wallet_details() {
    let owner_pubkey: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;
    // let owner_pubkey: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;
    // let owner_pubkey: b256 = 0x000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c65;

    let loader_cfgs = [
        LoaderConfig::new(M00_BLOB_ID, M00_SEC_LEN),
        LoaderConfig::new(M01_BLOB_ID, M01_SEC_LEN),
        LoaderConfig::new(M02_BLOB_ID, M02_SEC_LEN),
        LoaderConfig::new(M03_BLOB_ID, M03_SEC_LEN),
        LoaderConfig::new(M04_BLOB_ID, M04_SEC_LEN),
        LoaderConfig::new(M05_BLOB_ID, M05_SEC_LEN),
        LoaderConfig::new(M06_BLOB_ID, M06_SEC_LEN),
        LoaderConfig::new(M07_BLOB_ID, M07_SEC_LEN),
        LoaderConfig::new(M08_BLOB_ID, M08_SEC_LEN),
        LoaderConfig::new(MASTER_BLOB_ID, MASTER_SEC_LEN),
    ];

    // Create the context
    let ctx = WalletContext::new(owner_pubkey, V1_MANAGER_CID, loader_cfgs);

    // Calculate everything in one call
    let wallet_details = match calculate_complete_wallet_details(ctx) {
        Result::Ok(details) => details,
        Result::Err(_) => {
            log(String::from_ascii_str("Failed to calculate wallet details"));
            revert(0);
        }
    };

    // Log results
    log(String::from_ascii_str("nonce_asset_id:"));
    log(b256_to_hex(ctx.nonce_asset_id));

    // Log each module
    let module_names = [
        String::from_ascii_str("M00"),
        String::from_ascii_str("M01"),
        String::from_ascii_str("M02"),
        String::from_ascii_str("M03"),
        String::from_ascii_str("M04"),
        String::from_ascii_str("M05"),
        String::from_ascii_str("M06"),
        String::from_ascii_str("M07"),
        String::from_ascii_str("M08"),
    ];
    let mut i = 0;
    while i < 9 {
        log(module_names[i]);
        log(String::from_ascii_str("asset_id:"));
        log(b256_to_hex(wallet_details.module_asset_ids[i]));
        log(String::from_ascii_str("addr:"));
        log(b256_to_hex(wallet_details.module_addrs[i]));
        i += 1;
    }
    // Log master
    log(String::from_ascii_str("Master:"));
    log(String::from_ascii_str("master_addr:"));
    log(b256_to_hex(wallet_details.master_addr));
}

// forc test test_102_verify_receiver_ctx --logs
#[test()]
fn test_102_verify_receiver_ctx() {

    let owner_pubkey: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;
    let owner_zapwallet_addr = 0x1de83a24021f5d39ab4f0194f1347f1c8696f9c94ab6c64866c15da7b066024e;

    let loader_cfgs = [
        LoaderConfig::new(M00_BLOB_ID, M00_SEC_LEN),
        LoaderConfig::new(M01_BLOB_ID, M01_SEC_LEN),
        LoaderConfig::new(M02_BLOB_ID, M02_SEC_LEN),
        LoaderConfig::new(M03_BLOB_ID, M03_SEC_LEN),
        LoaderConfig::new(M04_BLOB_ID, M04_SEC_LEN),
        LoaderConfig::new(M05_BLOB_ID, M05_SEC_LEN),
        LoaderConfig::new(M06_BLOB_ID, M06_SEC_LEN),
        LoaderConfig::new(M07_BLOB_ID, M07_SEC_LEN),
        LoaderConfig::new(M08_BLOB_ID, M08_SEC_LEN),
        LoaderConfig::new(MASTER_BLOB_ID, MASTER_SEC_LEN),
    ];

    // Create the context
    let receiver_zapwallet_ctx = WalletContext::new(owner_pubkey, V1_MANAGER_CID, loader_cfgs);

    // Calculate everything in one call
    let wallet_details = match calculate_complete_wallet_details(receiver_zapwallet_ctx) {
        Result::Ok(details) => details,
        Result::Err(_) => {
            log(String::from_ascii_str("Failed to calculate wallet details"));
            revert(0);
        }
    };

    // Log master
    log(String::from_ascii_str("Master:"));
    log(String::from_ascii_str("master_addr:"));
    log(b256_to_hex(wallet_details.master_addr));

    let verify_res = verify_receiver(
        receiver_zapwallet_ctx,
        owner_zapwallet_addr,
    );

    if verify_res {
        log(String::from_ascii_str("TRUE"));
    } else {
        log(String::from_ascii_str("FALSE"));
    }
}

// Simple merkle functions
pub fn calculate_simple_merkle_root(single_leaf: Bytes) -> b256 {
    let leaf_hash = calculate_leaf_hash(single_leaf);
    leaf_hash
}

pub fn calculate_simple_merkle_predicate(single_leaf: Bytes) -> b256 {
    let leaf_hash = calculate_leaf_hash(single_leaf);
    calculate_predi_addr_from_root(leaf_hash)
}
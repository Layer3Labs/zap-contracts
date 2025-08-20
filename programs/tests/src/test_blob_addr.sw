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
const M01_BLOB_ID: b256 = 0xa82bd574e319a28914bb59e195fbdfe9a892cc5aa99c080a085a7e05dbc4f4d7;
const M02_BLOB_ID: b256 = 0x5dea3358854fb449394d7884f9f9d6fe461cc0184f34af468518eefb782aced8;
const M03_BLOB_ID: b256 = 0x593e568ee1ecb74d39899ec9ea0ef221207f1f626e176f53fcb47f7973f20883;
const M04_BLOB_ID: b256 = 0xb66a7d206c4623f24af1932ec9a7a1312d5f26d198506220f170e2a1baa01c90;
const M05_BLOB_ID: b256 = 0x5cca4dc452afecf08f7db490c50dca01b52004412da40fefcaff69477bd0e205;
const M06_BLOB_ID: b256 = 0xf8c2b3282ba4711c93d8a801d2e4e3bdb7996a3d6711a38360e7a4a6392150d7;
const M07_BLOB_ID: b256 = 0x0fc1f076ffb99827792711c75144a65f8113d102f2024f3782d9b7b0d7c2786f;
const M08_BLOB_ID: b256 = 0xf8c2b3282ba4711c93d8a801d2e4e3bdb7996a3d6711a38360e7a4a6392150d7;
const MASTER_BLOB_ID: b256 = 0xaf1a84a4b754c8077db3dc319abcde9099d6f9c9e5d55b4ab59af592445463ac;

const M00_ASSETID: b256 = 0x2397d6670424a3f28dcacb4b401d7d757a2fa56facf76a5986442b34c7259ff9;
const M01_ASSETID: b256 = 0x4756e1a0ce6b0b5f3f63918794cf205ea3412c18d764123e8a7061b1cea4989a;
const M02_ASSETID: b256 = 0x8f1bd6b7832909c15981b97733eb1f4a7d7000368673228f4ef03dcb97a2e480;
const M03_ASSETID: b256 = 0x015046ebbc05d3792f13b65f57548fd1991e0eab37ab68bdaf70cda2e4ec2be6;
const M04_ASSETID: b256 = 0x1dd3ba67f1faf36e236381ecb60e287875dae5dc1a978340eb2377625b6672a2;
const M05_ASSETID: b256 = 0xf7752800686d515c298cb5f7238fd46c34643079aa4277684e464c076b833720;
const M06_ASSETID: b256 = 0xad63368ef6a6ebd480edfa980cddf6adb8ac23c60ad87212db81c92a460e7185;
const M07_ASSETID: b256 = 0x315f7bf42059c013246c6d4f590a6d070f695a84001cfa2467a96cfe0274deeb;
const M08_ASSETID: b256 = 0xf842680bc78ea98cd9f75453d7a6f63c39130e86f93937d173fabee3fbcd5eb3;

const M00_ADDRESS: b256 = 0x00fd46df62abb9a0669fcfa8569174c9bf358ab4746b7a337bd0846eae674263;
const M01_ADDRESS: b256 = 0x67b5bdcd39333b8c44634434bcf3c6c12cda0599218c13165e4c4dcb3068d561;
const M02_ADDRESS: b256 = 0x32d20757304a6b3de439ea24ea738934aedf170636e431e8dc6e651423a78f3b;
const M03_ADDRESS: b256 = 0x6d4fdf201327510168c4d1a464f7c65271b5722963bba362c874365ec5643275;
const M04_ADDRESS: b256 = 0x4b5e71303488c1e2844713257ee53f0c7a3281dccf02fe21ba73aeee5c8ae144;
const M05_ADDRESS: b256 = 0x71873d998af2ca8183f730a8b36a8f9cdd3db468b160bcf6bb07ed5427d4fd22;
const M06_ADDRESS: b256 = 0x6a1b9d387e32d6a21efb52c5937cab3980b8196da0b07b30f27593ad979c4da5;
const M07_ADDRESS: b256 = 0x3979b021d56d5a5c6a8da57e4878c4de2cfba64ff3da7565ff55b8d3dc186291;
const M08_ADDRESS: b256 = 0x6ee3ce2e4a087e4bac25953928aaf8700530c1132a55873fad33353065780169;

// V1 ZapManager CID
const V1_MANAGER_CID: b256 = 0x8e046df8e45aeebaf4443498eced8102688e2628c3e4eb58893f061553b04cc7;


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

    let owner_pubkey: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;
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
        None,
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




// forc test test_103_zapwallet_via_fast_method --logs
#[test()]
fn test_103_zapwallet_via_fast_method() {
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

    let module_assetid_array: [b256; 9] = [
        M00_ASSETID,
        M01_ASSETID,
        M02_ASSETID,
        M03_ASSETID,
        M04_ASSETID,
        M05_ASSETID,
        M06_ASSETID,
        M07_ASSETID,
        M08_ASSETID,
    ];

    let module_address_array: [b256; 9] = [
        M00_ADDRESS,
        M01_ADDRESS,
        M02_ADDRESS,
        M03_ADDRESS,
        M04_ADDRESS,
        M05_ADDRESS,
        M06_ADDRESS,
        M07_ADDRESS,
        M08_ADDRESS,
    ];

    // Create the Option<MasterConfigs>
    let precomputed_modules: Option<MasterConfigs> = Some(MasterConfigs {
        module_assetid: module_assetid_array,
        module_address: module_address_array,
    });

    let (module_asset_ids, module_addrs) = match precomputed_modules {
        Some(master_cfgs) => {
            // If we have pre-configured values, use them directly
            (master_cfgs.module_assetid, master_cfgs.module_address)
        },
        None => {
            // If no pre-configured values, calculate them
            match ZapWalletBuilderV1::calculate_all_module_addresses(ctx) {
                Result::Ok((ids, addrs)) => (ids, addrs),
                Result::Err(_) => {
                    log(String::from_ascii_str("Failed to calculate module addresses"));
                    revert(0);
                }
            }
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
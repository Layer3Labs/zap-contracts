library;

// mod constants;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    convert::TryFrom,
    option::Option::{self, *},
    hash::*,
    tx::{
        tx_id,
        tx_witness_data,
    },
    inputs::{
        input_predicate,
        input_count,
    },
    outputs::{
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
        output_count,
    },
    vm::evm::{
        // ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    context::{
        this_balance, balance_of,
    },
    // message::send_message,
    asset::*,
    contract_id::*,
    // asset::mint_to,
};

use ::constants::{
    NONCE_MAX, KEY_NONCE,
};
use ::manager::UpgradeZapWallet;

use io_utils::{
    evmtx_io_utils::InpOut,
    io::*,
};


// ------------------------------
// only for debug
use helpers::{
    general_helpers::*,
    hex::*,
    numeric_utils::*,
};
// ------------------------------






pub fn mint_nonce_asset(
    evm_addr: EvmAddress,
    pred_acc: Address,
){

    let sub_id: b256 = get_sub_id(evm_addr, KEY_NONCE);
    log(sub_id);

    // calculated nonce assetid and checks that the current contract
    // has a zero balance of the asset.
    let modaid = AssetId::new(ContractId::this(), sub_id);
    log(modaid);

    assert(this_balance(modaid) == 0);
    log(this_balance(modaid));

    // mints the maximum number of nonce token and send this amount minus 1 to the prediacte master.
    // leaves 1 token owned by the ZapManager so the nonce key combo cannot be minted again.
    let mut mint_amount: u64 = NONCE_MAX;
    mint(sub_id, mint_amount);

    transfer(
        Identity::Address(pred_acc),
        AssetId::new(ContractId::this(), sub_id),
        mint_amount - 1
    );
}

pub fn mint_module_asset(
    evm_addr: EvmAddress,
    key: b256,
    module_addr: Address,
){

    let sub_id: b256 = get_sub_id(evm_addr, key);
    log(sub_id);

    // calculated module assetid and checks that the current contract
    // has a zero balance of the asset.
    let modaid = AssetId::new(ContractId::this(), sub_id);
    log(modaid);

    assert(this_balance(modaid) == 0);
    log(this_balance(modaid));

    // For any module key
    let mut mint_amount: u64 = 1;
    mint(sub_id, mint_amount);

    transfer(
        Identity::Address(module_addr),    // send to the Module Address.
        AssetId::new(ContractId::this(), sub_id),
        mint_amount      // send the unit amount to the Module Address.
    );

}

pub fn get_sub_id(
    evm_addr: EvmAddress,
    key: b256,
) -> b256 {

    let mut result_buffer_1 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(n_id: result_buffer_1, ptr: (evm_addr, key), bytes: 64) {
        s256 n_id ptr bytes;
    };

    // log(result_buffer_1);

    return(result_buffer_1);
}

pub fn get_module_assetid(
    evm_addr: EvmAddress,
    key: b256,
) -> AssetId {

    let sub_id: b256 = get_sub_id(evm_addr, key);

    // calculated module assetid and checks that the current contract
    // has a zero balance of the asset.
    let assetid = AssetId::new(ContractId::this(), sub_id);

    assetid
}


pub fn build_upgrade(
    nonce_assetid: b256,
    module00_assetid: b256,
) -> UpgradeZapWallet {

    // get all the inputs, outputs and change to thsi tx
    let (tx_inputs, tx_outputs, tx_change) = collect_inputs_outputs_change();

    // Get the owners owners ZapWallet address, this should be the owner of the
    // nonce asset input
    let old_zap_wallet: b256 = match check_asset_exists(tx_inputs, nonce_assetid ) {
        CheckAssetResult::Success(nonce_owner_from) => {
            log(String::from_ascii_str("Old ZapWallet addr:"));
            log(b256_to_hex(nonce_owner_from.into()));

            nonce_owner_from.into()
        },
        CheckAssetResult::Fail(error_code) => {
            // return Err(error_code);
            //NOTE - should probably just fail it here
            b256::zero()
        },
    };


    // find the UTXO ID for the Input Module00 asset
    let utxo_id = match find_utxoid_by_asset(module00_assetid) {
        Some(utxoid) => {
            // Handle the case where the asset is found
            log(String::from_ascii_str("Module00 UTXO ID:"));
            log(b256_to_hex(utxoid));

            utxoid
        },
        None => {
            log("Module00 Asset not found in inputs.");
            b256::zero()
        },
    };



    let upgrade = UpgradeZapWallet {
        contract_id: b256::zero(),
        old_zapWallet_address: b256::zero(),
        new_zapWallet_address: b256::zero(),
        new_version: String::from_ascii_str("blah:"),
        sponsored_transaction: String::from_ascii_str("foo"),
        upgrade_utxo: b256::zero(),
    };

    upgrade
}
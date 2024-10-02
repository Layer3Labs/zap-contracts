library;

use ::constants::{
    KEY00, KEY01, KEY02, KEY03, KEY04, KEYFF,
    NONCE_MAX, MODULE_ASSET_MAX,
    VERSION,
};

use std::{
    bytes::Bytes,
    b512::B512,
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


pub fn mint_module_asset(
    evm_addr: EvmAddress,
    key: b256,
    pred_acc: Address,
){

    let sub_id: b256 = get_sub_id(evm_addr, key);
    log(sub_id);

    // calculated module assetid and checks that the current contract
    // has a zero balance of the asset.
    let modaid = AssetId::new(ContractId::this(), sub_id);
    log(modaid);

    assert(this_balance(modaid) == 0);
    log(this_balance(modaid));

    // case key==1: mints the maximum number of nonce token and send this amount minus 1 to the prediacte master.
    // case key!=1
    // leaves 1 token owned by the noncemanager so the same key combo cannot be minted again.
    let mut mint_amount: u64 = 2;
    if KEY00 == key {
        mint_amount = NONCE_MAX;
    }
    mint(sub_id, mint_amount);

    let to_address = Identity::Address(pred_acc);
    transfer(to_address, AssetId::new(ContractId::this(), sub_id), mint_amount - 1);

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
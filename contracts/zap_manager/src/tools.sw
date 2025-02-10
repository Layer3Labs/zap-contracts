library;

use std::{
    bytes::Bytes,
    string::String,
    option::Option::{self, *},
    vm::evm::evm_address::EvmAddress,
    context::this_balance,
    asset::*,
    contract_id::*,
};
use ::constants::{
    NONCE_MAX, KEY_NONCE,
};


pub fn mint_nonce_asset(
    evm_addr: EvmAddress,
) -> (u64, AssetId) {

    let sub_id: b256 = get_sub_id(evm_addr, KEY_NONCE);
    log(sub_id);

    // calculated nonce assetid and checks that the current contract
    // has a zero balance of the asset.
    let modaid = AssetId::new(ContractId::this(), sub_id);
    log(modaid);

    assert(this_balance(modaid) == 0);
    log(this_balance(modaid));

    // Mints the maximum number of nonce token and send this amount minus one
    // to the prediacte master. Leaves 1 token owned by the ZapManager so the
    // nonce key combo cannot be minted again.
    let mut mint_amount: u64 = NONCE_MAX;
    mint(sub_id, mint_amount);

    (
        (NONCE_MAX - 1),
        AssetId::new(ContractId::this(), sub_id)
    )
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

    let mut result_buffer = b256::zero();
    asm(n_id: result_buffer, ptr: (evm_addr, key), bytes: 64) {
        s256 n_id ptr bytes;
    };

    return(result_buffer);
}

pub fn get_module_assetid(
    evm_addr: EvmAddress,
    key: b256,
) -> AssetId {

    let sub_id: b256 = get_sub_id(evm_addr, key);
    let assetid = AssetId::new(ContractId::this(), sub_id);

    assetid
}


pub fn get_key1(
    evm_addr: EvmAddress,
    master_addr: Address,
) -> b256 {

    let mut result_buffer = b256::zero();
    asm(n_id: result_buffer, ptr: (evm_addr, master_addr), bytes: 64) {
        s256 n_id ptr bytes;
    };

    return(result_buffer);
}

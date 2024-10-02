library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    vm::evm::evm_address::EvmAddress,
};



pub fn calc_asset_id(
    evm_addr: EvmAddress,
    dummy_sub_id: b256,
    contract_id: ContractId,
) -> b256 {

    let mut result_buffer_1 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(n_id: result_buffer_1, ptr: (evm_addr, dummy_sub_id), bytes: 64) {
        s256 n_id ptr bytes;
    };

    // log(result_buffer_1);

    // let contract_id = asm() { fp: b256 };
    let mut result_buffer_2 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(asset_id: result_buffer_2, ptr: (contract_id, result_buffer_1), bytes: 64) {
        s256 asset_id ptr bytes;
    };

    // log(result_buffer_2);

    return(result_buffer_2);

}

library;

use std::vm::evm::evm_address::EvmAddress;


pub struct BaseModules {
    pub module_addrs: [b256; 5],
}
pub struct Module {
    pub key: b256,
    pub module_addr: b256,
}

pub enum InitData {
    InitModules: BaseModules,
    NewModule: Module,

}

abi ZapManager {

    fn initialize_wallet(
        pred_acc: Address,
        owner_evm_addr: EvmAddress,
        initdata: InitData,
    ) -> EvmAddress;

    fn check_init(
        evm_addr: EvmAddress,
    ) -> bool;

    fn check_asset_status(
        evm_addr: EvmAddress,
        key: b256,
    ) -> u64;

    fn get_version() -> b256;

}

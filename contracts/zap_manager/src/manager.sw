library;

use std::{
    bytes::Bytes,
    string::String,
    hash::*,
    contract_id::*,
    vm::evm::evm_address::EvmAddress,
};
use standards::src5::{State, SRC5};


pub struct BaseModules {
    pub module_addrs: [b256; 9],
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

    /// Transfers ownership of the contract to a new owner.
    #[storage(read, write)]
    fn transfer_ownership(new_owner: Identity);

    /// Returns the status of contract ownership.
    #[storage(read)]
    fn ownership_status() -> (String, String);

    /// Sets the operational state of the contract for initialization and upgrade functionality.
    #[storage(read, write)]
    fn set_contract_state(allow_initialize: bool, allow_upgrade: bool);

    /// Returns the current operational status of the contract.
    #[storage(read)]
    fn contract_status() -> (bool, bool, bool, str[5], str[5]);

    /// Initializes a new wallet with specified modules.
    #[storage(read, write)]
    fn initialize_wallet( master_addr: Address, owner_evm_addr: EvmAddress, initdata: InitData ) -> EvmAddress;

    /// Checks if the given EVM address and master address combo have a nonce asset.
    #[storage(read)]
    fn initialized( master_address: Address, evm_addr: EvmAddress ) -> bool;

    /// Sets the ZapWallet versions for V1 and V2.
    #[storage(read, write)]
    fn set_zapwallet_versions( v1_version: str[5], v2_version: str[5] );

    /// Returns the current versions of V1 and V2 ZapWallet.
    #[storage(read)]
    fn zapwallet_versions() -> (str[5], str[5]);

    /// Upgrades a wallet to a new version.
    #[storage(read), payable]
    fn upgrade( owner_evm_addr: EvmAddress, sponsored: bool );

    /// Checks if the given EVM address has upgraded their wallet.
    fn has_upgraded(evm_addr: EvmAddress) -> bool;

}

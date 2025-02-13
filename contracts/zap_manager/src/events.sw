library;

use std::{ bytes::Bytes, b512::B512, string::String, vm::evm::evm_address::EvmAddress };


/// Event emitted when contract state is changed
pub struct ContractStateEvent { can_initialize: bool, can_upgrade: bool, sender: Identity }

impl ContractStateEvent {
    pub fn new(can_initialize: bool, can_upgrade: bool, sender: Identity) -> Self {
        Self {
            can_initialize,
            can_upgrade,
            sender,
        }
    }

    pub fn log(self) {
        log(self);
    }
}

/// Event emitted when initialize_wallet is called
pub struct InitializeWalletEvent { predicate_address: Address, owner_evm_address: EvmAddress, is_base_modules: bool }

impl InitializeWalletEvent {
    pub fn new(predicate_address: Address, owner_evm_address: EvmAddress, is_base_modules: bool) -> Self {
        Self { predicate_address, owner_evm_address, is_base_modules }
    }

    pub fn log(self) {
        log(self);
    }
}

/// Event emitted when wallet versions are updated
pub struct WalletVersionsEvent {
    v1_version: str[5],
    v2_version: str[5],
    sender: Identity,
}

impl WalletVersionsEvent {
    pub fn new(v1_version: str[5], v2_version: str[5], sender: Identity) -> Self {
        Self { v1_version, v2_version, sender }
    }

    pub fn log(self) {
        log(self);
    }
}

/// Event emitted when upgrade is called
pub struct UpgradeEvent {
    owner_evm_addr: EvmAddress,
    master_address: Address,
    is_sponsored: bool,
    verified_nonce: AssetId,
}

impl UpgradeEvent {
    pub fn new( owner_evm_addr: EvmAddress, master_address: Address, is_sponsored: bool, verified_nonce: AssetId,
    ) -> Self { Self { owner_evm_addr, master_address, is_sponsored, verified_nonce } }

    pub fn log(self) { log(self); }
}
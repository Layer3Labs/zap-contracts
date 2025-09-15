library;

use std::{
    bytes::Bytes,
    string::String,
    hash::*,
    contract_id::*,
    vm::evm::evm_address::EvmAddress,
};
use standards::src5::{State, SRC5};


abi ZapManager {

    /// Sets contract ownership from configurable to storage.
    #[storage(read, write)]
    fn set_configurable_owner();

    /// Transfers ownership of the contract to a new_owner.
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

    /// Sets the blob IDs for V1 ZapWallet.
    #[storage(read, write)]
    fn set_v1_blob_ids(blob_ids: [b256; 10]);

    /// Returns the stored V1 blob IDs.
    #[storage(read)]
    fn get_v1_blob_ids() -> [b256; 10];

    /// Initializes a new wallet with specified modules.
    #[storage(read, write)]
    fn initialize_wallet(
        owner_evm_addr: EvmAddress
    ) -> EvmAddress;

    /// Re-mints a single module for an existing wallet.
    #[storage(read)]
    fn remint_module(
        owner_evm_addr: EvmAddress,
        module_key: b256,
    ) -> EvmAddress;

    /// Checks if the given EVM address and master address combo have a nonce asset.
    #[storage(read)]
    fn initialized(
        master_address: Address,
        evm_addr: EvmAddress,
    ) -> bool;

    /// Sets the ZapWallet versions for V1 and V2.
    #[storage(read, write)]
    fn set_zapwallet_versions(
        v1_version: str[5],
        v2_version: str[5],
    );

    /// Returns the current versions of V1 and V2 ZapWallet.
    #[storage(read)]
    fn zapwallet_versions() -> (str[5], str[5]);

    #[storage(read, write)]
    fn set_v2_manager_details(v2_manager: ContractId, setup_selector: Bytes);

    #[storage(read, write)]
    fn set_v2_master_address(owner_address: EvmAddress, v2_master_address: b256);

    /// Upgrades a wallet to a new version.
    #[storage(read), payable]
    fn upgrade() -> bool;

    /// Checks if the given EVM address has upgraded their wallet.
    fn has_v1_wallet_upgraded(evm_addr: EvmAddress) -> bool;

}

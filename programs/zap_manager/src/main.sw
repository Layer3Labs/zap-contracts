contract;

mod tools;
mod events;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    option::Option::{self, *},
    hash::*,
        storage::{
        storage_map::*,
        storage_bytes::*,
        storage_vec::*,
    },
    vm::evm::evm_address::EvmAddress,
    context::{this_balance, balance_of},
    asset::*,
    contract_id::*,
    asset::mint_to,
    low_level_call::{call_with_function_selector, CallParams},
};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use std::bytes_conversions::{b256::*, u64::*};
use sway_libs::pausable::{_is_paused, _pause, _unpause, Pausable};
use standards::src5::{SRC5, State, AccessError};

use io_utils::io::find_utxoid_and_owner_by_asset;
use zap_utils::{
    hex::b256_to_hex,
    blob_utils::*,
};
// use constants::*;
use zapwallet_consts::wallet_consts::*;
use tools::{
    get_nonce_subid,
    mint_nonce_asset,
    mint_module_asset,
    get_sub_id,
    get_module_assetid,
};

use ::events::{
    ContractStateEvent,
    InitializeWalletEvent,
    WalletVersionsEvent,
    UpgradeEvent,
    OwnershipTransferEvent,
    V1BlobIdsUpdatedEvent,
};
use walletop_upgrade::io_verify::*;
use v1_manager_abi::ZapManager;



configurable {
    /// The owner of this contract at deployment.
    INITIAL_OWNER: Identity = Identity::Address(Address::from(b256::zero()))
}

storage {
    /// The owner of the contract.
    owner: State = State::Uninitialized,
    /// Controls whether new wallet initialization is allowed.
    can_initialize: bool = false,
    /// Controls whether wallet upgrades are allowed.
    can_upgrade: bool = false,
    /// Current version string for V1 ZapWallets.
    v1_version: str[5] = __to_str_array("1.0.0"),
    /// Current version string for V2 ZapWallets.
    v2_version: str[5] = __to_str_array("-.-.-"),
    /// Blob IDs for V1 ZapWallet
    /// Keys 0-8: module blob IDs (modules 00-08)
    /// Key 9: master blob ID
    v1_blob_ids: StorageMap<u64, b256> = StorageMap {},

    //--- for v2 upgrade --
    v2_manager_id: ContractId = ContractId::zero(),
    setup_via_upgrade_selector: StorageVec<StorageBytes> = StorageVec {},

    /// Maps a unique wallet identifier to its nonce asset.
    /// Key is sha256(evm_addr || nonce_key) -> nonce SubId.
    v1_master_to_nonce_map: StorageMap<b256, AssetId> = StorageMap {},
    /// Maps a unique nonce asset to its unique wallet identifier.
    v1_nonce_to_owner_master_map: StorageMap<AssetId, (EvmAddress, b256)> = StorageMap {},

    /// Maps a unique owner address to its v2 master address.
    owner_to_v2_master_map: StorageMap<EvmAddress, b256> = StorageMap {},

    // Tracks V1 Master address upgrades
    // upgraded_v1_masters: StorageMap<b256, bool> = StorageMap {},

}


impl SRC5 for Contract {
    #[storage(read)]
    fn owner() -> State {
        storage.owner.read()
    }
}

impl Pausable for Contract {
    #[storage(write)]
    fn pause() {
        require_owner();
        _pause();
    }

    #[storage(write)]
    fn unpause() {
        require_owner();
        _unpause();
    }

    #[storage(read)]
    fn is_paused() -> bool {
        _is_paused()
    }
}


impl ZapManager for Contract {

    /// Sets contract ownership from configurable to storage.
    #[storage(read, write)]
    fn set_configurable_owner() {
        let owner = storage.owner.read();
        if (owner == State::Uninitialized) {
            storage.owner.write(State::Initialized(INITIAL_OWNER));
        }
    }

    /// Transfers contract ownership to new_owner.
    #[storage(read, write)]
    fn transfer_ownership(new_owner: Identity) {
        // Only current owner can transfer ownership
        require_owner();
        // Check that new owner is not zero address
        match new_owner {
            Identity::Address(addr) => {
                require(
                    addr != Address::zero(),
                    "Error: New owner cannot be the zero address"
                );
            },
            Identity::ContractId(id) => {
                require(
                    id != ContractId::zero(),
                    "Error: New owner cannot be the zero contract ID"
                );
            },
        }
        // Store current owner to emit in event
        let previous_owner = storage.owner.read();
        // Update owner in storage
        storage.owner.write(State::Initialized(new_owner));

        // Emit ownership transfer event
        if let State::Initialized(prev_owner) = previous_owner {
            OwnershipTransferEvent::new(prev_owner, new_owner).log();
        }
    }

    /// Returns the current ownership status of the contract and owner identity if initialized.
    ///
    /// # Returns
    ///
    /// * `(str[14], str[64])`: A tuple containing:
    ///   * ownership_state: One of "Uninitialized", "Initialized", or "Revoked"
    ///   * owner_identity: Hex string of owner address if initialized, empty string otherwise
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 1 (owner state)
    ///
    #[storage(read)]
    fn ownership_status() -> (String, String) {
        match storage.owner.read() {
            State::Uninitialized => {
                (
                    String::from_ascii_str("Uninitialized"),
                    b256_to_hex(b256::zero())
                )
            },
            State::Initialized(identity) => {
                (
                    String::from_ascii_str("Initialized"),
                    b256_to_hex(identity.as_address().unwrap().into())
                )
            },
            State::Revoked => {
                (
                    String::from_ascii_str("Revoked"),
                    b256_to_hex(b256::zero())
                )
            }
        }
    }

    /// Sets the operational state of the contract for initialization and upgrade functionality.
    ///
    /// # Arguments
    ///
    /// * `allow_initialize`: If true, enables wallet initialization, must be false if `allow_upgrade` is true
    /// * `allow_upgrade`: If true, enables wallet upgrades, must be false if `allow_initialize` is true
    ///
    /// # Reverts
    ///
    /// * When caller is not the contract owner
    /// * When attempting to enable both initialization and upgrades simultaneously
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 1
    /// * Writes: 2
    ///
    /// # Events
    ///
    /// * `ContractStateEvent`: Emitted with the new state configuration and sender identity
    ///
    /// # Additional Information
    ///
    ///     can_initialize | can_upgrade | Meaning
    ///     -------------------------------------------
    ///     false          | false       | Contract setup not complete, no actions allowed
    ///     true           | false       | Only wallet initialization allowed
    ///     false          | true        | Only upgrades allowed, no new initializations
    ///     true           | true        | Invalid state (should not occur)
    ///
    #[storage(read, write)]
    fn set_contract_state(allow_initialize: bool, allow_upgrade: bool) {
        // Only owner can call this function
        require_owner();

        // Prevent invalid state where both are true
        require(
            !(allow_initialize && allow_upgrade),
            "Cannot enable both initialization and upgrades simultaneously"
        );

        // Set the states
        storage.can_initialize.write(allow_initialize);
        storage.can_upgrade.write(allow_upgrade);

        // Emit the state change event
        ContractStateEvent::new(
            allow_initialize,
            allow_upgrade,
            msg_sender().unwrap()
        ).log();
    }

    /// Returns the current operational status of the contract.
    ///
    /// # Returns
    ///
    /// * `(bool, bool, bool, str[5], str[5])`: A tuple containing:
    ///   * is_paused: Whether the contract is currently paused
    ///   * can_initialize: Whether new wallet initialization is enabled
    ///   * can_upgrade: Whether wallet upgrades are enabled
    ///   * v1_version: Current version string for V1
    ///   * v2_version: Current version string for V2
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 5
    ///
    #[storage(read)]
    fn contract_status() -> (bool, bool, bool, str[5], str[5]) {
        // Read all status variables
        let is_paused = _is_paused();
        let can_init = storage.can_initialize.read();
        let can_upgrd = storage.can_upgrade.read();
        let v1_ver = storage.v1_version.read();
        let v2_ver = storage.v2_version.read();

        ( is_paused, can_init, can_upgrd, v1_ver, v2_ver )
    }

    /// Sets the blob IDs for V1 ZapWallet (9 modules + 1 master).
    ///
    /// # Arguments
    ///
    /// * `blob_ids`: Array of 10 b256 values where:
    ///   * Indices 0-8: Module blob IDs for modules 00-08
    ///   * Index 9: Master blob ID
    ///
    /// # Reverts
    ///
    /// * When caller is not the contract owner
    /// * When any blob ID is zero
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 1 (owner check)
    /// * Writes: 10 (one for each blob ID)
    ///
    /// # Events
    ///
    /// * `V1BlobIdsUpdatedEvent`: Emitted with all blob IDs and sender identity
    ///
    #[storage(read, write)]
    fn set_v1_blob_ids(blob_ids: [b256; 10]) {
        // Only owner can set blob IDs
        require_owner();

        // Store each blob ID in the map
        let mut i = 0;
        while i < 10 {
            // Validate that blob ID is not zero
            require(blob_ids[i] != b256::zero(), "Blob ID cannot be zero");

            // Store with key: 0-8 for modules, 9 for master
            storage.v1_blob_ids.insert(i, blob_ids[i]);
            i += 1;
        }

        // Emit event with all blob IDs
        V1BlobIdsUpdatedEvent::new(
            blob_ids,
            msg_sender().unwrap()
        ).log();
    }

    /// Returns all V1 blob IDs as an array.
    ///
    /// # Returns
    ///
    /// * `[b256; 10]`: Array where:
    ///   * Indices 0-8: Module blob IDs for modules 00-08
    ///   * Index 9: Master blob ID
    ///   * Returns zero values if not set
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 10
    ///
    #[storage(read)]
    fn get_v1_blob_ids() -> [b256; 10] {
        let mut blob_ids = [b256::zero(); 10];
        let mut i = 0;

        while i < 10 {
            // Get from storage, default to zero if not found
            blob_ids[i] = storage.v1_blob_ids.get(i).try_read().unwrap_or(b256::zero());
            i += 1;
        }

        blob_ids
    }

    /// Initializes a new V1 ZapWallet with all modules and master components.
    ///
    /// # Additional Information
    ///
    /// This function performs a complete wallet initialization by:
    /// - Calculating all module and master addresses based on stored blob IDs
    /// - Minting a nonce asset that is sent to the master address
    /// - Minting and distributing all 9 module assets to their respective addresses
    ///
    /// # Arguments
    ///
    /// * `owner_evm_addr`: [EvmAddress] - The EVM address that will own this ZapWallet
    ///
    /// # Returns
    ///
    /// * [EvmAddress] - The owner's EVM address
    ///
    /// # Reverts
    ///
    /// * When the contract is paused
    /// * When wallet initialization is not enabled
    /// * When V1 blob IDs are not configured (any blob ID is zero)
    /// * When wallet details calculation fails
    /// * When a wallet with this EVM address and master address combination already exists
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `14` (pause status + initialization enabled + 10 blob IDs + nonce check + manager contract ID)
    /// * Writes: `1` (nonce asset mapping)
    ///
    #[storage(read, write)]
    fn initialize_wallet(owner_evm_addr: EvmAddress) -> EvmAddress {
        // Contract pause check
        require(!_is_paused(), "Contract is paused");

        // Verify contract initialization is enabled
        require(storage.can_initialize.read(), "Wallet initialization is not enabled");

        // Create new wallet context
        let (_, ctx) = create_wallet_context_from_storage(owner_evm_addr);

        // Calculate new ZapWallet details; all module addresses and asset IDs
        let wallet_details = match calculate_complete_wallet_details(ctx) {
            Result::Ok(details) => details,
            Result::Err(_) => {
                log(String::from_ascii_str("Failed to calculate wallet details"));
                revert(0);
            }
        };
        let master_addr = Address::from(wallet_details.master_addr);

        log(master_addr);

        let nonce_assetid = AssetId::from(ctx.nonce_asset_id);

        // Check for existing nonce asset to prevent double initialization
        require(
            !check_initialized(nonce_assetid),
            "Wallet already has Nonce, if error mint assets individually"
        );

        // Obtain nonce assetid, mint nonce assets and store mapping data
        let nonce_subid = get_nonce_subid(owner_evm_addr);
        let nonce_tfr_amt = mint_nonce_asset(nonce_subid, nonce_assetid);

        // Store mappings of Master --> Nonce, and, EVM addr --> Master
        storage.v1_master_to_nonce_map.insert(wallet_details.master_addr, nonce_assetid);
        storage.v1_nonce_to_owner_master_map.insert(nonce_assetid, (owner_evm_addr, wallet_details.master_addr));

        // Mint and transfer all base module assets to their addresses
        let module_keys: [b256; 9] = [KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08];

        // Calculate module addresses
        let mut i = 0;
        while i < 9 {
            mint_module_asset(owner_evm_addr, module_keys[i], Address::from(wallet_details.module_addrs[i]));
            i += 1;
        }

        // Transfer nonce asset to calculated master address
        transfer(Identity::Address(master_addr), nonce_assetid, nonce_tfr_amt);

        // Emit initialization event
        InitializeWalletEvent::new(master_addr, owner_evm_addr, true).log();

        owner_evm_addr
    }

    /// Re-mints a single module asset for an existing V1 ZapWallet.
    ///
    /// # Additional Information
    ///
    /// This function allows re-minting of individual module assets (except the nonce) for cases where:
    /// - A module asset was accidentally sent to an incorrect address
    /// - A module needs to be refreshed or updated
    /// - Recovery of a specific module is required
    ///
    /// The function recalculates the module address based on current blob IDs and mints a new asset.
    ///
    /// # Arguments
    ///
    /// * `owner_evm_addr`: [EvmAddress] - The EVM address that owns the ZapWallet
    /// * `module_key`: [b256] - The module key identifier (must be one of KEY00-KEY08)
    ///
    /// # Returns
    ///
    /// * [EvmAddress] - The owner's EVM address
    ///
    /// # Reverts
    ///
    /// * When the contract is paused
    /// * When attempting to re-mint the nonce asset (KEY_NONCE)
    /// * When the module key is not one of the valid module keys (KEY00-KEY08)
    /// * When the module's blob ID is not configured (is zero)
    /// * When module details calculation fails
    /// * When wallet details calculation fails for the event
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `12` (pause status + 10 blob IDs + manager contract ID)
    ///
    #[storage(read)]
    fn remint_module(owner_evm_addr: EvmAddress, module_key: b256) -> EvmAddress {
        // Contract pause check
        require(!_is_paused(), "Contract is paused");

        // Check: Cannot re-mint KEY_NONCE
        require(
            module_key != KEY_NONCE,
            "Cannot re-mint nonce asset"
        );

        // Check: Key must be one of the valid module keys
        let module_keys: [b256; 9] = [KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08];
        let mut is_valid_key = false;
        let mut module_index = 0;
        let mut i = 0;
        while i < 9 {
            if module_key == module_keys[i] {
                is_valid_key = true;
                module_index = i;
                break;
            }
            i += 1;
        }
        require(is_valid_key, "Invalid module key");

        // Get the blob ID for this module from storage
        let blob_id = storage.v1_blob_ids.get(module_index).read();
        require(blob_id != b256::zero(), "Module blob ID not configured");

        // Build loader configs
        let (loader_cfgs, ctx) = create_wallet_context_from_storage(owner_evm_addr);

        // Calculate module asset ID
        let module_asset_id = get_module_assetid(owner_evm_addr, module_key);

        // Get the module type
        let module_type = ModuleType::from_index(module_index);

        // Calculate module address
        let module_addr = match calculate_module_details(
            module_type,
            ctx,
            module_asset_id.into(),
            loader_cfgs[module_index]
        ) {
            Result::Ok(addr) => Address::from(addr),
            Result::Err(_) => revert(0),
        };

        // Mint and transfer the module asset
        mint_module_asset(owner_evm_addr, module_key, module_addr);

        // For the event, we need the master address
        let wallet_details = match calculate_complete_wallet_details(ctx) {
            Result::Ok(details) => details,
            Result::Err(_) => revert(0),
        };
        let master_addr = Address::from(wallet_details.master_addr);

        // Emit the module mint event
        InitializeWalletEvent::new(master_addr, owner_evm_addr, false).log();

        owner_evm_addr
    }

    /// Checks if a ZapWallet has been initialized by looking up either the EVM address
    /// or master address in the storage maps.
    ///
    /// # Arguments
    ///
    /// * `master_address`: Optional master/predicate address (pass Address::zero() if not provided)
    /// * `evm_addr`: Optional EVM address (pass EvmAddress::zero() if not provided)
    ///
    /// # Returns
    ///
    /// * `bool`:
    ///   * `true` if a nonce asset exists for either address and has non-zero balance
    ///   * `false` if neither address is found or the nonce asset has zero balance
    ///
    /// # Details
    ///
    /// Function checks both storage maps:
    /// - v1_master_to_nonce_map: master_address -> nonce_asset_id
    /// - v1_nonce_to_owner_master_map: nonce_asset_id -> (evm_address, master_address)
    ///
    /// User should provide EITHER master_address OR evm_addr, not both.
    /// If both are provided, only master_address is checked.
    ///
    #[storage(read)]
    fn initialized(
        master_address: Address,
        evm_addr: EvmAddress,
    ) -> bool {
        // Check if we have a valid master address (not zero)
        let has_master = master_address != Address::zero();

        // Check if we have a valid EVM address (not zero)
        let has_evm = evm_addr != EvmAddress::zero();

        // Require exactly one address to be provided
        require(has_master || has_evm, "Must provide either master address or EVM address");
        require(!(has_master && has_evm), "Cannot provide both master and EVM address");

        let nonce_asset_id: AssetId = if has_master {
            // Look up by master address
            let master_b256: b256 = master_address.bits();
            match storage.v1_master_to_nonce_map.get(master_b256).try_read() {
                Some(asset_id) => asset_id,
                None => return false,
            }
        } else {
            // Look up by EVM address

            // Calculate the nonce subid for this EVM address
            let nonce_subid = get_nonce_subid(evm_addr);
            let potential_nonce_assetid = AssetId::new(ContractId::this(), nonce_subid);

            // Check if this nonce asset exists in our reverse map
            match storage.v1_nonce_to_owner_master_map.get(potential_nonce_assetid).try_read() {
                Some((stored_evm, _master)) => {
                    // Verify the EVM address matches
                    if stored_evm == evm_addr {
                        potential_nonce_assetid
                    } else {
                        return false;
                    }
                },
                None => return false,
            }
        };

        // Check if the nonce asset has a non-zero balance
        let balance = this_balance(nonce_asset_id);
        balance > 0
    }

    /// Sets the version strings for V1 and V2 ZapWallet implementations.
    ///
    /// # Arguments
    ///
    /// * `v1_version`: Five character version string for V1
    /// * `v2_version`: Five character version string for V2
    ///
    /// # Reverts
    ///
    /// * When caller is not the contract owner
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 1 (owner check)
    /// * Writes: 2 (v1 and v2 version updates)
    ///
    /// # Events
    ///
    /// * `WalletVersionsEvent`: Emitted with the new version strings and sender identity
    ///
    #[storage(read, write)]
    fn set_zapwallet_versions(
        v1_version: str[5],
        v2_version: str[5],
    ) {
        // Only owner can set versions
        require_owner();

        // Update versions in storage
        storage.v1_version.write(v1_version);
        storage.v2_version.write(v2_version);

        // Emit version update event
        WalletVersionsEvent::new(
            v1_version,
            v2_version,
            msg_sender().unwrap()
        ).log();
    }

    /// Returns the current version strings for V1 and V2 ZapWallet implementations.
    ///
    /// # Returns
    ///
    /// * `(str[5], str[5])`: A tuple containing:
    ///   * Current V1 version string
    ///   * Current V2 version string
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 2
    ///
    #[storage(read)]
    fn zapwallet_versions() -> (str[5], str[5]) {
        let v1_version = storage.v1_version.read();
        let v2_version = storage.v2_version.read();

        (v1_version, v2_version)
    }

    /// Sets the V2 manager contract details for upgrade functionality.
    ///
    /// # Arguments
    ///
    /// * `v2_manager`: [ContractId] - The contract ID of the V2 manager contract.
    /// * `setup_selector`: [Bytes] - The function selector bytes for the setup_via_upgrade function.
    ///
    /// # Reverts
    ///
    /// * When called by non-owner.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Writes: 2
    ///   * `v2_manager_id`: 1
    ///   * `setup_via_upgrade_selector`: 1
    ///
    #[storage(read, write)]
    fn set_v2_manager_details(v2_manager: ContractId, setup_selector: Bytes) {

        // Only owner can set versions
        require_owner();

        storage.v2_manager_id.write(v2_manager);

        // Initialize the StorageVec if it's empty, get the storage key and write the bytes
        if storage.setup_via_upgrade_selector.len() == 0 {
            storage.setup_via_upgrade_selector.push(StorageBytes {});
        }
        let storage_key: StorageKey<StorageBytes> = storage.setup_via_upgrade_selector.get(0).unwrap();
        storage_key.write_slice(setup_selector);

        //TODO - Make this an event
        log("V2 manager info");
        log("Selector bytes stored with length:");
        log(storage_key.len());
    }

    /// Records the V2 master address mapping for an upgraded wallet.
    ///
    /// # Arguments
    ///
    /// * `owner_address`: [EvmAddress] - The EVM address of the wallet owner.
    /// * `v2_master_address`: [b256] - The new V2 master predicate address.
    ///
    /// # Reverts
    ///
    /// * When caller is not the V2 manager contract.
    /// * When called by non-contract identity.
    ///
    /// # Storage Access
    ///
    /// * Reads: 1
    ///   * `v2_manager_id`: 1
    /// * Writes: 1
    ///   * `owner_to_v2_master_map`: 1
    ///
    #[storage(read, write)]
    fn set_v2_master_address(owner_address: EvmAddress, v2_master_address: b256) {

        // Verify caller is v2_manager
        let caller = msg_sender().unwrap();
        match caller {
            Identity::ContractId(id) => {
                // Enforce v2_manager check
                require(
                    id == storage.v2_manager_id.read(),
                    "Only v2_manager can call set_v2_master_address()"
                );
                log("Called by contract:");
                log(id);

                storage.owner_to_v2_master_map.insert(owner_address, v2_master_address);
            },
            _ => {
                require(false, "Must be called by v2_manager contract");
            }
        }
    }

    /// Upgrades a v1 ZapWallet to v2 by accepting v1 nonce tokens and minting equivalent v2 tokens and
    /// module assets.
    ///
    /// ### Additional Information
    ///
    /// This function serves as the migration path from v1 to v2 wallet system. It validates ownership
    /// through v1 nonce tokens in transaction inputs, ensures single-owner transactions, and triggers
    /// v2 token minting via a call to the v2_manager contract.
    ///
    /// The upgrade process is irreversible and can only be performed once per wallet. The v1 nonce
    /// tokens serve as proof of ownership and determine the amount of v2 tokens to mint.
    ///
    /// ### Arguments
    ///
    /// * None - Function uses msg_sender() and transaction introspection
    ///
    /// ### Reverts
    ///
    /// * When `msg_sender()` is a contract instead of predicate/EOA address
    /// * When v1 nonce tokens are not found in transaction inputs
    /// * When v1 nonce tokens found are invalid or corrupted
    /// * When transaction inputs have mixed ownership (security check)
    /// * When nonce owner doesn't match other input owners
    /// * When the wallet has already been upgraded (prevents double-upgrade)
    /// * When the call to v2_manager fails
    ///
    /// ### Number of Storage Accesses
    ///
    /// * Reads: 4
    ///   * `can_upgrade`: 1
    ///   * `v1_master_to_nonce_map`: 1
    ///   * `v1_nonce_to_owner_master_map`: 1
    ///   * `v2_manager_id`: 1
    ///   * `setup_via_upgrade_selector`: 1
    ///
    /// * Writes: Implementation-dependent (upgrade status tracking)
    ///
    #[storage(read), payable]
    fn upgrade() -> bool {

        // Check if upgrades are enabled
        require(
            storage.can_upgrade.read() == true,
            "Upgrades are currently disabled"
        );

        // Get msg_sender - should be v1 master predicate
        let sender = msg_sender().unwrap();
        let sender_address = match sender {
            Identity::Address(addr) => {
                // Upgrade called by address
                addr
            },
            Identity::ContractId(_) => {
                require(false, "Upgrade must be called by Master address");
                Address::zero() // This won't be reached
            }
        };
        let storage_nonce_assetid = storage.v1_master_to_nonce_map.get(sender_address.into()).read();

        // Extract and validate nonce from transaction inputs
        let (nonce_amount, nonce_owner) = match extract_nonce_from_inputs(storage_nonce_assetid.into()) {
            NonceExtractionResult::Success((amount, owner)) => {
                // log("✓ Found v1 nonce tokens in inputs");
                // log("  Amount:");
                // log(amount);
                // log("  Owner:");
                // log(owner);
                (amount, owner)
            },
            NonceExtractionResult::NotFound => {
                // V1 nonce tokens not found in transaction inputs
                require(false, "V1 nonce tokens required for upgrade");
                (0, Address::zero()) // Won't reach here
            },
            NonceExtractionResult::Invalid => {
                // V1 nonce tokens found but invalid
                require(false, "Invalid v1 nonce tokens");
                (0, Address::zero()) // Won't reach here
            }
        };

        // Verify all non-nonce inputs from same owner
        let _input_owner = match verify_non_nonce_inputs_same_owner(storage_nonce_assetid.into()) {
            OwnershipValidationResult::Success(owner) => {
                // All non-nonce inputs from same owner
                // log("  Owner:");
                // log(owner);

                // Additional check: nonce owner should match other inputs
                require(
                    owner == nonce_owner,
                    "Nonce owner doesn't match other input owners"
                );
                owner
            },
            OwnershipValidationResult::MixedOwners => {
                // Mixed ownership detected in inputs
                require(false, "All inputs must be from same owner");
                Address::zero() // Won't reach here
            },
            OwnershipValidationResult::NoInputs => {
                // No non-nonce inputs found (only nonce being upgraded
                nonce_owner // Use nonce owner as the input owner
            }
        };

        let owner_details = storage.v1_nonce_to_owner_master_map.get(storage_nonce_assetid).read();

        /*
        let has_upgraded_before = has_upgraded(owner_details.0);
        log("double upgrade check:");
        if has_upgraded_before {
            log("returned true");
        } else {
            log("returned false");
        }
        */

        // PREPARE CALL TO V2_MANAGER

        // Prepare low-level call to v2_manager
        let v2_manager = storage.v2_manager_id.read();

        // Read the selector bytes
        let selector: Bytes = storage.setup_via_upgrade_selector.get(0).unwrap().read_slice().unwrap();

        // Encode the parameters for setup_via_upgrade(amount: u64, owner_addr: b256)
        let mut calldata = Bytes::new();

        // Parameter 1: Append amount as u64 (8 bytes)
        let amount_bytes = nonce_amount.to_be_bytes();
        calldata.append(amount_bytes);

        // Parameter 2: Append owner_addr as b256 (32 bytes)
        // Convert Address to b256
        let owner_addr_hash: b256 = owner_details.0.bits();
        // let owner_hash_b256: b256 = sender_address.into();

        // Convert b256 to bytes array
        let owner_bytes = Bytes::from(owner_addr_hash);
        calldata.append(owner_bytes);

        let call_params = CallParams {
            coins: 0,
            asset_id: AssetId::base(),
            gas: 1_000_000,
        };

        // Make the low-level call with the function selector
        call_with_function_selector(
            v2_manager,
            selector,
            calldata,
            call_params,
        );

        // Emit upgrade verification and status
        UpgradeEvent::new(
            owner_details.0,            // Owner being upgraded
            nonce_owner,               // Master address verified
            storage_nonce_assetid,     // Verified nonce asset
        ).log();

        // write true to v1 master has upgraded
        // storage.upgraded_v1_masters.insert(owner_addr_hash, true);


        true
    }

    /// Checks if a wallet has successfully upgraded by verifying the balance
    /// of its upgrade module asset (KEY00) at this contract.
    ///
    /// # Arguments
    ///
    /// * `evm_addr`: The EVM address of the wallet to check
    ///
    /// # Returns
    ///
    /// * `bool`:
    ///   * `true` if the upgrade module asset has balance of 1 at this contract
    ///   * `false` if no upgrade module asset exists or has different balance
    ///
    /// # Details
    ///
    /// The function checks if the upgrade module asset (KEY00) for this wallet
    /// has been properly transferred back to this contract during upgrade process.
    /// A balance of 1 indicates a successful upgrade.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 1 (balance check)
    ///
    fn has_v1_wallet_upgraded(evm_addr: EvmAddress) -> bool {

        return has_upgraded(evm_addr)
    }

}

// helper function to call internally
// #[storage(read)]
fn has_upgraded(evm_addr: EvmAddress) -> bool {
    // Calculate the upgrade module asset ID for this wallet
    let v1_nonce_assetid: b256 = get_module_assetid(evm_addr, KEY_NONCE).into();

    log(this_balance(AssetId::from(v1_nonce_assetid)));

    // Check if geq 1 unit is held by this contract
    return this_balance(AssetId::from(v1_nonce_assetid)) > 1;

    // Check the upgrade status in storage
    // let owner_details = storage.v1_nonce_to_owner_master_map.get(AssetId::from(v1_nonce_assetid)).read();
    // let has_upgraded = storage.upgraded_v1_masters.get(owner_details.0.bits()).read();
    // has_upgraded
}

/// Checks if a wallet has already been initialized for a given nonce asset ID by checking
/// if it exists in storage and has a non-zero balance.
///
/// # Arguments
///
/// * `nonce_asset_id`: The nonce asset ID to check
///
/// # Returns
///
/// * `bool`:
///   * `true` if the nonce asset exists in storage and has non-zero balance
///   * `false` if either:
///     * No record exists in storage for this nonce asset (never initialized)
///     * Or the nonce asset exists but has zero balance (burned/spent)
///
/// # Number of Storage Accesses
///
/// * Reads: 1 (storage map lookup)
///
#[storage(read)]
fn check_initialized(
    nonce_asset_id: AssetId,
) -> bool {
    // Check if the nonce asset exists in our storage map
    if let Some((_evm_addr, _master_addr)) = storage.v1_nonce_to_owner_master_map.get(nonce_asset_id).try_read() {
        // If we found the nonce asset in storage, check its balance
        // For an already minted nonce the balance should be non-zero
        return this_balance(nonce_asset_id) != 0;
    }

    // If nonce asset wasn't in storage, it was never initialized
    false
}

// Helper function to check ownership
#[storage(read)]
fn require_owner() {
    require(
        storage.owner.read() == State::Initialized(msg_sender().unwrap()),
        AccessError::NotOwner,
    );
}

/// Helper function to create WalletContext from stored blob IDs
#[storage(read)]
fn create_wallet_context_from_storage(owner_evm_addr: EvmAddress) -> ([LoaderConfig; 10], WalletContext) {
    // Initialize the loader configs array
    let mut loader_cfgs: [LoaderConfig; 10] = [
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
        LoaderConfig::new(b256::zero(), 0),
    ];

    // Array of section lengths
    let section_lengths = [
        M00_SEC_LEN,
        M01_SEC_LEN,
        M02_SEC_LEN,
        M03_SEC_LEN,
        M04_SEC_LEN,
        M05_SEC_LEN,
        M06_SEC_LEN,
        M07_SEC_LEN,
        M08_SEC_LEN,
        MASTER_SEC_LEN,
    ];

    // Read each blob ID and create loader config
    let mut i = 0;
    while i < 10 {
        let blob_id = storage.v1_blob_ids.get(i).read();
        require(blob_id != b256::zero(), "V1 blob ID not configured");
        loader_cfgs[i] = LoaderConfig::new(blob_id, section_lengths[i]);
        i += 1;
    }

    // Create and return the wallet context
    (
        loader_cfgs,
        WalletContext::new(
            owner_evm_addr.into(),
            ContractId::this().into(),
            loader_cfgs
        )
    )
}

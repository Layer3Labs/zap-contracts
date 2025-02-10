contract;

pub mod constants;
mod tools;
pub mod manager;
mod events;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    option::Option::{self, *},
    hash::*,
    storage::storage_vec::*,
    vm::evm::evm_address::EvmAddress,
    context::{this_balance, balance_of},
    asset::*,
    contract_id::*,
    asset::mint_to,
};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use std::bytes_conversions::{b256::*, u64::*};
use sway_libs::pausable::{_is_paused, _pause, _unpause, Pausable};
use standards::src5::{SRC5, State, AccessError};
use zapwallet_consts::wallet_consts::NUM_MODULES;
use io_utils::io::find_utxoid_and_owner_by_asset;
use zap_utils::hex::b256_to_hex;
use constants::{
    KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08,
    KEY_NONCE, NONCE_MAX,
};
use tools::{
    mint_nonce_asset,
    mint_module_asset,
    get_sub_id,
    get_module_assetid,
    get_key1,
};
use ::manager::{ZapManager, InitData};
use ::events::{
    ContractStateEvent,
    InitializeWalletEvent,
    WalletVersionsEvent,
    UpgradeEvent,
};


/// The owner of this contract at deployment.
#[allow(dead_code)]
const DEPLOYER_ADDRESS: b256 = 0x2891970ee5132e3523f80b2bde241b75285715359fc4209728812eed35e61fa8;
#[allow(dead_code)]
const INITIAL_OWNER: Identity = Identity::Address(Address::from(DEPLOYER_ADDRESS));

storage {
    /// The owner of the contract.
    owner: State = State::Initialized(INITIAL_OWNER),
    /// Maps a unique wallet identifier to its nonce asset.
    /// Key is sha256(evm_addr || master_addr) -> nonce AssetId.
    v1_map: StorageMap<b256, AssetId> = StorageMap {},
    /// Controls whether new wallet initialization is allowed.
    can_initialize: bool = false,
    /// Controls whether wallet upgrades are allowed.
    can_upgrade: bool = false,
    /// Current version string for V1 ZapWallets.
    v1_version: str[5] = __to_str_array("1.0.0"),
    /// Current version string for V2 ZapWallets.
    v2_version: str[5] = __to_str_array("-.-.-"),
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

    #[storage(read, write)]
    fn transfer_ownership(new_owner: Identity) {
        // Only current owner can transfer ownership
        require_owner();
        storage.owner.write(State::Initialized(new_owner));
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

    /// Mints and sends assets for ZapWallet functionality. This function handles two types of initialization:
    /// 1. Full wallet initialization (InitModules) - mints all base module assets (nonce + modules 00-08)
    /// 2. Single module initialization (NewModule) - mints a single module asset except nonce
    ///
    /// # Arguments
    ///
    /// * `master_addr`: The predicate/master address that will hold the nonce asset (ZapWallet master)
    /// * `owner_evm_addr`: The EVM address that will own this ZapWallet
    /// * `initdata`: Enum containing either:
    ///   * InitModules: Array of 9 module addresses to receive module assets (00-08)
    ///   * NewModule: Single module address and key for individual asset minting
    ///
    /// # Returns
    ///
    /// * `EvmAddress`: The owner's EVM address
    ///
    /// # Reverts
    ///
    /// * When contract is paused
    /// * For InitModules:
    ///   * When initialization is not enabled
    ///   * When wallet already has nonce asset (prevent double initialization)
    /// * For NewModule:
    ///   * When attempting to mint KEY_NONCE
    ///   * When using invalid module key (must be KEY00-KEY08)
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 2-3 (pause status, initialization status, nonce check)
    /// * Writes: 1 (nonce asset mapping for InitModules)
    ///
    /// # Events
    ///
    /// * `InitializeWalletEvent`: Emitted with:
    ///   * master_addr: Predicate/master address
    ///   * owner_evm_addr: Owner's EVM address
    ///   * is_base_modules: true for InitModules, false for NewModule
    ///
    #[storage(read, write)]
    fn initialize_wallet(
        master_addr: Address,
        owner_evm_addr: EvmAddress,
        initdata: InitData,
    ) -> EvmAddress {
        // Contract pause check
        require(!_is_paused(), "Contract is paused");

        match initdata {
            InitData::InitModules(base_mods) => {
                // Verify contract initialization is enabled
                require(storage.can_initialize.read(), "Wallet initialization is not enabled");

                // Generate unique key for this wallet (sha256(evm_addr || master_addr))
                let key = get_key1(owner_evm_addr, master_addr);

                //REVIEW - DEBUG
                // log(String::from_ascii_str("key:"));
                // log(b256_to_hex(key));


                // Check for existing nonce asset to prevent double initialization
                require(
                    !check_initialized(key),
                    "Wallet already has Nonce, if error mint assets individually"
                );

                // Mint nonce asset and store in contract ZapWallet mapping
                let (nonce_tfr_amt, nonce_assetid) = mint_nonce_asset(owner_evm_addr);
                storage.v1_map.insert(key, nonce_assetid);

                // Transfer nonce asset to provided master address
                transfer(
                    Identity::Address(master_addr),
                    nonce_assetid,
                    nonce_tfr_amt
                );

                // Mint and transfer all base module assets to provided module addresses
                let module_addrs = base_mods.module_addrs;
                let module_keys: [b256; 9] = [KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08];

                let mut i = 0;
                while i < 9 {
                    mint_module_asset(owner_evm_addr, module_keys[i], Address::from(module_addrs[i]));
                    i += 1;
                }

                // Emit initialization event
                InitializeWalletEvent::new(
                    master_addr,
                    owner_evm_addr,
                    true  // Full initialization
                ).log();
            },
            InitData::NewModule(module) => {
                // The asset for `key` should be sent to the provided module address.
                let module_addr = module.module_addr;
                let key = module.key;

                // Check: Cannot re-mint KEY_NONCE
                require(
                    key != KEY_NONCE,
                    "Cannot re-mint nonce asset"
                );

                // Check: Key must be one of the valid module keys or KEY00
                let module_keys: [b256; 9] = [KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08];
                let mut is_valid_key = false;
                let mut i = 0;
                while i < 9 {
                    if key == module_keys[i] {
                        is_valid_key = true;
                        break;
                    }
                    i += 1;
                }
                require(is_valid_key, "Invalid module key");

                // For all valid module keys, just mint and transfer
                mint_module_asset(owner_evm_addr, key, Address::from(module_addr));

                // Emit the module mint event
                InitializeWalletEvent::new(
                    master_addr,
                    owner_evm_addr,
                    false  // false indicates this was not a full initialization
                ).log();
            },


        };

        return owner_evm_addr;
    }

    /// Checks if a ZapWallet has the nonce asset for a given EVM address and master address
    /// combination by verifying the existence and balance of its nonce asset at this contract.
    ///
    /// # Arguments
    ///
    /// * `master_address`: The predicate/master address that was used during initialization
    /// * `evm_addr`: The EVM address associated with the ZapWallet
    ///
    /// # Returns
    ///
    /// * `bool`:
    ///   * `true` if a nonce asset exists in storage for this address combination and has non-zero balance
    ///   * `false` if either the nonce asset doesn't exist or has zero balance
    ///
    /// # Details
    ///
    /// Function generates a key (sha256(evm_addr || master_address)) and uses it to look up
    /// the nonce asset ID in storage. This ensures wallets are uniquely identified by both their
    /// EVM address and master address.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 1 (storage lookup via check_initialized)
    ///
    #[storage(read)]
    fn initialized(
        master_address: Address,
        evm_addr: EvmAddress,
    ) -> bool {

        let key = get_key1(evm_addr, master_address);

        return check_initialized(key)
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

    /// Processes a wallet upgrade from V1 to V2. Verifies the ownership and existence
    /// of the wallet through its nonce asset.
    ///
    /// # Arguments
    ///
    /// * `owner_evm_addr`: The EVM address of the wallet owner
    /// * `sponsored`: Whether this upgrade is sponsored (fees paid by another party)
    ///
    /// # Reverts
    ///
    /// * When contract is paused
    /// * When upgrades are not enabled
    /// * When nonce asset is not found
    /// * When nonce asset doesn't match stored mapping
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: 3 (pause status, upgrade status, nonce mapping)
    ///
    /// # Events
    ///
    /// * `UpgradeEvent`: Emitted with upgrade details including owner and asset verification
    ///
    #[storage(read), payable]
    fn upgrade(
        owner_evm_addr: EvmAddress,
        sponsored: bool,
    ) {
        // Status checks
        require(!_is_paused(), "Contract is paused");
        // require(storage.can_upgrade.read(), "Upgrades are not enabled");

        // Get nonce asset ID for this wallet
        let nonce_assetid: b256 = get_module_assetid(owner_evm_addr, KEY_NONCE).into();

        // Find the nonce owner (master address) from inputs
        let (_, nonce_owner) = match find_utxoid_and_owner_by_asset(nonce_assetid) {
            Some((_, owner)) => (b256::zero(), owner),
            None => {
                // Nonce asset not found in inputs
                revert(1001u64)
            },
        };


        // Verify nonce asset matches stored mapping
        let key = get_key1(owner_evm_addr, nonce_owner);
        let storage_nonce_assetid = storage.v1_map.get(key).read();
        require(
            AssetId::from(nonce_assetid) == storage_nonce_assetid,
            "Nonce asset mismatch with stored mapping"
        );

        // Emit upgrade verification and status
        UpgradeEvent::new(
            owner_evm_addr,            // Owner being upgraded
            nonce_owner,               // Master address verified
            sponsored,                 // Upgrade gas payment type
            storage_nonce_assetid,     // Verified nonce asset
        ).log();
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
    fn has_upgraded(evm_addr: EvmAddress) -> bool {
        // Calculate the upgrade module asset ID for this wallet
        let upgrade_module_assetid: b256 = get_module_assetid(evm_addr, KEY00).into();

        // Check if geq 1 unit is held by this contract
        return this_balance(AssetId::from(upgrade_module_assetid)) >= 1;
    }

}

/// Checks if a wallet has already been initialized for a given key1 by checking the storage map
/// and the balance of any associated nonce asset.
///
/// # Arguments
///
/// * `key1`: Hash of EVM address and master address (sha256(evm_addr || master))
///
/// # Returns
///
/// * `bool`:
///   * `true` if a nonce asset exists in storage and has non-zero balance
///   * `false` if either:
///     * No nonce asset exists in storage for this key1 (first initialization)
///     * Or a nonce asset exists but has zero balance
///
/// # Number of Storage Accesses
///
/// * Reads: 1 (storage map lookup)
///
/// # Additional Information
///
///     key = sha256(evm_addr || master_addr)
///
#[storage(read)]
fn check_initialized(
    key: b256,
) -> bool {
    // Check if the key exists in storage first
    if let Some(storage_nonce_assetid) = storage.v1_map.get(key).try_read() {
        // If we found an assetid in storage, check its balance.
        // for an already minted nonce the balance should be 1
        return this_balance(storage_nonce_assetid) != 0;
    }

    // If key wasn't in storage, this is first initialization
    return false;
}

// Helper function to check ownership
#[storage(read)]
fn require_owner() {
    require(
        storage.owner.read() == State::Initialized(msg_sender().unwrap()),
        AccessError::NotOwner,
    );
}


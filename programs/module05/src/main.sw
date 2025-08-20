predicate;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    hash::{keccak256},
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::{
        input_count,
        input_coin_owner,
    },
    outputs::{
        output_count,
        output_asset_to,
        output_asset_id,
    },
};
use std::primitive_conversions::{u16::*, u64::*};
use standards::src16::SRC16Payload;
use module05_utils::{
    io_utils::{verify_coin_output, verify_module_output, check_asset_exists, TransferAssetResult},
    native_transfer_v1::{
        NativeTransfer, get_domain_separator
    },
};
use zap_utils::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_output_change,
        verify_input_coin,
        verify_output_coin,
        output_coin_asset_id,
        output_coin_to,
        output_coin_amount,
    },
    blob_utils::*,
};
use io_utils::{
    io::{
        find_utxoid_and_owner_by_asset,
        InpOut, collect_inputs_outputs_change,
    },
    evmtx_io_utils::verify_change_output,
};
use zapwallet_consts::wallet_consts::*;


configurable {
    /// The address of the ZapWallet master owner.
    OWNER_ADDRESS: b256 = b256::zero(),
    /// The nonce native assetid ascoiated with the owners ZapWallet.
    NONCE_ASSETID: b256 = b256::zero(),
    /// This modules assetid as a b256.
    MODULE_KEY05_ASSETID: b256 = b256::zero(),
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
    /// Module Blob ID's as b256 values.
    M00_BLOB_ID: b256 = b256::zero(), M01_BLOB_ID: b256 = b256::zero(),
    M02_BLOB_ID: b256 = b256::zero(), M03_BLOB_ID: b256 = b256::zero(),
    M04_BLOB_ID: b256 = b256::zero(), M05_BLOB_ID: b256 = b256::zero(),
    M06_BLOB_ID: b256 = b256::zero(), M07_BLOB_ID: b256 = b256::zero(),
    M08_BLOB_ID: b256 = b256::zero(),
    /// Master Blob ID as a b256.
    MASTER_BLOB_ID: b256 = b256::zero(),
    /// V1 Zap Manager contract id as a b256
    V1_MANAGER_CID: b256 = b256::zero(),
}


/// Defines the sponsorship status of a transaction
///
/// # Additional Information
///
/// Used to determine whether a transaction is sponsored and if so, by whom
pub enum SponsorType {
    /// Represents an unsponsored transaction where the sender pays gas
    Unsponsored: (),
    /// Represents a sponsored transaction where a third party pays gas
    /// Contains the sponsor's address
    Sponsored: (b256),
}

/// Defines the type of asset being transferred
///
/// # Additional Information
///
/// Distinguishes between BASE_ASSET transfers and other native asset transfers
pub enum AssetType {
    /// Represents a transfer of the network's base asset
    Base: (),
    /// Represents a transfer of any other native asset
    /// Contains the asset's ID as 256 bits
    Native: (b256),
}

/// ZapWallet Module 05.
///
/// Validates native asset transfers, supporting both sponsored and unsponsored transactions.
///
/// # Additional Information
///
/// This predicate supports four types of transactions:
///
/// **Type 1: Non-Sponsored BASE_ASSET transfer (05A)**
/// - Inputs: BASE_ASSET (1 or more UTXOs)
/// - Outputs:
///   * [0] OutputChange of BASE_ASSET to sender
///   * [1] OutputCoin BASE_ASSET to transfer recipient
///   * [2] OutputCoin MODULE05_ASSET to Module05 address
///
/// **Type 2: Sponsored BASE_ASSET transfer (05B)**
/// - Inputs:
///   * BASE_ASSET (1 or more UTXOs) from sponsor
///   * BASE_ASSET (1 or more UTXOs) from sender
/// - Outputs:
///   * [0] OutputChange of BASE_ASSET to sponsor
///   * [1] OutputCoin BASE_ASSET to transfer recipient
///   * [2] OutputCoin BASE_ASSET to sender (remaining amount)
///   * [3] OutputCoin MODULE05_ASSET to sender
///
/// **Type 3: Non-Sponsored other asset transfer (05C)**
/// - Inputs:
///   * BASE_ASSET (1 or more UTXOs)
///   * TRANSFER_ASSET (1 or more UTXOs)
/// - Outputs:
///   * [0] OutputChange of BASE_ASSET to sender
///   * [1] OutputCoin TRANSFER_ASSET to transfer recipient
///   * [2] OutputChange of TRANSFER_ASSET to sender
///   * [3] OutputCoin MODULE05_ASSET to sender
///
/// **Type 4: Sponsored other asset transfer (05D)**
/// - Inputs:
///   * BASE_ASSET (1 or more UTXOs) from sponsor
///   * TRANSFER_ASSET (1 or more UTXOs) from sender
/// - Outputs:
///   * [0] OutputChange BASE_ASSET to sponsor
///   * [1] OutputCoin TRANSFER_ASSET to transfer recipient
///   * [2] OutputChange TRANSFER_ASSET to sender
///   * [3] OutputCoin MODULE05_ASSET to sender
///
/// # Arguments
///
/// * `signature`: [B512] - The owner's compact signature for transaction validation
/// * `transfer_asset`: [AssetType] - The type of asset being transferred (BASE_ASSET or other native asset)
/// * `sponsor_type`: [SponsorType] - The sponsorship status of the transaction and sponsor address if applicable
/// * `precomputed_modules` - Optional pre-calculated module asset IDs and addresses for the receiver's
///
/// # Returns
///
/// * [bool] - Returns true if the transaction is valid according to all rules and constraints
///
/// # Reverts
///
/// * When any input coin verification fails
/// * When the master predicate is used as a sponsor (invalid sponsor configuration)
/// * When the nonce asset is present in inputs (prevented by design)
/// * When input coins don't match expected ownership patterns based on transaction type
/// * When output structure doesn't match the expected pattern for the transaction type
/// * When transfer amount exceeds available input amount from sender
/// * When input coin owners don't match either the sender or sponsor addresses
/// * When input asset types don't match the transaction requirements
/// * When signature recovery fails or doesn't match the owner address
///
fn main(
    signature: B512,
    transfer_asset: AssetType,
    sponsor_type: SponsorType,
    precomputed_modules: Option<MasterConfigs>,
) -> bool {

    // Verify that there is no Nonce asset input(s).
    if !verify_no_nonce_assets() {
        return false;
    }

    let loader_cfgs = [
        LoaderConfig::new(M00_BLOB_ID, M00_SEC_LEN),
        LoaderConfig::new(M01_BLOB_ID, M01_SEC_LEN),
        LoaderConfig::new(M02_BLOB_ID, M02_SEC_LEN),
        LoaderConfig::new(M03_BLOB_ID, M03_SEC_LEN),
        LoaderConfig::new(M04_BLOB_ID, M04_SEC_LEN),
        LoaderConfig::new(M05_BLOB_ID, M05_SEC_LEN),
        LoaderConfig::new(M06_BLOB_ID, M06_SEC_LEN),
        LoaderConfig::new(M07_BLOB_ID, M07_SEC_LEN),
        LoaderConfig::new(M08_BLOB_ID, M08_SEC_LEN),
        LoaderConfig::new(MASTER_BLOB_ID, MASTER_SEC_LEN),
    ];

    // Create receiver context
    let owner_zapwallet_ctx = WalletContext::new(OWNER_ADDRESS, V1_MANAGER_CID, loader_cfgs);

    // Calculate the owner wallet details
    let owner_wallet_details = match precomputed_modules {
        Some(configs) => {
            // Fast path: use pre-calculated module configurations
            match calculate_wallet_details_fast_path(owner_zapwallet_ctx, configs) {
                Result::Ok(details) => details,
                Result::Err(_) => return false,
            }
        },
        None => {
            // Slow path: calculate everything from scratch
            match calculate_complete_wallet_details(owner_zapwallet_ctx) {
                Result::Ok(details) => details,
                Result::Err(_) => return false,
            }
        }
    };

    let owner_zapwallet_addr = owner_wallet_details.master_addr;

    // Find module05 owner and transaction utxoid
    let (utxo_id, module05_owner) = match find_utxoid_and_owner_by_asset(MODULE_KEY05_ASSETID) {
        Some((utxoid, owner)) => {
            (utxoid, owner)
        },
        None => {
            //TODO - Handle the case where module05's asset input was not found
            (b256::zero(), Address::zero())
        }
    };

    // If this is a sponsored transaction, the gas payer will be the sponsor address passed in through
    // as a parameter. Otherwise its the master predicate.
    let (gas_payer, is_sponsored) = if let SponsorType::Sponsored(sponsor_address) = sponsor_type {
        // The master predicate cannot be used as a sponsor
        assert(sponsor_address != owner_zapwallet_addr);

        (sponsor_address, true)
    } else {
        (owner_zapwallet_addr, false)
    };

    // The Asset ID to be transferred is taken from the parameters, it is either the
    // BASE_ASSET or the passed in asset id.
    let transfer_asset_id = match transfer_asset {
        AssetType::Base => FUEL_BASE_ASSET,
        AssetType::Native(asset_id) => {
            // The base asset cannot be used with the Native transaction type
            assert(asset_id != FUEL_BASE_ASSET);
            asset_id
        }
    };

    // Tracks the amount of the asset_id to be transferred that was input by the sender.
    let mut transfer_asset_amount_input: u64 = 0;

    // Iterate through all inputs and ensure that they are valid
    let mut i = 0;
    let n_inputs: u64 = input_count().into();

    while (i < n_inputs) {
        assert(verify_input_coin(i));
        let coin_owner = input_coin_owner(i).unwrap();
        let coin_asset_id = input_coin_asset_id(i);
        let coin_asset_amount = input_coin_amount(i);

        // Only process non-MODULE05_ASSET inputs
        if (coin_asset_id != MODULE_KEY05_ASSETID) {
            // Non-owner input validation path
            // If a coin doesn't come from the master predicate, it needs
            // to have come from the gas sponsor and be a base asset
            if (coin_owner != Address::from(owner_zapwallet_addr)) {
                assert(
                    is_sponsored &&
                    coin_owner == Address::from(gas_payer) &&
                    coin_asset_id == FUEL_BASE_ASSET
                );
            // Otherwise if it came from the master predicate it needs
            // to be either base or native, depending on the transaction type
            } else {
                match (transfer_asset, sponsor_type) {
                    // Base asset transfer validation
                    // If this is a base asset trx, regardless of sponsorship, it can only be FUEL_BASE_ASSET
                    (AssetType::Base, _) => {
                        assert(coin_asset_id == FUEL_BASE_ASSET);
                        transfer_asset_amount_input = transfer_asset_amount_input + coin_asset_amount;
                    },
                    // Unsponsored native asset transfer validation
                    // If this is an unsponsored native trx it can be either the base asset
                    // or the native asset
                    (AssetType::Native(asset_id), SponsorType::Unsponsored) => {
                        assert(
                            coin_asset_id == FUEL_BASE_ASSET ||
                            coin_asset_id == asset_id
                        );
                        if (coin_asset_id == asset_id) {
                            transfer_asset_amount_input = transfer_asset_amount_input + coin_asset_amount;
                        }
                    },
                    // Sponsored native asset transfer validation
                    // If this is a sponsored native transaction it can only be the native asset
                    (AssetType::Native(asset_id), SponsorType::Sponsored(_)) => {
                        assert(coin_asset_id == asset_id);
                        transfer_asset_amount_input = transfer_asset_amount_input + coin_asset_amount;
                    }
                }
            }
        }
        i += 1;
    }

    // The receiver address, the receiver amount
    let mut transfer_receiver: (b256, u64) = (b256::zero(), 0);

    // Collect transaction inputs, outputs and change.
    let (tx_inputs, tx_outputs, tx_change) = collect_inputs_outputs_change();

    //REVIEW - THIS IN THE MASTER ANYWAY
    // Verify that there is the Module Coin or Change Output with correct credentials
    if !verify_module_output(
        tx_inputs,
        tx_change,
        MODULE_KEY05_ASSETID,
        module05_owner
    ) { return false; }

    // The transfer_asset is the AssetID of the asset being transfered.
    match (transfer_asset, sponsor_type) {
        (AssetType::Base, SponsorType::Unsponsored) => {
            // find change output and verify that its BASE_ASSET and back to owner
            if !verify_change_output(
                tx_change,
                FUEL_BASE_ASSET,
                Address::from(owner_zapwallet_addr)
            ) { return false; }

            // find the Base Asset receiver and amount as an explicit CoinOutput in the tx_outputs vector
            let mut ignorelist: Vec<Address> = Vec::new();
            ignorelist.push(Address::from(owner_zapwallet_addr));
            let check_asset_result = check_asset_exists(
                tx_outputs,
                FUEL_BASE_ASSET,
                ignorelist,
            );

            transfer_receiver = match check_asset_result {
                TransferAssetResult::Success((owner, amount)) => (owner.into(), amount),
                TransferAssetResult::Fail(_error_code) => { return false; }
            };
            // Verify the transfer amount doesn't exceed what the owner put in
            assert(transfer_receiver.1 <= transfer_asset_amount_input);
        },
        (AssetType::Base, SponsorType::Sponsored(_)) => {
            // Verify change output goes to sponsor (gas_payer)
            if !verify_change_output(
                tx_change,
                FUEL_BASE_ASSET,
                Address::from(gas_payer)
            ) { return false; }

            // Find the Base Asset transfer to recipient (excluding owner, sponsor, and module05)
            let mut ignorelist: Vec<Address> = Vec::new();
            ignorelist.push(Address::from(owner_zapwallet_addr));
            ignorelist.push(Address::from(gas_payer));
            ignorelist.push(module05_owner); // Also ignore module05 owner

            let check_asset_result = check_asset_exists(
                tx_outputs,
                FUEL_BASE_ASSET,
                ignorelist,
            );

            transfer_receiver = match check_asset_result {
                TransferAssetResult::Success((owner, amount)) => (owner.into(), amount),
                TransferAssetResult::Fail(_error_code) => { return false; }
            };

            // Verify the transfer amount doesn't exceed what the owner put in
            assert(transfer_receiver.1 <= transfer_asset_amount_input);

            // Verify the owner receives back the difference as a Coin output
            let expected_return_to_owner = transfer_asset_amount_input - transfer_receiver.1;

            // Only check for return if there's actually a difference
            if expected_return_to_owner > 0 {
                if !verify_coin_output(
                    tx_outputs,
                    FUEL_BASE_ASSET,
                    Address::from(owner_zapwallet_addr),
                    expected_return_to_owner
                ) { return false; }
            }
        },
        (AssetType::Native(asset_id), SponsorType::Unsponsored) => {
            // Verify BASE_ASSET change output goes back to owner (who pays gas)
            if !verify_change_output(
                tx_change,
                FUEL_BASE_ASSET,
                Address::from(owner_zapwallet_addr)
            ) { return false; }

            // Verify NATIVE asset change output also goes back to owner
            if !verify_change_output(
                tx_change,
                asset_id,
                Address::from(owner_zapwallet_addr)
            ) { return false; }

            // Find the Native Asset transfer to recipient
            let mut ignorelist: Vec<Address> = Vec::new();
            ignorelist.push(Address::from(owner_zapwallet_addr));
            ignorelist.push(module05_owner); // Ignore module05 owner

            let check_asset_result = check_asset_exists(
                tx_outputs,
                asset_id,
                ignorelist,
            );

            transfer_receiver = match check_asset_result {
                TransferAssetResult::Success((owner, amount)) => (owner.into(), amount),
                TransferAssetResult::Fail(_error_code) => { return false; }
            };
            // Verify the transfer amount doesn't exceed what the owner put in
            assert(transfer_receiver.1 <= transfer_asset_amount_input);
        },
        (AssetType::Native(asset_id), SponsorType::Sponsored(_)) => {
            // Verify BASE_ASSET change output goes to sponsor (who pays gas)
            if !verify_change_output(
                tx_change,
                FUEL_BASE_ASSET,
                Address::from(gas_payer)  // Sponsor gets BASE change, not owner
            ) { return false; }

            // Verify NATIVE asset change output goes back to owner
            if !verify_change_output(
                tx_change,
                asset_id,
                Address::from(owner_zapwallet_addr)
            ) { return false; }

            // Find the Native Asset transfer to recipient
            let mut ignorelist: Vec<Address> = Vec::new();
            ignorelist.push(Address::from(owner_zapwallet_addr));
            ignorelist.push(Address::from(gas_payer));  // Also ignore sponsor
            ignorelist.push(module05_owner); // Ignore module05 owner

            let check_asset_result = check_asset_exists(
                tx_outputs,
                asset_id,
                ignorelist,
            );

            transfer_receiver = match check_asset_result {
                TransferAssetResult::Success((owner, amount)) => (owner.into(), amount),
                TransferAssetResult::Fail(_error_code) => { return false; }
            };
            // Verify the transfer amount doesn't exceed what the owner put in
            assert(transfer_receiver.1 <= transfer_asset_amount_input);
        },
    }

    // Reconsrust signed transaction params
    let reconstructed_native_transfer = NativeTransfer {
        assetid: transfer_asset_id,
        amount: asm(r1: (0, 0, 0, transfer_receiver.1)) { r1: u256 },
        from: owner_zapwallet_addr,
        to: transfer_receiver.0,
        maxtxcost: asm(r1: (0, 0, 0, 0)) { r1: u256 },
        utxoid: utxo_id,
    };
    let struct_hash = reconstructed_native_transfer.struct_hash();
    let payload = SRC16Payload {
        domain: get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => { return false; },
    };
    let recovered_adderss = match ec_recover_evm_address(signature, encoded_hash) {
        Ok(signer) => signer,
        Err(_) => { return false; }
    };

    return (recovered_adderss == EvmAddress::from(OWNER_ADDRESS));
}

/// Verifies that no inputs consume the nonce asset associated with this ZapWallet.
///
/// # Returns
///
/// * [bool] - False if a nonce asset input is found, true otherwise.
///
/// # Additional Information
///
/// This validation ensures that nonce assets can only be consumed through
/// the use of other Zap modules specifically designed to handle nonce inputs
/// and outputs. This preventing unauthorized spending of nonce assets even
/// with a valid signature.
///
fn verify_no_nonce_assets() -> bool {
    let in_count: u64 = input_count().into();
    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let coin_asset_id = input_coin_asset_id(i);
            if (coin_asset_id == NONCE_ASSETID) {
                return false;
            }
        }
        i += 1;
    }

    return true;
}

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
    },
};
use std::primitive_conversions::{u16::*, u64::*};
use standards::src16::SRC16Payload;
use module05_utils::native_transfer::{
    NativeTransfer, get_domain_separator
};
use zap_utils::{
    merkle_utils::{MerkleUtils, V1Predicate},
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_output_change,
        verify_input_coin,
        verify_output_coin,
        output_coin_asset_id,
        output_coin_to,
        output_coin_amount,
    }
};
use io_utils::io::find_utxoid_and_owner_by_asset;
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;


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
/// A native transfer predicate that handles both sponsored and unsponsored transactions
/// for transferring BASE_ASSET or other native assets on the Fuel Network.
///
/// # Additional Information
///
/// This predicate supports four types of transactions:
/// 1. Non-Sponsored BASE_ASSET transfer
///    - Inputs: BASE_ASSET (1 or more UTXOs)
///    - Outputs:
///      * OutputChange of BASE_ASSET to sender
///      * OutputCoin BASE_ASSET to transfer recipient
///      * OutputCoin MODULE05_ASSET to sender
///
/// 2. Non-Sponsored other asset transfer
///    - Inputs:
///      * BASE_ASSET (1 or more UTXOs)
///      * TRANSFER_ASSET (1 or more UTXOs)
///    - Outputs:
///      * OutputChange of BASE_ASSET to sender
///      * OutputCoin TRANSFER_ASSET to transfer recipient
///      * OutputChange of TRANSFER_ASSET to sender
///      * OutputCoin MODULE05_ASSET to sender
///
/// 3. Sponsored BASE_ASSET transfer
///    - Inputs:
///      * BASE_ASSET (1 or more UTXOs) from sponsor
///      * BASE_ASSET (1 or more UTXOs) from sender
///    - Outputs:
///      * OutputChange of BASE_ASSET to sponsor
///      * OutputCoin BASE_ASSET to transfer recipient
///      * OutputCoin BASE_ASSET to sender (remaining amount)
///      * OutputCoin MODULE05_ASSET to sender
///
/// 4. Sponsored other asset transfer
///    - Inputs:
///      * BASE_ASSET (1 or more UTXOs) from sponsor
///      * TRANSFER_ASSET (1 or more UTXOs) from sender
///    - Outputs:
///      * OutputChange BASE_ASSET to sponsor
///      * OutputCoin TRANSFER_ASSET to transfer recipient
///      * OutputChange TRANSFER_ASSET to sender
///      * OutputCoin MODULE05_ASSET to sender
///
/// Each transaction type has specific input and output requirements that must be met
/// for the predicate to validate successfully.
///
/// # Arguments
///
/// * `signature`: [B512] - The owners compact signature for transaction validation
/// * `transfer_asset`: [AssetType] - The type of asset being transferred (BASE_ASSET or other native asset)
/// * `sponsor_type`: [SponsorType] - The sponsorship status of the transaction and sponsor address if applicable
/// * `sender_wallet_bytecode`: [Bytes] - The bytecode of the sender's ZapWallet (see additional information)
///
/// # Returns
///
/// * [bool] - Returns true if the transaction is valid according to all rules and constraints
///
/// # Fails
///
/// * When the master predicate is used as a sponsor (invalid sponsor configuration)
/// * When input coins don't match expected ownership patterns based on transaction type
/// * When output structure doesn't match the expected pattern for the transaction type
/// * When transfer amount exceeds available input amount from sender
/// * When input coin owners don't match either the sender or sponsor addresses
/// * When input asset types don't match the transaction requirements
///
/// # Additional Information
///
/// additional infor about bytecode setup
///
fn main(
    signature: B512,
    transfer_asset: AssetType,
    sponsor_type: SponsorType,
    sender_wallet_bytecode: Bytes,
) -> bool {

    // Verify that there is no Nonce asset input(s).
    if !verify_no_nonce_assets() {
        return false;
    }

    // Calculate the senders v1 predicate address
    // Specific bytecode bytes from receivers zapwallet master.
    let mut sender_bytecode = sender_wallet_bytecode;
    let v1_predicate = V1Predicate::new();
    let owner_zapwallet_addr = v1_predicate.calculate_predicate_address(
        sender_bytecode,
        OWNER_ADDRESS
    );

    // Find module05 owner and transaction utxoid
    let (utxo_id, _module05_owner) = match find_utxoid_and_owner_by_asset(MODULE_KEY05_ASSETID) {
        Some((utxoid, owner)) => {
            (utxoid, owner)
        },
        None => {
            //TODO - Handle the case where module05's asset input was not found
            (b256::zero(), Address::zero())
        }
    };

    // ---------- PROCESS PARAMETERS ------------

    // If this is a sponsored trx, the gas payer will be the sponsor address passed in through
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

    // ---------- PROCESS AND VERIFY INPUTS ------------

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

        // Ignore asset_id coin
        if (coin_asset_id == MODULE_KEY05_ASSETID) {
            continue;
        // If a coin doesnt come from the master predicate, it needs
        // to have come from the gas sponsor and be a base asset
        } else if (coin_owner != Address::from(owner_zapwallet_addr)) {
            assert(
                is_sponsored &&
                coin_owner == Address::from(gas_payer) &&
                coin_asset_id == FUEL_BASE_ASSET
            );
        // Otherwise if it came from the master predicate it needs
        // to be either base or native, depending on the transaction type
        } else {
            match (transfer_asset, sponsor_type) {
                // If this is a base asset trx, regardless of sponsorship, it can only be FUEL_BASE_ASSET
                (AssetType::Base, _) => {
                    assert(coin_asset_id == FUEL_BASE_ASSET);
                    transfer_asset_amount_input = transfer_asset_amount_input + coin_asset_amount;
                },
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
                // If this is a sponsored native trx it can only be the native asset
                (AssetType::Native(asset_id), SponsorType::Sponsored(_)) => {
                    assert(coin_asset_id == asset_id);
                    transfer_asset_amount_input = transfer_asset_amount_input + coin_asset_amount;
                }
            }
        }

        i = i + 1;
    }

    // ---------- PROCESS AND VERIFY OUTPUTS ------------

    // If this is a non sponsored base asset transfer there will be three outputs. Otherwise
    // in all cases there will be four outputs
    let expected_outputs: u64 = match (transfer_asset, sponsor_type) {
        (AssetType::Base, SponsorType::Unsponsored) => 3,
        _ => 4,
    };
    assert(output_count().as_u64() == expected_outputs);

    // The first output is always a ChangeOutput of BASE_ASSET back to the gas payer.
    assert(output_coin_asset_id(0).unwrap() == FUEL_BASE_ASSET);
    assert(output_coin_to(0) == gas_payer);
    if !verify_output_change(0).unwrap() { return false; }

    // In all cases the second output should be a coin output to the transfer recipient
    // with asset id of the asset to be transferred
    if !verify_output_coin(1) { return false; }
    assert(output_coin_asset_id(1).unwrap() == FUEL_BASE_ASSET);

    let transfer_amount = output_coin_amount(1);
    let transfer_to = output_coin_to(1);

    // Require that the owner master sent at least enough of the asset to be transferred
    // to cover the transfer.
    assert(transfer_amount <= transfer_asset_amount_input);

    match (transfer_asset, sponsor_type) {
        // If the transaction is a base transfer and it is sponsored, the third output
        // will be an OutputCoin of the base asset with amount of the total eth they
        // sent in as input minus the amount that was transferred
        (AssetType::Base, SponsorType::Sponsored(_)) => {
            let expected_value: u64 = transfer_asset_amount_input - transfer_amount;

            if !verify_output_coin(2) { return false; }
            assert(output_coin_asset_id(2).unwrap() == FUEL_BASE_ASSET);
            assert(output_coin_amount(2) == expected_value);
            assert(output_coin_to(2) == owner_zapwallet_addr);


        },
        // If the transaction is a native transfer the third output will be an OutputChange
        // of the native asset_id back to the sender
        (AssetType::Native(asset_id), _) => {

            if !verify_output_change(0).unwrap() { return false; }
            assert(output_coin_asset_id(2).unwrap() == asset_id);
            assert(output_coin_to(2) == owner_zapwallet_addr);

        },
        // Otherwise do nothing (third output is the module 05 asset handled by the master)
        _ => {}
    }

    // Checking the remaining module 05 master is handled by the master predicate

    // ---------- RECONSTRUCT AND VERIFY 712 SIGNATURE  ------------

    let reconstructed_native_transfer = NativeTransfer {
        Asset_Id: transfer_asset_id,
        Amount: asm(r1: (0, 0, 0, transfer_amount)) { r1: u256 },
        From: owner_zapwallet_addr,
        To: transfer_to,
        Max_Tx_Cost: asm(r1: (0, 0, 0, 0)) { r1: u256 },
        Utxo_ID: utxo_id,
    };
    let struct_hash = reconstructed_native_transfer.struct_hash();
    let payload = SRC16Payload {
        domain: get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    let recovered_adderss = ec_recover_evm_address(signature, encoded_hash).unwrap();

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

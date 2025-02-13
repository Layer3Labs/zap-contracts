library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    hash::*,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::input_coin_owner,
    outputs::{
        output_asset_id,
        output_asset_to,
        // Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use standards::{ src16::{ SRC16Base, EIP712, EIP712Domain, DomainHash, TypedDataHash, DataEncoder, SRC16Payload, SRC16Encode } };
use zapwallet_consts::wallet_consts::FUEL_BASE_ASSET;
use zap_utils::{
    rlp_helpers::bytes_read_b256,
    transaction_utls::{ input_coin_amount, input_coin_asset_id, output_coin_asset_id, verify_input_coin, verify_input_contract, verify_output_change, input_txn_hash, },
};


/// A ZapWallet master operation.
pub struct WalletOp {
    /// The Ethereum address associated with this operation
    pub evm_addr: b256,
    /// The compact signature bytes for the operation
    pub compsig: Bytes,
    /// The command string to execute
    pub command: String,
}

/// This struct is used for EIP712 typed data signing and verification
/// during wallet initialization.
///
pub struct Initialization {
    /// The command string identifying the initialization operation
    pub command: String,
    /// The Ethereum address to associate with this wallet
    pub evmaddr: b256,
    /// The UTXO ID used in the initialization transaction
    pub utxoid: b256,
}

impl Initialization {

    pub fn new( command: String, evmaddr: b256, utxoid: b256, ) -> Initialization { Initialization { command, evmaddr, utxoid } }

}

/// The Keccak256 hash of the type Initialization as UTF8 encoded bytes.
///
/// "Initialization(string command,bytes32 evmaddr,bytes32 utxoid)"
///
/// 08d5b62c7103e6be4fc2b983b884488c8f966e443b73813750cf3f724dcc1bd1
///
const INITIALIZE_ZAPWALLET_TYPE_HASH: b256 = 0xa26c68f9751fd3f7eaffd4edc8cd9601ce5b772d61f68c74357f105a338871b1;

impl TypedDataHash for Initialization {

    fn type_hash() -> b256 {
        INITIALIZE_ZAPWALLET_TYPE_HASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        encoded.append( INITIALIZE_ZAPWALLET_TYPE_HASH.to_be_bytes() );
        encoded.append( DataEncoder::encode_string(self.command).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.evmaddr).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.utxoid).to_be_bytes() );
        keccak256(encoded)
    }
}

/// Implementation of the SRC16 encode function for Initialization
impl SRC16Encode<Initialization> for Initialization {

    fn encode(s: Initialization) -> b256 {
        // encodeData hash
        let data_hash = s.struct_hash();
        // setup payload
        let payload = SRC16Payload { domain: _get_domain_separator(), data_hash: data_hash, };

        // Get the final encoded hash
        match payload.encode_hash() {
            Some(hash) => hash,
            None => revert(0),
        }
    }
}

fn _get_domain_separator() -> EIP712Domain {

    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;

    EIP712Domain::new( String::from_ascii_str("ZapWallet"), String::from_ascii_str("1"), (asm(r1: (0, 0, 0, 9889)) { r1: u256 }), verifying_contract.into() )
}

/// Validates the initialization transaction structure and signature.
///
/// # Arguments
///
/// * `in_count`: [u64] - Number of transaction inputs
/// * `out_count`: [u64] - Number of transaction outputs
/// * `op`: [WalletOp] - The wallet operation to verify
/// * `owner_address`: [b256] - The owner's public key to verify against
///
/// # Returns
///
/// * [bool] - True if initialization is valid, false otherwise
///
pub fn verify_init_struct(in_count: u64, out_count: u64, op: WalletOp, owner_address: b256) -> bool {

    // Check there is only two inputs, one for contract, and one for gas
    // Check there exists an output change of base asset and no other
    // base asset outputs.
    let (inpok, utxoid, change_to) = check_inputs(in_count);
    let chgok = check_change(out_count, change_to);
    if inpok && chgok {
        // compact signature reconstruct from parts
        let mut ptr: u64 = 0;
        let (cs_lhs, ptr) = bytes_read_b256(op.compsig, ptr, 32);
        let (cs_rhs, _ptr) = bytes_read_b256(op.compsig, ptr, 32);
        let compactsig = B512::from((cs_lhs, cs_rhs));

        let init = Initialization::new( String::from_ascii_str("ZapWalletInitialize"), op.evm_addr, utxoid, );
        let encoded_hash = Initialization::encode(init);
        let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();

        return (recovered_signer == owner_address);
    } else {
        return false;
    }

}

/// Verifies transaction inputs and returns relevant information.
/// Requirements:
/// 1. Exactly two inputs
/// 2. One Coin input with FUEL_BASE_ASSET
/// 3. One Contract input
///
/// # Arguments
/// * `in_count`: Number of inputs in the transaction
///
/// # Returns
/// * `(bool, b256, b256)`: (valid inputs, coin input UTXO ID, coin owner)
///
pub fn check_inputs(in_count: u64) -> (bool, b256, b256) {
    // Early return if not exactly 2 inputs
    if in_count != 2 {
        return (false, b256::zero(), b256::zero());
    }

    let mut coin_found = false;
    let mut contract_found = false;
    let mut utxo_id = b256::zero();
    let mut owner = b256::zero();

    let mut i = 0;
    while i < 2 {
        // Check for coin input
        if verify_input_coin(i) {
            // Return false if we already found a coin input or asset isn't FUEL_BASE_ASSET
            if coin_found || input_coin_asset_id(i) != FUEL_BASE_ASSET {
                return (false, b256::zero(), b256::zero());
            }
            coin_found = true;
            utxo_id = input_txn_hash(i);
            owner = input_coin_owner(i).unwrap().into();
        }
        // Check for contract input
        else if verify_input_contract(i) {
            // Return false if we already found a contract input
            if contract_found { return (false, b256::zero(), b256::zero()); }
            contract_found = true;
        }
        i += 1;
    }

    // Return true only if we found exactly one coin and one contract
    (coin_found && contract_found, utxo_id, owner)
}

/// Checks if the transaction has valid change output configuration
/// Returns true only if:
/// 1. Exactly one change output exists
/// 2. Change asset is FUEL_BASE_ASSET
/// 3. Change recipient matches change_to address
///
pub fn check_change(out_count: u64, change_to: b256) -> bool {
    let mut found_valid_change = false;

    // Early return if no outputs
    if out_count == 0 {
        return false;
    }

    let mut i = 0;
    while i < out_count {
        // Check if this output is marked as change
        if let Some(true) = verify_output_change(i) {
            // If we already found a valid change output, this is a second one - fail
            if found_valid_change {
                return false;
            }

            // Get asset ID and recipient for this change output
            let asset_id: b256 = match output_asset_id(i) {
                Some(id) => id.into(),
                None => return false,
            };

            let recipient: b256 = match output_asset_to(i) {
                Some(addr) => addr.into(),
                None => return false,
            };

            // Check if this change output meets all criteria
            if asset_id == FUEL_BASE_ASSET && recipient == change_to {
                found_valid_change = true;
            } else {
                return false;
            }
        }
        i += 1;
    }

    found_valid_change
}
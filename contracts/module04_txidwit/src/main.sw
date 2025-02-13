predicate;

use std::{ b512::B512, bytes::Bytes, tx::{tx_id, tx_witness_data}, vm::evm::ecr::ec_recover_evm_address, inputs::input_count };
use io_utils::io::verify_no_nonce_assets;
use zap_utils::{ personal_sign::personal_sign_hash, transaction_utls::{verify_input_coin, input_coin_asset_id} };


configurable {
    /// The address of the ZapWallet master owner.
    OWNER_ADDRESS: b256 = b256::zero(),
    /// The nonce native assetid ascoiated with the owners ZapWallet.
    NONCE_ASSETID: b256 = b256::zero(),
    /// Compile version identifier into bytecode.
    #[allow(dead_code)]
    VERSION: b256 = b256::zero(),
}


/// ZapWallet Module 04.
///
/// This predicate verifies that a transaction id has been witnessed by the owner.
/// It uses EIP-191 personal sign format for signature verification.
///
/// # Arguments
///
/// * `witness_index`: u64 - The index of the witness data containing the signature.
///
/// # Returns
///
/// * `bool` - True if the signature is valid and matches the configured signer, false otherwise.
///
/// # Description
///
/// The main function performs the following steps:
///
/// 1. Verifies that there is no inputs that are of type NONCE_ASSETID for the owners ZapWallet.
/// 2. Retrieves the signature from the transaction's witness data.
/// 3. Computes the personal sign hash of the txid.
/// 4. Attempts to recover the EVM signers (padded) pubkey from the signature and hash.
/// 5. Compares the recovered address with the configured owner address.
/// 6. Returns true if they match, false otherwise.
///
/// # References:
/// see: https://github.com/FuelLabs/fuel-connectors/blob/main/packages/evm-predicates/predicate/src/main.sw
///
fn main(witness_index: u64) -> bool {

    // Verify that there is no Nonce asset input(s).
    if !verify_no_nonce_assets(NONCE_ASSETID) {
        return false;
    }

    let signature: B512 = tx_witness_data(witness_index).unwrap();
    let result = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));
    if result.is_ok() {
        if OWNER_ADDRESS == result.unwrap().into() {
            return true;
        }
    }

    return false;
}

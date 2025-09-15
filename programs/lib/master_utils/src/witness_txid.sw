library;

use std::*;
use ::types::*;
use ::tools::verify_no_nonce_assets;
use std::{
    b512::B512,
    bytes::Bytes,
    tx::{tx_id, tx_witness_data},
    vm::evm::ecr::ec_recover_evm_address,
};
use zap_utils::personal_sign::personal_sign_hash;


/// Verifies that a transaction has been witnessed by the wallet owner using EIP-191 signature.
///
/// ### Additional Information
///
/// Implements signature verification using the EIP-191 personal sign format, which is the
/// standard for Ethereum wallet signatures. This ensures compatibility with existing EVM
/// wallets and signing infrastructure.
///
/// The function first checks that no nonce assets are being consumed (security measure),
/// then verifies the signature against the transaction ID.
///
/// ### Arguments
///
/// * `op` - [WalletOp] - Operation containing optional witness index override
/// * `owner_address` - [b256] - Expected signer's address (EVM address as b256)
/// * `v1_manager_id` - [b256] - V1 manager contract address for nonce asset calculation
///
/// ### Returns
///
/// * [bool] - `true` if signature is valid and from owner, `false` otherwise
///
/// ### Reverts
///
/// * When witness data at specified index is not found (via unwrap)
///
/// ### References
///
/// * [EIP-191](https://eips.ethereum.org/EIPS/eip-191) - Signed Data Standard
/// * [Fuel Connectors](https://github.com/FuelLabs/fuel-connectors/blob/main/packages/evm-predicates/predicate/src/main.sw)

pub fn verify_witness_tx_id(
    op: WalletOp,
    owner_address: b256,
    v1_manager_id: b256,
) -> bool {

    // Verify that there is no Nonce asset input(s).
    if !verify_no_nonce_assets(owner_address, v1_manager_id) {
        return false; // Reject transaction with nonce inputs
    }
    // Get the witness
    let witness_index = op.override_witness_index.unwrap_or(0);
    let compact_signature: B512 = tx_witness_data(witness_index).unwrap();

    // Recover the signer and compare
    match ec_recover_evm_address(compact_signature, personal_sign_hash(tx_id())) {
        Ok(recovered_address) => owner_address == recovered_address.into(),
        Err(_) => false,
    }
}
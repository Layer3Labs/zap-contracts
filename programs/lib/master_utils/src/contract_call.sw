library;

use std::*;
use ::types::*;
use ::tools::verify_no_nonce_assets;
use walletop_contract_call::contract_call::*;


pub fn verify_wallet_contract_call(
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

    verify_contract_call(owner_address, witness_index)
}
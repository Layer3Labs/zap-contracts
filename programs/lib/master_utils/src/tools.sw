
library;

use std::{
    option::Option::{self, *},
    asset::*,
    inputs::input_count,
};
use zapwallet_consts::wallet_consts::KEY_NONCE;
use zap_utils::transaction_utls::{verify_input_coin, input_coin_asset_id};


/// Computes the asset id for a ZapWallet v1 nonce asset.
///
/// ### Additional Information
///
/// Generates a unique nonce asset id by double-hashing the owner address with a
/// predefined nonce key and the v1 manager address. This ensures each wallet has a
/// unique, deterministic nonce asset identifier.
///
/// ### Arguments
///
/// * `owner_addr` - [b256] - The owner's address (typically an EVM address hash)
/// * `v1_manager` - [b256] - The v1 manager contract address
///
/// ### Returns
///
/// * [b256] - The computed nonce asset id
///
pub fn get_nonce_assetid(
    owner_addr: b256,
    v1_manager: b256,
) -> b256 {

    let mut result_buffer = b256::zero();
    let mut var = b256::zero();
    asm(n_id: var, ptr: (owner_addr, KEY_NONCE), bytes: 64) { s256 n_id ptr bytes; };
    asm(n_id: result_buffer, ptr: (v1_manager, var), bytes: 64) { s256 n_id ptr bytes; };

    return(result_buffer);
}

/// Verifies that no transaction inputs consume the nonce asset associated with this ZapWallet.
///
/// ### Additional Information
///
/// This validation ensures that nonce assets can only be consumed through
/// authorized Zap modules specifically designed to handle nonce inputs and outputs.
/// This prevents unauthorized spending of nonce assets even with a valid signature.
///
/// ### Arguments
///
/// * `owner_addr` - [b256] - The owner's address (typically an EVM address hash)
/// * `v1_manager` - [b256] - The v1 manager contract address
///
/// ### Returns
///
/// * [bool] - `true` if no nonce asset inputs found, `false` if nonce asset detected
///
pub fn verify_no_nonce_assets(
    owner_address: b256,
    v1_manager: b256,
) -> bool {

    // Calculate the zap wallet v1 nonce asset id
    let v1_nonce_assetid = get_nonce_assetid(owner_address, v1_manager);

    let in_count: u64 = input_count().into();
    let mut i = 0;
    while i < in_count {
        if verify_input_coin(i) {
            let coin_asset_id = input_coin_asset_id(i);
            if (coin_asset_id == v1_nonce_assetid) {
                return false;
            }
        }
        i += 1;
    }

    return true;
}


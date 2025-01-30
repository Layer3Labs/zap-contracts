predicate;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    hash::*,
    vm::evm::ecr::ec_recover_evm_address,
    inputs::{
        input_coin_owner,
        input_count,
        input_asset_id,
        input_amount,
        Input,
    },
    outputs::{
        output_type,
        output_asset_id,
        output_asset_to,
        output_amount,
        Output,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use ptools::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_input_coin,
        output_count,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        verify_output_change,
        verify_output_coin,
    },
};

use helpers::{
    // hex::*,
    general_helpers::string_to_bytes,
};

use io_utils::{
    // evmtx_io_utils::InpOut,
    io::*,
    // nonce::*,
};

use module00_utils::{
    ack_message::WalletUpgradeAcknowledgment,
    personal_sign_string::*,
    // verify_io::*,
    // verify_zapwallet_address_from_code,
    // nonce_check_upgrade,
};


//-----------------------------------------
//FIXME - this can be removed
use helpers::general_helpers::{
    hex_string_to_bytes,
    char_to_hex,
};
//-----------------------------------------


configurable {
    OWNER_PUBKEY: b256 = b256::zero(),
    NONCE_ASSETID: b256 = b256::zero(),
    MODULE_KEY00_ASSETID: b256 = b256::zero(),
}


fn main(
    compact_signature: B512,
) -> bool {

    //TODO - add VERSION in a consts file
    // Compile version identifier into bytecode.
    // let version = VERSION;

    // Collect inputs and outputs:
    let (tx_inputs, tx_outputs, tx_change) = collect_inputs_outputs_change();

    // Get the owner of the nonce asset, this should be the owners ZapWallet
    let from_address: b256 = match check_asset_exists(tx_inputs, NONCE_ASSETID ) {
        CheckAssetResult::Success(nonce_owner_from) => {
            nonce_owner_from.into()
        },
        CheckAssetResult::Fail(error_code) => {
            // return Err(error_code);
            //NOTE - should probably just fail it here
            b256::zero()
        },
    };

    // receiving master address
    // again get from the nonce asset output to

    let to_address: b256 = match check_asset_exists(tx_outputs, NONCE_ASSETID ) {
        CheckAssetResult::Success(nonce_to) => {
            nonce_to.into()
        },
        CheckAssetResult::Fail(error_code) => {
            // return Err(error_code);
            //NOTE - should probably just fail it here
            b256::zero()
        },
    };

    //
    let current_version = String::from_ascii_str("1.0.0");

    //TODO - should get this value from passed, as we are not going to
    // know the final v2 version number.
    let new_version = String::from_ascii_str("2.0.0");

    let acknowledgment = WalletUpgradeAcknowledgment::new(
        from_address,
        to_address,
        current_version,
        new_version,
    );

    let message = acknowledgment.get_message();

    //
    let eip191_message_hash = personal_sign_string(message);

    let result = ec_recover_evm_address(compact_signature, eip191_message_hash);
    if result.is_ok() {
        if OWNER_PUBKEY == result.unwrap().into() {
            return true;
        }
    }

    return false;
}

library;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    hash::*,
    vm::evm::ecr::ec_recover_evm_address,
};
use module00_utils::ack_message::*;
use zap_utils::{
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
    personal_sign_string::*,
};


const TEST_CONST_EVM_SINGER: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

// forc test test_wallet_upgrade_acknowledgment --logs
#[test]
fn test_wallet_upgrade_acknowledgment() {

    // An known compact signature for the below string data and signer
    // Original Signer : 333339d42a89028ee29a9e9f4822e651bac7ba14
    let mut compactsig_hex_string = String::from_ascii_str("a8e85791699c515f7cf23d30cd6189a3ba9337b739d4738fecf8dd38eff82ffd3d1a06ddca7766f351d7a67ec39ac477401470b7885b81ac1fe03a88327a107a1b");
    let compactsig_bytes = hex_string_to_bytes(compactsig_hex_string).unwrap();
    let mut ptr: u64 = 0;
    let (cs_lhs, ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    let (cs_rhs, _ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    // log(cs_lhs);
    // log(cs_rhs);
    let compact_signature = B512::from((cs_lhs, cs_rhs));


    let from_address = 0x0101010101010101010101010101010101010101010101010101010101010101;
    let to_address = 0x0202020202020202020202020202020202020202020202020202020202020202;
    let utxoid = 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd;

    let current_version = String::from_ascii_str("1.0.0");
    let new_version = String::from_ascii_str("2.0.0");

    let acknowledgment = WalletUpgradeAcknowledgment::new(
        from_address,
        to_address,
        current_version,
        new_version,
        utxoid,
    );

    let message = acknowledgment.get_message();

    log(String::from_ascii_str("message:"));
    log(message);

    let eip191_message_hash = personal_sign_string(message);
    // EIP-191 message included
    log(String::from_ascii_str("Message hash EIP-191 prefix included:"));
    log(b256_to_hex(eip191_message_hash));

    let result = ec_recover_evm_address(compact_signature, eip191_message_hash);
    if result.is_ok() {
        log(String::from_ascii_str("Recovered Signer:"));

        let recovered_signer: b256 = result.unwrap().into();
        log(b256_to_hex(recovered_signer));

        let expected_signer = TEST_CONST_EVM_SINGER;
        assert(recovered_signer == expected_signer);
    }

}



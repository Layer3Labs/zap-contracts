library;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    hash::*,
    vm::evm::ecr::ec_recover_evm_address,
};
use ptools::{
    personal_sign::personal_sign_hash,
};
use helpers::{
    hex::*,
    general_helpers::*,
};

use ::personal_sign_string::*;


pub struct WalletUpgradeAcknowledgment {
    from_address: b256,
    to_address: b256,
    current_version: String,
    new_version: String,
}

impl WalletUpgradeAcknowledgment {
    pub fn new(
        from_address: b256,
        to_address: b256,
        current_version: String,
        new_version: String,
    ) -> Self {
        Self {
            from_address,
            to_address,
            current_version,
            new_version,
        }
    }

    pub fn get_message(self) -> String {
        let mut message_bytes = Bytes::new();

        // Create the header
        message_bytes.append(String::from_ascii_str("UPGRADE ACKNOWLEDGMENT:").as_bytes());

        message_bytes.push(0x0A); // \n
        message_bytes.append(String::from_ascii_str("I understand and authorize that:").as_bytes());
        message_bytes.push(0x0A); // \n

        // Part 1
        message_bytes.append(String::from_ascii_str("1. ALL assets (Tokens, NFTs, and ETH) will be transferred from 0x").as_bytes());
        message_bytes.append(b256_to_hex(self.from_address).as_bytes());
        message_bytes.append(String::from_ascii_str(" to 0x").as_bytes());
        message_bytes.append(b256_to_hex(self.to_address).as_bytes());
        message_bytes.push(0x0A); // \n

        // Part 2
        message_bytes.append(String::from_ascii_str("2. This upgrade will change my wallet from version ").as_bytes());
        message_bytes.append(self.current_version.as_bytes());
        message_bytes.append(String::from_ascii_str(" to ").as_bytes());
        message_bytes.append(self.new_version.as_bytes());
        message_bytes.push(0x0A); // \n

        // Part 3
        message_bytes.append(String::from_ascii_str("3. This action cannot be reversed once executed").as_bytes());
        message_bytes.push(0x0A); // \n

        // Part 4
        message_bytes.append(String::from_ascii_str("4. This authorization is valid only for this specific upgrade request").as_bytes());

        // Convert final bytes back to string
        String::from_ascii(message_bytes)
    }


}

// forc test test_wallet_upgrade_acknowledgment --logs
#[test]
fn test_wallet_upgrade_acknowledgment() {

    // an already known compact signature for the below string data
    // Original Signer : 333339d42a89028ee29a9e9f4822e651bac7ba14
    let mut compactsig_hex_string = String::from_ascii_str("004d3bc4007543a9fc52628916405d8df648308afe91bf4ec41b193a2583a28b576b92e48782bf2219d48b9baa0dbe958aeb75d97627d108a1f3578e84789578");
    let compactsig_bytes = hex_string_to_bytes(compactsig_hex_string).unwrap();
    let mut ptr: u64 = 0;
    let (cs_lhs, ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    let (cs_rhs, _ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    // log(cs_lhs);
    // log(cs_rhs);
    let compact_signature = B512::from((cs_lhs, cs_rhs));


    let from_address = 0x0101010101010101010101010101010101010101010101010101010101010101;
    let to_address = 0x0202020202020202020202020202020202020202020202020202020202020202;

    let current_version = String::from_ascii_str("1.0.0");
    let new_version = String::from_ascii_str("2.0.0");

    let acknowledgment = WalletUpgradeAcknowledgment::new(
        from_address,
        to_address,
        current_version,
        new_version,
    );

    let message = acknowledgment.get_message();
    let message_bytes = string_to_bytes(message).unwrap();

    // // Log each byte for debugging
    // let message_bytes = string_to_bytes(message).unwrap();
    // let mut i = 0;
    // while i < message_bytes.len() {
    //     log(message_bytes.get(i).unwrap());
    //     i += 1;
    // }

    log(String::from_ascii_str("message:"));
    log(message);


    let eip191_message_hash = personal_sign_string(message);


    // EIP-191 message included
    log(String::from_ascii_str("Message hash EIP-191 prefix included:"));
    log(b256_to_hex(eip191_message_hash));



    let result = ec_recover_evm_address(compact_signature, eip191_message_hash);
    if result.is_ok() {
        log(String::from_ascii_str("Recovered Signer:"));
        log(b256_to_hex(result.unwrap().into()));
    }


}



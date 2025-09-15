library;

use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    hash::*,
    vm::evm::ecr::ec_recover_evm_address,
};
use zap_utils::{
    hex::b256_to_hex,
    rlp_helpers::{
        hash_bytes, bytes_read_b256,
    },
    string_helpers::*,
    personal_sign_string::*,
};

pub struct WalletUpgradeAcknowledgment {
    from_address: b256,
    to_address: b256,
    current_version: String,
    new_version: String,
    utxoid: b256,
}

impl WalletUpgradeAcknowledgment {
    pub fn new(
        from_address: b256,
        to_address: b256,
        current_version: String,
        new_version: String,
        utxoid: b256,
    ) -> Self {
        Self {
            from_address,
            to_address,
            current_version,
            new_version,
            utxoid,
        }
    }

    /// Generates a formatted upgrade acknowledgment message for wallet upgrade authorization.
    ///
    /// # Additional Information
    ///
    /// The message follows a standardized format with 5 key points:
    /// 1. Asset transfer notification with source and destination addresses
    /// 2. Version upgrade details
    /// 3. Irreversibility warning
    /// 4. Single-use authorization notice
    /// 5. Unique UTXO ID for this upgrade
    ///
    /// The message format is:
    /// ```text
    /// UPGRADE ACKNOWLEDGMENT:
    /// I understand and authorize that:
    /// 1. ALL assets (Tokens, NFTs, and ETH) will be transferred from 0x{from_address} to 0x{to_address}
    /// 2. This upgrade will change my wallet from version {current_version} to {new_version}
    /// 3. This action cannot be reversed once executed
    /// 4. This authorization is valid only for this specific upgrade request
    /// 5. One time upgrade UTXO ID: 0x{utxoid}
    /// ```
    ///
    /// # Returns
    ///
    /// * [String] - The formatted acknowledgment message that will be signed by the wallet owner
    ///
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
        message_bytes.push(0x0A); // \n

        // Part 5
        message_bytes.append(String::from_ascii_str("5. One time upgrade UTXO ID: 0x").as_bytes());
        message_bytes.append(b256_to_hex(self.utxoid).as_bytes());

        // Convert final bytes back to string
        String::from_ascii(message_bytes)
    }

}

library;

use std::{
    b512::B512,
    bytes::Bytes,
    constants::ZERO_B256,
    tx::{
        tx_id,
        tx_witness_data,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
    },
    string::String,
};
use std::*;

use zap_utils::*;
use zap_utils::{
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
    personal_sign::*,
};

/// Personal sign prefix for Ethereum inclusive of the 32 bytes for the length of the Tx ID.
///
/// # Additional Information
///
/// Take "\x19Ethereum Signed Message:\n64" and converted to hex.
/// The 00000000 at the end is the padding added by Sway to fill the word.
const ETHEREUM_PREFIX = 0x19457468657265756d205369676e6564204d6573736167653a0a363400000000;

struct SignedData {
    /// The id of the transaction to be signed.
    transaction_id: (b256, b256),
    /// EIP-191 personal sign prefix.
    ethereum_prefix: b256,
    /// Additional data used for reserving memory for hashing (hack).
    #[allow(dead_code)]
    empty: b256,
}

// configurable {
//     /// The Ethereum address that signed the transaction.
//     SIGNER: b256 = ZERO_B256,
// }


const ASCII_MAP: [u8; 16] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102
];

fn b256_to_ascii_bytes(val: b256) -> (b256, b256) {
    let bytes = Bytes::from(val);
    let mut ascii_bytes = Bytes::with_capacity(64);
    let mut idx = 0;

    while idx < 32 {
        let b = bytes.get(idx).unwrap();
        ascii_bytes.push(ASCII_MAP[(b >> 4).as_u64()]);
        ascii_bytes.push(ASCII_MAP[(b & 15).as_u64()]);
	    idx = idx + 1;
    }

    asm(ptr: ascii_bytes.ptr()) {
        ptr: (b256, b256)
    }
}

/// Return the Keccak-256 hash of the transaction ID in the format of EIP-191.
///
/// # Arguments
///
/// * `transaction_id`: [b256] - Fuel Tx ID.
fn personal_sign_hash(transaction_id: b256) -> b256 {
    // Hack, allocate memory to reduce manual `asm` code.
    let transaction_id_utf8 = b256_to_ascii_bytes(transaction_id);
    let data = SignedData {
        transaction_id: transaction_id_utf8,
        ethereum_prefix: ETHEREUM_PREFIX,
        empty: ZERO_B256,
    };

    // Pointer to the data we have signed external to Sway.
    let data_ptr = asm(ptr: data.transaction_id) {
        ptr
    };

    // The Ethereum prefix is 28 bytes (plus padding we exclude).
    // The Tx ID is 64 bytes at the end of the prefix.
    let len_to_hash = 28 + 64;

    // Create a buffer in memory to overwrite with the result being the hash.
    let mut buffer = b256::min();

    // Copy the Tx ID to the end of the prefix and hash the exact len of the prefix and id (without
    // the padding at the end because that would alter the hash).
    asm(
        hash: buffer,
        tx_id: data_ptr,
        end_of_prefix: data_ptr + len_to_hash,
        prefix: data.ethereum_prefix,
        id_len: 64,
        hash_len: len_to_hash,
    ) {
        mcp end_of_prefix tx_id id_len;
        k256 hash prefix hash_len;
    }

    // The buffer contains the hash.
    buffer
}


/*
fn main(witness_index: u64) -> bool {
    // Retrieve the Ethereum signature from the witness data in the Tx at the specified index.
    let signature: B512 = tx_witness_data(witness_index).unwrap();

    // Hash the Fuel Tx (as the signed message) and attempt to recover the signer from the signature.
    let result = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));

    // If the signers match then the predicate has validated the Tx.
    if result.is_ok() {
        if SIGNER == result.unwrap().into() {
            return true;
        }
    }

    // Otherwise, an invalid signature has been passed and we invalidate the Tx.
    false
}
*/



// forc test test_874_personal_sign_v2_txid --logs
#[test]
fn test_874_personal_sign_v2_txid(){

    let txid: b256 = 0xffa581667d51d2e1fa81e2a1ad8dae6c98acb27c3c58b9553ac8fd324fe8857d;

    let mut compactsig_hex_string = String::from_ascii_str("3c49b6977c5034b7ca68facc50f4dad2e8bda09fe2f0c5a544afae1a3e573b02865b00ac5a0fe78a88976d7c9eef5438aa6057fc0359e69509896070d5e583a3");
    let compactsig_bytes = hex_string_to_bytes(compactsig_hex_string).unwrap();
    let mut ptr: u64 = 0;
    let (cs_lhs, ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    let (cs_rhs, _ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    // log(cs_lhs);
    // log(cs_rhs);
    let compactsig = B512::from((cs_lhs, cs_rhs));

    let result = ec_recover_evm_address(compactsig, personal_sign_hash(txid));

    // log(b256_to_hex(recovered_signer.unwrap().into()));

    if result.is_ok() {
        // log recoverd signer
        log(b256_to_hex(result.unwrap().into()));
    }

}


// forc test test_875_personal_sign_v2_txid --logs
// signed in Rust, with ethers, in zap-executor module04 integration test
// sign with EVM account: 333339d42a89028ee29a9e9f4822e651bac7ba14
// tx_id            : 3a02867fa0c627c9eaa04e7064eab8c7b93b39bbcb62d8880ec66ba44b88b369
// Witness (compact): 436317605ce0b3439c720216026159a81370473bce4f6002c00d6e1988c34144fcac94b672f951471c34fb7e10484d725530c48c47636d06b868491ed5eb0541
//
#[test]
fn test_875_personal_sign_v2_txid(){

    let txid: b256 = 0x3a02867fa0c627c9eaa04e7064eab8c7b93b39bbcb62d8880ec66ba44b88b369;

    let mut compactsig_hex_string = String::from_ascii_str("436317605ce0b3439c720216026159a81370473bce4f6002c00d6e1988c34144fcac94b672f951471c34fb7e10484d725530c48c47636d06b868491ed5eb0541");
    let compactsig_bytes = hex_string_to_bytes(compactsig_hex_string).unwrap();
    let mut ptr: u64 = 0;
    let (cs_lhs, ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    let (cs_rhs, _ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    // log(cs_lhs);
    // log(cs_rhs);
    let compactsig = B512::from((cs_lhs, cs_rhs));

    let result = ec_recover_evm_address(compactsig, personal_sign_hash(txid));

    // log(b256_to_hex(recovered_signer.unwrap().into()));

    if result.is_ok() {
        // log recoverd signer
        log(b256_to_hex(result.unwrap().into()));
    }

}







/*

Download the React DevTools for a better development experience: https://reactjs.org/link/react-devtools
index.tsx:185 Restored connection to: 0x333339d42a89028ee29a9e9f4822e651bac7ba14
index.tsx:64 --- TXID Witness TransferSigner -->
index.tsx:65 paddedEvmaddr: 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14
index.tsx:66 formattedTxid: 0xffa581667d51d2e1fa81e2a1ad8dae6c98acb27c3c58b9553ac8fd324fe8857d
index.tsx:70 UTF-8 Encoded TxID: 0x66666135383136363764353164326531666138316532613161643864616536633938616362323763336335386239353533616338666433323466653838353764
index.tsx:75 Attempting to sign TXID Witness Transfer EIP-191 data...
index.tsx:111 Standard recovery result: 0x55931624EFeAee364F4052634cF90B590c5e419d
index.tsx:123 TXID Witness via EIP-191 Details:
{original_txid: '0xffa581667d51d2e1fa81e2a1ad8dae6c98acb27c3c58b9553ac8fd324fe8857d', utf8_encoded_txid: '0x666661353831363637643531643265316661383165326131…3336335386239353533616338666433323466653838353764', prefix_used: '\x19Ethereum Signed Message:\n64', manual_prefix_bytes: '0x19457468657265756d205369676e6564204d6573736167653a0a3634', manual_message_bytes: '0x19457468657265756d205369676e6564204d657373616765…3336335386239353533616338666433323466653838353764', …}
calculated_hash
:
"0xd850c0df1d11c240a35426f645b97299919f68a0ed09ac0e91f243aa66a1c16d"
compact_signature
:
"0x3c49b6977c5034b7ca68facc50f4dad2e8bda09fe2f0c5a544afae1a3e573b02865b00ac5a0fe78a88976d7c9eef5438aa6057fc0359e69509896070d5e583a3"
manual_message_bytes
:
"0x19457468657265756d205369676e6564204d6573736167653a0a363466666135383136363764353164326531666138316532613161643864616536633938616362323763336335386239353533616338666433323466653838353764"
manual_prefix_bytes
:
"0x19457468657265756d205369676e6564204d6573736167653a0a3634"
original_txid
:
"0xffa581667d51d2e1fa81e2a1ad8dae6c98acb27c3c58b9553ac8fd324fe8857d"
prefix_used
:
"\u0019Ethereum Signed Message:\n64"
signature
:
"0x3c49b6977c5034b7ca68facc50f4dad2e8bda09fe2f0c5a544afae1a3e573b02065b00ac5a0fe78a88976d7c9eef5438aa6057fc0359e69509896070d5e583a31c"
signature_valid
:
false
signer
:
"0x333339d42a89028ee29a9e9f4822e651bac7ba14"
standard_recovered_signer
:
"0x55931624EFeAee364F4052634cF90B590c5e419d"
utf8_encoded_txid
:
"0x66666135383136363764353164326531666138316532613161643864616536633938616362323763336335386239353533616338666433323466653838353764"
[[Prototype]]
:
Object


*/
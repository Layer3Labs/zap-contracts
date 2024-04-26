contract;

//
//  Zap Nonce Manager Contract
//
//  development version: 0.0.4
//  forc version: 0.49.2
//
//
//  2024-03-02: Bump to Beta-5 compatability.
//

mod constants;

use nonce_manager_abi::NonceManager;

use std::{
    bytes::Bytes,
    b512::B512,
    convert::TryFrom,
    option::Option::{self, *},
    hash::*,
    constants::{
        ZERO_B256,
        BASE_ASSET_ID,
    },
    tx::{
        tx_id,
        tx_witness_data,
    },
    inputs::{
        input_predicate,
    },
    outputs::{
        output_type,
        output_pointer,
        output_asset_id,
        output_asset_to,
        output_amount,
        output_count,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    context::{
        this_balance,
    },
    call_frames::{
        contract_id,
    },
    low_level_call::{call_with_function_selector, call_with_function_selector_vec, CallParams},
    context::balance_of,
    message::send_message,
    asset::*,
};

use std::bytes_conversions::u64::*;
use std::bytes_conversions::b256::*;

use constants::{
    DEFAULT_KEY,
    NONCE_MAX,
    VERSION,
};



pub const GTF_OUTPUT_CONTRACT_INPUT_INDEX = 0x304;
pub const GTF_OUTPUT_CONTRACT_BALANCE_ROOT = 0x305;
pub const GTF_OUTPUT_CONTRACT_STATE_ROOT = 0x306;
pub const GTF_OUTPUT_CONTRACT_CREATED_CONTRACT_ID = 0x307;
pub const GTF_OUTPUT_CONTRACT_CREATED_STATE_ROOT = 0x308;




impl NonceManager for Contract {

    /// mint nonce_tokens & send to predicate account & verify witness.
    fn mint_nonce_assets(
        pred_acc: Address,
        key: b256,
        witness_index: u64,
    ) -> EvmAddress {

        // The validatation mechanism for this function:
        //
        //REVIEW -
        // 1. This function extracts the signer (evm pk) from the witness - this function does not
        // check if the evm address recovered is mapped to the predicate address.
        //
        // 2. If the witness is signed incorrectly. i.e., by an evm pk that is not the owner of
        // the predicate wallet, this function will ignore this and create a sub_id from the resulting
        // recovered packed evm pk.
        //
        // 3. However - in the predicate itself, which in the correct case should be an input to this
        // fucntion call, for tx_type=0, the witness is matched to the predicate owner.
        //
        // 4. Anyone can call this function with an Address (predicate, EOA etc,), a key and a
        // witness index. Therefore anyone can mint assets from this function. However for assets
        // of type "nonce token" to be created, the signer of the witness needs to be a unique
        // evm address that also matces the predicate wallet owner.
        //
        // 5. Note, once the nonce assets have been minted, no additional assets with the same
        // asset_id can be minted.
        //
        //TODO - Constrain this function to mint assets only to predicate wallets. get merkle root
        // of the predicate input to this function call and use this Address (pred_acc currently) to
        // send the newly minted assets to.
        //TODO - required above - write merkle root in sway.

        //-------------------------------------------

        // let input_predicate_bytes = input_predicate(input_index);
        // log(input_predicate_bytes);

        //-------------------------------------------

        log(tx_id());   // b256

        log(key);   // b256

        // Retrieve the Ethereum signature from the witness data in the Tx at the specified index.
        let signature: B512 = tx_witness_data(witness_index);

        log(signature);     // B512

        // Hash the Fuel Tx (as the signed message) and attempt to recover the signer from the signature.
        let result = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));
        log(result.unwrap());       // EVMAddress

        let mut f = EvmAddress {
            value: ZERO_B256,
        };

        // If the signer is recovered, then an evm address validated the Tx.
        // use this evm address + key to calculate the sub_id of the nonce token asset.
        if result.is_ok() {

            let evm_addr = result.unwrap();
            log(evm_addr);      // EVMAddress


            let sub_id: b256 = get_sub_id(evm_addr, key);
            //let sub_id: b256 = ZERO_B256; // debug
            log(sub_id);

            // checks that the current contract has a zero balance of the nonce token.

            // sha256((sub_id, contract_id()))
            let ntid = AssetId::new(contract_id(), sub_id);
            log(ntid);

            assert(this_balance(ntid) == 0);
            log(this_balance(ntid));

            // mint tokens --> (to, sub_id, amount)
            // mint_to_address(pred_acc, sub_id, 102u64);

            // mints the maximum number of nonce token and send this amount minus 1 to the prediacte account.
            // leaves 1 token owned by the noncemanager so the same key combo cannot be minted again.
            let mint_amount: u64 = NONCE_MAX;
            mint(sub_id, mint_amount);
            transfer_to_address(pred_acc, AssetId::new(contract_id(), sub_id), mint_amount - 1);

            f = evm_addr;      // returns the EvmAddress of the signer
        }
        // Otherwise, an invalid signature has been passed and we invalidate the Tx.
        // f = returns and EvmAddress that should be zerod()
        return f;       //
    }

    /// return the version of this nonce manager contract.
    fn get_version() -> b256 {
        return VERSION;
    }

}


//------------------------------------------------------------------------------------------------------

fn get_sub_id(
    evm_addr: EvmAddress,
    key: b256,
) -> b256 {

    let mut result_buffer_1 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(n_id: result_buffer_1, ptr: (evm_addr, key), bytes: 64) {
        s256 n_id ptr bytes;
    };

    // log(result_buffer_1);

    return(result_buffer_1);

}




//------------------------------------------------------------------------------------------------------
// This is now part of the std-lib:
// https://github.com/FuelLabs/sway/issues/5787

/// Personal sign prefix for Ethereum inclusive of the 32 bytes for the length of the Tx ID.
///
/// # Additional Information
///
/// Take "\x19Ethereum Signed Message:\n32" and converted to hex.
/// The 00000000 at the end is the padding added by Sway to fill the word.
const ETHEREUM_PREFIX = 0x19457468657265756d205369676e6564204d6573736167653a0a333200000000;

struct SignedData {
    /// The id of the transaction to be signed.
    transaction_id: b256,
    /// EIP-191 personal sign prefix.
    ethereum_prefix: b256,
    /// Additional data used for reserving memory for hashing (hack).
    #[allow(dead_code)]
    empty: b256,
}

/// Return the Keccak-256 hash of the transaction ID in the format of EIP-191.
///
/// # Arguments
///
/// * `transaction_id`: [b256] - Fuel Tx ID.
fn personal_sign_hash(transaction_id: b256) -> b256 {
    // Hack, allocate memory to reduce manual `asm` code.
    let data = SignedData {
        transaction_id,
        ethereum_prefix: ETHEREUM_PREFIX,
        empty: ZERO_B256,
    };

    // Pointer to the data we have signed external to Sway.
    let data_ptr = asm(ptr: data.transaction_id) { ptr };

    // The Ethereum prefix is 28 bytes (plus padding we exclude).
    // The Tx ID is 32 bytes at the end of the prefix.
    let len_to_hash = 28 + 32;

    // Create a buffer in memory to overwrite with the result being the hash.
    let mut buffer = b256::min();

    // Copy the Tx ID to the end of the prefix and hash the exact len of the prefix and id (without
    // the padding at the end because that would alter the hash).
    asm(hash: buffer, tx_id: data_ptr, end_of_prefix: data_ptr + len_to_hash, prefix: data.ethereum_prefix, id_len: 32, hash_len: len_to_hash) {
        mcp  end_of_prefix tx_id id_len;
        k256 hash prefix hash_len;
    }

    // The buffer contains the hash.
    buffer
}

//------------------------------------------------------------------------------------------------------

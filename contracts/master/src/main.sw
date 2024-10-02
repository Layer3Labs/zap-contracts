predicate;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    tx::{
        tx_id,
        tx_witness_data,
    },
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::{
        GTF_INPUT_COIN_ASSET_ID,
        GTF_INPUT_COIN_AMOUNT,
        input_coin_owner,
        // input_predicate_pointer, sway 0.63.1 this function is now private
        input_predicate_length,
        input_predicate,
        input_type,
        input_count,
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

use zapwallet_consts::{
    module_addresses::{
        MODULE_TXTYPE1_ADDR,
        MODULE_TXTYPE2_ADDR, // Address
        MODULE_ERC20_ADDR,
        MODULE_EIP712_ADDR,
        MODULE_TXIDWIT_ADDR,
        MODULE_UPGRADE_ADDR,
    },
    module_assets::{
        get_module_key01_assetid,
        get_module_key02_assetid,
        get_module_key03_assetid,
        get_module_key04_assetid,
        get_module_key05_assetid,
        get_module_keyff_assetid,
    },
    wallet_consts::{
        DUMMY_1_OWNER_EVM_ADDR,
        VERSION,
    },
};
use ptools::{
    predi_utls::{
        get_merkle_root,
        get_predi_addr_from_root,
        get_predi_addr_from_bytes,
        // get_predi_root_from_bytes,
    },
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        // input_count,
        output_count,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        tx_tip,
        verify_input_coin,
        verify_input_contract,
        verify_output_change,
        verify_output_coin,
        //
        // input_asset_id,
        output_amount_at_index,
    },
    personal_sign::personal_sign_hash,
};



fn main() -> bool {
    // make version into compiled bytecode
    let version: Bytes = Bytes::from(VERSION);

    // Modules Assetid's & nt Assetid:
    // let calculated_nonce_asset_id = get_dummy_nonce_asset_id(); // real one is in rlp_helpers.sw calc_asset_id()

    let calculated_module_txtype1_assetid = get_module_key01_assetid();
    let calculated_module_txtype2_assetid = get_module_key02_assetid();
    let calculated_module_erc20_assetid = get_module_key03_assetid();
    let calculated_module_eip712_assetid = get_module_key04_assetid();
    let calculated_module_txidwit_assetid = get_module_key05_assetid();
    let calculated_module_upgrade_assetid = get_module_keyff_assetid();

    //---------------------------------------------------------------------------
    // Critial bools for validation success:
    let mut found_module_txtype1_input: bool = false;
    let mut correct_module_txtype1_addr: bool = false;

    let mut found_module_txtype2_input: bool = false;   // can only have one of these inputs, check for multiple.
    let mut correct_module_txtype2_addr: bool = false;  // input owner matches known addr.

    let mut found_module_erc20_input: bool = false;
    let mut correct_module_erc20_addr: bool = false;

    let mut found_module_eip712_input: bool = false;
    let mut correct_module_eip712_addr: bool = false;

    let mut found_module_txidwit_input: bool = false;
    let mut correct_module_txidwit_addr: bool = false;

    let mut found_module_upgrade_input: bool = false;
    let mut correct_module_upgrade_addr: bool = false;

    let mut all_checks: bool = false;
    let mut init_check: bool = false;


    //---------------------------------------------------------------------------
    //

    let in_count: u64 = input_count().into();
    let out_count: u64 = output_count();

    let mut i = 0;
    while i < in_count {
        let inp_coin_owner = input_coin_owner(i);       // Option<Address>

        if verify_input_coin(i) {
            let coin_asset_id = input_coin_asset_id(i);

            // MATCH TXTYPE1 MODULE:
            if (calculated_module_txtype1_assetid == coin_asset_id) &&
                (found_module_txtype1_input != true) {

                let coin_owner = inp_coin_owner.unwrap();
                if (coin_owner == MODULE_TXTYPE1_ADDR) {
                    correct_module_txtype1_addr = true;

                }
            }
            // MATCH TXTYPE2 MODULE:
            // match the assetid of the module txtype2's unique assetid to a single input (key=2).
            // this is a pre-known assetid value in this master wallet.
            // i.e., only one predicate can contain this asset.
            if (calculated_module_txtype2_assetid == coin_asset_id) &&
                (found_module_txtype2_input != true) {  // make sure this is not another input for the same assetid

                let input_amount = input_coin_amount(i);
                if (input_amount == 1u64) { // make sure the amount is equal one.
                    found_module_txtype2_input = true;
                }

                // get the input predicate bytes at index i, this should be the module txtype2 predicate
                // check the predicate that holds this asset is the one we have audited.
                // let input_predicate = input_predicate(i);
                // let pred_addr = get_predi_addr_from_bytes(input_predicate); // this takes way too long to execute.

                let coin_owner = inp_coin_owner.unwrap();
                // check that input owner of the txtype2 assetid, is a match the pre-configured module address,
                // that includes the specific owner of the txtype2 module.
                //NOTE - should coin_owner should always be the correct address for the predicate?
                // i.e., no need to merkelize the bytecode and re-calc the address.
                // if (coin_owner == MODULE_TXTYPE2_ADDR) && (pred_addr == MODULE_TXTYPE2) { // this match to Address and b256 could be cleaned up.
                //     correct_module_txtype2_addr = true;
                // }
                if (coin_owner == MODULE_TXTYPE2_ADDR) { // this match to Address and b256 could be cleaned up.
                    correct_module_txtype2_addr = true;

                }


            }
            // MATCH ERC20 MODULE:
            if (calculated_module_erc20_assetid == coin_asset_id) &&
                (found_module_erc20_input != true) {

                let coin_owner = inp_coin_owner.unwrap();
                if (coin_owner == MODULE_ERC20_ADDR) {
                    correct_module_erc20_addr = true;

                }
            }
            // MATCH EIP-712 MODULE:
            if (calculated_module_eip712_assetid == coin_asset_id) &&
                (found_module_eip712_input != true) {

                let coin_owner = inp_coin_owner.unwrap();
                if (coin_owner == MODULE_EIP712_ADDR) {
                    correct_module_eip712_addr = true;

                }

            }
            // MATCH TXID WITNESS MODULE:
            if (calculated_module_txidwit_assetid == coin_asset_id) &&
                (found_module_txidwit_input != true) {

                let coin_owner = inp_coin_owner.unwrap();
                if (coin_owner == MODULE_TXIDWIT_ADDR) {
                    correct_module_txidwit_addr = true;

                }

            }
            // MATCH UPDRADE CRITERIA:
            if (calculated_module_upgrade_assetid == coin_asset_id) &&
                (found_module_upgrade_input != true) {

                let coin_owner = inp_coin_owner.unwrap();
                if (coin_owner == MODULE_UPGRADE_ADDR) {
                    correct_module_upgrade_addr = true;

                }

            }



        }

        i += 1;
    }

    //---------------------------------------------------------------------------
    // do final checks or init.

    let module_checks: bool = (
        correct_module_txtype2_addr
        && true
        );
    if (module_checks == false) {
        // MATCH INIT TX.
        init_check = verify_init(in_count, out_count);
    }

    all_checks = (module_checks || init_check) && !(module_checks && init_check);
    return all_checks;
}


//---------------------------------------------------------------------------
//

// Validation logic for the master predicate funding the initialization tx.
// for this to validate:
// there must only be two inputs of type Coin & Contract, with Coin being the default assetid,
// the Contract input, and,
// the wallet owner must have witnessed the txid.
pub fn verify_init(in_count: u64, out_count: u64) -> bool {
    /*
    if check_inputs(in_count) {

        let SIGNER_1 = EvmAddress::from(DUMMY_1_OWNER_EVM_ADDR);
        // validate the witness data, which means
        // the owner has signed the txid of this transaction.
        let witness_index = 0u64;
        let signature: B512 = tx_witness_data(witness_index).unwrap();
        // Hash the txid (as the signed message) and attempt to recover the signer from the signature.
        let result_signer_1 = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));
        // If the signers match then the owner witnessed the tx.
        return result_signer_1.is_ok() && SIGNER_1 == result_signer_1.unwrap();
    } else {
        return false;
    }
    */

    //DEBUG
    if check_inputs(in_count) {

        let SIGNER_1 = EvmAddress::from(DUMMY_1_OWNER_EVM_ADDR);
        // validate the witness data, which means
        // the owner has signed the txid of this transaction.
        let witness_index = 0u64;
        let signature: B512 = tx_witness_data(witness_index).unwrap();
        // Hash the txid (as the signed message) and attempt to recover the signer from the signature.
        let result_signer_1 = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));
        // If the signers match then the owner witnessed the tx.
        return result_signer_1.is_ok() && SIGNER_1 == result_signer_1.unwrap();


        // return true;
    } else {
        return false;
    }

}

/// verify there is only two inputs of type Coin and Contract, and that the
/// Coin input has an AssetId of default.
fn check_inputs(in_count: u64) -> bool {
    if (in_count == 2){
        let mut coin_count = 0;
        let mut contract_count = 0;
        let mut i = 0;
        while i < 2 {
            if verify_input_coin(i) {
                coin_count += 1;
                if input_coin_asset_id(i) != b256::zero() {
                    return false;
                }
            } else if verify_input_contract(i) {
                contract_count += 1;
            }
            i += 1;
        }
        return (coin_count == 1 && contract_count == 1);
    } else {
        return false;
    }
}




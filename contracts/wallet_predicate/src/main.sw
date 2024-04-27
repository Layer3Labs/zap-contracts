predicate;

//
//  Zap Predicate Wallet
//
//  development v.00.01.04
//  forc version: 0.49.2
//
// predicate root  : 5f50d15b64d1f6e77e981edf8197b83d33c5bc664b861d5b96c571d7b6bd163c
// sha256(bytecode): 28a671578ceed6c30f58f0210fa54e62b068b9dd9b2f56b2f9550a068c2c6fb7
//

mod transaction_utils;
mod rlp_utils5;
mod address_book;
mod constants;
mod personal_sign;

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
        evm_address::EvmAddress,
    },
    inputs::*,
    outputs::{
        output_type,
        output_pointer,
        output_asset_id,
        output_asset_to,
        output_amount,
    },
};

const GTF_INPUT_TYPE = 0x200;
const INPUT_TYPE_COIN = 0u64;
const INPUT_TYPE_CONTRACT = 1u64;

use std::bytes_conversions::u64::*;
use std::bytes_conversions::b256::*;

use address_book::{
    SIGNER_1, SIGNER_2,
    NMAN3_CONTRACT_ADDR,
    get_owner_b256_evm_addr,
};

use transaction_utils::{
    input_coin_amount,
    input_coin_asset_id,
    input_count,
    output_count,
    output_coin_asset_id,
    output_coin_amount,
    output_coin_to,
    tx_gas_limit,
    tx_gas_price,
    // verify_input_coin,
    verify_output_change,
    verify_output_coin,
    //
    input_asset_id,
};

use rlp_utils5::{
    decode_signed_tx_digest_sig,
};

use constants::{
    DEFAULT_KEY,
    NONCE_MAX,
    VERSION,
};

use personal_sign::{
    personal_sign_hash,
};

//---------------------------------------------------------------------------------------------------

/// The input type for a transaction.
pub enum Input {
    /// A coin input.
    Coin: (),
    /// A contract input.
    Contract: (),
    /// A message input.
    Message: (),
}



//---------------------------------------------------------------------------------------------------

pub struct Init {
    signature_owner: B512,      // signature of the Assetid
    key: b256,                  // the Key, which is used in the AssetId calculation (below)
    wit_index: u64,             // witness index
}

pub enum SuppliedData {
    InitData: Init,         // (0) data contained in the Init struct.
    SignedData: Bytes,      // (1) signed_tx data.
}

struct PValidation {
    tx_type: u64,
    data: SuppliedData,
}

//---------------------------------------------------------------------------------------------------


fn main(tx: PValidation ) -> bool {
    // make version into compiled bytecode
    let version: Bytes = Bytes::from(VERSION);

    match tx.tx_type {
        0 => {
            //---------------------------------------------------------------------------
            // Critial bools for validation success:
            let mut tx_witness_by_owner: bool = false;
            let mut nid_signed_by_owner: bool = false;
            let mut ntoken_correct: bool = false;
            let mut all_checks_pass: bool = false;

            let f = tx.data;
            let init_data = match f {
                SuppliedData::InitData(initdata) => {
                    Some(initdata)
                },
                SuppliedData::SignedData(_) => {
                    None
                },
            };
            if init_data.is_some() {
                let id = init_data.unwrap();
                let so = id.signature_owner;
                let key = id.key;
                let witness_index = id.wit_index;

                // FIRST: validate the witness data, which is:
                // the SIGNER has signed the txid of this transaction.
                let signature: B512 = tx_witness_data(witness_index);
                // Hash the Fuel Tx (as the signed message) and attempt to recover the signer from the signature.
                let result_signer_1 = ec_recover_evm_address(signature, personal_sign_hash(tx_id()));

                // If the signers match then the owner witnessed the tx.
                if result_signer_1.is_ok() {
                    if SIGNER_1 == result_signer_1.unwrap() {
                        tx_witness_by_owner = true;
                    }
                } else {
                    return false;
                }

                // SECOND: validate the init data, which is:
                // the SIGNER has signed the nonce token asset id.
                // you need to calculate the nt asset id to use in ec_recover.
                // the nt_asset_id can be calcd from SHA256({NMAN3_CONTRACT_ADDR:SHA256({SIGNER:KEY})})

                // get nonce token asset id
                let nman3_id = ContractId::from(NMAN3_CONTRACT_ADDR);
                let calculated_nonce_asset_id = calc_asset_id(SIGNER_1, DEFAULT_KEY, nman3_id);
                let result_signer_2 = ec_recover_evm_address(so, personal_sign_hash(calculated_nonce_asset_id));

                // log(nman3_id);
                // log(calculated_nonce_asset_id);
                // log(result_signer_2.unwrap());

                // If the signers match then the owner signed the data bytes (nt asset id).
                if result_signer_2.is_ok() {
                    if SIGNER_1 == result_signer_2.unwrap() {
                        nid_signed_by_owner = true;
                    }
                } else {
                    return false;
                }
                //NOTE - could restrict this further by checking outputs from the tx.

            } else {
                return false;
            }
            if (
                tx_witness_by_owner && nid_signed_by_owner
            ){
                all_checks_pass = true;
            }
            //log(all_checks_pass);
            return all_checks_pass;
        },
        1 => {
            // tx_type = 1
            // validates against an signed typed evm transaction.
            // return true;

            // let script_bytecode_hash: b256 = tx_script_bytecode_hash();
            // log(script_bytecode_hash);

            let nman3_id = ContractId::from(NMAN3_CONTRACT_ADDR);
            let calculated_nonce_asset_id = calc_asset_id(SIGNER_2, DEFAULT_KEY, nman3_id);
            // log(calculated_nonce_asset_id);

            //---------------------------------------------------------------------------
            // variables:

            let mut nonce_token_owner_this_predicate: Address =  Address::from(ZERO_B256);
            let mut nonce_val_in_signed_tx = 0u64;

            //---------------------------------------------------------------------------
            // Critial bools for validation success:

            let mut evm_tx_signed_by_owner: bool = false;
            let mut found_noncetoken_input: bool = false;
            let mut found_noncetoken_output: bool = false;

            //---------------------------------------------------------------------------
            // decode evm tx:

            let signed_evm_tx = match tx.data {
                SuppliedData::InitData(initdata) => {
                    None
                },
                SuppliedData::SignedData(tx) => {
                    Some(tx)
                },
            };

            if signed_evm_tx.is_some() {

                let (type_identifier, chain_id, tx_nonce, maxFeePerGas, gasLimit, value, to, asset_id,
                    digest, txlengeth, tx_data_start, tx_data_end,
                    signature, tx_from) = decode_signed_tx_digest_sig(signed_evm_tx.unwrap());

                // CHECK: evm tx was signed by the owner:
                // log(from);
                if(tx_from == get_owner_b256_evm_addr()){
                    evm_tx_signed_by_owner = true;
                } else {
                    return false;   // if not, then just kill it here to save exe.
                }

                // set nonce value from signed tx, to be checked later agaisnt input/output.
                nonce_val_in_signed_tx = tx_nonce;
                // log(nonce_val_in_signed_tx);

            } else {
                return false;
            }

            //---------------------------------------------------------------------------
            // NONCE:
            // For Inputs:
            // calcs the mint amount minus the transaction nt amount.
            // checks if the above matches the nonce in the signed tx data.
            // e.g.,
            //      tx_nonce = 0x01
            //      nt_at_input = 0xFE
            //      nt_MAX = 0xFF
            //      calculated nonce (from input) = nt_MAX - nt_at_input
            //      0x01 = 0xFF - 0xFE
            //      assert ((nt_MAX - nt_at_input), tx_nonce)
            //
            // code:
            // let nt_input_amount_to_tx = input_coin_amount(i);
            // let nonce_inp_calc = NONCE_MAX - nt_input_amount_to_tx;
            // assert(nonce_val_in_signed_tx == nonce_inp_calc);
            //
            // For Outputs:
            // make sure that there is an output for the amount:
            // calcualted nt amount at output = nt_MAX - (tx_nonce + 1)

            let nonce_out_calc = NONCE_MAX - ( nonce_val_in_signed_tx + 1);

            //---------------------------------------------------------------------------
            // INPUTS:

            let in_count: u64 = input_count();
            // log(in_count);

            let mut i = 0;
            while i < in_count {


                let inp_coin_owner = input_coin_owner(i);       // Option<Address>
                // log(inp_coin_owner);



                if inp_coin_owner.is_some() {
                    let inp_predicate_ptr = input_predicate_pointer(i);
                    // log(inp_predicate_ptr); --> not loggable

                    let inp_predicate_len = input_predicate_length(i);
                    // log(inp_predicate_len);

                    let inp_predicate_data = input_predicate(i);

                    if verify_input_coin(i) {
                        let coin_asset_id = input_coin_asset_id(i);
                        // log(coin_asset_id);

                        if calculated_nonce_asset_id == coin_asset_id {

                            // log(coin_asset_id);

                            // see above note:
                            let nt_input_amount_to_tx = input_coin_amount(i);
                            let nonce_inp_calc = NONCE_MAX - nt_input_amount_to_tx;

                            // log(nonce_inp_calc);

                            assert(nonce_val_in_signed_tx == nonce_inp_calc);
                            found_noncetoken_input = true;

                            // if checks get this far, we have found the nonce token, amount and owner:
                            // store the address of this coin owner (the predicate address), it will
                            // be used in the outputs to verify the noce details.
                            // would really like to implement merkle hash in Sway to
                            // calculate a predicate inputs' own root.
                            nonce_token_owner_this_predicate = input_coin_owner(i).unwrap();    // Option<Address>
                            // log(nonce_token_owner_this_predicate);
                        }

                    }

                }

                i += 1;
            }
            // log(found_noncetoken_input);

            //---------------------------------------------------------------------------
            // OUTPUTS:

            let out_count = output_count();
            // log(out_count);
            let mut j = 0;
            while j < out_count {

                // let o_ass_id = output_asset_id(j);
                // let o_ass_id = output_asset_id_modified(j);
                // log(o_ass_id);

                let o_ass_to = output_asset_to(j);      // Option<b256>
                // log(o_ass_to);

                let is_change = verify_output_change(j);
                // log(is_change);

                let o_type = output_type(j);
                // log(o_type);

                let o_amount = output_amount_at_index(j);
                // log(o_amount);

                let o_ass_id = output_asset_id(j);  // Option<AssetId>
                if o_ass_id.is_some() {

                    // some asset id was found, log it
                    // log(o_ass_id.unwrap());

                    // CHECK: if
                    // output asset_is is the nonce token.
                    // AND output value of the nonce token is signed_tx amount minus one.
                    // AND the nonce tokens are returned to the owner (the predicate address).
                    if (
                        (o_ass_id.unwrap() == AssetId::from(calculated_nonce_asset_id)) &&
                        (o_amount == nonce_out_calc) &&
                        (Address::from(o_ass_to.unwrap()) == nonce_token_owner_this_predicate)
                    ) {
                        found_noncetoken_output = true;
                    }
                }

                j += 1;
            }
            // log(found_noncetoken_output);

            // is this necesssary?
            let mut all_checks_pass: bool = false;
            if (
                evm_tx_signed_by_owner
                && found_noncetoken_input
                && found_noncetoken_output
            ){
                all_checks_pass = true;
            }

            // log(all_checks_pass);
            return all_checks_pass;
        },
        2 => {
            return false;
        },
        99 => {
            // FOR TESTING
            return false;
        },
        _ => {
            return false;
        }
    };

    false
}


//------------------------------------------------------------------------------------------------------
//

/// Get the asset ID of a coin input
pub fn input_coin_asset_id(index: u64) -> b256 {
    __gtf::<b256>(index, GTF_INPUT_COIN_ASSET_ID)
}

/// Get the amount of a coin input
pub fn input_coin_amount(index: u64) -> u64 {
    __gtf::<u64>(index, GTF_INPUT_COIN_AMOUNT)
}

/// Verifies an input at the given index is a coin input
pub fn verify_input_coin(index: u64) -> bool {
    __gtf::<u64>(index, GTF_INPUT_TYPE) == INPUT_TYPE_COIN
}

fn output_amount_at_index(index: u64) -> u64 {
    let ptr = output_pointer(index);
    asm(r1, r2, r3: ptr) {
        addi r2 r3 i40;
        lw r1 r2 i0;
        r1: u64
    }
}

//------------------------------------------------------------------------------------------------------

fn calc_asset_id(
    evm_addr: EvmAddress,
    dummy_sub_id: b256,
    contract_id: ContractId,
) -> b256 {

    let mut result_buffer_1 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(n_id: result_buffer_1, ptr: (evm_addr, dummy_sub_id), bytes: 64) {
        s256 n_id ptr bytes;
    };

    // log(result_buffer_1);

    // let contract_id = asm() { fp: b256 };
    let mut result_buffer_2 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    asm(asset_id: result_buffer_2, ptr: (contract_id, result_buffer_1), bytes: 64) {
        s256 asset_id ptr bytes;
    };

    // log(result_buffer_2);

    return(result_buffer_2);

}

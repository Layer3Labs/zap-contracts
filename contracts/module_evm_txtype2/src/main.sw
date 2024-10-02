predicate;

mod module_consts;

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
        input_predicate_length,
        input_count,
        input_predicate,
        input_asset_id,
        // input_type,
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
    decode_1559::decode_signed_typedtx_1559,
    constants::{
        DEFAULT_KEY,
        NONCE_MAX,
        VERSION,
    },
    predi_utls::{
        get_merkle_root,
        get_predi_addr_from_root,
    },
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        verify_input_coin,
        output_count,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        tx_tip,
        verify_output_change,
        verify_output_coin,
        output_amount_at_index,
    }
};

use module_consts::{
    get_owner_b256_evm_addr,
    ASSET_KEY00,
};



fn main(signed_evm_tx: Bytes) -> bool {

    //---------------------------------------------------------------------------
    // Critial bools for validation success:

    let mut evm_tx_signed_by_owner: bool = false;
    let mut found_noncetoken_input: bool = false;
    let mut found_noncetoken_output: bool = false;

    //---------------------------------------------------------------------------
    // variables

    let mut nonce_val_in_signed_tx = 0u64;

    //---------------------------------------------------------------------------
    // decode evm tx:

    let (type_identifier, chain_id, tx_nonce, maxFeePerGas, gasLimit, value, to, asset_id,
        digest, txlengeth, tx_data_start, tx_data_end,
        signature, tx_from) = decode_signed_typedtx_1559(signed_evm_tx);

    // CHECK: evm tx was signed by the owner:
    // log(from);
    if(tx_from == get_owner_b256_evm_addr()){
        evm_tx_signed_by_owner = true;
    } else {
        return false;   // if not, then just kill it here to save exe.
    }

    // set nonce value from signed tx, to be checked later agaisnt input/output.
    nonce_val_in_signed_tx = tx_nonce;

    //---------------------------------------------------------------------------
    let in_count: u64 = input_count().as_u64();
    let out_count: u64 = output_count();

    //---------------------------------------------------------------------------
    // NONCE:
    // For Inputs:
    // calcs the setup amount minus the transaction amount.
    // checks if the above matches the nonce in the signed tx data.

    let nonce_out_calc = NONCE_MAX - ( nonce_val_in_signed_tx + 1);

    let mut i = 0;
    i = 0;
    while i < in_count {

        let inp_coin_owner = input_coin_owner(i);       // Option<Address>

        if inp_coin_owner.is_some() {

            if verify_input_coin(i) {
                let coin_asset_id = input_coin_asset_id(i);

                // check that there is an input for the nt. (AssetId key=1)
                if ASSET_KEY00 == coin_asset_id {

                    // get the amount of nt input to the tx:
                    let nt_input_amount_to_tx = input_coin_amount(i);
                    let nonce_inp_calc = NONCE_MAX - nt_input_amount_to_tx;

                    if (nonce_val_in_signed_tx == nonce_inp_calc){
                        found_noncetoken_input = true;
                    }

                }
            }
        }

        i += 1;
    }


    //---------------------------------------------------------------------------
    // do other accounting




    //---------------------------------------------------------------------------
    // do final checks

    let mut all_checks_pass: bool = false;
    if (
        evm_tx_signed_by_owner
        && found_noncetoken_input
        && true
    ){
        all_checks_pass = true;
    }

    return all_checks_pass;
    // return true;
}

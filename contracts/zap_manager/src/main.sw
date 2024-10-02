contract;

//
//  Zap Manager Contract
//
//  development version: 0.0.6
//  forc version: 0.63.1


mod constants;
mod tools;

use zap_manager_abi::ZapManager;
use zap_manager_abi::InitData;

use std::{
    bytes::Bytes,
    b512::B512,
    convert::TryFrom,
    option::Option::{self, *},
    hash::*,
    tx::{
        tx_id,
        tx_witness_data,
    },
    inputs::{
        input_predicate,
        input_count,
    },
    outputs::{
        output_type,
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
    // call_frames::{
    //     contract_id,
    // },
    // low_level_call::{call_with_function_selector, call_with_function_selector_vec, CallParams},
    context::balance_of,
    message::send_message,
    asset::*,
    contract_id::*,
    asset::mint_to,
};

use std::primitive_conversions::{u16::*, u32::*, u64::*};
use std::bytes_conversions::{b256::*, u64::*};


use constants::{
    KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEYFF,
    NONCE_MAX, MODULE_ASSET_MAX,
    VERSION,
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
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        tx_tip,
        verify_input_coin,
        verify_output_change,
        verify_output_coin,
        verify_input_contract,
        output_amount_at_index,
    },
    personal_sign::personal_sign_hash,
};

use tools::{
    mint_module_asset,
    get_sub_id,
};


pub const GTF_OUTPUT_CONTRACT_INPUT_INDEX = 0x304;
pub const GTF_OUTPUT_CONTRACT_BALANCE_ROOT = 0x305;
pub const GTF_OUTPUT_CONTRACT_STATE_ROOT = 0x306;
pub const GTF_OUTPUT_CONTRACT_CREATED_CONTRACT_ID = 0x307;
pub const GTF_OUTPUT_CONTRACT_CREATED_STATE_ROOT = 0x308;


impl ZapManager for Contract {

    /// mint and send the assets necesary to obtain basic wallet with basic functionality.
    /// if the call is made with InitData.InitModules, then keys={00,01,02,03,04,05,ff(see note)} will be minted, otherwise
    /// if InitData.NewModule will supply the key to be minted and the module addr.
    /// Note: ff to get built.
    fn initialize_wallet(
        pred_acc: Address,
        owner_evm_addr: EvmAddress,
        initdata: InitData,
    ) -> EvmAddress {

        log(owner_evm_addr);

        let in_count: u64 = input_count().into();
        let out_count: u64 = output_count().as_u64();
        log(in_count);
        log(out_count);

        let inpcoin_assetid = input_coin_asset_id(1);
        log(inpcoin_assetid);

        log(verify_input_contract(0));  //
        log(verify_input_coin(1));      //

        log(check_inputs(in_count));

        match initdata {
            InitData::InitModules(bmods) => { // the base modules only.
                let module_addrs = bmods.module_addrs;

                log(pred_acc); // log the master address, which will hold the nt.
                // mint the nonce assets and transfer.
                mint_module_asset(owner_evm_addr, KEY00, pred_acc);
                //mint_module_asset(owner_evm_addr, KEYFF, pred_acc);

                let module_keys: [b256; 5] = [KEY01, KEY02, KEY03, KEY04, KEY05];
                let mut i = 0;
                while i < 5 {
                    log(module_addrs[i]); // log the module addresses, which will hold the module asset.
                    // mint the module assets and transfer.
                    mint_module_asset(owner_evm_addr, module_keys[i], Address::from(module_addrs[i]));

                    i += 1;
                }
            },
            InitData::NewModule(amod) => { // addd a new module.
                let module_addr = amod.module_addr;
                let key = amod.key;

                log(key);
            },
        };


        return owner_evm_addr;
    }

    /// checks if the EVM address has an already existing wallet with the base modules
    fn check_init(
        evm_addr: EvmAddress,
    ) -> bool {

        let keys: [b256; 6] = [KEY00, KEY01, KEY02, KEY03, KEY04, KEY05];
        let mut i = 0;
        while i < 6 {
            let sub_id: b256 = get_sub_id(evm_addr, keys[i]);
            let modaid = AssetId::new(ContractId::this(), sub_id);
            if this_balance(modaid) != 1 {
                return false;
            }
            i += 1;
        }
        return true;
    }

    /// returns the balance of the asset with key for EVM address.
    fn check_asset_status(
        evm_addr: EvmAddress,
        key: b256,
    ) -> u64 {

        let sub_id: b256 = get_sub_id(evm_addr, key);
        log(sub_id);
        let modaid = AssetId::new(ContractId::this(), sub_id);
        log(modaid);

        this_balance(modaid)
    }








    /// return the version of this nonce manager contract.
    fn get_version() -> b256 {
        return VERSION;
    }

}






//------------------------------------------------------------------------------------------------------
// for debug:

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


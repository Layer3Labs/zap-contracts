contract;

//
//  Zap Manager Contract
//
//  development version: 0.0.6



pub mod constants;
mod tools;
pub mod manager;

// mod constants;
// mod tools;
// mod manager;

// use zap_manager_abi::{
//     ZapManager,
//     InitData,
//     UpgradeZapWallet,
// };


//FIXME - what from std's dont we need?
use std::{
    bytes::Bytes,
    b512::B512,
    string::String,
    convert::TryFrom,
    option::Option::{self, *},
    hash::*,
    storage::storage_vec::*,
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
use zapwallet_consts::wallet_consts::NUM_MODULES;

//FIXME - what from these dont we need?
use ptools::{
    transaction_utls::{
        input_coin_amount,
        input_coin_asset_id,
        output_coin_asset_id,
        output_coin_amount,
        output_coin_to,
        tx_gas_limit,
        verify_input_coin,
        verify_output_change,
        verify_output_coin,
        verify_input_contract,
        // output_amount_at_index,
    },
    personal_sign::personal_sign_hash,
};


use std::primitive_conversions::{u16::*, u32::*, u64::*};
use std::bytes_conversions::{b256::*, u64::*};

use ::manager::{
    ZapManager,
    InitData,
    V2Leaf,
    UpgradeZapWallet,
};

use constants::{
    KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08,
    KEY_NONCE,
    NONCE_MAX,
    VERSION,
};

use tools::{
    mint_nonce_asset,
    mint_module_asset,
    get_sub_id,
    get_module_assetid,
    build_upgrade,
};

use zap_utils::merkle_utils::get_v2master_addr_leaf_hash_and_bytes;


// ------------------------------
// only for debug
use helpers::{
    general_helpers::*,
    hex::*,
    numeric_utils::*,
};
// ------------------------------



storage {
    v2_leaves: StorageVec<V2Leaf> = StorageVec {},
    v2_total_leaves: u64 = 0,
    v2_swap_position: u64 = 0,
    v2_version: str[5] = __to_str_array("2.0.0"),
}


impl ZapManager for Contract {

    /// Mint and send the assets necesary to obtain a base module wallet functionality.
    /// if the call is made with InitData.InitModules, then keys={00,...,08} will be minted, otherwise
    /// if InitData.NewModule will supply the key to be minted and the module addr.
    ///
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
                mint_nonce_asset(owner_evm_addr, pred_acc);
                //mint_module_asset(owner_evm_addr, KEYFF, pred_acc);

                let module_keys: [b256; 9] = [KEY00, KEY01, KEY02, KEY03, KEY04, KEY05, KEY06, KEY07, KEY08];
                let mut i = 0;
                while i < 9 {
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

    /// checks if the EVM address has an already existing wallet with the
    /// upgrade module and the nonce asset.
    fn check_init(
        evm_addr: EvmAddress,
    ) -> bool {

        // only check KEY_NONCE and KEY00
        let keys: [b256; 2] = [KEY_NONCE, KEY00];
        let mut i = 0;
        while i < 2 {
            let sub_id: b256 = get_sub_id(evm_addr, keys[i]);
            let modaid = AssetId::new(ContractId::this(), sub_id);
            if this_balance(modaid) != 1 {
                return false;
            }
            i += 1;
        }

        return true;
    }

    //FIXME - UNUSED.
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


    #[storage(read, write)]
    fn set_v2_params(
        v2leaves: Vec<V2Leaf>,
        v2_total_leaves: u64,
        v2_swap_position: u64,
        version: str[5],
    ) {
        //TODO - this needs to be only owner
        // let update_v2leaves_amount = v2leaves.len();
        // assert(update_v2leaves_amount == v2_total_leaves); //REVIEW - do we need this?

        // Owner check
        // require_owner();

        // Check the number of leaves passed in is correct (total - 1)
        let update_v2leaves_amount = v2leaves.len();
        assert(update_v2leaves_amount == (v2_total_leaves + 1));

        // Clear existing storage
        storage.v2_leaves.clear();

        // Populate storage vector with the new leaves
        let mut i = 0;
        while i < update_v2leaves_amount {
            let leaf = v2leaves.get(i).unwrap();

            // Verify leaf number is correct (should match its position)
            assert(leaf.number == i);

            storage.v2_leaves.push(leaf);
            i += 1;
        }

        // Update other storage values
        storage.v2_total_leaves.write(v2_total_leaves);
        storage.v2_swap_position.write(v2_swap_position);
        storage.v2_version.write(version);



        // Debug logging
        log(String::from_ascii_str("Updated v2_leaves count:"));
        log(u256_to_hex(asm(r1: (0, 0, 0, storage.v2_leaves.len())) { r1: u256 }));
        log(String::from_ascii_str("Total leaves (including final):"));
        log(u256_to_hex(asm(r1: (0, 0, 0, v2_total_leaves)) { r1: u256 }));
        log(String::from_ascii_str("Swap position:"));
        log(u256_to_hex(asm(r1: (0, 0, 0, v2_swap_position)) { r1: u256 }));

    }


/*

    v2_leaves: StorageVec<V2Leaf> = StorageVec {},
    v2_total_leaves: u64 = 0,
    v2_swap_position: u64 = 0,
    v2_version: str[5] = __to_str_array("2.0.0"),




*/




    #[storage(read, write), payable]
    fn upgrade(
        owner_evm_addr: EvmAddress,
        upgrade_compact_signature: B512,
        sponsored: bool,
        receiver_v2_final_leaf_bytecode: Bytes,
    ) {

        // 1. Contract_ID


        // 2. Old_ZapWallet_Address
        // pass in owner evm addr,
        // calculate nonce assetid
        // get owner v1 zapwallet from nonce input

        let nonce_assetid: b256 = get_module_assetid(owner_evm_addr, KEY_NONCE).into();
        let module00_assetid: b256 = get_module_assetid(owner_evm_addr, KEY00).into();

        //DEBUG
        log(String::from_ascii_str("nonce_assetid:"));
        log(b256_to_hex(nonce_assetid));


        // 3. New_ZapWallet_Address
        //
        // read the stored leaves, number that make u the total
        // from:
        // v2_leaves: StorageVec<V2Leaf> = StorageVec {},
        // v2_swap_position: u64 = 0;
        // v2_total_leaves: u64 = 0,

        //TODO - read all the v2_leaves and construct the v2_leaf_hashes array
        // dont include the final leaf as we will be building this from a combination
        // of the owners v2 bytecode and pubkey:
        // --> write routing that read StorageVec<V2Leaf> and populates below
        // note: this is restriced to 8 total leaves.

        // Total number of leaves in the v2 bytecode
        //TODO - read from storage and used in the routine below
        let v2_num_leaves = 2;

        let mut v2_leaf_hashes: [b256; 8] = [
            0x887f618e0e5af1cc4ff0269243f7ce0dc8f0a8e2d240a62027fd2be36e805110, // H1
            0xe85ee99f4887c5ea53be14a833bbe383059b0a1af80f159b517e1983e178f220, // H2
            b256::min(), // H3
            b256::min(), // H4
            b256::min(), b256::min(), b256::min(), b256::min(), // max 8 leaves
        ];

        // read the v2_swap_position from storage
        //TODO -
        let mut new_v2_bytecode = receiver_v2_final_leaf_bytecode;
        let swap_position: u64 = 100;

        //NOTE - DEBUG
        // let final_leaf_posiiton = (v2_num_leaves - 1);
        let final_leaf_posiiton = 2; // just place it elsewhere for debug



        //-----------------
        //NOTE - DEBUG log out what we have
        log(String::from_ascii_str("v2_num_leaves:"));
        log(u256_to_hex(asm(r1: (0, 0, 0, v2_num_leaves)) { r1: u256 }));




        log(String::from_ascii_str("swap_position:"));
        log(u256_to_hex(asm(r1: (0, 0, 0, swap_position)) { r1: u256 }));

        log(String::from_ascii_str("final_leaf_posiiton:"));
        log(u256_to_hex(asm(r1: (0, 0, 0, final_leaf_posiiton)) { r1: u256 }));


        let blah_addr = get_v2master_addr_leaf_hash_and_bytes(
            v2_leaf_hashes,
            v2_num_leaves,          // total leaves (inc final leaf).
            new_v2_bytecode,        // reciving v2 zapwallet final leaf bytecode.
            final_leaf_posiiton,    // final leaf number.
            owner_evm_addr.into(),
            swap_position,
        );


        log(String::from_ascii_str("New ZapWallet addr:"));
        log(b256_to_hex(blah_addr));

        //NOTE - DEBUG
        let new_wallet_addr = 0x77a31ce8d22e3356e0829099abefd259bd5dda8f6fc27081de193964acf79b58;


        // 4. New_Version
        // need to get the value for this from storage

        //NOTE - DEBUG
        let v2v: str[5] = __to_str_array("2.0.0");
        let version = String::from_ascii_str(from_str_array(v2v));
        // let version = String::from_ascii_str("V2.0.0");

        //NOTE - DEBUG
        log(String::from_ascii_str("version:"));
        log(version);


        // 5. Sponsored_Transaction
        let sponsored_transaction = match sponsored {
            true => { String::from_ascii_str("YES") },
            false => { String::from_ascii_str("NO") },
        };

        log(String::from_ascii_str("sponsored_transaction:"));
        log(sponsored_transaction);

        // 6. Upgrade_UTXO
        // get Upgrade_UTXO
        // calculate owners module00 assetid,
        // find upgrade assetid (for the owner)
        // get utxoid from the upgrade assetid input
        //
        // this is done in build_upgrade()


        // 7. call build_upgrade() with the above

        let upgrade = build_upgrade(
            nonce_assetid,
            module00_assetid,
        );


        /*
        struct UpgradeZapWallet {
            Contract_ID: H256,
            Old_ZapWallet_Address: H256,
            New_ZapWallet_Address: H256,
            New_Version: String,
            Sponsored_Transaction: String,
            Upgrade_UTXO: H256,
        }
        */

        // let upgrade = UpgradeZapWallet {
        //     contract_id: b256::zero(),
        //     old_zapWallet_address: b256::zero(),
        //     new_zapWallet_address: b256::zero(),
        //     new_version: String::from_ascii_str("blah:"),
        //     sponsored_transaction: String::from_ascii_str("foo"),
        //     upgrade_utxo: b256::zero(),
        // };

        let encoded = UpgradeZapWallet::encode(upgrade);

        //DEBUG
        log(String::from_ascii_str("encoded:"));
        log(b256_to_hex(encoded));

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

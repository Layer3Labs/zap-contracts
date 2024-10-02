script;

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
use std::bytes_conversions::{b256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use std::logging::log;


use ptools::{
    decode_erc20::decode_signed_typedtx_erc20,
    decode_1559::decode_signed_typedtx_1559,
    decode_legacy::decode_signed_legacy_tx,
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
    },
    personal_sign::personal_sign_hash,
};
use helpers::general_helpers::{
    hex_string_to_bytes,
    char_to_hex,
};



fn main() -> bool {

    return true;
}



// forc test erc20_txbytes_1559_rlp_decode --logs
#[test()]
fn erc20_txbytes_1559_rlp_decode(){

    let mut hex_string = String::from_ascii_str("02f8b483aa36a7018459682f00850341ec18ef83012f8d947b79995e5f793a07bc00c21412e50ecae098e7f980b844a9059cbb000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c650000000000000000000000000000000000000000000000000000b5e620f48000c080a0295ab67ca026cc1b22e36bf9402512dc3008523ee47e94ad4fa1c7a5c55ba026a004c704aa7b1b3e7fc27968e8e4e4e367620297f90228d98324c8136154526bf2");
    // let mut hex_string = String::from_ascii_str("02f8b383aa36a7038459682f008502cea099b982cb28947b79995e5f793a07bc00c21412e50ecae098e7f980b844a9059cbb000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c65000000000000000000000000000000000000000000000000000078f679c15000c001a0ccb1fcdd97c17a9de8481a2e065fc54d19183b5448abed9b0ffc33313d08b970a0525759c7d51793465a12c78e1be556f3287b9cd515bbe3897c2ccb5f59861c11");

    let rlp_bytes = hex_string_to_bytes(hex_string).unwrap();

    log(hex_string.capacity());
    log(rlp_bytes.len());

    let (type_identifier, chain_id, tx_nonce, max_fee_per_gas, gasLimit, value, to, asset_id,
        digest, txlengeth, tx_data_start, tx_data_end,
        signature, tx_from) = decode_signed_typedtx_erc20(rlp_bytes);

    let expected_chainid: u64 = 0xaa36a7; // deciaml 11155111 = Sepolia
    log(chain_id);
    assert_eq(expected_chainid, chain_id);


    log(digest);

    log(tx_from);

}


// forc test txbytes_1559_rlp_decode --logs
#[test()]
fn txbytes_1559_rlp_decode(){

    /* Transaction Details:
    .-------------------------------------------------------------------------------------------------------------------------------------------------------------.
    | chain_id                 | 621512                                                                                                                           |
    | signer_nonce             | 1                                                                                                                                |
    | nonce_inp_calc           | 4294967294                                                                                                                       |
    | nonce_out_calc           | 4294967293                                                                                                                       |
    |                          |                                                                                                                                  |
    | gas_price                | 4761904761                                                                                                                       |
    | max_priority_fee_per_gas |                                                                                                                                  |
    | max_fee_per_gas          | 21000                                                                                                                            |
    | gas_limit                | 21000                                                                                                                            |
    | max_cost                 | 99999999981000                                                                                                                   |
    | destination              |                                                                                                                                  |
    | from                     | 0xff04…285a                                                                                                                      |
    | to                       | 0xff03…5c49                                                                                                                      |
    | payload                  |                                                                                                                                  |
    | amount                   | 1245500000000000000                                                                                                              |
    | access_list              | : AccessList([])                                                                                                                 |
    | signature_y_parity       | 1                                                                                                                                |
    | signature_r              | 101334884756125715225726774997052863315252374851952534682444314405566618258063                                                   |
    | signature_s              | 8992704100498376511724713139480016999501839508141619343917343218951185530759                                                     |
    |                          |                                                                                                                                  |
    | k256(tx bytes)           | 99eba5ce902e70b4397e2d871d34e2fda0b0e05d7cc12366018a1d349c493ccb                                                                 |
    |                          |                                                                                                                                  |
    | tx bytes rlp             | 02ef83097bc8018085011bd4e67982520894ff03ffd5d3e881c60a91eaa30c67d03aec025c49881148e7a6abbfc00080c0                               |
    |                          |                                                                                                                                  |
    | tx hash                  | f098ac7397c2e545b24fa40003da54b538de8111734ffde9df18d91b04358fa2                                                                 |
    |                          |                                                                                                                                  |
    | sig r:s                  | e00983222a8dbc155c3bf1ca1d4d88b6fedb9dbe9d56c69b21142aa72f5fca8f13e1b0ad9bdab14a6c019e1f7982f9843fe351ddcbfd16c614f35802462c7f87 |
    | sig r                    | e00983222a8dbc155c3bf1ca1d4d88b6fedb9dbe9d56c69b21142aa72f5fca8f                                                                 |
    | sig s                    | 13e1b0ad9bdab14a6c019e1f7982f9843fe351ddcbfd16c614f35802462c7f87                                                                 |
    | sig v                    | 0000000000000001                                                                                                                 |
    |                          |                                                                                                                                  |
    | sig recovery id          | 01                                                                                                                               |
    |                          |                                                                                                                                  |
    | recovered signer         | ff04ff9252178b00700c297243784ace4f30285a                                                                                         |
    '-------------------------------------------------------------------------------------------------------------------------------------------------------------'
    */

    let mut hex_string = String::from_ascii_str("02f87283097bc8018085011bd4e67982520894ff03ffd5d3e881c60a91eaa30c67d03aec025c49881148e7a6abbfc00080c001a0e00983222a8dbc155c3bf1ca1d4d88b6fedb9dbe9d56c69b21142aa72f5fca8fa013e1b0ad9bdab14a6c019e1f7982f9843fe351ddcbfd16c614f35802462c7f87");
    let rlp_bytes = hex_string_to_bytes(hex_string).unwrap();

    // the signed tx has 234 characters in the hex encoded string, thats 0-116 bytes (117 total),
    assert(hex_string.capacity() == 234u64);    // 0xea length.
    assert(rlp_bytes.len() == 117u64);          // 0x75 length (half of above).

    let (type_identifier, chain_id, tx_nonce, max_fee_per_gas, gasLimit, value, to, asset_id,
        digest, txlengeth, tx_data_start, tx_data_end,
        signature, tx_from) = decode_signed_typedtx_1559(rlp_bytes);

    let test_type_identifier: u64 = 02;
    let test_chain_id: u64 = 621512;
    let test_max_fee_per_gas: u64 = 21000;
    // log(max_fee_per_gas);
    let test_amount: u64 = 1245500000000000000;
    let test_from: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;

    log(test_chain_id);

    assert_eq(test_type_identifier, type_identifier);
    assert_eq(test_chain_id, chain_id);
    // assert_eq(test_max_fee_per_gas, max_fee_per_gas);
    assert_eq(test_amount, value);
    assert_eq(test_from, tx_from);
}


// forc test txbytes_legacy_rlp_decode --logs
#[test()]
fn txbytes_legacy_rlp_decode(){

    /* Transaction Details:
    .-------------------------------------------------------------------------------------------------------------------------------------------------------------.
    | chain_id                 | 621512                                                                                                                           |
    | signer_nonce             | 4                                                                                                                                |
    | nonce_inp_calc           | 4294967291                                                                                                                       |
    | nonce_out_calc           | 4294967290                                                                                                                       |
    |                          |                                                                                                                                  |
    | gas_price                | 26723                                                                                                                            |
    | max_priority_fee_per_gas |                                                                                                                                  |
    | max_fee_per_gas          | 21000                                                                                                                            |
    | gas_limit                | 21000                                                                                                                            |
    | max_cost                 | 561183000                                                                                                                        |
    | destination              |                                                                                                                                  |
    | from                     | 0xff04…285a                                                                                                                      |
    | to                       | 0xff03…5c49                                                                                                                      |
    | payload                  |                                                                                                                                  |
    | amount                   | 245500000000000000                                                                                                               |
    | access_list              | no access list items.                                                                                                            |
    | signature_y_parity       | 1243059                                                                                                                          |
    | signature_r              | 53956108037002696102105540939109512654696022068321422501505579584874854617956                                                    |
    | signature_s              | 47117762139040053000054852946087686241795149840627700864464931260213153665682                                                    |
    |                          |                                                                                                                                  |
    | k256(tx bytes)           | ed026390545fe0d348f05e19791cc7d7bb4bb862cc74c9f3d70d37ee060d9917                                                                 |
    |                          |                                                                                                                                  |
    | tx bytes rlp             | ec0482686382520894ff03ffd5d3e881c60a91eaa30c67d03aec025c4988036830f3045bc0008083097bc88080                                       |
    |                          |                                                                                                                                  |
    | sig r:s                  | 774a132dfae4d36975109ecb0bfa17ae4894ae81ab66822d0c14c5aca84a1364682bb55353d9d7ce526c965b19bdd49fe1677d905fcd00d02eeff33e0bba9292 |
    | sig r                    | 774a132dfae4d36975109ecb0bfa17ae4894ae81ab66822d0c14c5aca84a1364                                                                 |
    | sig s                    | 682bb55353d9d7ce526c965b19bdd49fe1677d905fcd00d02eeff33e0bba9292                                                                 |
    | sig v                    | 000000000012f7b3                                                                                                                 |
    |                          |                                                                                                                                  |
    | sig recovery id          | 00                                                                                                                               |
    |                          |                                                                                                                                  |
    | recovered signer         | ff04ff9252178b00700c297243784ace4f30285a                                                                                         |
    '-------------------------------------------------------------------------------------------------------------------------------------------------------------'
    */

    let mut hex_string = String::from_ascii_str("f86c0482686382520894ff03ffd5d3e881c60a91eaa30c67d03aec025c4988036830f3045bc000808312f7b3a0774a132dfae4d36975109ecb0bfa17ae4894ae81ab66822d0c14c5aca84a1364a0682bb55353d9d7ce526c965b19bdd49fe1677d905fcd00d02eeff33e0bba9292");
    let rlp_bytes = hex_string_to_bytes(hex_string).unwrap();

    // the signed tx has 220 characters in the hex encoded string, thats 0-109 bytes (110 total).
    assert(hex_string.capacity() == 220u64);    // 0xdc length.
    assert(rlp_bytes.len() == 110u64);          // 0x6e length (half of above).

    let (type_identifier, chain_id, tx_nonce, maxFeePerGas, gasLimit, value, to, asset_id,
        digest, txlengeth, tx_data_start, tx_data_end,
        signature, tx_from) = decode_signed_legacy_tx(rlp_bytes);

    let test_type_identifier: u64 = 00;
    let test_chain_id: u64 = 621512;
    let test_amount: u64 = 245500000000000000;
    let test_from: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;

    assert_eq(test_type_identifier, type_identifier);
    assert_eq(test_chain_id, chain_id);
    assert_eq(test_amount, value);
    assert_eq(test_from, tx_from);
}

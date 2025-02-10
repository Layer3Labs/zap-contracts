library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
};
use std::*;
use std::bytes_conversions::{b256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use std::logging::log;
use zapwallet_consts::wallet_consts::NONCE_MAX;
use zap_utils::{
    decode_erc20::*,
    decode_1559::*,
    decode_legacy::*,
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
};


// forc test txbytes_01_erc20_rlp_decode --logs
#[test()]
fn txbytes_01_erc20_rlp_decode(){

    /*
    Transaction Details:
    .-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.
    | chain_id                 | 9889                                                                                                                                                                                                                                 |
    |                          |                                                                                                                                                                                                                                      |
    | signer_nonce             | 1                                                                                                                                                                                                                                    |
    | nonce_inp_calc           | 4294967294                                                                                                                                                                                                                           |
    | nonce_out_calc           | 4294967293                                                                                                                                                                                                                           |
    |                          |                                                                                                                                                                                                                                      |
    | gas_price                | 2000000000                                                                                                                                                                                                                           |
    | max_priority_fee_per_gas |                                                                                                                                                                                                                                      |
    | max_fee_per_gas          | 100000                                                                                                                                                                                                                               |
    | gas_limit                | 100000                                                                                                                                                                                                                               |
    | max_cost                 | 200000000000000                                                                                                                                                                                                                      |
    |                          |                                                                                                                                                                                                                                      |
    | amount (Wei)             | 0                                                                                                                                                                                                                                    |
    |                          |                                                                                                                                                                                                                                      |
    | destination:             |                                                                                                                                                                                                                                      |
    | from                     | 333339d42a89028ee29a9e9f4822e651bac7ba14                                                                                                                                                                                             |
    | to                       | 7b79995e5f793a07bc00c21412e50ecae098e7f9                                                                                                                                                                                             |
    | payload                  |                                                                                                                                                                                                                                      |
    |                          |                                                                                                                                                                                                                                      |
    | access_list              | : AccessList([])                                                                                                                                                                                                                     |
    |                          |                                                                                                                                                                                                                                      |
    | data                     | a9059cbb000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c650000000000000000000000000000000000000000000000000000000047868c00                                                                                             |
    |                          |                                                                                                                                                                                                                                      |
    | signature_y_parity       | 1                                                                                                                                                                                                                                    |
    | signature_r              | 47572330670619835131601972305846360216528575930650663639893870345864621819448                                                                                                                                                        |
    | signature_s              | 45208782320559818219154593247435657713282900383621949289453576005801576328017                                                                                                                                                        |
    |                          |                                                                                                                                                                                                                                      |
    | k256(tx bytes)           | 3a162ff4db61d703da5706b0606381cfcdef3537d91338c1181857faa10537b0                                                                                                                                                                     |
    |                          |                                                                                                                                                                                                                                      |
    | tx bytes rlp             | 02f86f8226a101843b9aca008477359400830186a0947b79995e5f793a07bc00c21412e50ecae098e7f980b844a9059cbb000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c650000000000000000000000000000000000000000000000000000000047868c00c0 |
    |                          |                                                                                                                                                                                                                                      |
    | tx hash                  | 0df45fdb1e50c8b9860075c623277bfb8cfa44c6f9db07cf776b1b79eadf2209                                                                                                                                                                     |
    |                          |                                                                                                                                                                                                                                      |
    | sig r:s                  | 692cfc27428eacb68533758d6d1a214a23f6e5dde4ee81ea2247b40cfcb7863863f343967c2f02cba9a50cf0a7c0a759bbda261e9c63063e1199c1e36b196b51                                                                                                     |
    | sig r                    | 692cfc27428eacb68533758d6d1a214a23f6e5dde4ee81ea2247b40cfcb78638                                                                                                                                                                     |
    | sig s                    | 63f343967c2f02cba9a50cf0a7c0a759bbda261e9c63063e1199c1e36b196b51                                                                                                                                                                     |
    | sig v                    | 0000000000000001                                                                                                                                                                                                                     |
    |                          |                                                                                                                                                                                                                                      |
    | sig recovery id          | 01                                                                                                                                                                                                                                   |
    |                          |                                                                                                                                                                                                                                      |
    | recovered signer         | 333339d42a89028ee29a9e9f4822e651bac7ba14                                                                                                                                                                                             |
    |                          |                                                                                                                                                                                                                                      |
    | tx_sig                   | 02f86f8226a101843b9aca008477359400830186a0947b79995e5f793a07bc00c21412e50ecae098e7f980b844a9059cbb000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c650000000000000000000000000000000000000000000000000000000047868c00c0 |
    | tx_sig k256 hash         | 3a162ff4db61d703da5706b0606381cfcdef3537d91338c1181857faa10537b0                                                                                                                                                                     |
    |                          |                                                                                                                                                                                                                                      |
    '-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'

    ERC20 Transfer Details:
	Selector    : 0xa9059cbb
	Data Items  :
	  0: Address(ff02ffaee94c93a6318f932f3e6b910b6b075c65)
	  1: Amount(1200000000)
	Contract ID : 7b79995e5f793a07bc00c21412e50ecae098e7f9
	Recipient   : ff02ffaee94c93a6318f932f3e6b910b6b075c65
	Amount      : 1200000000


    */

    let mut hex_string = String::from_ascii_str("02f8b28226a101843b9aca008477359400830186a0947b79995e5f793a07bc00c21412e50ecae098e7f980b844a9059cbb000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c650000000000000000000000000000000000000000000000000000000047868c00c001a0692cfc27428eacb68533758d6d1a214a23f6e5dde4ee81ea2247b40cfcb78638a063f343967c2f02cba9a50cf0a7c0a759bbda261e9c63063e1199c1e36b196b51");

    let rlp_bytes = hex_string_to_bytes(hex_string).unwrap();

    log(hex_string.capacity());
    log(rlp_bytes.len());

    // Decode signed evm erc20 transfer tx rlp into its constituent fields:
    let (
        _tx_type_identifier,
        tx_chain_id,
        _tx_nonce,
        _tx_max_fee_per_gas,
        _tx_gas_limit,
        tx_value,
        tx_to,
        _tx_asset_id,
        tx_digest,
        _tx_lengeth,
        _tx_data_start,
        _tx_data_end,
        _tx_signature,
        tx_from,
        tx_ct_to,
        tx_ct_amount,
    ) = match decode_signed_typedtx_erc20(rlp_bytes) {
        DecodeERC20RLPResult::Success(result) => { result },
        DecodeERC20RLPResult::Fail(error_code) => {
            // rlp decoding failed with error code.
            // return false;
            revert(error_code);
        },
    };

    // chain id:
    // test chain id: 9889 (deciaml)
    let expected_chainid = asm(r1: (0, 0, 0, 9889u64)) { r1: b256 };
    let tx_chainid_bn = asm(r1: (0, 0, 0, tx_chain_id)) { r1: b256 };

    log(String::from_ascii_str("Chain Id (expected / tx):"));
    log(b256_to_hex(expected_chainid));
    log(b256_to_hex(tx_chainid_bn));
    assert_eq(expected_chainid, tx_chainid_bn);

    // Digest
    let expected_digest: b256 = 0x3a162ff4db61d703da5706b0606381cfcdef3537d91338c1181857faa10537b0;
    log(String::from_ascii_str("Digest:"));
    log(b256_to_hex(tx_digest));
    assert_eq(expected_digest, tx_digest);

    // Tx From
    let expected_from: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;
    log(String::from_ascii_str("Tx From:"));
    log(b256_to_hex(tx_from));
    assert_eq(expected_from, tx_from);

    // Tx To (is the ERC20 Contract ID)
    let expected_to: b256 = 0x0000000000000000000000007b79995e5f793a07bc00c21412e50ecae098e7f9;
    log(String::from_ascii_str("Tx To (is the ERC20 Contract ID):"));
    log(b256_to_hex(tx_to));
    assert_eq(expected_to, tx_to);

    // Tx Value (this should be zero for a erc20 transfer)
    let expected_value = asm(r1: (0, 0, 0, 0)) { r1: u256 };
    log(String::from_ascii_str("Tx Value (should be zero):"));
    let tx_value_as_u256 = asm(r1: (0, 0, 0, tx_value)) { r1: u256 };
    log(u256_to_hex(tx_value_as_u256));
    assert_eq(expected_value, tx_value_as_u256);

    // Tx ERC20 Receiver
    let expected_receiver: b256 = 0x000000000000000000000000ff02ffaee94c93a6318f932f3e6b910b6b075c65;
    log(String::from_ascii_str("Tx ERC20 Receiver:"));
    log(b256_to_hex(tx_ct_to));
    assert_eq(expected_receiver, tx_ct_to);

    // Tx ERC20 Amount
    // 1200000000
    let expected_erc20value = asm(r1: (0, 0, 0, 1200000000)) { r1: u256 };
    log(String::from_ascii_str("Tx ERC20 Amount:"));
    log(b256_to_hex(tx_ct_amount));
    assert_eq(expected_erc20value, tx_ct_amount.into());


}

// forc test txbytes_02_1559_rlp_decode --logs
#[test()]
fn txbytes_02_1559_rlp_decode(){

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

    // Decode signed_evm_tx rlp into its constituent fields:
    let (
        type_identifier,
        chain_id,
        tx_nonce,
        max_fee_per_gas,
        _gas_limit,
        value_wei,
        _to,
        _asset_id,
        _digest,
        _txlengeth,
        _tx_data_start,
        _tx_data_end,
        _signature,
        tx_from
    ) = match decode_signed_typedtx_1559(rlp_bytes) {
        DecodeType02RLPResult::Success(result) => { result },
        DecodeType02RLPResult::Fail(error_code) => {
            // rlp decoding failed with error code.
            // return false;
            revert(error_code);
        },
    };

    let test_type_identifier: u64 = 02;
    let test_chain_id: u64 = 621512;
    // let test_max_fee_per_gas: u64 = 21000;

    log(max_fee_per_gas);

    let ex_amount: u64 = 1245500000000000000;
    let test_amount = asm(r1: (0, 0, 0, ex_amount)) { r1: u256 };
    let test_nonce: u64 = 4294967294 - 4294967293;  // 1
    let test_from: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;

    assert_eq(test_type_identifier, type_identifier);
    assert_eq(test_chain_id, chain_id);
    // assert_eq(test_max_fee_per_gas, max_fee_per_gas);
    assert_eq(test_amount, value_wei);
    assert_eq(test_from, tx_from);

    log(String::from_ascii_str("Tx Nonce:"));
    log(u256_to_hex( asm(r1: (0, 0, 0, tx_nonce)) { r1: u256 } ));
    assert_eq(test_nonce, tx_nonce);

}

// forc test txbytes_03_legacy_rlp_decode --logs
#[test()]
fn txbytes_03_legacy_rlp_decode(){

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

    // let (type_identifier, chain_id, tx_nonce, maxFeePerGas, gasLimit, value, to, asset_id,
    //     digest, txlengeth, tx_data_start, tx_data_end,
    //     signature, tx_from) = decode_signed_legacy_tx(rlp_bytes);

    let (
        _tx_type_identifier,    // u64,    // type_identifier
        tx_chain_id,            // u64,    // chain_id
        _tx_nonce,              // u64,    // nonce
        _tx_max_fee_per_gas,    // u64,    // maxFeePerGas
        _tx_gas_limit,          // u64,    // gasLimit
        _tx_value_wei,          // u64,    // value
        _tx_to,                 // b256,   // to
        _tx_asset_id,           // b256,   // asset_id
        tx_digest,              // b256,   // digest
        _tx_lengeth,            // u64,    // length
        _tx_data_start,         // u64,    // tx_data_start
        _tx_data_end,           // u64,    // tx_data_end
        _tx_signature,          // B512,   // signature
        tx_from                 // b256,   // from
    ) = match decode_signed_legacy_tx(rlp_bytes) {
        DecodeLegacyRLPResult::Success(result) => { result },
        DecodeLegacyRLPResult::Fail(error_code) => {
            // rlp decoding failed with error code.
            // return false;
            revert(error_code);
        },
    };

    // let test_type_identifier: u64 = 00;
    let test_chain_id: u64 = 621512;
    // let test_amount: u64 = 245500000000000000;
    // let test_from: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;

    // assert_eq(test_type_identifier, tx_type_identifier);
    // assert_eq(test_chain_id, tx_chain_id);
    // assert_eq(test_amount, tx_value_wei);
    // assert_eq(test_from, tx_from);

    // Chain ID:
    log(String::from_ascii_str("Chain Id: (expected / got):"));
    // let tx_chainid = asm(r1: (0, 0, 0, tx_chain_id)) { r1: b256 };
    log(b256_to_hex( asm(r1: (0, 0, 0, test_chain_id)) { r1: b256 } ));
    log(b256_to_hex( asm(r1: (0, 0, 0, tx_chain_id)) { r1: b256 } ));
    // assert_eq(test_chain_id, tx_chain_id);

    // Digest:
    log(String::from_ascii_str("Digest:"));
    log(b256_to_hex(tx_digest));

    // Tx From:
    log(String::from_ascii_str("Tx From:"));
    log(b256_to_hex(tx_from));

}

// forc test txbytes_04_legacy_rlp_decode --logs
#[test()]
fn txbytes_04_legacy_rlp_decode(){

    /* Transaction Details:
    .-------------------------------------------------------------------------------------------------------------------------------------------------------------.
    | chain_id                 | 9889                                                                                                                             |
    |                          |                                                                                                                                  |
    | signer_nonce             | 1                                                                                                                                |
    | nonce_inp_calc           | 4294967294                                                                                                                       |
    | nonce_out_calc           | 4294967293                                                                                                                       |
    |                          |                                                                                                                                  |
    | gas_price                | 10208702357                                                                                                                      |
    | max_priority_fee_per_gas |                                                                                                                                  |
    | max_fee_per_gas          | 23100                                                                                                                            |
    | gas_limit                | 23100                                                                                                                            |
    | max_cost                 | 235821024446700                                                                                                                  |
    |                          |                                                                                                                                  |
    | amount (Wei)             | 2300000000000000                                                                                                                 |
    |                          |                                                                                                                                  |
    | destination:             |                                                                                                                                  |
    | from                     | 333339d42a89028ee29a9e9f4822e651bac7ba14                                                                                         |
    | to                       | ff02ffaee94c93a6318f932f3e6b910b6b075c65                                                                                         |
    | payload                  |                                                                                                                                  |
    |                          |                                                                                                                                  |
    | access_list              | no access list items.                                                                                                            |
    |                          |                                                                                                                                  |
    | data                     | None                                                                                                                             |
    |                          |                                                                                                                                  |
    | signature_y_parity       | 19814                                                                                                                            |
    | signature_r              | 113833457662185482354228525240782570098790253298623923217148455496057780956575                                                   |
    | signature_s              | 3537573844740564909452691926442245628052596255812777302893226321187786780958                                                     |
    |                          |                                                                                                                                  |
    | k256(tx bytes)           | e90d6de04e3a5fc269bc2229e785615439e320e98f4a30b688ebe95b84ee8ed2                                                                 |
    |                          |                                                                                                                                  |
    | tx bytes rlp             | ed018502607c6f95825a3c94ff02ffaee94c93a6318f932f3e6b910b6b075c6587082bd67afbc000808226a18080                                     |
    |                          |                                                                                                                                  |
    | tx hash                  | f1e8e193d3f10c4f9b5932f603f69ec85a6ea0313cc3ac4b8f577d10ed158d01                                                                 |
    |                          |                                                                                                                                  |
    | sig r:s                  | fbab742d255cb1fef54b69d700fed4a18d9feaa400b014f1043368c35f0fed9f07d23222a25cab642bdbd29c332ef168371db79c1cedb4b3a32a0152a4c0f11e |
    | sig r                    | fbab742d255cb1fef54b69d700fed4a18d9feaa400b014f1043368c35f0fed9f                                                                 |
    | sig s                    | 07d23222a25cab642bdbd29c332ef168371db79c1cedb4b3a32a0152a4c0f11e                                                                 |
    | sig v                    | 0000000000004d66                                                                                                                 |
    |                          |                                                                                                                                  |
    | sig recovery id          | 01                                                                                                                               |
    |                          |                                                                                                                                  |
    | recovered signer         | 333339d42a89028ee29a9e9f4822e651bac7ba14                                                                                         |
    |                          |                                                                                                                                  |
    | tx_sig                   | ed018502607c6f95825a3c94ff02ffaee94c93a6318f932f3e6b910b6b075c6587082bd67afbc000808226a18080                                     |
    | tx_sig k256 hash         | e90d6de04e3a5fc269bc2229e785615439e320e98f4a30b688ebe95b84ee8ed2                                                                 |
    |                          |                                                                                                                                  |
    '-------------------------------------------------------------------------------------------------------------------------------------------------------------'
    tx_bytes: f86d018502607c6f95825a3c94ff02ffaee94c93a6318f932f3e6b910b6b075c6587082bd67afbc00080824d66a0fbab742d255cb1fef54b69d700fed4a18d9feaa400b014f1043368c35f0fed9fa007d23222a25cab642bdbd29c332ef168371db79c1cedb4b3a32a0152a4c0f11e
    */

    let mut hex_string = String::from_ascii_str("f86d018502607c6f95825a3c94ff02ffaee94c93a6318f932f3e6b910b6b075c6587082bd67afbc00080824d66a0fbab742d255cb1fef54b69d700fed4a18d9feaa400b014f1043368c35f0fed9fa007d23222a25cab642bdbd29c332ef168371db79c1cedb4b3a32a0152a4c0f11e");
    let rlp_bytes = hex_string_to_bytes(hex_string).unwrap();

    // the signed tx has 220 characters in the hex encoded string, thats 0-109 bytes (110 total).
    // assert(hex_string.capacity() == 220u64);    // 0xdc length.
    // assert(rlp_bytes.len() == 110u64);          // 0x6e length (half of above).

    // let (type_identifier, chain_id, tx_nonce, maxFeePerGas, gasLimit, value, to, asset_id,
    //     digest, txlengeth, tx_data_start, tx_data_end,
    //     signature, tx_from) = decode_signed_legacy_tx(rlp_bytes);

    let (
        _tx_type_identifier,    // u64,    // type_identifier
        tx_chain_id,            // u64,    // chain_id
        _tx_nonce,              // u64,    // nonce
        tx_gas_price,           // u64,    // gasPrice
        tx_gas_limit,           // u64,    // gasLimit
        tx_value_wei,           // u64,    // value
        _tx_to,                 // b256,   // to
        _tx_asset_id,           // b256,   // asset_id
        tx_digest,              // b256,   // digest
        _tx_lengeth,            // u64,    // length
        _tx_data_start,         // u64,    // tx_data_start
        _tx_data_end,           // u64,    // tx_data_end
        _tx_signature,          // B512,   // signature
        tx_from                 // b256,   // from
    ) = match decode_signed_legacy_tx(rlp_bytes) {
        DecodeLegacyRLPResult::Success(result) => { result },
        DecodeLegacyRLPResult::Fail(error_code) => {
            // rlp decoding failed with error code.
            // return false;
            revert(error_code);
        },
    };

    // let test_type_identifier: u64 = 00;
    let test_chain_id: u64 = 9889;
    // let test_amount: u64 = 2300000000000000;
    // let test_from: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

    // assert_eq(test_type_identifier, tx_type_identifier);
    // assert_eq(test_chain_id, tx_chain_id);
    // assert_eq(test_amount, tx_value_wei);
    // assert_eq(test_from, tx_from);

    // Chain ID:
    log(String::from_ascii_str("Chain Id: (expected / got):"));
    // let tx_chainid = asm(r1: (0, 0, 0, tx_chain_id)) { r1: b256 };
    log(b256_to_hex( asm(r1: (0, 0, 0, test_chain_id)) { r1: b256 } ));
    log(b256_to_hex( asm(r1: (0, 0, 0, tx_chain_id)) { r1: b256 } ));
    assert_eq(test_chain_id, tx_chain_id);

    // Digest:
    log(String::from_ascii_str("Digest:"));
    log(b256_to_hex(tx_digest));

    // Tx From:
    log(String::from_ascii_str("Tx From:"));
    log(b256_to_hex(tx_from));

    // Tx Value (wei) as u256:
    log(String::from_ascii_str("Tx Value (wei):"));
    log(u256_to_hex(tx_value_wei));
    // 0x082bd67afbc000 = 2300000000000000

    // Tx Cost:
    // max_cost = gas_price × gas_limit
    // = 10208702357 × 23100
    // = 235821024446700 wei
    // ≈ 0.0002358 ETH
    // Expected max_cost_bn: 0x00d67a5c6488ec = 235821024446700
    log(String::from_ascii_str("Max tx cost:"));
    let max_cost_bn = tx_gas_price.as_u256() * tx_gas_limit.as_u256();
    log(u256_to_hex(max_cost_bn));

}

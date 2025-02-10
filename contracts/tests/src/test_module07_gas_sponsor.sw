library;

use std::{
    b512::B512,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    bytes::Bytes,
    math::*,
    option::Option,
    string::String,
};
use std::*;
use std::bytes_conversions::{b256::*, u256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use helpers::{
    general_helpers::{
        hex_string_to_bytes,
        string_to_bytes,
        extend,
        bytes_read_b256,
    },
    hex::b256_to_hex,
    numeric_utils::*,
};

// use ptools::gas_sponsor_tools_v2::{
//     SponsorOp, GasSponsor, EIP712Domain, Eip712,
// };

use module07_utils::gas_sponsor_tools_v3::{
    SponsorOp, GasSponsor,
};

use standards::src16::{
    SRC16Base,
    EIP712,
    EIP712Domain,
    DomainHash,
    TypedDataHash,
    DataEncoder,
    SRC16Payload,
    SRC16Encode,
};





const TEST_CONST_DOMAIN_SEP_HASH: b256 = 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08;
const TEST_CONST_TYPE_HASH: b256 = 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8;

/*
command: "sponsor"

Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
Struct Hash      : 0xa65e39f42cb8baa1cbfb61bf9eefa5e2270dea0e517ee3219383f78bd508af08
Encoded EIP-712  : 0xa28538cffc96e9113fb8766fcf1c9fbca316504e8b5bd0e17c5335fbf7d563fd
*/
const TEST_CONST_A_STRUCT_HASH: b256 = 0xa65e39f42cb8baa1cbfb61bf9eefa5e2270dea0e517ee3219383f78bd508af08;
const TEST_CONST_A_ENCODED_HASH: b256 = 0xa28538cffc96e9113fb8766fcf1c9fbca316504e8b5bd0e17c5335fbf7d563fd;

/*
command: "sponsor"

Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
Struct Hash      : 0x75b8150553bc268aa10fd86011656ca87aa239b103539f8af8d480a51a2818fa
Encoded EIP-712  : 0xcccd067a02c854748838898c68a5c14b3b3a72e31a88e6d76dbb26158d740a91
*/
const TEST_CONST_B_STRUCT_HASH: b256 = 0x75b8150553bc268aa10fd86011656ca87aa239b103539f8af8d480a51a2818fa;
const TEST_CONST_B_ENCODED_HASH: b256 = 0xcccd067a02c854748838898c68a5c14b3b3a72e31a88e6d76dbb26158d740a91;

/*
command: "cancel"

Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
Struct Hash      : 0x8100dd06753bfe78c3ce5344aea822f17d9549112cebe22a5d2b7e63545ce4ac
Encoded EIP-712  : 0xa5308f4d457db8327fc2aa14d12ef7d2d3ea1f170f50a70273e2bddf412a3e82
*/
const TEST_CONST_C_STRUCT_HASH: b256 = 0x8100dd06753bfe78c3ce5344aea822f17d9549112cebe22a5d2b7e63545ce4ac;
const TEST_CONST_C_ENCODED_HASH: b256 = 0xa5308f4d457db8327fc2aa14d12ef7d2d3ea1f170f50a70273e2bddf412a3e82;


const TEST_CONST_EVM_SINGER: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;



// forc test gassponsor712v4_domain_hash --logs
// test the calculation of domain_hash
#[test]
fn gassponsor712v4_domain_hash(){
    let eip712_domain_type_hash = _get_domain_separator().domain_hash();
    log(b256_to_hex(eip712_domain_type_hash));
    let expected_domain_hash = TEST_CONST_DOMAIN_SEP_HASH;
    assert(eip712_domain_type_hash == expected_domain_hash );
    /*
        8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f --> EIP712_DOMAIN_TYPE_HASH
        66834a862a0f3e61bc1ede225d0f26b3b93dc33a0962ed512034712a71ad63b5 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract
        2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08 --> final hash
    */
}


/*
// forc test gassponsor712_domain_hash_precalc --logs
#[test]
fn gassponsor712_domain_hash_precalc(){
    let eip712_domain_type_hash = EIP712Domain::new().domin_separator_hash_precalc();
    log(b256_to_hex(eip712_domain_type_hash));
    let expected_domain_hash = TEST_CONST_DOMAIN_SEP_HASH;
    assert(eip712_domain_type_hash == expected_domain_hash );
}

// forc test gassponsor712v4_type_precalc --logs
#[test]
fn gassponsor712v4_type_precalc(){
    let eip712_type_hash = GasSponsor::type_hash();
    log(b256_to_hex(eip712_type_hash));
    let expected_type_hash = TEST_CONST_TYPE_HASH;
    assert(eip712_type_hash == expected_type_hash );
}
*/

// forc test gassponsor712v4_struct_hash_command_sponsor --logs
// test tx struct hash with "sponsor" params.
#[test]
fn gassponsor712v4_struct_hash_command_sponsor(){
    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance
    ) = get_setup_tx_params_command_sponsor();
    let struct_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    // type_hash_encoded                         : 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
    // command_encoded_hash                      : e80fb92299ed640261f22bb7d7b1b877eb589e85f26da49c85e89a10bc53fe07
    // return_address_encoded_hash               : abababababababababababababababababababababababababababababababab
    // input_gas_utxoid_encoded_hash             : 0101010101010101010101010101010101010101010101010101010101010101
    // expected_gas_output_amount_encoded_hash   : 000000000000000000000000000000000000000000000000000000003b9aca00
    // expected_output_asset_encoded_hash        : 0202020202020202020202020202020202020202020202020202020202020202
    // input_output_amount_encoded_hash          : 0000000000000000000000000000000000000000000000000000000077359400
    // tolerance_encoded_hash                    : 00000000000000000000000000000000000000000000000000000000000000fa
    // encoded     : 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8e80fb92299ed640261f22bb7d7b1b877eb589e85f26da49c85e89a10bc53fe07abababababababababababababababababababababababababababababababab0101010101010101010101010101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000003b9aca000202020202020202020202020202020202020202020202020202020202020202000000000000000000000000000000000000000000000000000000007735940000000000000000000000000000000000000000000000000000000000000000fa
    // encoded struct hash                       : a65e39f42cb8baa1cbfb61bf9eefa5e2270dea0e517ee3219383f78bd508af08

    log(b256_to_hex(struct_hash));
    let expected_struct_hash = TEST_CONST_A_STRUCT_HASH;
    assert(struct_hash == expected_struct_hash );
}

// forc test gassponsor712v4_hash_encode712_command_sponsor --logs
// test the encoding and hashing domain and sruct (using "sponsor" params) according to EIP-712 spec.
#[test]
fn gassponsor712v4_hash_encode712_command_sponsor(){

    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ) = get_setup_tx_params_command_sponsor();
    let data_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: data_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    log(b256_to_hex(encoded_hash));

    let expected_encoded_hash = TEST_CONST_A_ENCODED_HASH;
    assert(encoded_hash == expected_encoded_hash);
}

// forc test gassponsor712v4_struct_hash_command_gasspass --logs
// test tx struct hash with "gasspass" params.
#[test]
fn gassponsor712v4_struct_hash_command_gasspass(){
    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance
    ) = get_setup_tx_params_command_gasspass();
    let struct_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    // type_hash_encoded                         : 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
    // command_encoded_hash                      : 87ee5e931e0a649a7cb9ee452bdc104d4adfc6282a2a89f31052143760986c52
    // return_address_encoded_hash               : abababababababababababababababababababababababababababababababab
    // input_gas_utxoid_encoded_hash             : 0101010101010101010101010101010101010101010101010101010101010101
    // expected_gas_output_amount_encoded_hash   : 000000000000000000000000000000000000000000000000000000003b9aca00
    // expected_output_asset_encoded_hash        : 0000000000000000000000000000000000000000000000000000000000000000
    // input_output_amount_encoded_hash          : 0000000000000000000000000000000000000000000000000000000000000000
    // tolerance_encoded_hash                    : 0000000000000000000000000000000000000000000000000000000000000000
    // encoded    : 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d887ee5e931e0a649a7cb9ee452bdc104d4adfc6282a2a89f31052143760986c52abababababababababababababababababababababababababababababababab0101010101010101010101010101010101010101010101010101010101010101000000000000000000000000000000000000000000000000000000003b9aca00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    // encoded struct hash                       : 75b8150553bc268aa10fd86011656ca87aa239b103539f8af8d480a51a2818fa

    log(b256_to_hex(struct_hash));
    let expected_struct_hash = TEST_CONST_B_STRUCT_HASH;
    assert(struct_hash == expected_struct_hash );
}

// forc test gassponsor712v4_hash_encode712_command_gasspass --logs
// test the encoding and hashing domain and sruct (using "gasspass" params) according to EIP-712 spec.
#[test]
fn gassponsor712v4_hash_encode712_command_gasspass(){

    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance
    ) = get_setup_tx_params_command_gasspass();
    let data_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: data_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    log(b256_to_hex(encoded_hash));

    let expected_encoded_hash = TEST_CONST_B_ENCODED_HASH;
    assert(encoded_hash == expected_encoded_hash);
}

// forc test gassponsor712v4_struct_hash_command_cancel --logs
// test tx struct hash with "cancel" params.
#[test]
fn gassponsor712v4_struct_hash_command_cancel(){
    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance
    ) = get_setup_tx_params_command_cancel();
    let struct_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    // type_hash_encoded                         : 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
    // command_encoded_hash                      : 8a979287743fc9323bd8e3f513f06468849cf4695b9599f9e20e9704e0077523
    // return_address_encoded_hash               : 0000000000000000000000000000000000000000000000000000000000000000
    // input_gas_utxoid_encoded_hash             : 0101010101010101010101010101010101010101010101010101010101010101
    // expected_gas_output_amount_encoded_hash   : 0000000000000000000000000000000000000000000000000000000000000000
    // expected_output_asset_encoded_hash        : 0000000000000000000000000000000000000000000000000000000000000000
    // input_output_amount_encoded_hash          : 0000000000000000000000000000000000000000000000000000000000000000
    // tolerance_encoded_hash                    : 0000000000000000000000000000000000000000000000000000000000000000
    // encoded    : 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d88a979287743fc9323bd8e3f513f06468849cf4695b9599f9e20e9704e0077523000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    // encoded struct hash                       : 8100dd06753bfe78c3ce5344aea822f17d9549112cebe22a5d2b7e63545ce4ac

    log(b256_to_hex(struct_hash));
    let expected_struct_hash = TEST_CONST_C_STRUCT_HASH;
    assert(struct_hash == expected_struct_hash );
}

// forc test gassponsor712v4_hash_encode712_command_cancel --logs
// test the encoding and hashing domain and sruct (using "cancel" params) according to EIP-712 spec.
#[test]
fn gassponsor712v4_hash_encode712_command_cancel(){

    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance
    ) = get_setup_tx_params_command_cancel();
    let data_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: data_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    log(b256_to_hex(encoded_hash));

    let expected_encoded_hash = TEST_CONST_C_ENCODED_HASH;
    assert(encoded_hash == expected_encoded_hash);
}

// forc test gassponsor712v4_recover_signer_from_sponsor712tx --logs
// test recovery from a mock transaction input of amount, receiver, compact signature (added as witness).
#[test]
fn gassponsor712v4_recover_signer_from_sponsor712tx(){

    let (
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance
    ) = get_setup_tx_params_command_sponsor();
    let data_hash = GasSponsor::new(
        some_command,
        some_return_addr,
        some_inputgasutxoid,
        some_expectedgasoutputamount,
        some_expectedoutputasset,
        some_expectedoutputamount,
        some_tolerance,
    ).struct_hash();

    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: data_hash,
    };

    let mut compactsig_hex_string = String::from_ascii_str("eb3dba252352de5f17153ee269478eadef39e749835ce6a832e0f010d11b42a4c496a2bb6faea0d0e41c578f82d8e0621b52c5670501d125eea042a56c8e2804");

    let compactsig_bytes = hex_string_to_bytes(compactsig_hex_string).unwrap();
    let mut ptr: u64 = 0;
    let (cs_lhs, ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    let (cs_rhs, _ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);

    // log(cs_lhs);
    // log(cs_rhs);
    let compactsig = B512::from((cs_lhs, cs_rhs));

    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };

    let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();
    log(b256_to_hex(recovered_signer));

    let expected_signer = TEST_CONST_EVM_SINGER;
    assert(recovered_signer == expected_signer);
}

/// struct params for a sponsorship with expected swap
/// set command to "sponsor" and specify the utxoid available, the expected
/// gas return amount, the expected assetid tip, amount and tolerance.
fn get_setup_tx_params_command_sponsor() -> (String, b256, b256, u256, b256, u256, u256) {

    let command = String::from_ascii_str("sponsor");
    let utxoid_in: b256 = 0x0101010101010101010101010101010101010101010101010101010101010101;
    let return_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let gas_amount_out = asm(r1: (0, 0, 0, 1000000000)) { r1: u256 };   // 1_000_000_000u64
    let asset_out: b256 = 0x0202020202020202020202020202020202020202020202020202020202020202;
    let amount_out = asm(r1: (0, 0, 0, 2000000000)) { r1: u256 };   // 2_000_000_000u64
    let tolerance_bps = asm(r1: (0, 0, 0, 250)) { r1: u256 };   // 2.5% tolerance

    (command, return_addr, utxoid_in, gas_amount_out, asset_out, amount_out, tolerance_bps)
}

/// Struct params for a sponsorship with no swap expected, but does require some gas difference.
/// only the command is set to "gasspass", gas utxoid and expect gas output amount, everything else should be zero'd
fn get_setup_tx_params_command_gasspass() -> (String, b256, b256, u256, b256, u256, u256) {

    let command = String::from_ascii_str("gasspass");
    let utxoid_in: b256 = 0x0101010101010101010101010101010101010101010101010101010101010101;
    let return_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let gas_amount_out = asm(r1: (0, 0, 0, 1000000000)) { r1: u256 };   // 1_000_000_000u64
    let asset_out: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let amount_out = asm(r1: (0, 0, 0, 0)) { r1: u256 };
    let tolerance_bps = asm(r1: (0, 0, 0, 0)) { r1: u256 };

    (command, return_addr, utxoid_in, gas_amount_out, asset_out, amount_out, tolerance_bps)
}

/// struct params for a cancellation.
/// for use when the gas sponsor wants to cancel sponsorship utxo.
/// only the command is set to "cancel", and gas utxoid, everything else should be zero'd
fn get_setup_tx_params_command_cancel() -> (String, b256, b256, u256, b256, u256, u256) {
    let command = String::from_ascii_str("cancel");
    let utxoid_in: b256 = 0x0101010101010101010101010101010101010101010101010101010101010101;
    let return_addr: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let gas_amount_out = asm(r1: (0, 0, 0, 0)) { r1: u256 };
    let asset_out: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let amount_out = asm(r1: (0, 0, 0, 0)) { r1: u256 };
    let tolerance_bps = asm(r1: (0, 0, 0, 0)) { r1: u256 };

    (command, return_addr, utxoid_in, gas_amount_out, asset_out, amount_out, tolerance_bps)
}

///
fn _get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapGasSponsor"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }),
        verifying_contract,
    )
}


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
    bytes_conversions::{b256::*, u256::*, u64::*},
    primitive_conversions::{u16::*, u32::*, u64::*}
};
use zap_utils::{
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
};
use walletop_contract_call::verify_contract_call::*;
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


const TEST_CONST_CONTRACT_INTERACTION_DOMAIN_SEP_HASH: b256 = 0xd20955a62cebb4162e9755cd2d30fc761c526752258a0e5984e92c49d9f54e36;
const TEST_CONST_CONTRACT_INTERACTION_TYPE_HASH: b256 = 0x487e85d7d66271510f1f573ad7c66ae909916de5605a1c13f771ff11c91fdf55;
const TEST_CONST_CONTRACT_INTERACTION_STRUCT_HASH: b256 = 0x4ad15bd71d68ac650addcfc75382270345dc28d432544bab6e521e6f5f2987f8;
const TEST_CONST_CONTRACT_INTERACTION_ENCODED_HASH: b256 = 0x1e56960e6b74577b4ccc99d628af9ab2c7e98bbb9404cdd83ecd36bbbd025899;
const TEST_CONST_EVM_SINGER: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

// forc test test_061_contract_call_domain_hash --logs
// test the calculation of domain_hash
#[test]
fn test_061_contract_call_domain_hash(){
    /*
        8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f --> EIP712_DOMAIN_TYPE_HASH
        8d1c8386c16b9235c3c30d07a770c3cd11a787e8d74f9a8a1ca2fd5121fe93bc --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract
        d20955a62cebb4162e9755cd2d30fc761c526752258a0e5984e92c49d9f54e36 --> final hash
    */
    let eip712_domain_type_hash = _get_domain_separator().domain_hash();
    log(b256_to_hex(eip712_domain_type_hash));
    let expected_domain_hash = TEST_CONST_CONTRACT_INTERACTION_DOMAIN_SEP_HASH;

    assert(eip712_domain_type_hash == expected_domain_hash );
}

// forc test test_062_contract_call_type_hash --logs
// test initialization type hash.
#[test]
fn test_062_contract_call_type_hash(){

    let type_hash = ContractInteraction::type_hash();
    log(b256_to_hex(type_hash));
    let expected_type_hash = TEST_CONST_CONTRACT_INTERACTION_TYPE_HASH;

    assert(type_hash == expected_type_hash );
}

// forc test test_063_contract_call_struct_hash --logs
// test initialization struct hashparams.
#[test]
fn test_063_contract_call_struct_hash(){

    let struct_hash = get_setup_tx().struct_hash();
    log(b256_to_hex(struct_hash));
    let expected_struct_hash = TEST_CONST_CONTRACT_INTERACTION_STRUCT_HASH;

    assert(struct_hash == expected_struct_hash );
}

// forc test test_064_contract_call_encoded_hash --logs
// test the encoding, hashing domain and sruct according to EIP-712 spec.
#[test]
fn test_064_contract_call_encoded_hash(){

    let struct_hash = get_setup_tx().struct_hash();
    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    log(b256_to_hex(encoded_hash));
    let expected_encoded_hash = TEST_CONST_CONTRACT_INTERACTION_ENCODED_HASH;

    assert(encoded_hash == expected_encoded_hash);
}

// forc test test_065_contract_call_recover_signer --logs
// test recovery from a mock native transfer tx, compact signature.
#[test]
fn test_065_contract_call_recover_signer(){

    let struct_hash = get_setup_tx().struct_hash();
    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    let mut compactsig_hex_string = String::from_ascii_str("1e857d01562987a2b74266664dd6ab1c0bcb14f5e5bc7b64e1e8a34dc183b98db49a94f4ae5adbcab0349583550bc4afe3e9a8ab69b3b546dffaee7ea2b2ef0a");
    let compactsig_bytes = hex_string_to_bytes(compactsig_hex_string).unwrap();
    let mut ptr: u64 = 0;
    let (cs_lhs, ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    let (cs_rhs, _ptr) = bytes_read_b256(compactsig_bytes, ptr, 32);
    // log(cs_lhs);
    // log(cs_rhs);
    let compactsig = B512::from((cs_lhs, cs_rhs));
    let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();
    log(b256_to_hex(recovered_signer));
    let expected_signer = TEST_CONST_EVM_SINGER;

    assert(recovered_signer == expected_signer);
}

fn get_setup_tx() -> ContractInteraction {
    let dummy_contract_id: b256 = 0xb8b62b273f4560b99554d7405315592c18ca5521d2d499d917b7685e05ebb6a3;
    let dummy_function_name = String::from_ascii_str("test_selector_extraction");
    let dummy_tx_id: b256 = 0x5fb04d8ed89d87eddb55dbaa50250376b0c983523d1d6842a15cae58c341f0e1;

    ContractInteraction::new(
        dummy_contract_id,
        dummy_function_name,
        dummy_tx_id,
    )
}

fn _get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapWalletContractCall"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889)) { r1: u256 }),
        verifying_contract.into()
    )
}


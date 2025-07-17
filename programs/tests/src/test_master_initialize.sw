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
// use std::*;
// use std::bytes_conversions::{b256::*, u256::*, u64::*};
// use std::primitive_conversions::{u16::*, u32::*, u64::*};

use zap_utils::{
    rlp_helpers::*,
    hex::*,
    string_helpers::*,
};
use master_utils::initialize::{
    Initialization,
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

const TEST_CONST_INITIALIZE_DOMAIN_SEP_HASH: b256 = 0x48dc110e86b2fcc7f0081b52dba202c4b7b50485a8ed792349806563aca3eff9;
const TEST_CONST_INITIALIZE_TYPE_HASH: b256 = 0xa26c68f9751fd3f7eaffd4edc8cd9601ce5b772d61f68c74357f105a338871b1;
const TEST_CONST_INITIALIZE_STRUCT_HASH: b256 = 0x38f8f8c7fa4976d1757a57905448e6cc0e8d7c3fd266d31e32c5837aa5a89494;
const TEST_CONST_INITIALIZE_ENCODED_HASH: b256 = 0x2d204690597dea9e4b3e439a45b27f18496fbdeeed6211ef0154e2fd66344741;
const TEST_CONST_EVM_SINGER: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

// forc test test_01_initialization_domain_hash --logs
// test the calculation of domain_hash
#[test]
fn test_01_initialization_domain_hash(){
    let eip712_domain_type_hash = _get_domain_separator().domain_hash();
    log(b256_to_hex(eip712_domain_type_hash));
    let expected_domain_hash = TEST_CONST_INITIALIZE_DOMAIN_SEP_HASH;
    assert(eip712_domain_type_hash == expected_domain_hash );
    /*
        8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f --> EIP712_DOMAIN_TYPE_HASH
        d5c2ba6aaeb729a135ee676a1dee466cc774a046f08ea2623147792dcd5bffd3 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract
        48dc110e86b2fcc7f0081b52dba202c4b7b50485a8ed792349806563aca3eff9 --> final hash
    */
}

// forc test test_02_initialization_type_hash --logs
// test initialization type hash.
#[test]
fn test_02_initialization_type_hash(){

    let type_hash = Initialization::type_hash();
    log(b256_to_hex(type_hash));
    let expected_type_hash = TEST_CONST_INITIALIZE_TYPE_HASH;

    assert(type_hash == expected_type_hash );
}

// forc test test_03_initialization_struct_hash --logs
// test initialization struct hashparams.
#[test]
fn test_03_initialization_struct_hash(){

    let struct_hash = get_setup_tx().struct_hash();
    log(b256_to_hex(struct_hash));
    let expected_struct_hash = TEST_CONST_INITIALIZE_STRUCT_HASH;

    assert(struct_hash == expected_struct_hash );
}

// forc test test_04_initialization_encoded_hash --logs
// test the encoding and hashing domain and sruct according to EIP-712 spec.
#[test]
fn test_04_initialization_encoded_hash(){

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
    let expected_encoded_hash = TEST_CONST_INITIALIZE_ENCODED_HASH;

    assert(encoded_hash == expected_encoded_hash);
}

// forc test test_05_initialization_recover_signer --logs
// test recovery from a mock initialization tx, receiver, compact signature.
#[test]
fn test_05_initialization_recover_signer(){

    let struct_hash = get_setup_tx().struct_hash();
    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    let mut compactsig_hex_string = String::from_ascii_str("bc57a44b3ec4f5f0bb7fe214d633b2b95797b99b8b40febdb969477e62f85aa39caba02d0bfd425780f088215648a78f829d64f4390fa6bd0a519a1e92f45036");
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

fn get_setup_tx() -> Initialization {
    let dummy_evmaddr: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let dummy_utxo_id: b256 = 0x0101010101010101010101010101010101010101010101010101010101010101;
    Initialization::new(
        String::from_ascii_str("ZapWalletInitialize"),
        dummy_evmaddr,
        dummy_utxo_id,
    )
}

fn _get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapWallet"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889)) { r1: u256 }),
        verifying_contract.into()
    )
}


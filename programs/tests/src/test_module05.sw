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
use module05_utils::native_transfer_v1::NativeTransfer;
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


const TEST_CONST_NATIVE_TRANSFER_DOMAIN_SEP_HASH: b256 = 0xdee11a989e80388e652a31465673368e24174850d9dd390c31a6634e5cfe2ebd;
const TEST_CONST_NATIVE_TRANSFER_TYPE_HASH: b256 = 0x08ce60fbaed7c5d3f4b3c926fe52992f1fc80905f58361603381e83cf472d3ac;
const TEST_CONST_NATIVE_TRANSFER_STRUCT_HASH: b256 = 0x78102304944056c8f0cff2ada245ffd5bb851d34ffd78d39a4d7a7b14681b886;
const TEST_CONST_NATIVE_TRANSFER_ENCODED_HASH: b256 = 0x4079ed83ef2669e9b65d9b5d176476c1c38e61e79f242723d71b34204a889ed9;
const TEST_CONST_EVM_SINGER: b256 = 0x000000000000000000000000333339d42a89028ee29a9e9f4822e651bac7ba14;

// forc test test_51_nativetransfer_domain_hash --logs
// test the calculation of domain_hash
#[test]
fn test_51_nativetransfer_domain_hash(){
    /*
        8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f --> EIP712_DOMAIN_TYPE_HASH
        8d1c8386c16b9235c3c30d07a770c3cd11a787e8d74f9a8a1ca2fd5121fe93bc --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract
        6744d60a1be36c90e65970c7c85081afc0249849dee1952af299de75ae3ac218 --> final hash
    */
    let eip712_domain_type_hash = _get_domain_separator().domain_hash();
    log(b256_to_hex(eip712_domain_type_hash));
    let expected_domain_hash = TEST_CONST_NATIVE_TRANSFER_DOMAIN_SEP_HASH;

    assert(eip712_domain_type_hash == expected_domain_hash );
}

// forc test test_52_nativetransfer_type_hash --logs
// test initialization type hash.
#[test]
fn test_52_nativetransfer_type_hash(){

    let type_hash = NativeTransfer::type_hash();
    log(b256_to_hex(type_hash));
    let expected_type_hash = TEST_CONST_NATIVE_TRANSFER_TYPE_HASH;

    assert(type_hash == expected_type_hash );
}

// forc test test_53_nativetransfer_struct_hash --logs
// test initialization struct hashparams.
#[test]
fn test_53_nativetransfer_struct_hash(){

    let struct_hash = get_setup_tx().struct_hash();
    log(b256_to_hex(struct_hash));
    let expected_struct_hash = TEST_CONST_NATIVE_TRANSFER_STRUCT_HASH;

    assert(struct_hash == expected_struct_hash );
}

// forc test test_54_nativetransfer_encoded_hash --logs
// test the encoding, hashing domain and sruct according to EIP-712 spec.
#[test]
fn test_54_nativetransfer_encoded_hash(){

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
    let expected_encoded_hash = TEST_CONST_NATIVE_TRANSFER_ENCODED_HASH;

    assert(encoded_hash == expected_encoded_hash);
}

// forc test test_55_nativetransfer_recover_signer --logs
// test recovery from a mock native transfer tx, compact signature.
#[test]
fn test_55_nativetransfer_recover_signer(){

    let struct_hash = get_setup_tx().struct_hash();
    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };
    let mut compactsig_hex_string = String::from_ascii_str("026558f592a8c85434a1664865b8f3db7e9fe4ce3f15049cd1e22d729826aec23b00d748938defb0041c14acc0ae5f81c105d483f7998051220629548d3ae6d5");
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

fn get_setup_tx() -> NativeTransfer {
    let dummy_asset_id: b256 = 0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07;
    let dummy_amount: u256 = asm(r1: (0, 0, 0, 299999999u64)) { r1: u256 };
    let dummy_from: b256 = 0xc6895b18986a58b6d8d5ae4541cd19c346cd6d61639c38f5cae13f49be83ea9e;
    let dummy_to: b256 = 0x2891970ee5132e3523f80b2bde241b75285715359fc4209728812eed35e61fa8;
    let dummy_max_tx_cost: u256 = asm(r1: (0, 0, 0, 0)) { r1: u256 };
    let dummy_utxo_id: b256 = 0xbb15e98684a1fdbfe03d2e709b43001700966ab2fb87423eab9ebf7f257d77b3;

    NativeTransfer::new(
        dummy_asset_id,
        dummy_amount,
        dummy_from,
        dummy_to,
        dummy_max_tx_cost,
        dummy_utxo_id,
    )
}

fn _get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapNativeTransfer"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 129514)) { r1: u256 }),
        verifying_contract.into()
    )
}

// forc test test_56_nativetransfer_recover_signer --logs
// test recovery from a mock native transfer tx, compact signature.
/*
#[test]
fn test_56_nativetransfer_recover_signer(){

    let struct_hash = get_setup_tx2().struct_hash();
    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => revert(0),
    };

    log(b256_to_hex(encoded_hash));

    let mut compactsig_hex_string = String::from_ascii_str("9d6e3d105654e5b02481fb95ae3a91f583856317c22dc1e1d2561f683fe106d0f2440274ee5bd27648ff486e14f97150eb07088e581b79d1d5a3d21164b9f274");
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

fn get_setup_tx2() -> NativeTransfer {
    let dummy_asset_id: b256 = 0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07;
    let dummy_amount: u256 = asm(r1: (0, 0, 0, 7001u64)) { r1: u256 };
    let dummy_from: b256 = 0xc6895b18986a58b6d8d5ae4541cd19c346cd6d61639c38f5cae13f49be83ea9e;
    let dummy_to: b256 = 0x2891970ee5132e3523f80b2bde241b75285715359fc4209728812eed35e61fa8;
    let dummy_max_tx_cost: u256 = asm(r1: (0, 0, 0, 0)) { r1: u256 };
    let dummy_utxo_id: b256 = 0xbb15e98684a1fdbfe03d2e709b43001700966ab2fb87423eab9ebf7f257d77b3;

    NativeTransfer::new(
        dummy_asset_id,
        dummy_amount,
        dummy_from,
        dummy_to,
        dummy_max_tx_cost,
        dummy_utxo_id,
    )
}
*/


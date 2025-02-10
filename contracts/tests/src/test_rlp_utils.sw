library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    assert::*,
    option::Option,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
};
use std::*;
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use zap_utils::{
    decode_erc20::*,
    decode_1559::*,
    decode_legacy::*,
    rlp_utls6::*,
};



// Tests:

// forc test tests_normalize_v --logs
// Tests for normalization of sig v value.
#[test]
fn tests_normalize_v() {

    let var1 = 1243059u64;
    let var2 = 1243060u64;
    let var3 = 27u64;
    let var4 = 28u64;
    let var5 = 0u64;
    let var6 = 1u64;

    assert(normalize_recovery_id(var1) == 0u8 );
    assert(normalize_recovery_id(var2) == 1u8 );
    assert(normalize_recovery_id(var3) == 0u8 );
    assert(normalize_recovery_id(var4) == 1u8 );
    assert(normalize_recovery_id(var5) == 0u8 );
    assert(normalize_recovery_id(var6) == 1u8 );

}

// forc test test_signature_spec --logs
// Tests for signature recovery from known digests, signatures combos for sig v values.
#[test]
fn test_signature_spec(){
    let expected: b256 = 0x000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a;

    // DEBUG06.md
    // type 02 transaction built with MM
    let t1_r: b256 = 0xcafc2b2a1e474859ed2fde107d6de5ad020d7e4f1f0c1838e6ae1f95aa65f7f1;
    let t1_s: b256 = 0x7a5ee832672368630df1fc9ab62f247f4260a03477c7354ef8765c4b40d78b7a;
    let t1_v: u64 = 1;
    let t1_digest: b256 = 0xd1cd6fd19dfec18c42f18dcbc896116d4eafb77c8d397e5b94555bc6b0dba21c;

    let t1_sig = compact_signature_normalize(t1_r, t1_s, t1_v);
    let t1_from: b256 = ec_recover_evm_address(t1_sig, t1_digest).unwrap().into();
    assert(t1_from == expected);

    // DEBUG06.md
    // type 02 transaction built with ethers
    let t2_r: b256 = 0x219e0df36f00e5511d9279bdda0ef317996c9017c4ea4c06eca82d73a690bc2d;
    let t2_s: b256 = 0x0e994a03f0904c932b7b480b5a5b0a53738e01eb6b0513a185e99723914ed641;
    let t2_v: u64 = 0;
    let t2_digest: b256 = 0xb6314e2de6ae205ddfb247a7f977e5e8363a27381e838bd26075a4d37eae6111;

    let t2_sig = compact_signature_normalize(t2_r, t2_s, t2_v);
    let t2_from: b256 = ec_recover_evm_address(t2_sig, t2_digest).unwrap().into();
    assert(t2_from == expected);

    // DEBUG02.md
    // legacy tx, created with coinbase wallet
    let t3_r: b256 = 0x542fae74e0157dead597483a999016ab81ba9e4d046e47379235a287fb8844a9;
    let t3_s: b256 = 0x3c7c632e5c6f5bd33b240a0a009e4155ab97c16a17c04346f2b2a223e4dd7a60;
    let t3_v: u64 = 1243059;
    let t3_digest: b256 = 0xd4c4b53f1f000f4781aa9c62f4f5183c501d8f3ae576e16d9f923d3d8bbec2e3;

    let t3_sig = compact_signature_normalize(t3_r, t3_s, t3_v);
    let t3_from: b256 = ec_recover_evm_address(t3_sig, t3_digest).unwrap().into();
    assert(t3_from == expected);

    // DEBUG04.md
    // legacy tx, created with coinbase wallet
    let t4_r: b256 = 0x5fc787c5a651732383e5125d7828b1b009bfd7c507a2ebfaeed093e2149ccd3a;
    let t4_s: b256 = 0x5bdfe3215a8e0be4bd5ab8f993dba8d8ec5cc60caef507de3a623e62f2e9ab72;
    let t4_v: u64 = 1243060;
    let t4_digest: b256 = 0x608b0486d8daacfdc00b8309591c50c0af6cd0cad1001f9c4c17eefe5de08da3;

    let t4_sig = compact_signature_normalize(t4_r, t4_s, t4_v);
    let t4_from: b256 = ec_recover_evm_address(t4_sig, t4_digest).unwrap().into();
    assert(t4_from == expected);

    // DEBUG07.md
    // legacy tx, created with ethers
    let t5_r: b256 = 0x774a132dfae4d36975109ecb0bfa17ae4894ae81ab66822d0c14c5aca84a1364;
    let t5_s: b256 = 0x682bb55353d9d7ce526c965b19bdd49fe1677d905fcd00d02eeff33e0bba9292;
    let t5_v: u64 = 1243059;
    let t5_digest: b256 = 0xed026390545fe0d348f05e19791cc7d7bb4bb862cc74c9f3d70d37ee060d9917;

    let t5_sig = compact_signature_normalize(t5_r, t5_s, t5_v);
    let t5_from: b256 = ec_recover_evm_address(t5_sig, t5_digest).unwrap().into();
    assert(t5_from == expected);

}









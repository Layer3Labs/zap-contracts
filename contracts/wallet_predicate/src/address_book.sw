library;

use std::{
    b512::B512,
    bytes::Bytes,
    constants::ZERO_B256,
    option::Option,
    vm::evm::evm_address::EvmAddress,
};


pub const DUMMY_1_OWNER_EVM_ADDR: b256 = 0xff00ff01ff02ff03ff04ff05ff06ff07ff08ff09ff0aff0bff0cff0dff0eff0f;
pub const SIGNER_1: EvmAddress = EvmAddress {
    value: DUMMY_1_OWNER_EVM_ADDR,
};

pub const DUMMY_2_OWNER_EVM_ADDR: b256 = 0xff00ff11ff22ff33ff44ff55ff66ff77ff88ff99ffaaffbbffccffddffeeffff;
pub const SIGNER_2: EvmAddress = EvmAddress {
    value: DUMMY_2_OWNER_EVM_ADDR,
};

pub const DUMMY_3_OWNER_EVM_ADDR: b256 = 0xff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ffff9999999900ff;

pub fn get_owner_b256_evm_addr() -> b256 {
    DUMMY_3_OWNER_EVM_ADDR
}


// Address of the deployed nonce manager contract:
// on zap devnet:
pub const NMAN3_CONTRACT_ADDR: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;
// on beta-5:
// pub const NMAN3_CONTRACT_ADDR: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000;








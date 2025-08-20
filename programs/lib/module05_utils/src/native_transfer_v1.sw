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
    hash::*,
};
use std::*;
use std::bytes_conversions::{b256::*, u256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
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
use zapwallet_consts::wallet_consts::FUEL_CHAINID;


pub struct NativeTransfer {
    pub assetid: b256,
    pub amount: u256,
    pub from: b256,
    pub to: b256,
    pub maxtxcost: u256,
    pub utxoid: b256,
}

impl NativeTransfer {

    pub fn new(
        assetid: b256,
        amount: u256,
        from: b256,
        to: b256,
        maxtxcost: u256,
        utxoid: b256,
    ) -> NativeTransfer {
        NativeTransfer {
            assetid: assetid,
            amount: amount,
            from: from,
            to: to,
            maxtxcost: maxtxcost,
            utxoid: utxoid
        }
    }
}

/// The Keccak256 hash of the type NativeTransfer as encoded bytes.
//
// NativeTransfer(bytes32 assetid,uint256 amountin,bytes32 from,bytes32 to,uint256 maxtxcost,bytes32 utxoid)
//
// 0x08ce60fbaed7c5d3f4b3c926fe52992f1fc80905f58361603381e83cf472d3ac
//
const NATIVE_TRANSFER_TYPEHASH: b256 = 0x08ce60fbaed7c5d3f4b3c926fe52992f1fc80905f58361603381e83cf472d3ac;

impl TypedDataHash for NativeTransfer {

    fn type_hash() -> b256 {
        NATIVE_TRANSFER_TYPEHASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        // Add the NativeTransfer type hash.
        encoded.append(
            NATIVE_TRANSFER_TYPEHASH.to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.assetid).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_u256(self.amount).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.from).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.to).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_u256(self.maxtxcost).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.utxoid).to_be_bytes()
        );

        keccak256(encoded)
    }
}

impl SRC16Encode<NativeTransfer> for NativeTransfer {
    fn encode(s: NativeTransfer) -> b256 {
        let data_hash = s.struct_hash();

        let payload = SRC16Payload {
            domain: get_domain_separator(),
            data_hash: data_hash,
        };

        match payload.encode_hash() {
            Some(hash) => hash,
            None => revert(0),
        }
    }
}

pub fn get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapNativeTransfer"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, FUEL_CHAINID)) { r1: u256 }),
        verifying_contract.into(),
    )
}

library;

use std::{ b512::B512, vm::evm::{ ecr::ec_recover_evm_address, evm_address::EvmAddress, }, bytes::Bytes, math::*, option::Option, string::String, hash::*,};
use std::*;
use std::bytes_conversions::{b256::*, u256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use standards::src16::{ SRC16Base, EIP712, EIP712Domain, DomainHash, TypedDataHash, DataEncoder, SRC16Payload, SRC16Encode, };



pub struct NativeTransfer {
    pub Asset_Id: b256,
    pub Amount: u256,
    pub From: b256,
    pub To: b256,
    pub Max_Tx_Cost: u256,
    pub Utxo_ID: b256,
}

impl NativeTransfer {

    pub fn new( assetid: b256, amount: u256, from: b256, to: b256, maxtxcost: u256, utxoid: b256,) -> NativeTransfer {
        NativeTransfer { Asset_Id: assetid, Amount: amount, From: from, To: to, Max_Tx_Cost: maxtxcost, Utxo_ID: utxoid }
    }
}

/// The Keccak256 hash of the type NativeTransfer as encoded bytes.
///
// NativeTransfer(bytes32 assetId,uint256 amountIn,bytes32 from,bytes32 to,uint256 maxTxCost,bytes32 utxoID)
//
// 0xdbb904c4c25f238b71c43a55db0492150688fd29ddacf2136609ccd9621091d4
//
const NATIVE_TRANSFER_TYPEHASH: b256 = 0xdbb904c4c25f238b71c43a55db0492150688fd29ddacf2136609ccd9621091d4;

impl TypedDataHash for NativeTransfer {

    fn type_hash() -> b256 {
        NATIVE_TRANSFER_TYPEHASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        // Add the NativeTransfer type hash.
        encoded.append( NATIVE_TRANSFER_TYPEHASH.to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.Asset_Id).to_be_bytes() );
        encoded.append( DataEncoder::encode_u256(self.Amount).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.From).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.To).to_be_bytes() );
        encoded.append( DataEncoder::encode_u256(self.Max_Tx_Cost).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.Utxo_ID).to_be_bytes() );
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
    EIP712Domain::new( String::from_ascii_str("ZapNativeTransfer"), String::from_ascii_str("1"), (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }), verifying_contract.into(), )
}

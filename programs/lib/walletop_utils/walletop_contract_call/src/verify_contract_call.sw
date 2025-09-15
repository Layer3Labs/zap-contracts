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
use zap_utils::hex::*;

pub struct ContractInteraction {
    pub Contract_Id: b256,
    pub Function_Name: String,
    pub Txid: b256,
}

impl ContractInteraction {

    pub fn new(
        cotractid: b256,
        functionname: String,
        txid: b256,
    ) -> ContractInteraction {
        ContractInteraction {
            Contract_Id: cotractid,
            Function_Name: functionname,
            Txid: txid,
        }
    }
}

/// The Keccak256 hash of the type ContractInteraction as encoded bytes.
///
// ContractInteraction(bytes32 contractId,string functionName,bytes32 txid)
//
// 0x487e85d7d66271510f1f573ad7c66ae909916de5605a1c13f771ff11c91fdf55
//
const CONTRACT_INTERACTION_TYPEHASH: b256 = 0x487e85d7d66271510f1f573ad7c66ae909916de5605a1c13f771ff11c91fdf55;

impl TypedDataHash for ContractInteraction {

    fn type_hash() -> b256 {
        CONTRACT_INTERACTION_TYPEHASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        // Add the ContractInteraction type hash.
        encoded.append(
            CONTRACT_INTERACTION_TYPEHASH.to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.Contract_Id).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.Function_Name).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.Txid).to_be_bytes()
        );

        keccak256(encoded)
    }
}

impl SRC16Encode<ContractInteraction> for ContractInteraction {
    fn encode(s: ContractInteraction) -> b256 {
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
        String::from_ascii_str("ZapWalletContractCall"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, FUEL_CHAINID)) { r1: u256 }),
        verifying_contract.into(),
    )
}

fn _get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapWalletContractCall"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, FUEL_CHAINID)) { r1: u256 }),
        verifying_contract.into()
    )
}

pub fn verify_contract_call_signer(
    expected_signer: b256,
    compact_signature: B512,
    contract_id: ContractId,
    function_name: String,
    tx_id: b256,
) -> bool {

    let struct_hash = ContractInteraction::new(
        contract_id.into(),
        function_name,
        tx_id,
    ).struct_hash();
    let payload = SRC16Payload {
        domain: _get_domain_separator(),
        data_hash: struct_hash,
    };
    let encoded_hash = match payload.encode_hash() {
        Some(hash) => hash,
        None => return false,
    };

    // Recover the signer and compare
    match ec_recover_evm_address(compact_signature, encoded_hash) {
        Ok(recovered_address) => expected_signer == recovered_address.into(),
        Err(_) => false,
    }
}
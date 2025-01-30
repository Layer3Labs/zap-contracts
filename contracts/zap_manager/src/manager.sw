library;

use std::{
    bytes::Bytes,
    string::String,
    b512::B512,
    hash::*,
    contract_id::*,
    vm::evm::evm_address::EvmAddress,
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


pub struct BaseModules {
    pub module_addrs: [b256; 9],
}

pub struct Module {
    pub key: b256,
    pub module_addr: b256,
}

pub enum InitData {
    InitModules: BaseModules,
    NewModule: Module,
}

pub struct V2Leaf {
    pub hash: b256,
    pub number: u64,
}


pub struct UpgradeZapWallet {
    pub contract_id: b256,
    pub old_zapWallet_address: b256,
    pub new_zapWallet_address: b256,
    pub new_version: String,
    pub sponsored_transaction: String,
    pub upgrade_utxo: b256,
}

/// The Keccak256 hash of the type UpgradeZapWallet as UTF8 encoded bytes.
///
/// "UpgradeZapWallet(bytes32 contractID,bytes32 oldZapWalletAddress,bytes32 newZapWalletAddress,string newVersion,string sponsoredTransaction,bytes32 upgradeUTXO)"
///
/// 08d5b62c7103e6be4fc2b983b884488c8f966e443b73813750cf3f724dcc1bd1
///
const UPGRADE_ZAPWALLET_TYPE_HASH: b256 = 0x08d5b62c7103e6be4fc2b983b884488c8f966e443b73813750cf3f724dcc1bd1;

impl TypedDataHash for UpgradeZapWallet {

    fn type_hash() -> b256 {
        UPGRADE_ZAPWALLET_TYPE_HASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        encoded.append(
            UPGRADE_ZAPWALLET_TYPE_HASH.to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.contract_id).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.old_zapWallet_address).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.new_zapWallet_address).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.new_version).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.sponsored_transaction).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.upgrade_utxo).to_be_bytes()
        );

        keccak256(encoded)
    }
}

/// Implementation of the encode function for UpgradeZapWallet using SRC16Payload
impl SRC16Encode<UpgradeZapWallet> for UpgradeZapWallet {

    fn encode(s: UpgradeZapWallet) -> b256 {
        // encodeData hash
        let data_hash = s.struct_hash();
        // setup payload
        let payload = SRC16Payload {
            domain: _get_domain_separator(),
            data_hash: data_hash,
        };

        // Get the final encoded hash
        match payload.encode_hash() {
            Some(hash) => hash,
            None => revert(0),
        }
    }
}

impl SRC16Base for Contract {

    fn domain_separator_hash() -> b256 {
        _get_domain_separator().domain_hash()
    }

    fn data_type_hash() -> b256 {
        UPGRADE_ZAPWALLET_TYPE_HASH
    }
}

impl EIP712 for Contract {

    fn domain_separator() -> EIP712Domain {
        _get_domain_separator()
    }

}

//NOTE - should we make this configurable? "ZapWallet", "1", chain_id etc ?
fn _get_domain_separator() -> EIP712Domain {
    EIP712Domain::new(
        String::from_ascii_str("ZapWallet"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889)) { r1: u256 }),
        ContractId::this()
    )
}



abi ZapManager {

    fn initialize_wallet(
        pred_acc: Address,
        owner_evm_addr: EvmAddress,
        initdata: InitData,
    ) -> EvmAddress;

    fn check_init(
        evm_addr: EvmAddress,
    ) -> bool;

    fn check_asset_status(
        evm_addr: EvmAddress,
        key: b256,
    ) -> u64;

    fn get_version() -> b256;

    #[storage(read, write)]
    fn set_v2_params(
        v2leaves: Vec<V2Leaf>,
        v2_total_leaves: u64,
        v2_swap_position: u64,
        version: str[5],
    );

    #[storage(read, write), payable]
    fn upgrade(
        owner_evm_addr: EvmAddress,
        upgrade_compact_signature: B512,
        sponsored: bool,
        receiver_v2_final_leaf_bytecode: Bytes,
    );


}

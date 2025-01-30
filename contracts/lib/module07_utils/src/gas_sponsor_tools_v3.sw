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

use helpers::general_helpers::{
    hex_string_to_bytes,
    string_to_bytes,
    extend,
    hash_bytes,
    bytes_read_b256,
    to_b256,
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

// Zap Sponsor, validated through EIP-712
//

    /*
    Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
    Type Hash        : 0xbbf829f5506241b26d58fff32c209df1b76ef88e07c3eeafc707d5e199c2fb4b
    Struct Hash      : 0x8b996a142db60dc78f14267c32a9f92bd93bc164d5921e0a5880dae864bd5d03
    Encoded EIP-712  : 0x8997dec7cd4683dc2d6490d7d0833416d41d36634f00b5f2ef0b12799c6b4c54
    */

// const EIP712_DOMAIN_TYPE_HASH: b256 = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;


//----------------------------------------------------------------------------------------

// sponsor_addr --> this is for messaging, so the tx builder knows who to
//                  to send the gas difference to and tip asset. The actual
//                  owner of the gas is:
// In the case of predicate sponsor: is another address, which can be set as aconfigurable at compile time.
// In the case of ZapWallet sponsor: is the address of the owner, which can be obtained from the gas utxo id input details.

pub struct SponsorOp {
    // pub sponsor_addr: b256,
    pub compsig: Bytes,
    pub witnss_idx: u64,
    pub sponsor_details: GasSponsor,
}

pub struct GasSponsor {
    pub command: String,
    pub returnaddress: b256,
    pub inputgasutxoid: b256,
    pub expectedgasoutputamount: u256,
    pub expectedoutputasset: b256,
    pub expectedoutputamount: u256,
    pub tolerance: u256,
}

impl GasSponsor {

    pub fn new(
        command: String,
        returnaddress: b256,
        inputgasutxoid: b256,
        expectedgasoutputamount: u256,
        expectedoutputasset: b256,
        expectedoutputamount: u256,
        tolerance: u256,
    ) -> GasSponsor {
        GasSponsor {
            command,
            returnaddress,
            inputgasutxoid,
            expectedgasoutputamount,
            expectedoutputasset,
            expectedoutputamount,
            tolerance
        }
    }
}


/// The Keccak256 hash of the type Mail as GasSponsor encoded bytes.
///
/// "GasSponsor(string command,bytes32 returnaddress,bytes32 inputgasutxoid,uint256 expectedgasoutputamount,bytes32 expectedoutputasset,uint256 expectedoutputamount,uint256 tolerance)"
///
/// 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
///
const GASSPONSOR_TYPE_HASH: b256 = 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8;

impl TypedDataHash for GasSponsor {

    fn type_hash() -> b256 {
        GASSPONSOR_TYPE_HASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        // Add the GasSponsor type hash.
        encoded.append(
            GASSPONSOR_TYPE_HASH.to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.command).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.returnaddress).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.inputgasutxoid).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_u256(self.expectedgasoutputamount).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.expectedoutputasset).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_u256(self.expectedoutputamount).to_be_bytes()
        );
        // tolerance u256
        encoded.append(
            DataEncoder::encode_u256(self.tolerance).to_be_bytes()
        );

        keccak256(encoded)
    }

}

impl SRC16Encode<GasSponsor> for GasSponsor {

    fn encode(s: GasSponsor) -> b256 {
        // encodeData hash
        let data_hash = s.struct_hash();
        // setup payload
        let payload = SRC16Payload {
            domain: get_domain_separator(),
            data_hash: data_hash,
        };

        // Get the final encoded hash
        match payload.encode_hash() {
            Some(hash) => hash,
            None => revert(0),
        }
    }
}

/*
fn _get_domain_separator() -> EIP712Domain {
    EIP712Domain::new(
        String::from_ascii_str(from_str_array(DOMAIN)),
        String::from_ascii_str(from_str_array(VERSION)),
        (asm(r1: (0, 0, 0, CHAIN_ID)) { r1: u256 }),
        ContractId::this().into()
    )
}
*/
pub fn get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new(
        String::from_ascii_str("ZapGasSponsor"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }),
        verifying_contract.into(),
    )
}

//-------------------------------------------------------------------------------------------


/*
pub struct EIP712Domain {
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: b256,
}

impl EIP712Domain {

    pub fn new() -> EIP712Domain {
        EIP712Domain {
            name: String::from_ascii_str("ZapGasSponsor"),
            version: String::from_ascii_str("1"),
            chain_id: 9889,
            verifying_contract: 0x0000000000000000000000000000000000000000000000000000000000000001,
        }
    }

    // precalculated domain separator hash
    pub fn domin_separator_hash_precalc(self) -> b256 {
        let dsh: b256 = 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08;
        dsh
    }

    pub fn domain_separator_hash(self) -> b256 {
        let mut encoded = Bytes::new();

        // 1. Add EIP712_DOMAIN_TYPE_HASH
        // extend(encoded, EIP712_DOMAIN_TYPE_HASH.to_be_bytes(), 32);
        encoded.append(EIP712_DOMAIN_TYPE_HASH.to_be_bytes());

        // 2. Add hash of name
        // let name_hash = hash_bytes(string_to_bytes(self.name).unwrap());
        // extend(encoded, name_hash.to_be_bytes(), 32);

        // let name_hash = keccak256(string_to_bytes(self.name).unwrap());

        // let name_hash = keccak256(Bytes::from(self.name));
        // encoded.append(name_hash.to_be_bytes());

        encoded.append(
            keccak256(Bytes::from(self.name)).to_be_bytes()
        );

        // 3. Add hash of version
        // let version_hash = hash_bytes(string_to_bytes(self.version).unwrap());
        // extend(encoded, version_hash.to_be_bytes(), 32);
        encoded.append(
            keccak256(Bytes::from(self.version)).to_be_bytes()
        );

        // 4. Add chainId (as 32-byte big-endian)
        // let chainid = to_b256((0, 0, 0, self.chain_id));
        // extend(encoded, chainid.to_be_bytes(), 32);
        encoded.append(
            (asm(r1: (0, 0, 0, self.chain_id)) { r1: b256 }).to_be_bytes()
        );

        // 5. Add verifyingContract
        // extend(encoded, self.verifying_contract.to_be_bytes(), 32);
        encoded.append(
            self.verifying_contract.to_be_bytes()
        );

        // 6. Compute final hash
        // let final_hash = hash_bytes(encoded);
        // final_hash

        keccak256(encoded)
    }

}

pub trait Eip712 {
    fn encode_eip712(self) -> Option<b256>;
}

impl Eip712 for (EIP712Domain, GasSponsor) {

    /// Calculate the encoded EIP-712 hash by concatenating the
    /// components as per EIP-712 specification.
    /// capacity of byte aray sould be 2 + 32 + 32 = 66 bytes total.
    /// --> digest_input = \x19\x01 + domain_separator + struct_hash
    /// --> domain separator hash = keccak256(digest_input);
    fn encode_eip712(self) -> Option<b256> {

        let (mut domain, tx) = self;
        let domain_separator = domain.domin_separator_hash_precalc();
        // log(domain_separator);

        let dsh_bytes = domain_separator.to_be_bytes();
        let sh_bytes = tx.struct_hash().to_be_bytes();

        let mut digest_input = Bytes::with_capacity(66);
        // add prefix
        digest_input.push(0x19);
        digest_input.push(0x01);
        // add domain_separator then struct_hash
        extend(digest_input, dsh_bytes, 32);
        extend(digest_input, sh_bytes, 32);

        let hash = hash_bytes(digest_input);
        Some(hash)
    }
}
*/
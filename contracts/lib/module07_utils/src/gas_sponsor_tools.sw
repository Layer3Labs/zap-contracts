library;

use std::{ b512::B512, vm::evm::{ ecr::ec_recover_evm_address, evm_address::EvmAddress, }, bytes::Bytes, math::*, option::Option, string::String, hash::*,};
use std::*;
use std::bytes_conversions::{b256::*, u256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};
use standards::src16::{ SRC16Base, EIP712, EIP712Domain, DomainHash, TypedDataHash, DataEncoder, SRC16Payload, SRC16Encode,};


/// Operation wrapper for gas sponsorship signatures and parameters.
///
/// # Additional Information
///
/// This struct bundles an EIP-712 signature with gas sponsorship parameters,
/// enabling validation of gas UTXO usage in the ZapWallet ecosystem.
pub struct SponsorOp {
    /// Index of the witness containing the sponsor's signature.
    pub witnss_idx: u64,
    /// Parameters of the gas sponsorship operation.
    pub sponsor_details: GasSponsor,
}

/// Parameters and constraints for a gas sponsorship operation signed via EIP-712.
///
/// # Additional Information
///
/// This struct defines the parameters for a gas sponsorship operation, including:
/// - The type of operation ("sponsor", "gaspass", or "cancel")
/// - The gas UTXO being used
/// - Expected output amounts and assets
/// - Tolerance bounds for asset exchange
///
pub struct GasSponsor {
    /// Operation type: "sponsor", "gaspass", or "cancel".
    pub command: String,
    /// Address where remaining gas should be returned.
    pub returnaddress: b256,
    /// UTXO ID of the gas input being spent.
    pub inputgasutxoid: b256,
    /// Amount of gas that should be returned to owner.
    pub expectedgasoutputamount: u256,
    /// Asset ID expected in exchange for gas (for "sponsor" command).
    pub expectedoutputasset: b256,
    /// Amount of asset expected in exchange for gas.
    pub expectedoutputamount: u256,
    /// Acceptable deviation from expected output amount.
    pub tolerance: u256,
}

impl GasSponsor {

    pub fn new( command: String, returnaddress: b256, inputgasutxoid: b256, expectedgasoutputamount: u256, expectedoutputasset: b256, expectedoutputamount: u256, tolerance: u256, ) -> GasSponsor {
        GasSponsor { command, returnaddress, inputgasutxoid, expectedgasoutputamount, expectedoutputasset, expectedoutputamount, tolerance }
    }
}

/// The Keccak256 hash of the type GasSponsor as encoded bytes.
///
/// "GasSponsor(string command,bytes32 returnaddress,bytes32 inputgasutxoid,uint256 expectedgasoutputamount,bytes32 expectedoutputasset,uint256 expectedoutputamount,uint256 tolerance)"
///
/// 12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
///
const GASSPONSOR_TYPE_HASH: b256 = 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8;

impl TypedDataHash for GasSponsor {

    fn type_hash() -> b256 { GASSPONSOR_TYPE_HASH }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        // Add the GasSponsor type hash.
        encoded.append( GASSPONSOR_TYPE_HASH.to_be_bytes());
        encoded.append( DataEncoder::encode_string(self.command).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.returnaddress).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.inputgasutxoid).to_be_bytes() );
        encoded.append( DataEncoder::encode_u256(self.expectedgasoutputamount).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.expectedoutputasset).to_be_bytes() );
        encoded.append( DataEncoder::encode_u256(self.expectedoutputamount).to_be_bytes() );
        // tolerance u256
        encoded.append( DataEncoder::encode_u256(self.tolerance).to_be_bytes() );
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

pub fn get_domain_separator() -> EIP712Domain {
    let verifying_contract: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    EIP712Domain::new( String::from_ascii_str("ZapGasSponsor"), String::from_ascii_str("1"), (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }), verifying_contract.into(), )
}

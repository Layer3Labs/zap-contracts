library;

use std::{
    b512::B512,
    bytes::Bytes,
    string::String,
    hash::*,
    vm::evm::{
        ecr::ec_recover_evm_address,
        evm_address::EvmAddress,
    },
    inputs::input_coin_owner,
    outputs::{
        output_asset_id,
        output_asset_to,
    },
    tx::{
        tx_script_data,
        tx_script_data_length,
        tx_id,
        tx_witness_data,
    },
    logging::log,
};
use std::bytes_conversions::u64::*;
use std::primitive_conversions::{u16::*, u32::*, u64::*};

use zap_utils::{
    rlp_helpers::bytes_read_b256,
    transaction_utls::{
        verify_input_contract,
    },
};

use ::verify_contract_call::*;




/// Trait for extracting contract call data from script data
pub trait ContractCallData {
    /// Extract the contract ID from bytes 40-71
    fn contract_id(self) -> Option<ContractId>;

    /// Extract the function name from bytes 96+ (with length at 88-95)
    fn function_name(self) -> Option<Bytes>;

}

/// Implementation for extracting data from tx_script_data
pub struct TxScriptData {}

impl ContractCallData for TxScriptData {
    fn contract_id(self) -> Option<ContractId> {
        extract_contract_id_from_data()
    }

    fn function_name(self) -> Option<Bytes> {
        extract_and_validate_function_name()
    }

}

/// Extracts the contract ID from script data bytes 40-71
pub fn extract_contract_id_from_data() -> Option<ContractId> {
    let data_len = match tx_script_data_length() {
        Some(len) => len,
        None => return None,
    };

    if data_len < 72 {
        return None;
    }

    // Read enough to get the contract ID at bytes 40-71
    let data = match tx_script_data::<[u8; 72]>() {
        Some(bytes) => bytes,
        None => return None,
    };

    // Extract bytes 40-71 as the contract ID
    let mut contract_id_bytes = b256::zero();
    let mut i = 0;
    while i < 32 {
        // Convert to b256 properly
        let ptr = __addr_of(contract_id_bytes);
        let byte_ptr = ptr.add::<u8>(i);
        byte_ptr.write(data[40 + i]);
        i += 1;
    }

    Some(ContractId::from(contract_id_bytes))
}

/// Extracts and validates function name from tx_script_data
pub fn extract_and_validate_function_name() -> Option<Bytes> {
    let data_len = match tx_script_data_length() {
        Some(len) => len,
        None => return None,
    };

    // Minimum: 96 bytes header + at least 1 byte for name
    if data_len < 97 {
        return None;
    }

    // Read header (first 96 bytes)
    let header = match tx_script_data::<[u8; 96]>() {
        Some(bytes) => bytes,
        None => return None,
    };

    // Extract function name length from bytes 88-95 (big-endian u64)
    let mut name_length = 0u64;
    let mut i = 0;
    while i < 8 {
        name_length = (name_length << 8) | header[88 + i].as_u64();
        i += 1;
    }

    // Validate reasonable length
    if name_length == 0 || name_length > 64 {
        return None;
    }

    // Check sufficient data for the name
    if data_len < 96 + name_length {
        return None;
    }

    // Read the function name (handle up to 50 chars)
    if name_length <= 50 {
        let full_data = match tx_script_data::<[u8; 146]>() {
            Some(bytes) => bytes,
            None => return None,
        };

        let mut function_name = Bytes::with_capacity(name_length);
        let mut j = 0;
        while j < name_length {
            let byte = full_data[96 + j];

            // Validate ASCII function name characters (a-z, A-Z, 0-9, _)
            if !((byte >= 48 && byte <= 57) ||  // 0-9
                 (byte >= 65 && byte <= 90) ||  // A-Z
                 (byte >= 97 && byte <= 122) || // a-z
                 byte == 95) {                  // _
                return None;
            }

            function_name.push(byte);
            j += 1;
        }

        return Some(function_name);
    }

    None
}


/// Check if a function name is in the allowed list
pub fn is_function_allowed(function_name: Bytes, allowed_functions: Vec<Bytes>) -> bool {
    let mut i = 0;
    while i < allowed_functions.len() {
        let allowed = allowed_functions.get(i).unwrap();

        // Compare function names
        if function_name.len() == allowed.len() {
            let mut matches = true;
            let mut j = 0;
            while j < function_name.len() {
                match function_name.get(j) {
                    Some(byte1) => {
                        match allowed.get(j) {
                            Some(byte2) => {
                                if byte1 != byte2 {
                                    matches = false;
                                    break;
                                }
                            },
                            None => {
                                matches = false;
                                break;
                            }
                        }
                    },
                    None => {
                        matches = false;
                        break;
                    }
                }
                j += 1;
            }

            if matches {
                return true;
            }
        }
        i += 1;
    }

    false
}

pub fn verify_contract_call(
    owner_address: b256,
    witness_index: u64,
) -> bool {
    let tx_data = TxScriptData {};

    if let (Some(cid), Some(fname), Some(sig)) =
        (tx_data.contract_id(), tx_data.function_name(), tx_witness_data(witness_index)) {
        verify_contract_call_signer(
            owner_address,
            sig,
            cid,
            String::from_ascii(fname),
            tx_id(),
        )
    } else {
        false
    }
}
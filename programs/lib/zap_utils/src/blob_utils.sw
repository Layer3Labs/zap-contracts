library;

use std::{
    bytes::Bytes,
    string::String,
};
use ::{
    merkle_utils::{calculate_leaf_hash, calculate_predi_addr_from_root},
    hex::*,
    string_helpers::*,
};
use zapwallet_consts::wallet_consts::*;


// V1 ZapWallet Builder Errors
pub enum BuilderError {
    InvalidConfiguration: (),
    MissingRequiredField: (),
    ModuleDetailCalcFail: (),
    CalculationFailed: (),
}

// contains version/ident info
pub enum ModuleType {
    Module00: b256,
    Module01: b256,
    Module02: b256,
    Module03: b256,
    Module04: b256,
    Module05: b256,
    Module06: b256,
    Module07: b256,
    Module08: b256,
}

impl ModuleType {
    /// Creates a ModuleType from an index with the appropriate version/ident
    pub fn from_index(index: u64) -> ModuleType {
        match index {
            0 => ModuleType::Module00(M00_VERSION),
            1 => ModuleType::Module01(M01_VERSION),
            2 => ModuleType::Module02(M01_VERSION),
            3 => ModuleType::Module03(M01_VERSION),
            4 => ModuleType::Module04(M04_VERSION),
            5 => ModuleType::Module05(M05_VERSION),
            6 => ModuleType::Module06(M06_IDENT),
            7 => ModuleType::Module07(M07_VERSION),
            8 => ModuleType::Module08(M08_IDENT),
            _ => revert(0),
        }
    }

    /// Gets the module index from a ModuleType
    pub fn to_index(self) -> u64 {
        match self {
            ModuleType::Module00(_) => 0,
            ModuleType::Module01(_) => 1,
            ModuleType::Module02(_) => 2,
            ModuleType::Module03(_) => 3,
            ModuleType::Module04(_) => 4,
            ModuleType::Module05(_) => 5,
            ModuleType::Module06(_) => 6,
            ModuleType::Module07(_) => 7,
            ModuleType::Module08(_) => 8,
        }
    }

    /// Extracts the version/ident from the ModuleType
    pub fn version(self) -> b256 {
        match self {
            ModuleType::Module00(v) => v,
            ModuleType::Module01(v) => v,
            ModuleType::Module02(v) => v,
            ModuleType::Module03(v) => v,
            ModuleType::Module04(v) => v,
            ModuleType::Module05(v) => v,
            ModuleType::Module06(v) => v,
            ModuleType::Module07(v) => v,
            ModuleType::Module08(v) => v,
        }
    }
}

// Loader config
pub struct LoaderConfig {
    pub blob_id: b256,
    pub section_len: u64,
}

impl LoaderConfig {
    pub fn new(blob_id: b256, section_len: u64) -> LoaderConfig {
        LoaderConfig {blob_id, section_len}
    }
}

// Module configuration struct
pub struct ModuleConfig {
    pub module_type: ModuleType,
    pub blob_id: b256,
    pub section_len: u64,
    pub version_or_ident: b256,
}

pub struct WalletContext {
    pub evm_addr: b256,
    pub nonce_asset_id: b256,
    pub manager_cid: b256,
    pub master_blob_id: b256,
    pub loader_cfgs: [LoaderConfig; 10], // 9 modules + 1 master
}

impl WalletContext {
    pub fn new(evm_addr: b256, manager_cid: b256, loader_cfgs: [LoaderConfig; 10]) -> Self {
        let nonce_asset_id = calc_assetid(evm_addr, KEY_NONCE, manager_cid);
        WalletContext {
            evm_addr,
            nonce_asset_id,
            manager_cid,
            master_blob_id: loader_cfgs[9].blob_id,
            loader_cfgs,
        }
    }
}

// V1 Zap Wallet Builder
pub trait ZapWallet {
    fn get_module_config(
        module_type: ModuleType,
        loader_cfg: LoaderConfig
    ) -> ModuleConfig;

    fn build_module_configurables(
        config: ModuleConfig,
        ctx: WalletContext,
        module_asset_id: b256,
    ) -> Result<Bytes, BuilderError>;

    fn calculate_master_details(
        ctx: WalletContext,
        module_asset_ids: [b256; 9],
        module_addrs: [b256; 9],
    ) -> Result<b256, BuilderError>;

    fn calculate_all_module_addresses(
        ctx: WalletContext,
    ) -> Result<([b256; 9], [b256; 9]), BuilderError>;

    // fn blah(
    //     ctx: WalletContext,
    // ) -> Result<WalletDetails, BuilderError>;
}

// Helper function to build configurables, module specific
fn build_module_configurables_direct(
    config: ModuleConfig,
    ctx: WalletContext,
    module_asset_id: b256,
) -> Bytes {
    let mut configurables_bytes = Bytes::new();

    match config.module_type {
        ModuleType::Module00 => {
            configurables_bytes.append(module_asset_id.to_be_bytes());
            configurables_bytes.append(ctx.nonce_asset_id.to_be_bytes());
            configurables_bytes.append(ctx.evm_addr.to_be_bytes());
            configurables_bytes.append(config.version_or_ident.to_be_bytes());
            configurables_bytes.append(ctx.manager_cid.to_be_bytes());
        },
        ModuleType::Module01 | ModuleType::Module02 | ModuleType::Module03
            | ModuleType::Module05 => {
            configurables_bytes.append(ctx.loader_cfgs[0].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[1].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[2].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[3].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[4].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[5].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[6].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[7].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.loader_cfgs[8].blob_id.to_be_bytes());
            configurables_bytes.append(ctx.master_blob_id.to_be_bytes());
            configurables_bytes.append(module_asset_id.to_be_bytes());
            configurables_bytes.append(ctx.nonce_asset_id.to_be_bytes());
            configurables_bytes.append(ctx.evm_addr.to_be_bytes());
            configurables_bytes.append(ctx.manager_cid.to_be_bytes());
            configurables_bytes.append(config.version_or_ident.to_be_bytes());
        },
        ModuleType::Module04 => {
            configurables_bytes.append(ctx.nonce_asset_id.to_be_bytes());
            configurables_bytes.append(ctx.evm_addr.to_be_bytes());
            configurables_bytes.append(config.version_or_ident.to_be_bytes());
        },
        ModuleType::Module06 | ModuleType::Module08 => {
            configurables_bytes.append(config.version_or_ident.to_be_bytes());
            configurables_bytes.append(ctx.evm_addr.to_be_bytes());
        },
        ModuleType::Module07 => {
            configurables_bytes.append(ctx.evm_addr.to_be_bytes());
            configurables_bytes.append(config.version_or_ident.to_be_bytes());
        },
    }

    configurables_bytes
}

// Calculate blob predicate address for module
pub fn calculate_module_details(
    module_type: ModuleType,
    ctx: WalletContext,
    module_asset_id: b256,
    loader_cfg: LoaderConfig,
) -> Result<b256, BuilderError> {
    // Extract version_or_ident for module
    let version_or_ident = module_type.version();
    let config = ModuleConfig {
        module_type: module_type,
        blob_id: loader_cfg.blob_id,
        section_len: loader_cfg.section_len,
        version_or_ident: version_or_ident,
    };
    let configurables = build_module_configurables_direct(
        config,
        ctx,
        module_asset_id,
    );
    let predicate_info = BlobPredicate {
        blob_id: loader_cfg.blob_id,
        section_len: loader_cfg.section_len,
        configurables: configurables,
    };

    Result::Ok(calculate_blob_predicate_address(predicate_info))
}

// Result struct for the complete wallet calculation
pub struct WalletDetails {
    pub module_asset_ids: [b256; 9],
    pub module_addrs: [b256; 9],
    pub master_addr: b256,
}

pub struct ZapWalletBuilderV1 {}

impl ZapWallet for ZapWalletBuilderV1 {
    fn get_module_config(module_type: ModuleType, loader_cfg: LoaderConfig) -> ModuleConfig {
        ModuleConfig {
            module_type: module_type,
            blob_id: loader_cfg.blob_id,
            section_len: loader_cfg.section_len,
            version_or_ident: module_type.version(),
        }
    }

    fn build_module_configurables(
        config: ModuleConfig,
        ctx: WalletContext,
        module_asset_id: b256,
    ) -> Result<Bytes, BuilderError> {
        Result::Ok(build_module_configurables_direct(
            config,
            ctx,
            module_asset_id,
        ))
    }

    fn calculate_master_details(
        ctx: WalletContext,
        module_asset_ids: [b256; 9],
        module_addrs: [b256; 9],
    ) -> Result<b256, BuilderError> {
        let mut configurables_bytes = Bytes::new();

        // Add all module asset IDs
        let mut i = 0;
        while i < 9 {
            configurables_bytes.append(module_asset_ids[i].to_be_bytes());
            i += 1;
        }
        // Add all module addresses
        let mut i = 0;
        while i < 9 {
            configurables_bytes.append(module_addrs[i].to_be_bytes());
            i += 1;
        }
        // Add owner pubkey and version
        configurables_bytes.append(ctx.evm_addr.to_be_bytes());
        configurables_bytes.append(MASTER_VERSION.to_be_bytes());

        let predicate_info = BlobPredicate {
            blob_id: ctx.loader_cfgs[9].blob_id,  // Master loader config is at index 9
            section_len: ctx.loader_cfgs[9].section_len,
            configurables: configurables_bytes,
        };

        Result::Ok(calculate_blob_predicate_address(predicate_info))
    }

    fn calculate_all_module_addresses(
        ctx: WalletContext,
    ) -> Result<([b256; 9], [b256; 9]), BuilderError> {
        let mut module_asset_ids: [b256; 9] = [b256::zero(); 9];
        let mut module_addrs: [b256; 9] = [b256::zero(); 9];

        // Module 00
        module_asset_ids[0] = calc_assetid(ctx.evm_addr, KEY00, ctx.manager_cid);
        module_addrs[0] = match calculate_module_details(
            ModuleType::Module00(M00_VERSION),
            ctx,
            module_asset_ids[0],
            ctx.loader_cfgs[0]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(_) => return Result::Err(BuilderError::ModuleDetailCalcFail),
        };

        // Module 01
        module_asset_ids[1] = calc_assetid(ctx.evm_addr, KEY01, ctx.manager_cid);
        module_addrs[1] = match calculate_module_details(
            ModuleType::Module01(M01_VERSION),
            ctx,
            module_asset_ids[1],
            ctx.loader_cfgs[1]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 02 (uses M01_VERSION)
        module_asset_ids[2] = calc_assetid(ctx.evm_addr, KEY02, ctx.manager_cid);
        module_addrs[2] = match calculate_module_details(
            ModuleType::Module02(M01_VERSION),
            ctx,
            module_asset_ids[2],
            ctx.loader_cfgs[2]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 03 (uses M01_VERSION)
        module_asset_ids[3] = calc_assetid(ctx.evm_addr, KEY03, ctx.manager_cid);
        module_addrs[3] = match calculate_module_details(
            ModuleType::Module03(M01_VERSION),
            ctx,
            module_asset_ids[3],
            ctx.loader_cfgs[3]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 04
        module_asset_ids[4] = calc_assetid(ctx.evm_addr, KEY04, ctx.manager_cid);
        module_addrs[4] = match calculate_module_details(
            ModuleType::Module04(M04_VERSION),
            ctx,
            module_asset_ids[4],
            ctx.loader_cfgs[4]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 05
        module_asset_ids[5] = calc_assetid(ctx.evm_addr, KEY05, ctx.manager_cid);
        module_addrs[5] = match calculate_module_details(
            ModuleType::Module05(M05_VERSION),
            ctx,
            module_asset_ids[5],
            ctx.loader_cfgs[5]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 06 (uses M06_IDENT)
        module_asset_ids[6] = calc_assetid(ctx.evm_addr, KEY06, ctx.manager_cid);
        module_addrs[6] = match calculate_module_details(
            ModuleType::Module06(M06_IDENT),
            ctx,
            module_asset_ids[6],
            ctx.loader_cfgs[6]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 07
        module_asset_ids[7] = calc_assetid(ctx.evm_addr, KEY07, ctx.manager_cid);
        module_addrs[7] = match calculate_module_details(
            ModuleType::Module07(M07_VERSION),
            ctx,
            module_asset_ids[7],
            ctx.loader_cfgs[7]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        // Module 08 (uses M08_IDENT)
        module_asset_ids[8] = calc_assetid(ctx.evm_addr, KEY08, ctx.manager_cid);
        module_addrs[8] = match calculate_module_details(
            ModuleType::Module08(M08_IDENT),
            ctx,
            module_asset_ids[8],
            ctx.loader_cfgs[8]
        ) {
            Result::Ok(addr) => addr,
            Result::Err(e) => return Result::Err(e),
        };

        Result::Ok((module_asset_ids, module_addrs))
    }
}


/// Calculates all module addresses, asset IDs, and the master address in one call
pub fn calculate_complete_wallet_details(
    ctx: WalletContext,
) -> Result<WalletDetails, BuilderError> {

    // Calculate all module addresses and asset IDs
    let (module_asset_ids, module_addrs) = match ZapWalletBuilderV1::calculate_all_module_addresses(ctx) {
        Result::Ok((ids, addrs)) => (ids, addrs),
        Result::Err(e) => return Result::Err(e),
    };

    // Calculate master address
    let master_addr = match ZapWalletBuilderV1::calculate_master_details(ctx, module_asset_ids, module_addrs) {
        Result::Ok(addr) => addr,
        Result::Err(e) => return Result::Err(e),
    };

    Result::Ok(WalletDetails {
        module_asset_ids,
        module_addrs,
        master_addr,
    })
}


// Struct to hold blob loader configs
pub struct BlobPredicate {
    pub blob_id: b256,
    pub section_len: u64,
    pub configurables: Bytes,
}

// Calculate blob predicate address
pub fn calculate_blob_predicate_address(blob_info: BlobPredicate) -> b256 {
    // Create loader with instructions
    let mut loader = create_loader_with_instructions();
    // Add blob ID
    loader.append(blob_info.blob_id.to_be_bytes());
    // Add section length
    loader.append(blob_info.section_len.to_be_bytes());
    // Add configurables
    loader.append(blob_info.configurables);

    // Calculate predicate address
    calculate_simple_merkle_predicate(loader)
}

// Get blob loader instructions
fn create_loader_with_instructions() -> Bytes {
    let instructions_hex = String::from_ascii_str("1a403000504100301a445000ba49000032400481504100205d490000504100083240048220451300524510044a440000");
    let instructions_bytes = hex_string_to_bytes(instructions_hex).unwrap();
    let mut loader = Bytes::new();
    loader.append(instructions_bytes);
    loader
}

fn calculate_simple_merkle_predicate(single_leaf: Bytes) -> b256 {
    let leaf_hash = calculate_leaf_hash(single_leaf);
    calculate_predi_addr_from_root(leaf_hash)
}

// Simple merkle functions
pub fn calculate_simple_merkle_root(single_leaf: Bytes) -> b256 {
    let leaf_hash = calculate_leaf_hash(single_leaf);
    leaf_hash
}

fn get_sub_id(evm_addr: b256, key: b256) -> b256 {
    let mut result_buffer = b256::zero();
    asm(n_id: result_buffer, ptr: (evm_addr, key), bytes: 64) { s256 n_id ptr bytes; };
    result_buffer
}

fn calc_assetid(evm_addr: b256, key: b256, contract_id: b256) -> b256 {
    let sub_id: b256 = get_sub_id(evm_addr, key);
    let mut assetid = b256::zero();
    asm(n_id: assetid, ptr: (contract_id, sub_id), bytes: 64) { s256 n_id ptr bytes; };
    assetid
}

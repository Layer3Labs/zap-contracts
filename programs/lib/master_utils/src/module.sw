library;


/// A basic struct used to track and validate transaction inputs and outputs
/// in a standardized format.
///
pub struct InpOut {
    /// The asset ID of the input/output
    pub assetid: b256,
    /// The amount of the asset, if applicable
    pub amount: Option<u64>,
    /// The destination address, if applicable
    pub owner_to: Option<Address>,
}

/// A module is identified by a unique combination of an asset ID and module address.
///
pub struct Module {
    /// The unique asset ID associated with this module and ZapWallet
    pub assetid: b256,
    /// The module predicate address where the module assets are held
    pub address: Address,
}

impl Module {
    pub fn new() -> Module {
        Module {
            assetid: b256::zero(),
            address: Address::from(b256::zero()),
        }
    }
}

/// Collection of all modules in a V1 ZapWallet.
///
pub struct WalletModules {
    pub module00: Module,
    pub module01: Module,
    pub module02: Module,
    pub module03: Module,
    pub module04: Module,
    pub module05: Module,
    pub module06: Module,
    pub module07: Module,
    pub module08: Module,
}

/// Initializes a complete set of wallet modules with their respective assets and addresses
/// for this unique ZapWallet.
///
/// # Arguments
///
/// * `ASSET_KEY00` through `ASSET_KEY08`: [b256] - Asset IDs for each module
/// * `MODULE00_ADDR` through `MODULE08_ADDR`: [Address] - Addresses for each module
///
/// # Returns
///
/// * [WalletModules] - Initialized wallet modules structure
///
pub fn setup_walletmodues(
    ASSET_KEY00: b256, MODULE00_ADDR: Address,
    ASSET_KEY01: b256, MODULE01_ADDR: Address,
    ASSET_KEY02: b256, MODULE02_ADDR: Address,
    ASSET_KEY03: b256, MODULE03_ADDR: Address,
    ASSET_KEY04: b256, MODULE04_ADDR: Address,
    ASSET_KEY05: b256, MODULE05_ADDR: Address,
    ASSET_KEY06: b256, MODULE06_ADDR: Address,
    ASSET_KEY07: b256, MODULE07_ADDR: Address,
    ASSET_KEY08: b256, MODULE08_ADDR: Address,
) -> WalletModules {

    // precalculated modules assetid's:
    // precalculated modules addresses:
    WalletModules {
        module00: Module {
            assetid: ASSET_KEY00,
            address: MODULE00_ADDR,
        },
        module01: Module {
            assetid: ASSET_KEY01,
            address: MODULE01_ADDR,
        },
        module02: Module {
            assetid: ASSET_KEY02,
            address: MODULE02_ADDR,
        },
        module03: Module {
            assetid: ASSET_KEY03,
            address: MODULE03_ADDR,
        },
        module04: Module {
            assetid: ASSET_KEY04,
            address: MODULE04_ADDR,
        },
        module05: Module {
            assetid: ASSET_KEY05,
            address: MODULE05_ADDR,
        },
        module06: Module {
            assetid: ASSET_KEY06,
            address: MODULE06_ADDR,
        },
        module07: Module {
            assetid: ASSET_KEY07,
            address: MODULE07_ADDR,
        },
        module08: Module {
            assetid: ASSET_KEY08,
            address: MODULE08_ADDR,
        },
    }
}

/// Compares two modules for equality.
///
/// # Arguments
///
/// * `a`: [Module] - First module to compare
/// * `b`: [Module] - Second module to compare
///
/// # Returns
///
/// * [bool] - True if modules have matching asset IDs and addresses
///
fn module_compare(a: Module, b: Module) -> bool {
    a.assetid == b.assetid && a.address == b.address
}

/// Matches a module against known wallet modules to find its index.
///
/// # Arguments
///
/// * `somemod`: [Module] - Module to match
/// * `walmods`: [WalletModules] - Collection of known modules
///
/// # Returns
///
/// * [Option<u64>] - Index of the matching module (0-8) or None if no match
///
/// # Additional Information
///
/// Used to identify which module is present in a transaction by comparing
/// against the known set of wallet modules.
///
pub fn match_module(somemod: Module, walmods: WalletModules) -> Option<u64> {
    if module_compare(somemod, walmods.module00) { Some(0) }
    else if module_compare(somemod, walmods.module01) { Some(1) }
    else if module_compare(somemod, walmods.module02) { Some(2) }
    else if module_compare(somemod, walmods.module03) { Some(3) }
    else if module_compare(somemod, walmods.module04) { Some(4) }
    else if module_compare(somemod, walmods.module05) { Some(5) }
    else if module_compare(somemod, walmods.module06) { Some(6) }
    else if module_compare(somemod, walmods.module07) { Some(7) }
    else if module_compare(somemod, walmods.module08) { Some(8) }
    else { None }
}

/// Verifies the existance of a modules' output in transaction outputs.
///
/// # Arguments
///
/// * `outputs`: [Vec<InpOut>] - Vector of transaction outputs
/// * `modulex`: [Module] - Module to verify
///
/// # Returns
///
/// * [bool] - True if proper module output is found
///
/// # Additional Information
///
/// Checks that:
/// - Module asset is present in outputs
/// - Amount is exactly 1
/// - Output is to correct module address
///
pub fn check_output_module(
    outputs: Vec<InpOut>,
    modulex: Module
) -> bool {
    let mut tx_outputs = outputs;
    let mut found = false;
    let mut k = 0;
    let num_outs = tx_outputs.len();
    while k < num_outs {

        let outp = tx_outputs.get(k).unwrap();

        if outp.assetid == modulex.assetid
            && outp.amount.unwrap() == 1u64
            && outp.owner_to.unwrap() == modulex.address {
                found = true;
                //REVIEW - ensure not multiple outputs of the module.
                // break;
        }
        k += 1;
    }

    found
}

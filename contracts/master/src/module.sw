library;

// use zapwallet_consts::{
//     module_addresses::{
//         MODULE01_TXTYPE1_ADDR,
//         MODULE02_TXTYPE2_ADDR, // Address
//         MODULE03_ERC20_ADDR,
//         MODULE04_TXIDWIT_ADDR,
//         MODULE05_EIP712_SIMPLE_ADDR,
//         MODULE06_EIP712_CONTRACT_ADDR,
//         MODULE07_GAS_SPONSOR_ADDR,
//         MODULE08_ADDR,
//         MODULEFF_UPGRADE_ADDR,
//     },
//     module_assets::{
//         ASSET_KEY01,
//         ASSET_KEY02,
//         ASSET_KEY03,
//         ASSET_KEY04,
//         ASSET_KEY05,
//         ASSET_KEY06,
//         ASSET_KEY07,
//         ASSET_KEY08,
//         ASSET_KEYFF,
//     },
// };


/// A basic struct to store information for either a
/// transaction input or output.
pub struct InpOut {
    pub assetid: b256,
    pub amount: Option<u64>,
    pub owner_to: Option<Address>,
}


pub struct Module {
    pub assetid: b256,
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




fn module_compare(a: Module, b: Module) -> bool {
    a.assetid == b.assetid && a.address == b.address
}


/// for the input, that has been Module'ised, check if we know it, and
/// if so, return its index of known modules.
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

/// verifies that there exists an output in the transaction outputs that match
/// the modulex assetid and address details. Also verifies amount == 1.
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

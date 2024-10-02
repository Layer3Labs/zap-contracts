library;

pub const ASSET_KEY00: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657930305F5F656E642E;
pub const ASSET_KEY01: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657930315F5F656E642E;
pub const ASSET_KEY02: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657930325F5F656E642E;
pub const ASSET_KEY03: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657930335F5F656E642E;
pub const ASSET_KEY04: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657930345F5F656E642E;
pub const ASSET_KEY05: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657930355F5F656E642E;
pub const ASSET_KEYFF: b256 = 0x64756D6D795F6D6F64756C655F617373657469645F6B657946465F5F656E642E;

const NT_ASSID: AssetId = AssetId::from(ASSET_KEY00);
const MODULE_TXTYPE1_ASSID: AssetId = AssetId::from(ASSET_KEY01);
const MODULE_TXTYPE2_ASSID: AssetId = AssetId::from(ASSET_KEY02);
const MODULE_KEY3_ASSID: AssetId = AssetId::from(ASSET_KEY03);
const MODULE_KEY4_ASSID: AssetId = AssetId::from(ASSET_KEY04);
const MODULE_KEY5_ASSID: AssetId = AssetId::from(ASSET_KEY05);
const MODULE_UPGRADE_ASSID: AssetId = AssetId::from(ASSET_KEYFF);

/// returns the assetid for the module txtype1.
pub fn get_module_key01_assetid() -> b256 {
    let module_assetid = b256::from(MODULE_TXTYPE1_ASSID);
    module_assetid
}
/// returns the assetid for the module txtype2.
pub fn get_module_key02_assetid() -> b256 {
    let module_assetid = b256::from(MODULE_TXTYPE2_ASSID);
    module_assetid
}
/// returns the assetid for the module erc20.
pub fn get_module_key03_assetid() -> b256 {
    let module_assetid = b256::from(MODULE_KEY3_ASSID);
    module_assetid
}
/// returns the assetid for the module eip-712.
pub fn get_module_key04_assetid() -> b256 {
    let module_assetid = b256::from(MODULE_KEY4_ASSID);
    module_assetid
}
/// returns the assetid for the module txidwit.
pub fn get_module_key05_assetid() -> b256 {
    let module_assetid = b256::from(MODULE_KEY5_ASSID);
    module_assetid
}
/// returns the assetid for the module upgrade.
pub fn get_module_keyff_assetid() -> b256 {
    let module_assetid = b256::from(MODULE_UPGRADE_ASSID);
    module_assetid
}

library;

pub const FUEL_CHAINID: u64 = 9889;

// Index 1-8 and upgrade index 0 = 9 modules.
pub const NUM_MODULES: u64 = 9;

//REVIEW - to be made to u64:MAX
pub const NONCE_MAX: u64 = 0xFFFFFFFF;

// Fuel native token BASE_ASSET Id on Mainnet and Testnet.
pub const FUEL_BASE_ASSET: b256 = 0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07;

// The position in the V1 Master bytecode where the owner address is to be swapped in.
pub const V1_SWAP_POSITION: u64 = 6760;
// The precalculated left hand hash of V1 Master bytecode
pub const V1_LEFT_LEAF_HASH: b256 = 0xa13c3357b40db04363621f0d164ccbc04bdd6ac2d02b4f85c469034e5db257ae;

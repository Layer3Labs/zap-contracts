library;

use std::vm::evm::evm_address::EvmAddress;


abi NonceManager {

    fn mint_nonce_assets(
        pred_acc: Address,
        sub_id: b256,
        witness_index: u64,
    ) -> EvmAddress;

    fn get_version() -> b256;

}

# Finding #2: Module Validation Bypass Attack

**Severity:** HIGH  
**Test File:** `attack_module_validation_bypass.sw`  
**Test Function:** `confirm_module_validation_bypass_attack()`

## Description

* That an attacker can create module assets utxos, owned by a non-module owner, therefore bypassing the Init path validation.

> Severity: HIGH | CVSS Score: 8.0 | Test File: attack_module_validation_bypass.swRoot Cause: The match_module() function can be bypassed by manipulating UTXO
ownership. When module assets are owned by non-master addresses, match_module()
returns None, causing the master predicate to follow the initialization path and bypass all
module validation.<br>
Attack Vector: Create transactions with module assets owned by attacker addresses instead
of the master predicate. The system treats this as initialization rather than a module operation,
completely bypassing check_output_module() validation.<br>
Impact: Complete module functionality bypass with direct asset theft capability. Attackers
can steal module assets without any validation. Entire wallet system can be disabled through
systematic module asset theft.<br>
Test Function: confirm_module_validation_bypass_attack()

## Response

### Summary

The security finding claims that the `ModuleCheckResult::Init` path can be exploited by an attacker using correctly formatted module assets that they control, thereby bypassing the initialization module check logic. This attack vector is not viable due to the predicate's strict validation requirements.

### Technical Analysis

### Why the Proposed Attack Fails

The `ModuleCheckResult::Init` path has a fundamental requirement that **no modules are found** in the transaction. An initialization transaction must spend only a single BASE_ASSET UTXO held at the master predicate, with no module assets present.

### Understanding the Assessor's Claim

The assessor appears to suggest that an attacker could:

1. Mint assets with IDs matching `MODULExx_ADDR` patterns
2. Send these assets to an attacker-controlled address
3. Construct a transaction using these fake module assets alongside a user's master predicate input
4. Bypass both the module ownership verification and the `module_check_controller()` → `ModuleCheckResult::Module(pos)` logic

### Why This Attack Vector Is Invalid

While it's theoretically possible to mint assets with arbitrary IDs during the Zap Master contract initialization flow, the master predicate's validation logic prevents exploitation:

1. **Immutable Module Configuration**: The `setup_walletmodules()` function creates a vector of pre-calculated module asset IDs and owner addresses from compile-time configurable constants:

```rust
let walletmodules = setup_walletmodules(
    ASSET_KEY00, MODULE00_ADDR,
    ASSET_KEY01, MODULE01_ADDR,
    ASSET_KEY02, MODULE02_ADDR,
    ASSET_KEY03, MODULE03_ADDR,
    ASSET_KEY04, MODULE04_ADDR,
    ASSET_KEY05, MODULE05_ADDR,
    ASSET_KEY06, MODULE06_ADDR,
    ASSET_KEY07, MODULE07_ADDR,
    ASSET_KEY08, MODULE08_ADDR,
);

```

1. **Strict Validation Logic**: The `match_module()` function only returns a match when **both** conditions are met:
    - The input's asset ID matches a configured module asset ID
    - The input's owner address matches the corresponding module owner address
2. **Isolated Validation State**: The `found_modules` vector is populated exclusively through successful `match_module()` calls:

```rust
if let Some(index) = match_module(potentialmodule, walletmodules) {
    assert(found_modules.get(index).unwrap() != true);
    found_modules.set(index, true);
}
```

### Critical Security Properties

- `walletmodules` is created as an **immutable, local variable** within predicate execution
- It cannot be modified by external inputs or transaction data
- The validation logic requires **exact matches** for both asset ID and owner address
- An attacker-controlled asset would fail validation because its owner address would not match the pre-configured module addresses

### Test Case Clarification

The test `confirm_module_validation_bypass_attack()` manually sets elements in the `found_modules` vector to simulate a successful match. This artificial manipulation does not reflect a real attack scenario because:

- In actual predicate execution, `found_modules` can only be modified through legitimate `match_module()` matches
- The test bypasses the actual validation logic rather than demonstrating a vulnerability in it

### Conclusion

The module validation bypass attack is not feasible because the master predicate enforces strict validation against immutable, pre-configured module definitions. An attacker cannot forge module matches as both the asset ID and owner address must match the compile-time configurable constants embedded in the predicate.

### Additional context for `ModuleCheckResult::Init` path validation security

The `ModuleCheckResult::Init` path in the master predicate requires that the OWNER has signed a EIP-712 struct containing the following data elements

```tsx

/// The Keccak256 hash of the type Initialization as UTF8 encoded bytes.
///
/// "Initialization(string command,bytes32 evmaddr,bytes32 utxoid)"
///
/// 08d5b62c7103e6be4fc2b983b884488c8f966e443b73813750cf3f724dcc1bd1
///
const INITIALIZE_ZAPWALLET_TYPE_HASH: b256 = 0xa26c68f9751fd3f7eaffd4edc8cd9601ce5b772d61f68c74357f105a338871b1;

impl TypedDataHash for Initialization {

    fn type_hash() -> b256 {
        INITIALIZE_ZAPWALLET_TYPE_HASH
    }

    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        encoded.append( INITIALIZE_ZAPWALLET_TYPE_HASH.to_be_bytes() );
        encoded.append( DataEncoder::encode_string(self.command).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.evmaddr).to_be_bytes() );
        encoded.append( DataEncoder::encode_b256(self.utxoid).to_be_bytes() );
        keccak256(encoded)
    }
}

```

The UTXO ID is the important data element here. The input that is being spend, needs to be signed by the OWNER.

The `ModuleCheckResult::Init` path validation mechanism is further constrained by only allowing two inputs:

- One Coin input with FUEL_BASE_ASSET
- One Contract input

and enforces that there is a ChangeOutput must be sent back to the owner of the input Coin. This does not enforce that it must be the owner however (see note 1 below)

For an attacked to spend any asset/utxo at the master predicate, without the OWNERs signature, by sending the correct module asset id utxos in as inputs to a transaction ow

### Note 1

We can enforce that the ChangeOutput ofthe initialization BASE_ASSET input should be returned to the OWNER only, by adjustting the `change_to` variable to a static value of the owner.

```rust
L125 in initialize.sw

let chgok = check_change(out_count, change_to);
```

## Status

No Change Required.
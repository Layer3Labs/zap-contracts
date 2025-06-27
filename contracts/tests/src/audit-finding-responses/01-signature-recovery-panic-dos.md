# Finding #1: Signature Recovery Panic DoS Attack

**Severity:** HIGH  
**Test File:** `attack_signature_recovery_panic_dos.sw`  
**Test Function:** `confirm_signature_recovery_panic_dos_attack()`

## Description

>**Severity:** HIGH | **CVSS Score:** 8.5 | **Test File:**`attack_signature_recovery_panic_dos.sw`<br>
**Root Cause:** Production modules use `ec_recover_evm_address().unwrap()` pattern in 6+ locations, causing transaction panic when signature recovery fails with malformed signatures.
**Vulnerable Locations:**<br>
`module07_sponsor/src/main.sw:185`<br>
`module05_eip712_simple/src/main.sw:361`<br>
`decode_legacy.sw:179`<br>
`decode_1559.sw:152`<br>
`decode_erc20.sw:162`<br>
`master_utils/initialize.sw:134`<br>
**Attack Vector:** Submit transactions with malformed signatures including r=0, s=0, or invalid
edge case values. The `ec_recover_evm_address()` function returns `Err()` for these inputs,
causing `.unwrap()` to panic and transaction to revert.<br>
**Impact:** 100% DoS rate achievable with trivial exploitation. Systematic user transaction
failures across multiple modules. No cryptographic sophistication required.<br>
**Test Function:** `confirm_signature_recovery_panic_dos_attack()`

## Fix


### Summary

The auditor correctly identifies that `.unwrap()` calls on `ec_recover_evm_address()` results can cause transaction panics when signature recovery fails. However, the impact is limited to transaction reversion.

### Current Behaviour

In Module07 and other modules, the pattern:

```rust
let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();
```

Will panic and revert the transaction if `ec_recover_evm_address()` returns an `EcRecoverError`, which occurs with malformed signatures (e.g., r=0, s=0, or invalid curve points).

### Impact Clarification

- **What happens**: Transaction reverts with a panic
- **What doesn't happen**: No unexpected behavior, no state corruption, no asset loss beyond gas fees
- **User experience**: Failed transaction with gas consumption

### Proposed Fix

Replace all `.unwrap()` calls with proper error handling:

```rust
// Current vulnerable code:
let recovered_signer: b256 = ec_recover_evm_address(compactsig, encoded_hash).unwrap().into();

// Correct implementation with proper error handling:
let recovered_signer: b256 = match ec_recover_evm_address(compactsig, encoded_hash) {
		Ok(signer) => signer.into(),
		Err(_) => {
		// return false for a any error in signature recovery
		return false;
		}
};

```

Files changes:

```rust
contracts/module07_sponsor/src/main.sw
contracts/module05_eip712_simple/src/main.sw
contracts/lib/zap_utils/src/decode_legacy.sw
contracts/lib/zap_utils/src/decode_erc20.sw
contracts/lib/zap_utils/src/decode_1559.sw
contracts/lib/master_utils/src/initialize.sw

```

Invalid signatures return `false` instead of panicking. **No functional change**: Valid signatures continue working exactly as before.

### Conclusion

While the vulnerability doesn't cause any "unexpected behavior" beyond transaction reversion, implementation of proper error handling eliminated any cases of a Revert error that could otherwise be a return false from the predicate for signature recovery operations.

## Status

✅ Fixed
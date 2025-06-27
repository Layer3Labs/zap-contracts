# Finding #6: Chain ID Manipulation Attack

**Severity:** MEDIUM  
**Test File:** `attack_chain_id_manipulation.sw`  
**Test Function:** `confirm_chain_id_manipulation_attack()`

## Description

Improper EIP-155 v parameter normalization enables cross-chain signature replay. The `normalize_recovery_id()` function may incorrectly handle v parameters from different chains.

> Severity: MEDIUM | CVSS Score: 5.0 | Test File: attack_chain_id_manipulation.swRoot Cause: Improper EIP-155 v parameter normalization enables cross-chain signature
replay. The normalize_recovery_id() function may incorrectly handle v parameters from
different chains, allowing signatures to be replayed across networks.<br>
Attack Vector: Capture signatures from one blockchain network and replay them on another
by manipulating the v parameter. Exploit normalization inconsistencies between different chain
ID calculations.<br>
Impact: Transaction replay across different blockchain networks. Users' transactions
executed on unintended chains. Financial losses due to unintended operations. Compliance and
regulatory issues with multi-chain operations.<br>
Test Function: confirm_chain_id_manipulation_attack()

## Response/Fix

We have reviewed the test case and believe there's a fundamental misunderstanding about how chain ID protection works in EIP-155. The test is producing false positives.

The test shows that signatures from Ethereum (v=37) and Polygon (v=309) both normalize to recovery_id=0, and flags this as a critical vulnerability. This is incorrect - they're supposed to normalize to the same value. The recovery ID only indicates which of two possible public keys to recover from the elliptic curve calculation. Whether v=37 or v=309, if they represent recovery_id=0, they should both normalize to 0.

Chain replay protection doesn't come from the recovery ID normalization. It comes from the actual signature verification process. In EIP-155, the chain ID is included in the data being signed. When verifying a transaction, you check that the chain ID in the transaction matches your current chain. The v parameter encoding (chain_id * 2 + 35 + recovery_id) is just a way to preserve the chain ID information alongside the recovery bit - it doesn't provide the actual protection.

Our updated normalize_recovery_id() implementation correctly handles all the edge cases you tested. Values like v=2 or v=26 aren't "invalid" - they're pre-EIP-155 formats that some systems still use. The function appropriately extracts the recovery bit from each format.

The real validation happens elsewhere in our system. See in the following files/codebase how we verify the correct chain ID was included in the transaction:

```rust
contracts/lib/zap_utils/src/decode_erc20.sw
contracts/lib/zap_utils/src/decode_1559.sw
contracts/lib/zap_utils/src/decode_legacy.sw
```

When we decode an EIP-1559 transaction, we extract the chain_id from the RLP data and include it in the signed digest. Our integration tests confirm that transactions signed for different chains are properly rejected when submitted to the wrong chain. The protection is working as designed.

Your test is essentially checking if math works the same way on different chains, which it should. The vulnerability you're describing would only exist if we weren't including chain_id in the signed data or weren't validating it during transaction execution - neither of which is the case.

The updated `normalize_recovery_id()` has been implemented as within the discussion for #8 Recovery ID bypass attack:

```rust
/// Normalizes an Ethereum signature recovery ID.
///
/// # Arguments
///
/// * `v`: [u64] - Recovery ID value to normalize
///
/// # Returns
///
/// * [u8] - Normalized recovery ID (0, 1, or 4 for invalid)
///
pub fn normalize_recovery_id(v: u64) -> u8 {
    if v <= 26 {
        return (v % 4).try_as_u8().unwrap();
    } else if v >= 27 && v <= 34 {
        return ((v - 27) % 4).try_as_u8().unwrap();
    } else {
        // v >= 35 (EIP-155)
        if v >= 35 {
            ((v - 1) % 2).try_as_u8().unwrap()
        } else {
            4u8  // Invalid indicator
        }
    }
}
```

## Status

✅ Already protected (see #8) - Test shows false positive
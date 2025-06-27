# Finding #5: ECDSA Signature Malleability Attack

**Severity:** MEDIUM  
**Test File:** `attack_signature_malleability.sw`  
**Test Function:** `confirm_signature_malleability_attack()`

## Description

ECDSA signatures are malleable - if (r,s) is valid, then (r, -s mod n) is also valid. ZapWallet doesn't enforce the canonical signature requirement that s ≤ secp256k1_order/2.

> Severity: MEDIUM | CVSS Score: 5.5 | Test File: attack_signature_malleability.swRoot Cause: No validation of S values for malleability. ECDSA signatures are mathematically
malleable - if (r,s) is valid, then (r, -s mod n) is also valid. ZapWallet doesn't enforce the
canonical signature requirement that s ≤ secp256k1_order/2.<br>
Attack Vector: Intercept legitimate signatures and create high-S variants. Both signatures
recover to the same address but have different transaction hashes, potentially enabling replay
attack variants.<br>
Impact: Multiple valid signatures for the same message. Transaction uniqueness
compromised. Potential for MEV extraction and replay attacks. Smart contract state confusion
possible.<br>
Test Function: confirm_signature_malleability_attack()

## Addition/Response

We acknowledge that our current implementation doesn't enforce canonical (low-S) signatures, However, we believe the MEDIUM severity rating overstates the practical risk in our specific context. 

The ZapWallet operates on Fuel's UTXO model where transaction hashes are derived from the input UTXOs being spent. This creates a fundamental constraint: any signature, malleable or not, must sign over the same UTXO references, and those UTXOs can only be spent once. An attacker can't create a different transaction that spends the same inputs with a malleable signature because the signature validates the entire transaction structure including those specific UTXO IDs.

The attack scenarios are limited to peripheral issues like execution confusion (at the sequencer or node executing the transaction) or potential problems with off-chain systems that track user operations by signature hash rather than transaction ID. While these are valid concerns, they don't enable direct theft or replay of user funds in the ZapWallet predicate-based system. We currently dont employ any off-chain verification for non transaction ID or UTXO ID validation mechanisms.

That said, we agree this should be addressed as it would eliminate an entire class of potential issues. We'll implement this check by adding the s ≤ secp256k1_order/2 check in our signature validation path in mechanisms on any ZapWallet functionality that uses validation outside of TXID, and UTXO ID methods.

This fix/addition is straightforward, constituting something similar to the below simplified example

```rust
if s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0 {
    return DecodeType02RLPResult::Fail(2052u64);
}
```

## Status

✅ To be fixed - Will add low-S validation on ZapWallet functionality that uses validation outside of Fuels TXID, and UTXO ID generation methods.
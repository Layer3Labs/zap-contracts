# Finding #7: Zero Values Signature Attack

**Severity:** MEDIUM  
**Test File:** `attack_zero_values_signature.sw`  
**Test Function:** `confirm_zero_values_signature_attack()`

## Description

ECDSA requires r ≠ 0 and s ≠ 0, but the system may not properly validate these constraints before processing.

>Severity: MEDIUM | CVSS Score: 4.5 | Test File: attack_zero_values_signature.swRoot Cause: Insufficient validation of ECDSA mathematical constraints. ECDSA requires r ≠
0 and s ≠ 0, but the system may not properly validate these constraints before processing.<br>
Attack Vector: Submit signatures with zero r or s values to test system validation. These
violate fundamental ECDSA constraints and should be immediately rejected.<br>
Impact: Potential ECDSA constraint violations leading to unexpected behavior. Possible
signature verification bypass if zero values are incorrectly accepted. Complete authentication
bypass in worst-case scenarios.<br>
Test Function: confirm_zero_values_signature_attack()

## Response

We've tested this scenario and confirmed that signatures with r=0 or s=0 are properly rejected by the underlying cryptographic implementation.

The `ec_recover` function relies on the fuel-core VM's `ecr1` opcode, which uses standard secp256k1 cryptographic libraries. These libraries inherently reject zero values because ECDSA recovery is mathematically undefined when r=0 or s=0. The elliptic curve operations simply cannot proceed with these values.

Running your test confirms this - all attempts to recover addresses from signatures with zero components fail with `EcRecoverError::UnrecoverablePublicKey`. This is the expected behavior and shows the system is working correctly.

Adding redundant zero-checks in our application layer would be unnecessary since the cryptographic layer already enforces these constraints. Unlike the low-S issue which involves accepting mathematically valid but non-canonical signatures, zero values are fundamentally invalid and cannot pass through the EC recovery algorithm.

The MEDIUM severity seems unwarranted given that the "vulnerability" doesn't exist - the ECR recovery system already rejects these invalid signatures at the appropriate layer.

## Status

✅ No vulnerability - Already protected at VM level
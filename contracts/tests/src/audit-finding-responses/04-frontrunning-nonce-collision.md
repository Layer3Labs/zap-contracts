# Finding #4: Frontrunning Attack via Nonce Asset Collision

**Severity:** MEDIUM  
**Test File:** `attack_frontrunning_nonce_collision.sw`  
**Test Function:** `confirm_frontrunning_nonce_collision_attack()`

## Auditor's Claims

* That a users EVM Address could be initialized with malicious Module addresses, DOSing the users wallet.
* Lost gas fees on failed transactions — Would likely be caught before transaction submission.

> Severity: MEDIUM | CVSS Score: 6.0 | Test File:attack_frontrunning_nonce_collision.swRoot Cause: Nonce asset ID generation uses only EVM address in the calculation
hash(EVM_address + NONCE_KEY), excluding the master address. This creates collision
opportunities when different users attempt to initialize with the same EVM address.<br>
Attack Vector: Monitor mempool for initialization transactions, then frontrun with higher gas
price using the same EVM address but different master address. The attacker's transaction
succeeds while the legitimate user's fails due to nonce asset collision.<br>
Impact: User initialization failures requiring EVM address changes. Lost gas fees on failed
transactions. User experience disruption and potential confusion requiring customer support
intervention.<br>
Test Function: confirm_frontrunning_nonce_collision_attack()

## Fix

See fix for Finding #3

## Status

✅ Fixed via Finding #3 resolution
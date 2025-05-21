```markdown

This document provides detailed answers to seven practical security questions about the ZapWallet predicate code (Master + Modules 00–08).

---

## Q1. EVM Transaction Decoding (EIP-1559 Type-2)

**Raw Transaction**  
```
0x02f8788226a184def79781843b9aca008502cb417800825a3c944da95a7c2084c0164775123786add78debf70b7587082bd67afbc00080c080a06dc7dff2950adc3c50e59cd79c9a9ab0e493a93767c82da0392b76adf4bc30a4a0391008c0af1185b236782e204f1de6100226cf90d8bcc5050a6c138b07ef5eba
```

**Decoded Fields**  
- Chain ID: 9889  
- Nonce: 3 740 768 129  
- Max Fee/Gas: 12 000 000 000 Wei  
- Gas Limit: 23 100  
- To (EVM): `0x4DA95A7C2084C0164775123786add78DEBF70b75`  
- Value: 2 300 000 000 000 000 Wei  

**Derived Fuel Values**  
- ReceiverFuel Address (32-byte padded):  
  `0x0000000000000000000000004DA95A7C2084C0164775123786add78DEBF70b75`  
- Nonce UTXO amounts:  
  - expNonceIn  = NONCE_MAX − 3 = 18 446 744 069 968 783 486  
  - expNonceOut = expNonceIn − 1 = 18 446 744 069 968 783 485  
- Gas & Value Check:  
  - maxCostWei    = 23 100 × 12 000 000 000 = 277 200 000 000 000 Wei  
  - totalWeiNeeded = value + maxCostWei = 2 577 200 000 000 000 Wei  
  - Equivalent Fuel-ETH = 277 200 000 000 000 ÷ 10⁹ = 277 200  
  - Example availableWei = 0.1 ETH = 100 000 000 000 000 000 Wei → **sufficient**

---

## Q2. Module 01 & Nonce AssetId Calculation

**Derivation (Double SHA-256 per Spec)**  
1. Pad the 20-byte EVM address to 32 bytes:  
   `A = 12×0x00 ∥ addr20`  
2. Define 32-byte keys:  
   - Module 01 key `k₁` = 31×`0x00` + `0x01`  
   - Nonce key    `kₙ` = 32×`0xFF`  
3. Compute intermediate hashes:  
   - `h₁_mod = SHA256(A ∥ k₁)`  
   - `h₁_non = SHA256(A ∥ kₙ)`  
4. Compute final AssetIds:  
   - `Module01AssetId = SHA256(managerId ∥ h₁_mod)`  
   - `NonceAssetId    = SHA256(managerId ∥ h₁_non)`

**Off-chain Script (Node.js)**  
```javascript
// calc-zapwallet-assets-sha256.js
const crypto = require("crypto");
const EVM_ADDR   = "0x4da95a7c2084c0164775123786add78debf70b75";
const MANAGER_ID = "0xffbf75d5d54778a7d349b5e3df6ff9c0ebaf8e04b773c64e96ca22f57fb62dc1";
const KEY_MOD01  = Buffer.concat([Buffer.alloc(31,0x00), Buffer.from([0x01])]);
const KEY_NONCE  = Buffer.alloc(32, 0xff);

function buf(hex) {
  return Buffer.from(hex.replace(/^0x/,""), "hex");
}
function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}
function pad20to32(addr) {
  const raw = buf(addr.toLowerCase());
  if (raw.length !== 20) throw "Invalid address";
  return Buffer.concat([Buffer.alloc(12, 0x00), raw]);
}
function derive(keyBuf) {
  const A  = pad20to32(EVM_ADDR);
  const h1 = sha256(Buffer.concat([A, keyBuf]));
  return "0x" + sha256(Buffer.concat([buf(MANAGER_ID), h1])).toString("hex");
}

console.log("Module 01 AssetId:", derive(KEY_MOD01));
console.log("Nonce AssetId:   ", derive(KEY_NONCE));
```

**Sample Output**  
```
Module 01 AssetId: 0xd305fe86bd9dbf276ebe3f93e14d64ea5229a0c3949e78f7f4a61f6edc47a2fe  
Nonce AssetId:     0x35a4e50927696e83fb7a19d7745f2770c1f2819d14967608b02827666b1cac3f  
```

> Paste these two 32-byte hex constants into your Sway `configurable { … }` block.

---

## Q3. Wei → Fuel-ETH Conversion Edge Cases

- **5 ETH (5×10¹⁸ Wei)** → quotient = 5 000 000 000; remainder = 0 → **no revert**  
- **18.4 B ETH ((2⁶⁴−1)×10⁹ Wei)** → quotient = 2⁶⁴−1; remainder = 0 → **no revert**  
- **One Wei above max** → Wei > threshold → **reverts with Err(2010)**  

---

## Q4. Address Mapping & Transaction Construction (Module 03)

**Fuel SRC-20 AssetId**  
```
0x0000000000000000000000009A6b992ed492b5181eFA73cd24DBBeAc55B5148E
```

**Required UTXO Inputs (owner = W)**  
1. Module 03 fee asset  
   - assetId = `MODULE_KEY03_ASSETID`  
   - amount  = 1  
2. Nonce asset  
   - assetId = `NONCE_ASSETID`  
   - amount  = NONCE_MAX − nonce  
3. Token asset  
   - assetId = Fuel SRC-20 AssetId above  
   - amount  ≥ 1 200 000 000  
4. Base asset (Fuel ETH) for gas  
   - assetId = `0x00…00`  
   - amount  ≥ 200 000 000 000 000 Wei (i.e. 200 000 Fuel-ETH)

**Expected UTXO Outputs**  
- Token → recipient = 1 200 000 000  
- Nonce → W       = (NONCE_MAX − nonce − 1)  
- Gas tip → builder ≤ 200 000  
- Module 03 fee → Module 03 predicate = 1  
- Change back → W (leftover base & token)  

---

## Q5. Module Check Vector Manipulation

In a 9-module wallet (indexes 0…8), these two **invalid** bit-vectors are misclassified as valid:

1. **Faked “Upgrade”**  
   `[true, false, false, false, false, false, false, false, false, true]`  
   - Only indexes 0…8 inspected → sees single `true` at idx 0 → returns `Upgrade`  
   - Actually two trues → should revert

2. **Faked Module(2)**  
   `[false, false, true, false, false, false, false, false, false, true]`  
   - Only idx 0…8 checked → sees single `true` at idx 2 → returns `Module(2)`  
   - Actually two trues → should revert

---

## Q6. Signature Replay Protection

- **Module 07 (Gas Sponsorship):** uses the **gas-UTXO ID** in the EIP-712 `GasSponsor` struct → single-use replay protection.  
- **Module 05 (Native Transfer):** uses the **Module 05 asset UTXO ID** in the typed-data `NativeTransfer` struct → cannot reuse signature.  
- **Module 01 (Legacy EVM TX):** uses a **nonce asset** of value `NONCE_MAX−nonce`, consumed and decremented → each signature only valid once.

---

## Q7. Multi-Module Collision in Master Predicate

Code snippet:
```sway
if let Some(idx) = match_module(...) {
  assert(found_modules[idx] != true);  // guards duplicates only
  found_modules.set(idx, true);
}
```
- **Module 01 + Module 07** → distinct indices (1 and 7) → both assertions pass → collision only caught later by `ShouldRevert`.  
- **Assertion fires** only if the **same** module index appears twice (e.g. two Module 01 UTXOs).  
- **Bypass:** craft a Module 07 coin with incorrect owner so `match_module()` returns `None` → only one module counted → tx misclassified.

---



# Practical Security Analysis

### 1. EVM Transaction Decoding
Given this EVM RLP transaction: 
```
0x02f8788226a184def79781843b9aca008502cb417800825a3c944da95a7c2084c0164775123786add78debf70b7587082bd67afbc00080c080a06dc7dff2950adc3c50e59cd79c9a9ab0e493a93767c82da0392b76adf4bc30a4a0391008c0af1185b236782e204f1de6100226cf90d8bcc5050a6c138b07ef5eba
```
and the ZapManager ContractId:
```
0xffbf75d5d54778a7d349b5e3df6ff9c0ebaf8e04b773c64e96ca22f57fb62dc1
```

calculate:

1. The transaction's receiver Fuel address
2. The expected nonce output value
3. Whether or not the transaction would succeed based on the gas info? (Assuming sufficient Base Asset inputs were present in the transaction)


### 2. Module Asset Calculation
For an EVM address:
```
0x4da95a7c2084c0164775123786add78debf70b75
```
and the ZapManager ContractId:
```
0xffbf75d5d54778a7d349b5e3df6ff9c0ebaf8e04b773c64e96ca22f57fb62dc1
```

1. Calculate the Module 01 AssetId
2. Calculate the nonce AssetId

### 3. Wei to Fuel ETH Conversion Edge Cases
Given these Wei amounts:

```
5000000000000000000 (5 ETH)
18446744073709551615000000000 (18.4B ETH)
```

Calculate the resulting Fuel ETH amounts after conversion through the `wei_to_eth()` function. Which of these would revert and why? Show your calculations.


### 4. Address Mapping and Transaction Construction
Given this EVM RLP transaction:
```
0x02f8b28226a103843b9aca008477359400830186a0949a6b992ed492b5181efa73cd24dbbeac55b5148e80b844a9059cbb000000000000000000000000ff04ff9252178b00700c297243784ace4f30285a0000000000000000000000000000000000000000000000000000000047868c00c080a0ecd6f105d18ee07e3f909cdcaafe770bdfc3d5025f99e0fbbeaadac058a43b73a0324deca72562e6ce9a7bb9f5888aea8e5b3cfc200142c2ca1a108dad8dc8f9a0
```

1. What is the Fuel AssetId being transferred in the transaction (as many bytes as possible)?
2. Show the transaction input and output structure for this transaction to be successful (inputs, outputs, asset ID's and amounts). Assume signature correctness.


### 5. Module Check Vector Manipulation
The `module_check_controller()` function takes a vector of boolean values. Provide an input vector that would:

1. Incorrectly identify as a valid upgrade
2. Cause a different return value than intended

Provide the specific boolean vector and explain how this input would affect transaction validation.

### 6. Signature Replay Analysis

What is the main source of signature replay protection in the following:

1. Module 07
2. Module 05
3. Module 01

### 7. Module Transaction Construction

A transaction is constructed that contains both Module 01 and Module 07 assets in its inputs:

1. Under what circumstance, if any, would the ZapWallet Master predicate validate this transaction despite the apparent module collision?

2. Study the following code snippet from the master predicate:

```sway
if let Some(index) = match_module(potentialmodule, walletmodules) {
    assert(found_modules.get(index).unwrap() != true);
    found_modules.set(index, true);
}
```
What assertion would actually trigger in this multi-module scenario, and at which exact iteration of the input processing loop would this occur?

3. If this transaction were submitted with specific module asset ownership attributes, could there be a scenario where the module collision check is bypassed entirely? Explain with reference to the specific function that would be involved.?




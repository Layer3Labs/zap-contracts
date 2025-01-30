# <h1 align="center">Zap Contracts </h1>

<p align="center">Contracts and Predicates for Stateless Account Abstraction on Fuel.</p>

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/Layer3Labs/zap-contracts/blob/main/assets/imgs/3a_Zap_Logo.png" width="708" height="365">
  <img alt="title image light / dark." src="https://github.com/Layer3Labs/zap-contracts/blob/main/assets/imgs/3a_Zap_Logo.png" width="708" height="365">
</picture>
</p>

<i>This project is being actively developed.</i>

## Notice Jan 2025

Some files may be missing as we are currently reworking the directory system.

## Compilation

Compile with `forc` version 0.66.5

```console
cd ./contracts
forc build
```

## Testing

```console
cd ./contracts
forc test
```


## Fuel network compatibility

Compatibility.

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                    │
│                                                                                    │
│        fuels = "0.66.5"                                                            │
│        fuel-vm = "0.58.2"                                                          │
│        fuel-core v0.40.0                                                           │
│                                                                                    │
│        Sway v0.66.5                                                                │
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

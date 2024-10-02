# <h1 align="center">Zap Contracts </h1>

<p align="center">Contracts and Predicates for Stateless Account Abstraction on Fuel.</p>

<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/Layer3Labs/zap-contracts/blob/main/assets/imgs/welcome_to_contracts.png" width="700" height="494">
  <img alt="title image light / dark." src="https://github.com/Layer3Labs/zap-contracts/blob/main/assets/imgs/welcome_to_contracts.png" width="700" height="494">
</picture>
</p>

<i>This project is being actively developed.</i>


## Compilation:

Compile with `forc` version 0.63.5

```console
cd ./contracts
forc build
```

## Testing

```console
cd ./contracts
forc test
```


## Fuel network compatibility:

Compatibility.

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                    │
│                                                                                    │
│        fuels = "0.66.x"                                                            │
│        fuel-vm = "0.56.0"                                                          │
│        fuel-core v0.35.0                                                           │
│                                                                                    │
│        Sway v0.63.5                                                                │
│                                                                                    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

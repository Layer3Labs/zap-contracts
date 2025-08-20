## [Unreleased]

## [0.1.11-dev] - 2025-08-20

### Added

### Changed
- Adjusted blob_utils.sw to include calculate_wallet_details_fast_path().
- Updated module01,02,03,05 to support precomputed modules fast path.
- Updated all EIP-712 structs to use FUEL_CHAINID from zapwallet_consts.
- Version bump for predicates to: `0x646576656C6F706D656E7400000000000000000000000000000076302E312E41` (dev-v0.1.11).

### Fixed

## [0.1.8-dev] - 2025-07-17

### Added
- Test for blob address functionality (test_blob_addr.sw).

### Changed
- File naming and module naming conventions.
- Version bump for predicates to: `0x646576656C6F706D656E7400000000000000000000000000000076302E312E38` (dev-v0.1.8).
- Adjusted blob_utils.sw to support v1 zap wallet address construction from blob IDs and manager CID.
- Updated module05 to support asset variable output utxo structure.
- Updated personal_sign.sw to match Fuel's current version.

### Fixed
- Security improvements based on audit recommendations.

[Unreleased]: https://github.com/Zap-Systems/zap-contracts/compare/v0.1.11-dev...HEAD
[0.1.11-dev]: https://github.com/Zap-Systems/zap-contracts/compare/v0.8.0...v0.1.11-dev
[0.1.8-dev]: https://github.com/Zap-Systems/zap-contracts/compare/v0.8.0...v0.1.8-dev

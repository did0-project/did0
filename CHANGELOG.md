# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/); while the version is below 1.0, minor releases may contain breaking changes.

## [0.1.0] - 2026-10-04

Initial public release. Alpha quality and not security-audited; see [SECURITY.md](SECURITY.md).

### Features

- **DID documents:** parse W3C DID documents (`parseDID`).
- **Signatures:** Ed25519 verification with W3C `Ed25519VerificationKey2020` (`z6Mk…`) or bare 32-byte multibase keys (`verifySignature`, `verifyDigestSignature`).
- **Credentials:** RFC 8785 JSON canonicalization (`canonicalize`), signing (`issueCredential`) and verification (`verifyCredential`) as `Ed25519(SHA-256(JCS(credential)))`.
- **peaq on-chain DID:** SCALE encoders for `add_attribute`, `update_attribute` and `remove_attribute` calls, with `valid_for` encoded as `Option<BlockNumber>` per `peaq-pallet-did`.
- **Wallets:** BIP-39 mnemonics with Substrate-compatible Ed25519 key derivation (polkadot-js `mnemonicToMiniSecret`), SS58 addresses for any registered prefix including peaq's 1221 (`ss58Prefix` option), and `did:peaq:` identifiers.
- Prebuilt binaries for macOS (arm64, x64) and Linux (x64, arm64; glibc and musl) distributed as `@did0/binding-*` packages.
- `DID0_BINDING_PATH` environment variable to load a specific native binary.

### Quality

- Known-answer tests (RFC 8032, RFC 8785, a published Substrate mini-secret, Polkadot and Kusama SS58 addresses) and differential tests against independent JavaScript implementations.
- Strict canonicalizer: rejects duplicate keys, trailing commas, non-standard numbers, raw control characters, lone surrogates and nesting deeper than 128 levels.
- Every argument crossing the Node-API boundary is validated; oversize or out-of-range input is rejected rather than truncated or wrapped.
- Reproducible benchmark (`npm run benchmark`) covering every operation, with baselines.

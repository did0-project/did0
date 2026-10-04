# Roadmap

did0 is pre-1.0. This is the direction, not a promise; priorities follow what peaq and DePIN developers need. Open an issue to discuss or to claim an item.

## Next (0.3)

- **Interop tests against a live peaq node** (agung testnet) in CI: build an `add_attribute` call, submit it with polkadot-js, read the DID back.
- **Derivation paths** (`//hard`, `/soft`) for Ed25519, matching polkadot-js.
- **sr25519** keys and signatures (the default account type in most Substrate wallets).
- **Fuzzing** of the JSON canonicalizer, DID parser and SCALE encoder (`zig build fuzz`).
- Return **all** verification methods, services and authentication entries from `parseDID`.

## Later

- secp256k1 / EVM-style keys for peaq's unified-address accounts.
- Windows x64 binaries.
- WebAssembly build for edge runtimes and browsers.
- W3C Data Integrity `eddsa-jcs-2022` proofs so credentials interoperate with other VC libraries.
- SCALE *decoding* and DID document assembly from on-chain attributes.
- Pure-Zig and C ABI packaging for use outside Node.js.
- Independent security review.

## Not planned

- A full Substrate light client or RPC layer. Use polkadot-js or peaq's SDKs and pass bytes to did0.

# Changelog

All notable changes are documented here. The project follows [Semantic Versioning](https://semver.org/); while the version is below 1.0, minor releases may contain breaking changes.

## [0.2.0] - 2026-10-04

### Breaking changes

- **Key derivation now matches Substrate tooling.** The Ed25519 seed is PBKDF2-HMAC-SHA512 over the mnemonic *entropy* (polkadot-js `mnemonicToMiniSecret`), not over the mnemonic text. The same mnemonic therefore produces a **different** key, address and DID than 0.1.x. Wallets created with 0.1.x must be migrated by moving funds/identities; 0.1.x is deprecated.
- **`publicKeyMultibase` is now the W3C form** (`z6Mk…`, multicodec prefix `0xed01`). Verification still accepts bare 32-byte keys.
- **`verifySignature` verifies the raw message only.** It previously also accepted a signature over the SHA-256 digest, which made the scheme ambiguous. Use the new `verifyCredential` (or `verifyDigestSignature`) for signatures from `issueCredential`.
- **SCALE `validity` is `Option<u32>`**, matching `valid_for` in `peaq-pallet-did`. Pass `null`/`undefined` for no expiry. The old plain-`u32` encoding would not decode on-chain.
- `createWallet()` no longer returns `seedHex`.
- Invalid arguments now throw instead of being truncated or wrapped: over-long names/values/messages, pallet/call indexes outside 0-255, negative or fractional numbers, non-string inputs.
- The canonicalizer is strict (see below); some inputs that were silently accepted now throw.
- `bs58` moved to `devDependencies`; the core package no longer ships prebuilt binaries inside its own tarball (they come from the `@did0/binding-*` packages).

### Added

- `verifyCredential(payload, signatureHex, publicKeyMultibase)` and `verifyDigestSignature(...)`.
- `createWallet({ ss58Prefix })` with full SS58 support (one- and two-byte prefixes, e.g. peaq's registered 1221).
- `DID0_BINDING_PATH` environment variable to load a specific native binary.
- Known-answer tests (RFC 8032, RFC 8785, Substrate mini-secret, SS58) and differential tests against independent JavaScript implementations.
- Reproducible benchmark covering every operation, with baselines.
- `CODE_OF_CONDUCT.md`, `ROADMAP.md`, issue and pull-request templates, Dependabot configuration.

### Fixed

- JCS number formatting: small magnitudes (`4.7e-6`) and large integers (`123456789012345680000`) were not serialized as ECMAScript does.
- JCS parser accepted trailing commas, trailing garbage, malformed numbers (`01`, `1.`), raw control characters and duplicate keys, and had no nesting limit (deep input could overflow the native stack).
- Base58 decoding had a fixed 32-byte output, silently overflowed on longer input and mishandled leading zeros.
- A `Buffer` message larger than 64 KiB in `verifySignature` read past a fixed buffer.
- Strings longer than the internal buffers were silently truncated before being SCALE-encoded.
- `npm ci` failed because unpublished platform packages were listed as `optionalDependencies`.
- A stale `prebuilds/` directory could shadow a freshly built local binary.

## [0.1.1] - 2026-10-04

- Release pipeline fixes. Deprecated.

## [0.1.0] - 2026-10-04

- Initial release. Deprecated.

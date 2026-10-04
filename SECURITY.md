# Security Policy

## Status

did0 is **alpha software and has not been independently audited**. Do not use it to protect keys that control real value until it has been reviewed. Pin exact versions and read the [changelog](CHANGELOG.md) before upgrading; breaking changes are possible in any 0.x release.

## Supported versions

| Version | Supported |
| :--- | :--- |
| 0.2.x | yes |

## What the library tries to guarantee

- **Memory safety:** parsing, canonicalization and encoding operate on fixed-size buffers; oversized or malformed input is rejected with an error instead of being truncated. The Node-API layer validates every argument.
- **Standard primitives:** Ed25519, SHA-256, HMAC/PBKDF2-SHA512 and Blake2b come from the Zig standard library. did0 does not implement its own curve or hash code. Constant-time behaviour is inherited from Zig's implementations and has not been separately verified.
- **Scratch-buffer hygiene:** native stack buffers that held entropy, seeds, mnemonics or secret keys are cleared with `std.crypto.secureZero` before the function returns.
- **Strict JSON handling for signing:** the canonicalizer rejects duplicate keys, trailing commas, non-standard numbers, raw control characters, lone surrogates and excessive nesting, so two parsers cannot disagree about what was signed.

## What it does not guarantee

- **Secrets exposed to JavaScript:** `createWallet` returns `mnemonic` and `privateKeyHex` as JavaScript strings. These live on the V8 heap, can be copied by the engine and appear in heap snapshots and core dumps, and cannot be wiped. The same applies to the private key you pass to `issueCredential`. If this matters for your deployment, do not use the JavaScript wallet API for production keys.
- **No side-channel hardening beyond the standard library.**
- **No protection against a compromised host process or malicious dependencies.**
- **Interoperability is not formally certified.** Key derivation, SS58 and SCALE output are tested against published vectors and the `peaq-pallet-did` source, but not against a live chain in CI.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through [GitHub Security Advisories](https://github.com/did0-project/did0/security/advisories/new) or by email to `security@did0.org`.

Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version and platform.

We aim to acknowledge reports within 3 working days and to share a fix or mitigation plan within 14 days. We will credit reporters in the release notes unless they prefer to stay anonymous.

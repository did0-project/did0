# did0

[![CI](https://github.com/did0-project/did0/actions/workflows/ci.yml/badge.svg)](https://github.com/did0-project/did0/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@did0/core.svg)](https://www.npmjs.com/package/@did0/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange.svg)](https://ziglang.org/)

A fast native identity toolkit for [peaq](https://www.peaq.network/) and other Substrate-based DePIN networks, written in Zig and exposed to Node.js through Node-API.

> **Status: alpha, not security-audited.** The API will change before 1.0. Do not use it to protect keys that control real value until it has had an independent review. See [SECURITY.md](SECURITY.md).

## What it does

| Area | What you get | Standards |
| :--- | :--- | :--- |
| **DID documents** | Parse a W3C DID document and read its `id` and first `publicKeyMultibase` | W3C DID Core 1.0 |
| **Signatures** | Verify Ed25519 signatures with `z6Mk…` / bare-32-byte multibase keys | RFC 8032, W3C `Ed25519VerificationKey2020` |
| **Credentials** | Canonicalize JSON, sign it, and verify it | RFC 8785 (JCS) |
| **peaq on-chain DID** | SCALE-encode `add_attribute`, `update_attribute` and `remove_attribute` calls | [`peaq-pallet-did`](https://github.com/peaqnetwork/peaq-pallet-did) |
| **Wallets** | BIP-39 mnemonics → Ed25519 key → SS58 address → `did:peaq:` identifier | BIP-39, Substrate key derivation, SS58 |

Everything runs in native code on fixed-size stack buffers: there is no heap allocation on the hot paths, and input that does not fit is rejected, never truncated.

### What it is not

- It is **not** a full Substrate client. It builds call bytes; it does not sign extrinsics, talk to RPC nodes or track nonces. Use [`@polkadot/api`](https://polkadot.js.org/docs/api/) or peaq's own SDKs for that, and feed them the bytes from here.
- It does **not** implement a W3C Data Integrity cryptosuite. `issueCredential` signs `SHA-256(JCS(credential))` with Ed25519 and returns a bare signature. That scheme is specific to did0 (documented below).
- It does **not** support sr25519 or secp256k1/EVM keys yet (see the [roadmap](ROADMAP.md)).
- It does **not** resolve DIDs over the network. Fetch the document yourself and pass it to `parseDID`.

## Install

```bash
npm install @did0/core
```

Requires Node.js 20+. Prebuilt binaries are installed automatically for:

| OS | CPU | libc |
| :--- | :--- | :--- |
| macOS | arm64, x64 | n/a |
| Linux | x64, arm64 | glibc, musl (Alpine) |

Windows is not supported yet. If your platform has no binary, the loader throws an error that names the missing package (check that you did not install with `--no-optional`).

### Build from source

Requires [Zig 0.16.0](https://ziglang.org/download/).

```bash
git clone https://github.com/did0-project/did0.git
cd did0
npm install
npm test        # builds, runs the Zig and Node test suites
```

## Usage

### Wallets

```js
const { createWallet, generateMnemonic, validateMnemonic } = require('@did0/core');

const wallet = createWallet();            // new random 12-word wallet
wallet.did;                               // did:peaq:5…
wallet.ss58Address;                       // 5…
wallet.publicKeyMultibase;                // z6Mk…  (W3C Ed25519VerificationKey2020)
wallet.mnemonic;                          // keep this secret
wallet.privateKeyHex;                     // keep this secret

// Restore, optionally with a passphrase
createWallet({ mnemonic: wallet.mnemonic, passphrase: '' });

// peaq's registered SS58 prefix is 1221; the default is 42 (generic Substrate)
createWallet({ mnemonic: wallet.mnemonic, ss58Prefix: 1221 });

validateMnemonic(generateMnemonic(24));   // true
```

Key derivation follows Substrate tooling: the Ed25519 seed is PBKDF2-HMAC-SHA512 over the mnemonic's **entropy** (as in `substrate-bip39` and polkadot-js `mnemonicToMiniSecret`), not over the phrase text as plain BIP-39 does. The phrase `abandon … about` gives mini-secret `4ed8d4b1…97e2` and public key `9125f505…b294`; this is covered by the tests. Derivation paths (`//hard`, `/soft`) are not supported yet.

> `mnemonic` and `privateKeyHex` are returned to JavaScript as strings. They are derived in native code and the native copies are wiped, but the JS strings live on the V8 heap and cannot be zeroed. Treat the process memory as sensitive.

### Signing and verifying credentials

```js
const { createWallet, issueCredential, verifyCredential } = require('@did0/core');

const issuer = createWallet();
const credential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'ChargingReceipt'],
  issuer: issuer.did,
  issuanceDate: '2026-10-04T10:20:00Z',
  credentialSubject: { id: 'did:peaq:5EVVehicle…', energyDeliveredKWh: 14.85 },
};

const signature = issueCredential(credential, issuer.privateKeyHex);   // 128 hex chars
verifyCredential(credential, signature, issuer.publicKeyMultibase);    // true
```

The scheme is: `signature = Ed25519(SHA-256(JCS(credential)))`. Key order and whitespace of the input do not matter; any change to the content makes verification fail. Because it is not a Data Integrity proof, other VC libraries will not verify these signatures out of the box; to interoperate, verify with `verifyDigestSignature(publicKeyMultibase, canonicalJson, signature)` or reimplement the three steps above.

The canonicalizer is strict: it rejects duplicate keys, trailing commas, invalid numbers, raw control characters, lone surrogates, and nesting deeper than 128 levels.

### Verifying a raw Ed25519 signature

```js
const { verifySignature } = require('@did0/core');

verifySignature(publicKeyMultibase, message /* string | Buffer */, signatureHex); // true | false
```

`verifySignature` checks the signature over the message bytes exactly. Signatures from `issueCredential` sign a digest and are **rejected** here by design; use `verifyCredential`. Malformed keys or signatures throw; a well-formed but wrong signature returns `false`.

### peaq on-chain DID calls

```js
const { createWallet, encodeAddAttributeCall } = require('@did0/core');

const wallet = createWallet();
const call = encodeAddAttributeCall(
  PALLET_INDEX,        // from the runtime metadata of the chain you target
  0,                   // peaq-did: add_attribute = 0, update_attribute = 1, remove_attribute = 3
  wallet.publicKeyHex, // the DID's AccountId (32 bytes, hex)
  'did/pubkey',        // attribute name (max 255 bytes)
  wallet.did,          // attribute value (max 8191 bytes)
  1_000_000            // valid_for in blocks, or null for no expiry
);
```

This returns the SCALE-encoded call (`pallet ++ call ++ did_account ++ name ++ value ++ Option<valid_for>`), matching [`peaq-pallet-did`](https://github.com/peaqnetwork/peaq-pallet-did). Pallet indexes differ per runtime; always read yours from the chain metadata. This library does not fetch it. Signing and submitting the extrinsic is up to you.

### Parsing a DID document

```js
const { parseDID } = require('@did0/core');

const doc = parseDID(jsonString);   // documents up to 4095 bytes
doc.id;                             // "did:peaq:5…"
doc.publicKeyMultibase;             // first verification method's key, if present
```

### TypeScript

Types ship with the package (`index.d.ts`) and the package works with both `import` and `require`.

## Performance

`npm run benchmark` reproduces this table. Measured on an Apple M-series laptop, Node 22, 100k iterations (fewer for the slow rows); your numbers will differ.

| Operation | Latency (µs) | Ops/sec |
| :--- | ---: | ---: |
| `parseDID` | 1.0 | ~970,000 |
| `canonicalize` (credential) | 1.9 | ~516,000 |
| baseline: `JSON.parse` + sorted `JSON.stringify` | 3.0 | ~336,000 |
| `encodeDidAttribute` | 0.4 | ~2,500,000 |
| `verifySignature` (Ed25519) | 52.6 | ~19,000 |
| baseline: `node:crypto` Ed25519 verify | 85.4 | ~11,700 |
| `issueCredential` | 86.4 | ~11,600 |
| `verifyCredential` | 51.7 | ~19,300 |
| `createWallet` (PBKDF2, 2048 rounds) | 3,581 | ~280 |
| baseline: `node:crypto` PBKDF2 | 684 | ~1,460 |

The honest summary: parsing, canonicalization and SCALE encoding are noticeably faster than pure JavaScript, Ed25519 verification is competitive with OpenSSL through `node:crypto`, and wallet derivation is about 5× **slower** than OpenSSL's PBKDF2 (it is a one-off operation per identity, so this rarely matters).

## Project layout

```
src/
  napi.zig          Node-API bindings (argument validation, no truncation)
  base58.zig        Base58 codec
  peaq/parser.zig   DID document parsing, multibase keys, Ed25519 verification
  scale.zig         SCALE encoder and peaq-did call builders
  jcs.zig           RFC 8785 JSON canonicalization
  wallet.zig        BIP-39, Substrate key derivation, SS58
  did0.zig          Library root (Zig module "did0")
  main.zig          Small CLI demo (`zig build run`)
index.js / .mjs / .d.ts   Node entry points and types
tests/              Known-answer, negative, and differential tests
scripts/            Multi-platform build and publish helpers
```

You can also use the Zig modules directly: add the package to `build.zig.zon` and `@import("did0")`.

## Testing

```bash
npm test                  # build + Zig unit tests + Node integration tests
npm run test:unit         # zig build test
npm run test:integration  # Node tests against ./did0.node
npm run benchmark         # node --expose-gc benchmark.js
```

The suite includes RFC 8032 and RFC 8785 vectors, a published Substrate mini-secret vector, SS58 vectors for Polkadot and Kusama, and differential tests that compare the canonicalizer against an independent JavaScript implementation on thousands of random documents. It has **not** been fuzzed beyond that or independently audited.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Planned work is in [ROADMAP.md](ROADMAP.md).

## License

[MIT](LICENSE)

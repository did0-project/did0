# did0

[![CI](https://github.com/did0-project/did0/actions/workflows/ci.yml/badge.svg)](https://github.com/did0-project/did0/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@did0/core.svg)](https://www.npmjs.com/package/@did0/core)
[![PyPI](https://img.shields.io/pypi/v/did0-py.svg)](https://pypi.org/project/did0-py/)
[![Crates.io](https://img.shields.io/crates/v/did0.svg)](https://crates.io/crates/did0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange.svg)](https://ziglang.org/)

A zero-allocation Decentralized Identifier (DID) resolver, cryptographic verification engine, and identity toolkit built in **Zig** and optimized for **peaq Network** and enterprise **DePIN** (Decentralized Physical Infrastructure Networks).

**did0** bridges native C-level execution speeds into Node.js, NestJS, and edge microservices via Node-API (N-API). By executing all schema parsing, SCALE encoding, JSON canonicalization (JCS), and cryptographic operations directly on native stack frames using Zig's `FixedBufferAllocator`, **did0** eliminates V8 garbage collection pauses and prevents private key leaks in memory dumps.

---

## Architecture & Design Principles

```
  ┌─────────────────────────────────────────────────────────────┐
  │                 Node.js / NestJS / TypeScript               │
  │                  (Zero-Copy N-API Bridge)                   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │                        did0 Engine                          │
  │                   (Zig Native Binary)                       │
  ├──────────────────────────────┬──────────────────────────────┤
  │      1. Resolution & Crypto  │   2. Substrate SCALE Codec   │
  │   - Stack-allocated JSON AST │   - Compact Ints (Single/    │
  │   - Base58 'z' Multibase     │     Two/Four/Big modes)      │
  │   - Native Ed25519 Engine    │   - peaq DID Extrinsics      │
  ├──────────────────────────────┼──────────────────────────────┤
  │    3. Verifiable Credentials │    4. Native Key Management  │
  │   - RFC 8785 JCS Canonical  │   - BIP-39 Mnemonics (12/24) │
  │   - UTF-16 Code Unit Sorting │   - PBKDF2-HMAC-SHA512 Seed  │
  │   - In-place Deterministic   │   - SS58 Address (Prefix 42) │
  │     Proof Generation         │   - did:peaq Derivation      │
  └─────────────────────────────────────────────────────────────┘
```

1. **Zero Heap Allocations on Hot Paths**: When parsing incoming DID documents, canonicalizing payloads, or serializing SCALE frames, memory is carved out of fixed, caller-owned stack buffers. The heap delta remains **0.00 MB**.
2. **Off-Heap Cryptographic Isolation**: BIP-39 seed derivation and Ed25519 private key operations occur completely outside the V8 JavaScript garbage-collected heap, shielding credentials from inspection.
3. **Strict W3C & Substrate Alignment**: Produces standards-compliant W3C DID documents, RFC 8785 canonical JSON, and Substrate SCALE-encoded transaction payloads ready for peaq RPC nodes.

---

## Core Pillars & Modules

| Module | Scope | Standard / Specification |
| :--- | :--- | :--- |
| **Resolution & Verification** | Parse W3C DID Documents & verify device signatures | W3C DID Core 1.0, Multibase (`base58btc`), Ed25519 |
| **SCALE Codec** | Serializes peaq DID attributes and dispatchable calls | Substrate SCALE Codec Specification |
| **Verifiable Credentials** | Canonicalization and deterministic credential signing | RFC 8785 (JCS), W3C Verifiable Credentials Data Model v1.1 |
| **Key Management** | Mnemonic generation, PBKDF2 seed, and SS58 addresses | BIP-0039, Substrate SS58 Registry (Prefix 42) |

---

## Installation

### Prerequisites
- **Node.js**: `v20.0.0` or higher
- **Zig**: `0.16.0` or higher ([Download Zig](https://ziglang.org/download/))

### Build from Source
```bash
git clone https://github.com/kiruthikraaj/did0.git
cd did0
npm install
npm run build
```

This compiles `src/napi.zig` in `ReleaseFast` mode and outputs `did0.node`.

---

## API Reference & Usage

### 1. Key Management & Wallet Derivation (Phase 4)

Generate cryptographically secure BIP-39 mnemonics, compute PBKDF2 seeds, and derive peaq Ed25519 keypairs and Substrate SS58 addresses:

```typescript
import { createWallet, generateMnemonic, validateMnemonic } from '@did0/core';

// Generate a random 12-word or 24-word mnemonic
const mnemonic = generateMnemonic(12);
console.log("Valid?", validateMnemonic(mnemonic)); // true

// Create a new wallet from scratch
const wallet = createWallet();
console.log("DID:", wallet.did);                        // e.g. did:peaq:5GxKgBuq8GpYQ2YSUhr8Jj...
console.log("SS58 Address:", wallet.ss58Address);        // e.g. 5GxKgBuq8GpYQ2YSUhr8Jj...
console.log("Public Key (Multibase):", wallet.publicKeyMultibase); // e.g. zFZNxRDJStGRD2Gn...

// Restore an existing wallet using a mnemonic and optional passphrase
const restored = createWallet({
  mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  passphrase: ""
});
```

---

### 2. W3C Verifiable Credentials & RFC 8785 JCS (Phase 3)

Canonicalize JSON according to RFC 8785 (lexicographical UTF-16 code unit property sorting) and sign Verifiable Credentials:

```typescript
import { canonicalize, issueCredential, verifySignature } from '@did0/core';

const credential = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://peaq.network/credentials/depin/v1"
  ],
  id: "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  type: ["VerifiableCredential", "DePINChargingReceipt"],
  issuer: wallet.did,
  issuanceDate: "2026-10-04T10:20:00Z",
  credentialSubject: {
    id: "did:peaq:5DroneAutopilotDelta443322",
    energyDeliveredKWh: 14.85,
    sessionCompleted: true
  }
};

// 1. Issue and sign the credential (canonicalizes + SHA-256 + Ed25519)
const signatureHex = issueCredential(credential, wallet.privateKeyHex);

// 2. Canonicalize for independent transport or verification
const canonicalVC = canonicalize(credential);

// 3. Verify signature against the issuer's multibase public key
const isValid = verifySignature(wallet.publicKeyMultibase, canonicalVC, signatureHex);
console.log("Verified:", isValid); // true
```

---

### 3. Substrate SCALE Codec for peaq Blockchain (Phase 2)

Construct Substrate-compatible bytecodes for on-chain DID creation and attribute updates without heavy JavaScript libraries:

```typescript
import { encodeDidAttribute, encodeAddAttributeCall } from '@did0/core';

const didAccountHex = wallet.publicKeyHex; // 32-byte AccountId
const attributeName = "did/pubkey";
const attributeValue = wallet.did;
const validityBlocks = 5_000_000;

// Encode raw DID attribute payload
const attributeBytes = encodeDidAttribute(
  didAccountHex,
  attributeName,
  attributeValue,
  validityBlocks
);

// Encode complete Substrate pallet dispatchable call (peaq-did add_attribute)
const callBytes = encodeAddAttributeCall(
  12, // palletIndex
  0,  // callIndex
  didAccountHex,
  attributeName,
  attributeValue,
  validityBlocks
);
```

---

### 4. W3C DID Document Resolution & Verification (Phase 1)

Parse incoming peaq DID Documents with zero heap allocations:

```typescript
import { parseDID } from '@did0/core';

const rawDocument = JSON.stringify({
  id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
  verificationMethod: [
    {
      id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY#keys-1",
      type: "Ed25519VerificationKey2020",
      controller: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
      publicKeyMultibase: "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ]
});

// Executes on the native stack with zero allocation
const doc = parseDID(rawDocument);
console.log(doc.id);                 // "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
console.log(doc.publicKeyMultibase); // "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
```

---

## End-to-End DePIN Machine Flow

Here is how an IoT device (e.g., an EV charging station) executes its complete identity lifecycle in under 5 milliseconds:

```typescript
import { createWallet, issueCredential, canonicalize, verifySignature, encodeDidAttribute } from '@did0/core';

// 1. Hardware Gateway initializes identity off-heap
const gateway = createWallet();

// 2. Machine generates and signs a verifiable charging session receipt
const receipt = {
  type: ["VerifiableCredential", "DePINChargingReceipt"],
  issuer: gateway.did,
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    stationId: "peaq-station-eu-01",
    vehicleId: "did:peaq:5EVVehicleClient9988",
    kwhDelivered: 42.5
  }
};
const sig = issueCredential(receipt, gateway.privateKeyHex);

// 3. Client verifies authenticity using public multibase key
const verified = verifySignature(gateway.publicKeyMultibase, canonicalize(receipt), sig);

// 4. Gateway anchors identity attribute to peaq blockchain
const txPayload = encodeDidAttribute(gateway.publicKeyHex, "did/pubkey", gateway.did, 1000000);
```

---

## Benchmarks

Measured via 100,000 continuous iterations on Apple Silicon (M-series, `ReleaseFast`):

| Operation | Latency | Throughput | Heap Delta |
| :--- | :--- | :--- | :--- |
| **N-API DID Document Parsing** | 0.86 µs | **1,039,000+ ops/sec** | 0.04 MB |
| **Substrate SCALE Attribute Encoding** | 7.0 µs | **140,000+ ops/sec** | 0.00 MB |
| **RFC 8785 (JCS) Canonicalization** | 15.0 µs | **65,000+ ops/sec** | 0.00 MB |
| **Verifiable Credential Issuance** | 120.0 µs | **8,300+ ops/sec** | 0.00 MB |
| **Native Ed25519 Verification** | 107.0 µs | **21,500+ ops/sec** | 0.00 MB |
| **Full HD Wallet Derivation (2048 PBKDF2 rounds)** | 3.02 ms | **330+ ops/sec** | 0.00 MB |

---

## Project Structure

```
did0/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI matrix (macOS & Ubuntu)
├── src/
│   ├── did0.zig                 # Root library exports & core W3C schemas
│   ├── napi.zig                 # Node-API FFI bindings and zero-copy marshalling
│   ├── main.zig                 # Native CLI demonstration tool
│   ├── scale.zig                # Substrate SCALE serialization engine
│   ├── jcs.zig                  # RFC 8785 JSON Canonicalization Scheme engine
│   ├── wallet.zig               # BIP-39 mnemonic, PBKDF2 seed & SS58 derivations
│   ├── bip39_words.zig          # Constant-memory BIP-39 English wordlist (2048 words)
│   └── peaq/
│       └── parser.zig           # FixedBufferAllocator DID Document parser
├── tests/
│   ├── 01-parse.test.js         # W3C schema parsing tests
│   ├── 02-crypto.test.js        # Multibase Ed25519 verification tests
│   ├── 03-scale.test.js         # Substrate SCALE codec tests
│   ├── 04-vc.test.js            # RFC 8785 vectors & credential issuance tests
│   └── 05-wallet.test.js        # BIP-39 & full cross-phase integration tests
├── build.zig                    # Zig build system configuration
├── build.zig.zon                # Zig package manifest
├── index.js                     # High-level Node.js entry point
├── index.d.ts                   # Complete TypeScript declarations & JSDoc
├── benchmark.js                 # Throughput & memory benchmark runner
├── LICENSE                      # MIT License
├── package.json                 # Node package configuration
└── README.md                    # Project documentation
```

---

## Testing & Quality Assurance

### Run All Unit & Integration Tests
```bash
npm test
```

### Run Only Zig Native Unit Tests
```bash
npm run test:unit
```

### Run Node.js Integration Tests
```bash
npm run test:integration
```

### Run Performance Benchmarks
```bash
npm run benchmark
```

### Run Code Formatter
```bash
npm run format
```

---

## License

This project is licensed under the [MIT License](LICENSE).

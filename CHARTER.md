# Project Handover & Setup Charter: did0

## 1. Executive Summary & Vision

* **Project Name**: did0
* **Domain**: did0.org
* **Target Ecosystem**: peaq Network (DePIN) / Substrate
* **Core Identity**: A zero-allocation, native-speed Decentralized Identifier (DID) and cryptographic toolkit for enterprise DePIN networks.

### The Vision
As DePIN networks scale, hardware gateways and backend microservices will process thousands of machine authentications, verifiable credentials, and transactions per second. Standard JavaScript runtimes degrade under this load due to V8 garbage collection and memory bloat. **did0** pushes the entire cryptographic and identity lifecycle down to memory-safe, zero-allocation Zig binaries. The goal is to provide the definitive, high-throughput infrastructure standard for W3C DIDs on the peaq network.

---

## 2. The Core Idea & Architecture

The project replaces traditional Node.js/TypeScript cryptographic dependencies with a unified Zig engine bridged via N-API.

* **Zero Heap Allocation**: Utilizes Zig's `FixedBufferAllocator` to parse payloads and execute mathematics directly on the stack, ensuring a memory delta of 0.00 MB during execution.
* **Native Speed**: Achieves 1,000,000+ parse operations and 21,000+ Ed25519 signature verifications per second per core.
* **Seamless Interop**: Compiles into a dynamic library (`.node`) with complete TypeScript definitions (`.d.ts`), making it a drop-in replacement for any Nx monorepo or NestJS microservice architecture.

---

## 3. Current State (Phase 1: Resolution & Verification)

The foundational engine is built and benchmarked.

### Completed Modules
* **W3C DID Document Schema Parsing**: Native schema parsing directly on the stack.
* **Native Multibase / Base58 Decoding**: Optimized `z`-prefix base58 decoding without heap allocations.
* **Ed25519 Signature Verification**: High-performance verification using Zig's standard library crypto engine.
* **N-API Node.js Bridge**: Zero-copy V8 string marshalling and native object construction.

### Validated Benchmarks
Measured via 100,000 continuous iterations (Apple Silicon, Zig `ReleaseFast`):
* **Parsing Throughput**: ~1.03M ops/sec (0.04 MB heap delta)
* **Crypto Verification**: ~21.5K ops/sec (0.00 MB heap delta)

---

## 4. Architectural Roadmap & Current Implementation Status

All four foundational architectural phases of the did0 engine are implemented, natively tested, and benchmarked:

### Phase 1: Resolution & Verification (Complete)
* Schema parsing of W3C DID Documents via `FixedBufferAllocator` (`src/peaq/parser.zig`).
* Native multibase / base58 decoding and Ed25519 signature verification via `std.crypto.sign.Ed25519`.

### Phase 2: Substrate SCALE Encoding (Write Operations) (Complete)
* Zero-allocation SCALE serializer in `src/scale.zig` supporting compact integers (all modes), little-endian numbers, booleans, optionals, and struct reflection.
* Native construction of peaq DID attributes and extrinsic bytecodes (`encodeDidAttribute`, `encodeAddAttributeCall`).

### Phase 3: Verifiable Credentials & Presentations (Complete)
* RFC 8785 JSON Canonicalization Scheme (JCS) engine in `src/jcs.zig`.
* In-place recursive UTF-16 code unit property sorting and ECMAScript 6 number formatting.
* Full credential issuance pipeline (`issueCredential`): canonicalization, SHA-256 digest computation, and Ed25519 signing.

### Phase 4: Native Key Management (BIP39 & Derivation) (Complete)
* Zero-allocation BIP-39 mnemonic generation (12 and 24 words) and checksum validation in `src/wallet.zig` and `src/bip39_words.zig`.
* Standard PBKDF2-HMAC-SHA512 (2048 iterations) seed derivation entirely off the V8 heap.
* Native Substrate SS58 address encoding (Blake2b-512 + Base58) and peaq DID derivation (`did:peaq:<address>`).

---

## 5. Technical Stack & Tooling

* **Systems Language**: Zig 0.16.0
* **FFI Boundary**: Node-API (N-API)
* **Backend Environment**: Node.js 22.x / Node.js 24.x, NestJS
* **Workspace Management**: Nx (Target integration environment)
* **Testing**: JavaScript native `perf_hooks` for throughput validation, Zig `std.testing` for binary logic.

---

## 6. Execution Tracking & Immediate Tickets

* **Ticket 1 (Active)**: Initialize Substrate SCALE Encoder module within the Zig source tree (`src/scale.zig` / `src/peaq/scale.zig`) to translate W3C DID structures and peaq DID transactions into valid peaq blockchain bytecodes.
* **Ticket 2**: Implement peaq DID extrinsic builders (`did:peaq` attribute creation and updates).
* **Ticket 3**: Expose SCALE encoding primitives and DID extrinsic builders to TypeScript via N-API.

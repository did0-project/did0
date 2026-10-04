# did0 Release & Distribution Strategy

This document outlines the production release, distribution, and go-to-market (GTM) strategy for **`did0`**, modeled after industry-standard native Node.js architectures (such as `esbuild`, `@swc/core`, `oxc`, and `napi-rs`).

---

## 1. Overview & Core Philosophy

`did0` is an ultra-high-performance, zero-allocation W3C DID, Substrate SCALE codec, RFC 8785 JCS canonicalization, and DePIN cryptographic engine written in Zig with native Node-API bindings.

To maintain its enterprise reliability and high developer experience (DX), distribution must adhere to three principles:
1. **Zero Runtime Bloat**: End users must never download dead binaries for architectures or operating systems they do not run.
2. **Zero Toolchain Friction**: End users must not be required to have Zig, Clang, or Python installed to consume `did0`. Precompiled, platform-specific native binaries must be delivered via standard package managers (`npm`, `pnpm`, `yarn`).
3. **Cryptographic Verifiability**: Every binary release must be accompanied by cryptographic provenance (SLSA Level 3 via GitHub Actions OIDC) and immutable SHA-256 checksum manifests.

---

## 2. Pillar 1: Distribution Architecture (Optional Dependencies Pattern)

### 2.1 The Platform Packages Model
Rather than packaging monolithic `.node` binaries into a single npm tarball, `did0` uses the scoped platform packages architecture.

```
                           ┌──────────────────────────┐
                           │      did0 (Core)         │
                           │  - JS/TS Loader          │
                           │  - High-level Wrappers   │
                           │  - TypeScript .d.ts      │
                           └─────────────┬────────────┘
                                         │ optionalDependencies
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
┌──────────────────┐           ┌──────────────────┐           ┌──────────────────┐
│ @did0/binding-   │           │ @did0/binding-   │           │ @did0/binding-   │
│ darwin-arm64     │           │ linux-x64-gnu    │           │ linux-x64-musl   │
│ (Apple Silicon)  │           │ (Ubuntu/Debian)  │           │ (Alpine Linux)   │
└──────────────────┘           └──────────────────┘           └──────────────────┘
```

The core `did0` package lists all platform targets under `optionalDependencies` in its `package.json`. Each platform-specific package defines its target environment using npm's `os` and `cpu` fields:

| Platform Package | OS (`os`) | Architecture (`cpu`) | Libc | Target Use Cases |
| :--- | :--- | :--- | :--- | :--- |
| `@did0/binding-darwin-arm64` | `["darwin"]` | `["arm64"]` | Darwin (BSD) | Apple Silicon (M1/M2/M3/M4) |
| `@did0/binding-darwin-x64` | `["darwin"]` | `["x64"]` | Darwin (BSD) | Intel macOS |
| `@did0/binding-linux-x64-gnu` | `["linux"]` | `["x64"]` | glibc | Standard Linux (Ubuntu, Debian, RHEL) |
| `@did0/binding-linux-x64-musl` | `["linux"]` | `["x64"]` | musl | Containerized Linux (Alpine Docker) |
| `@did0/binding-linux-arm64-gnu` | `["linux"]` | `["arm64"]` | glibc | AWS Graviton, Raspberry Pi (64-bit OS) |
| `@did0/binding-linux-arm64-musl`| `["linux"]` | `["arm64"]` | musl | Alpine Linux on ARM64 containers |

When a developer runs `npm install did0`, the package manager reads the host OS and CPU and fetches **only** the single matching binding package, keeping download size under ~200 KB.

### 2.2 Host Resolution & Dynamic Loader
The entry points (`index.js` for CJS and `index.mjs` for ESM) utilize a platform loader with:
1. Exact platform-triple resolution (`${process.platform}-${process.arch}-${libc}`).
2. Fallback to local `did0.node` in root for local monorepo development and testing.
3. Informative, actionable error messages if a platform binary is missing or blocked by `--no-optional`.

---

## 3. Pillar 2: Release Engineering & Supply Chain Security

### 3.1 Hermetic Cross-Compilation via Zig
Zig acts as a complete C/C++ cross-compiler and linker with built-in libc definitions for both `gnu` and `musl`. All 6 target binaries can be built reproducibly:

```bash
# macOS
zig build addon -Dtarget=aarch64-macos -Doptimize=ReleaseFast
zig build addon -Dtarget=x86_64-macos -Doptimize=ReleaseFast

# Linux (glibc & musl)
zig build addon -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast
zig build addon -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
zig build addon -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast
zig build addon -Dtarget=aarch64-linux-musl -Doptimize=ReleaseFast
```

### 3.2 Automated CI/CD Release Pipeline (`release.yml`)
Triggered strictly by pushing semantic version tags (e.g., `v0.1.0`):
1. **Validation Stage**:
   - Run unit tests (`zig build test`).
   - Run integration tests (`npm run test:integration`).
   - Verify code formatting (`npm run format`).
2. **Matrix Compilation Stage**:
   - Cross-compile release binaries across all 6 targets.
   - Package each binary into its corresponding scoped package directory under `npm/`.
3. **Containerized Smoke Tests**:
   - Test loading and running credentials verification in `node:20-bookworm-slim` (glibc).
   - Test loading and running credentials verification in `node:20-alpine` (musl).
4. **Publish Stage**:
   - Generate SHA-256 manifest (`checksums.txt`).
   - Create GitHub Release with release notes and binary assets.
   - Publish all `@did0/binding-*` platform packages to npm.
   - Publish the primary `did0` package to npm with `--provenance` via GitHub Actions OIDC.

---

## 4. Pillar 3: API & Developer Experience (DX) Hardening

### 4.1 Dual CommonJS and ESM Support
`did0` supports both modern ESM import syntax and legacy CommonJS require syntax seamlessly:
```json
{
  "exports": {
    ".": {
      "types": "./index.d.ts",
      "import": "./index.mjs",
      "require": "./index.js"
    }
  }
}
```

### 4.2 Comprehensive TypeScript Typings
Strict type declarations in `index.d.ts` provide compile-time guarantees, auto-complete, and inline documentation for:
- W3C DID Document structures.
- Verifiable Credential parameters and proofs.
- Peaq Substrate SCALE calls (`peaq-did:add_attribute`, `read_attribute`).
- BIP-39 mnemonic phrase and Ed25519 keypair generation.

---

## 5. Pillar 4: Ecosystem Go-To-Market (GTM)

### 5.1 Peaq Network & DePIN Positioning
- **The Benchmark Story**: Compare `did0` against standard `@polkadot/api` and `did-jwt` stacks. While typical JS stacks consume 50MB+ in `node_modules` and require hundreds of milliseconds for crypto initialization, `did0` operates in sub-millisecond time with zero heap allocations.
- **DePIN Edge Devices**: Position `did0` as the premier lightweight library for Raspberry Pi, IoT gateways, and vehicle telemetry units connecting to the Peaq blockchain.
- **Grant & Builders Submission**: Submit `did0` to the Peaq Network Ecosystem Grants / Builders Portal.

### 5.2 Public Launch Sequence
1. **v0.1.0 Pre-flight**: Complete Milestone A (build scripts, platform loader, dual ESM/CJS exports).
2. **v0.1.0 Automation**: Complete Milestone B (CI release workflow and smoke test containers).
3. **v0.1.0 Release**: Publish packages to npm and tag GitHub release.
4. **Community Launch**:
   - Peaq Developer Discord & Community Forums.
   - Polkadot / Substrate Forum.
   - Technical post on Hacker News (`Show HN: did0 – Zero-Allocation W3C DID & Cryptographic Engine in Zig`).
   - Reddit (`r/Zig`, `r/Node`, `r/cryptocurrency`).

---

## 6. Execution Milestones

- **Milestone A (Current)**:
  - [x] Author comprehensive release strategy (`RELEASE_STRATEGY.md`).
  - [ ] Implement multi-target build script (`scripts/build-platforms.js`).
  - [ ] Implement platform loader with scoped package resolution and local fallback.
  - [ ] Add dual CommonJS (`index.js`) and ESM (`index.mjs`) exports.
  - [ ] Verify test suite across modules.
- **Milestone B**:
  - [ ] Setup `npm/` platform package templates (`package.json` for each `@did0/binding-*`).
  - [ ] Create `.github/workflows/release.yml` with multi-platform matrix and npm provenance.
  - [ ] Add Docker smoke tests for Alpine (musl) and Debian (glibc).
- **Milestone C**:
  - [ ] Finalize npm credentials & tag `v0.1.0`.
  - [ ] Execute release and verify registry packages.
- **Milestone D**:
  - [ ] Publish benchmark report and launch ecosystem outreach.

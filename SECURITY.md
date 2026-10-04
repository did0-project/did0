# Security Policy

## Supported Versions

| Version | Supported          |
| :---    | :---               |
| 0.1.x   | :white_check_mark: |

---

## Cryptographic Guarantees & Threat Model

**did0** is designed for high-assurance DePIN infrastructure and edge hardware gateways. The core engine adheres to the following cryptographic invariants:

1. **Zero-Allocation Stack Execution**: All parsing, canonicalization, and SCALE serialization occur within fixed caller-allocated buffers on the stack (`FixedBufferAllocator`). No sensitive data is allocated on the heap where it might persist across garbage collection cycles.
2. **Memory Scrubbing**: Sensitive cryptographic buffers (including BIP-39 entropy, mnemonic buffers, PBKDF2 intermediate seeds, and Ed25519 mini-secrets) are zeroed using `std.crypto.secureZero` before stack frames exit.
3. **Constant-Time Verification**: Ed25519 signature checks leverage constant-time field arithmetic in Zig's standard cryptographic library to mitigate timing side-channel attacks.

---

## Reporting a Vulnerability

If you discover a security vulnerability within `did0`, please disclose it responsibly. **Do not open a public issue.**

Instead, please send an encrypted or private advisory email to:
- **Security Contact**: `security@did0.org` (or directly via GitHub Security Advisories)

### Please Include:
- A description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept (PoC).
- Affected version(s) and operating system / architecture details.

We commit to acknowledging your report within **48 hours** and providing regular progress updates until a patch is released.

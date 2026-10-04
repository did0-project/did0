# Contributing to did0

Thank you for your interest in contributing to **did0**! We welcome contributions that maintain our high performance, memory-safe, and zero-allocation standards.

---

## Prerequisites

- **Zig**: `0.16.0` or higher ([ziglang.org](https://ziglang.org/download/))
- **Node.js**: `v20.0.0` or higher
- **npm**: `v9.0.0` or higher

---

## Development Workflow

### 1. Fork & Clone
```bash
git clone https://github.com/kiruthikraaj/did0.git
cd did0
npm install
```

### 2. Building
```bash
# Build the native Node-API addon (ReleaseFast mode)
npm run build

# Build debug target
npm run build:debug

# Build CLI executable
zig build run
```

### 3. Running Tests
All pull requests must pass both the native Zig test suite and Node.js integration tests:
```bash
# Run all tests (Zig unit tests + Node.js integration tests)
npm test

# Run only native Zig test vectors
npm run test:unit

# Run only Node.js integration tests
npm run test:integration
```

### 4. Code Formatting
All Zig code must strictly follow standard formatting rules:
```bash
npm run format
```

### 5. Generating Documentation
```bash
zig build docs
```
Generated HTML documentation is output to `zig-out/docs/`.

---

## Design Principles to Maintain

When submitting contributions:
1. **Zero Heap Allocations on Hot Paths**: Functions should accept caller-provided buffers or explicit `std.mem.Allocator` instances. Do not use global allocators.
2. **Secure Zeroing**: Any scratch buffers containing private keys, seeds, or mnemonics must be cleared using `std.crypto.secureZero`.
3. **Cross-Platform Compatibility**: Ensure code compiles and tests pass on both macOS (`.dylib`) and Linux (`.so`).

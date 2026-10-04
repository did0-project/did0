# Contributing to did0

Thanks for your interest in did0. Bug reports, tests, docs and pull requests are all welcome. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## Prerequisites

- [Zig](https://ziglang.org/download/) 0.16.0
- Node.js 20+ and npm 9+

## Getting started

```bash
git clone https://github.com/did0-project/did0.git
cd did0
npm install
npm test
```

| Command | What it does |
| :--- | :--- |
| `npm run build` | Build the native addon (`ReleaseFast`) into `./did0.node` |
| `npm run build:debug` | Debug build |
| `npm run test:unit` | Zig unit tests (`zig build test`) |
| `npm run test:integration` | Node tests against the freshly built `./did0.node` |
| `npm test` | Build, then both of the above |
| `npm run format` | `zig fmt` |
| `npm run benchmark` | Micro-benchmarks (`node --expose-gc benchmark.js`) |
| `zig build run` | Run the CLI demo |

The integration tests set `DID0_BINDING_PATH=./did0.node`, so they always exercise the binary you just built even if an old `prebuilds/` directory exists.

## Guidelines

1. **Correctness over speed.** Anything that encodes bytes someone else will decode (SCALE, SS58, multibase, JCS, key derivation) needs a known-answer test taken from a specification, a reference implementation or a live chain, not only a round trip through our own code.
2. **No silent truncation or wrapping.** Inputs that do not fit a fixed buffer, or fall outside a numeric range, must produce an error.
3. **No heap allocation on hot paths.** Take caller-provided buffers or an explicit `std.mem.Allocator`; no global allocators.
4. **Wipe secrets.** Scratch buffers holding keys, seeds, entropy or mnemonics are cleared with `std.crypto.secureZero`.
5. **Be honest in docs.** Do not claim guarantees (memory isolation, constant time, audited, standard-compliant) the tests do not demonstrate.
6. **Cross-platform.** Code must build on macOS and Linux (glibc and musl).

Run `npm run format` and `npm test` before opening a pull request, and add an entry to `CHANGELOG.md` for user-visible changes.

## Releasing (maintainers)

1. Update the version in `package.json`, `package-lock.json` (`npm version <x.y.z> --no-git-tag-version`), `build.zig.zon` and the banner in `src/main.zig`; finalize the `CHANGELOG.md` entry.
2. Merge to `main` once CI is green.
3. Tag the merge commit `vX.Y.Z` and push the tag. The **Release Pipeline** workflow then tests, cross-compiles all six targets, creates a GitHub release with checksums, publishes the `@did0/binding-*` packages, links them as `optionalDependencies`, and publishes `@did0/core` with npm provenance. The tag must match `package.json`; the workflow refuses to publish otherwise.
4. npm versions are immutable: a published version can never be re-published, so fix problems with a new patch version.

The repository needs an `NPM_TOKEN` Actions secret with publish rights to the `@did0` scope.

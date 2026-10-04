#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const PREBUILDS_DIR = path.join(ROOT_DIR, 'prebuilds');

const TARGETS = [
  {
    id: 'darwin-arm64',
    zigTarget: 'aarch64-macos',
    libExt: 'dylib',
    artifactName: 'did0.darwin-arm64.node',
    pkgName: '@did0/binding-darwin-arm64',
    os: ['darwin'],
    cpu: ['arm64'],
  },
  {
    id: 'darwin-x64',
    zigTarget: 'x86_64-macos',
    libExt: 'dylib',
    artifactName: 'did0.darwin-x64.node',
    pkgName: '@did0/binding-darwin-x64',
    os: ['darwin'],
    cpu: ['x64'],
  },
  {
    id: 'linux-x64-gnu',
    zigTarget: 'x86_64-linux-gnu',
    libExt: 'so',
    artifactName: 'did0.linux-x64-gnu.node',
    pkgName: '@did0/binding-linux-x64-gnu',
    os: ['linux'],
    cpu: ['x64'],
  },
  {
    id: 'linux-x64-musl',
    zigTarget: 'x86_64-linux-musl',
    libExt: 'so',
    artifactName: 'did0.linux-x64-musl.node',
    pkgName: '@did0/binding-linux-x64-musl',
    os: ['linux'],
    cpu: ['x64'],
  },
  {
    id: 'linux-arm64-gnu',
    zigTarget: 'aarch64-linux-gnu',
    libExt: 'so',
    artifactName: 'did0.linux-arm64-gnu.node',
    pkgName: '@did0/binding-linux-arm64-gnu',
    os: ['linux'],
    cpu: ['arm64'],
  },
  {
    id: 'linux-arm64-musl',
    zigTarget: 'aarch64-linux-musl',
    libExt: 'so',
    artifactName: 'did0.linux-arm64-musl.node',
    pkgName: '@did0/binding-linux-arm64-musl',
    os: ['linux'],
    cpu: ['arm64'],
  },
];

function buildTarget(target, optimize = 'ReleaseFast') {
  console.log(`\n🔨 Building target: ${target.id} (${target.zigTarget}, ${optimize})...`);
  const cmd = `zig build addon -Dtarget=${target.zigTarget} -Doptimize=${optimize}`;
  execSync(cmd, { cwd: ROOT_DIR, stdio: 'inherit' });

  const builtLib = path.join(ROOT_DIR, 'zig-out', 'lib', `libdid0.${target.libExt}`);
  if (!fs.existsSync(builtLib)) {
    throw new Error(`Expected build artifact not found at ${builtLib}`);
  }

  // 1. Copy to prebuilds/ directory
  if (!fs.existsSync(PREBUILDS_DIR)) {
    fs.mkdirSync(PREBUILDS_DIR, { recursive: true });
  }
  const prebuildDest = path.join(PREBUILDS_DIR, target.artifactName);
  fs.copyFileSync(builtLib, prebuildDest);
  console.log(`✅ Staged artifact: ${path.relative(ROOT_DIR, prebuildDest)}`);

  // 2. If host matches target, also update local did0.node for instant development feedback
  const isHostDarwinArm64 = process.platform === 'darwin' && process.arch === 'arm64' && target.id === 'darwin-arm64';
  const isHostDarwinX64 = process.platform === 'darwin' && process.arch === 'x64' && target.id === 'darwin-x64';
  const isHostLinuxX64 = process.platform === 'linux' && process.arch === 'x64' && target.id === 'linux-x64-gnu';
  const isHostLinuxArm64 = process.platform === 'linux' && process.arch === 'arm64' && target.id === 'linux-arm64-gnu';

  if (isHostDarwinArm64 || isHostDarwinX64 || isHostLinuxX64 || isHostLinuxArm64) {
    const rootAddon = path.join(ROOT_DIR, 'did0.node');
    fs.copyFileSync(builtLib, rootAddon);
    console.log(`🔄 Synced local dev addon: did0.node`);
  }
}

function main() {
  const args = process.argv.slice(2);
  const targetFilter = args[0];

  if (!targetFilter || targetFilter === '--all') {
    console.log(`🚀 Starting hermetic build across all ${TARGETS.length} platform targets...`);
    for (const target of TARGETS) {
      buildTarget(target);
    }
  } else {
    const target = TARGETS.find((t) => t.id === targetFilter || t.zigTarget === targetFilter);
    if (!target) {
      console.error(`❌ Unknown target: "${targetFilter}". Valid targets are:\n  ${TARGETS.map((t) => t.id).join('\n  ')}`);
      process.exit(1);
    }
    buildTarget(target);
  }

  console.log('\n✨ Build process completed successfully.');
}

main();

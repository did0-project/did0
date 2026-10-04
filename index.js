// did0 - Enterprise W3C DID & DePIN Cryptographic Engine
// Dynamic Platform Binding Loader

const fs = require('fs');
const path = require('path');

function isMusl() {
  if (process.platform !== 'linux') return false;
  if (process.report && typeof process.report.getReport === 'function') {
    try {
      const header = process.report.getReport().header;
      if (header && header.glibcVersionRuntime) return false;
    } catch (_) {}
  }
  try {
    if (fs.existsSync('/etc/alpine-release')) return true;
    const ldd = require('child_process').execSync('ldd --version 2>&1').toString();
    return ldd.includes('musl');
  } catch (_) {
    return false;
  }
}

function loadNativeBinding() {
  const platform = process.platform;
  const arch = process.arch;
  const musl = isMusl();

  let pkgName = null;
  let prebuildName = null;

  switch (platform) {
    case 'darwin':
      if (arch === 'arm64') {
        pkgName = '@did0/binding-darwin-arm64';
        prebuildName = 'did0.darwin-arm64.node';
      } else if (arch === 'x64') {
        pkgName = '@did0/binding-darwin-x64';
        prebuildName = 'did0.darwin-x64.node';
      }
      break;

    case 'linux':
      if (arch === 'x64') {
        if (musl) {
          pkgName = '@did0/binding-linux-x64-musl';
          prebuildName = 'did0.linux-x64-musl.node';
        } else {
          pkgName = '@did0/binding-linux-x64-gnu';
          prebuildName = 'did0.linux-x64-gnu.node';
        }
      } else if (arch === 'arm64') {
        if (musl) {
          pkgName = '@did0/binding-linux-arm64-musl';
          prebuildName = 'did0.linux-arm64-musl.node';
        } else {
          pkgName = '@did0/binding-linux-arm64-gnu';
          prebuildName = 'did0.linux-arm64-gnu.node';
        }
      }
      break;

    default:
      break;
  }

  // 1. Try loading from platform optionalDependencies package
  if (pkgName) {
    try {
      return require(pkgName);
    } catch (e) {
      // Continue to local fallbacks
    }
  }

  // 2. Try loading from prebuilds/ directory
  if (prebuildName) {
    const prebuildPath = path.join(__dirname, 'prebuilds', prebuildName);
    if (fs.existsSync(prebuildPath)) {
      try {
        return require(prebuildPath);
      } catch (e) {
        // Continue to local dev fallback
      }
    }
  }

  // 3. Fallback to local root did0.node (built via `npm run build` or `zig build addon`)
  const localDevAddon = path.join(__dirname, 'did0.node');
  if (fs.existsSync(localDevAddon)) {
    try {
      return require(localDevAddon);
    } catch (e) {
      throw new Error(`[did0] Failed to load local native addon at ${localDevAddon}: ${e.message}`);
    }
  }

  // 4. Detailed diagnosis if no binary was found
  const detectedEnv = `${platform}-${arch}${musl ? '-musl' : (platform === 'linux' ? '-glibc' : '')}`;
  throw new Error(
    `[did0] Unsupported platform or missing native binary for environment "${detectedEnv}".\n` +
    (pkgName ? `Expected package "${pkgName}" was not installed (ensure --no-optional was not used).\n` : '') +
    `If developing locally, run "npm run build" to compile the native addon.`
  );
}

const did0 = loadNativeBinding();

function canonicalize(payload) {
  const jsonStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return did0.canonicalize(jsonStr);
}

function issueCredential(payload, privateKeyHex) {
  const jsonStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return did0.issueCredential(jsonStr, privateKeyHex);
}

function createWallet(options = {}) {
  const passphrase = options.passphrase || '';
  const mnemonic = options.mnemonic || '';
  return did0.createWallet(passphrase, mnemonic);
}

module.exports = {
  ...did0,
  canonicalize,
  issueCredential,
  createWallet,
};

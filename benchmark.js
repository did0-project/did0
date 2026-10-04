// benchmark.js: reproducible micro-benchmarks for every operation in the README table.
//
//   npm run build && node --expose-gc benchmark.js
//
// Each operation is timed after a warm-up. "Heap delta" is the change in V8 heapUsed measured
// across the timed loop after a forced GC; it only reflects the JavaScript heap, not native memory.
// Baselines use node:crypto (OpenSSL) and a small pure-JS reference so the numbers have context.

const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const did0 = require('./index.js');
const bs58 = require('bs58');
const b58encode = bs58.encode || bs58.default.encode;

const gc = typeof global.gc === 'function' ? global.gc : () => {};

function bench(name, iterations, fn) {
  for (let i = 0; i < Math.min(1000, iterations / 10); i++) fn(i);
  gc();
  const heapBefore = process.memoryUsage().heapUsed;
  const t0 = performance.now();
  for (let i = 0; i < iterations; i++) fn(i);
  const ms = performance.now() - t0;
  gc();
  const heapDelta = (process.memoryUsage().heapUsed - heapBefore) / 1024 / 1024;
  return { name, iterations, usPerOp: (ms * 1000) / iterations, opsPerSec: (iterations / ms) * 1000, heapDelta };
}

// --- fixtures -----------------------------------------------------------------------------------
const wallet = did0.createWallet();
const message = 'Device-001:Auth-Challenge:998877';
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const nodePub = 'z' + b58encode(Buffer.concat([Buffer.from([0xed, 1]), Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url')]));
const nodeSig = crypto.sign(null, Buffer.from(message), privateKey);
const nodeSigHex = nodeSig.toString('hex');

const didDoc = JSON.stringify({
  id: 'did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY',
  verificationMethod: [{
    id: 'did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY#keys-1',
    type: 'Ed25519VerificationKey2020',
    controller: 'did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY',
    publicKeyMultibase: wallet.publicKeyMultibase,
  }],
});

const credential = {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://peaq.network/credentials/depin/v1'],
  id: 'urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6',
  type: ['VerifiableCredential', 'DePINChargingReceipt'],
  issuer: wallet.did,
  issuanceDate: '2026-10-04T10:20:00Z',
  credentialSubject: { id: 'did:peaq:5DroneAutopilotDelta443322', energyDeliveredKWh: 14.85, sessionCompleted: true, stationId: 'peaq-station-eu-01' },
};
const credentialJson = JSON.stringify(credential);
const credentialSig = did0.issueCredential(credential, wallet.privateKeyHex);

function refCanonicalize(v) {
  if (Array.isArray(v)) return '[' + v.map(refCanonicalize).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + refCanonicalize(v[k])).join(',') + '}';
  return JSON.stringify(v);
}

const mnemonic = did0.generateMnemonic(12);
const N = 100_000;

console.log(`did0 benchmark on ${process.platform}/${process.arch}, Node ${process.version}${typeof global.gc === 'function' ? '' : ' (run with --expose-gc for heap numbers)'}\n`);

const results = [
  bench('parseDID', N, () => did0.parseDID(didDoc)),
  bench('JCS canonicalize (credential)', N, () => did0.canonicalize(credentialJson)),
  bench('JCS baseline: JSON.parse + sorted stringify (pure JS)', N, () => refCanonicalize(JSON.parse(credentialJson))),
  bench('SCALE encodeDidAttribute', N, () => did0.encodeDidAttribute(wallet.publicKeyHex, 'did/pubkey', wallet.did, 1_000_000)),
  bench('Ed25519 verifySignature', N, () => did0.verifySignature(nodePub, message, nodeSigHex)),
  bench('Ed25519 baseline: node:crypto verify (OpenSSL)', N, () => crypto.verify(null, Buffer.from(message), publicKey, nodeSig)),
  bench('issueCredential (JCS + SHA-256 + sign)', 20_000, () => did0.issueCredential(credential, wallet.privateKeyHex)),
  bench('verifyCredential', 20_000, () => did0.verifyCredential(credential, credentialSig, wallet.publicKeyMultibase)),
  bench('createWallet from mnemonic (PBKDF2 2048 rounds)', 500, () => did0.createWallet({ mnemonic })),
  bench('PBKDF2 baseline: node:crypto pbkdf2Sync', 500, () => crypto.pbkdf2Sync(mnemonic, 'mnemonic', 2048, 64, 'sha512')),
];

console.log('| Operation | Latency (µs) | Ops/sec | JS heap Δ (MB) |');
console.log('| :--- | ---: | ---: | ---: |');
for (const r of results) {
  console.log(`| ${r.name} | ${r.usPerOp.toFixed(2)} | ${Math.round(r.opsPerSec).toLocaleString('en-US')} | ${r.heapDelta.toFixed(2)} |`);
}

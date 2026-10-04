// benchmark.js
const did0 = require('./index.js');
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const bs58Module = require('bs58');
const encodeBase58 = bs58Module.encode || bs58Module.default.encode;

const ITERATIONS = 100_000;

// Setup cryptographic test data
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const jwk = publicKey.export({ format: 'jwk' });
const pubKeyBytes = Buffer.from(jwk.x, 'base64url');
const publicKeyMultibase = 'z' + encodeBase58(pubKeyBytes);

const message = "Device-001:Auth-Challenge:998877";
const signatureHex = crypto.sign(null, Buffer.from(message), privateKey).toString('hex');

const payload = JSON.stringify({
  id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
  verificationMethod: [
    {
      id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY#keys-1",
      type: "Ed25519VerificationKey2020",
      controller: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
      publicKeyMultibase: publicKeyMultibase
    }
  ]
});


console.log(`\n🚀 Starting did0 Stress Test: ${ITERATIONS.toLocaleString()} iterations\n`);

// --- 1. Memory-Safe Parsing Benchmark ---
const startMemParse = process.memoryUsage().heapUsed;
const startParse = performance.now();

for (let i = 0; i < ITERATIONS; i++) {
    did0.parseDID(payload);
}

const endParse = performance.now();
const endMemParse = process.memoryUsage().heapUsed;

console.log(`[1] N-API Parsing Throughput`);
console.log(`├─ Total Time : ${(endParse - startParse).toFixed(2)} ms`);
console.log(`├─ Speed      : ${((ITERATIONS / (endParse - startParse)) * 1000).toFixed(0)} ops/sec`);
console.log(`╰─ Heap Delta : ${((endMemParse - startMemParse) / 1024 / 1024).toFixed(2)} MB\n`);

// --- 2. Cryptographic Verification Benchmark ---
const startMemVerify = process.memoryUsage().heapUsed;
const startVerify = performance.now();

for (let i = 0; i < ITERATIONS; i++) {
    did0.verifySignature(publicKeyMultibase, message, signatureHex);
}

const endVerify = performance.now();
const endMemVerify = process.memoryUsage().heapUsed;

console.log(`[2] Native Ed25519 Verification`);
console.log(`├─ Total Time : ${(endVerify - startVerify).toFixed(2)} ms`);
console.log(`├─ Speed      : ${((ITERATIONS / (endVerify - startVerify)) * 1000).toFixed(0)} ops/sec`);
console.log(`╰─ Heap Delta : ${((endMemVerify - startMemVerify) / 1024 / 1024).toFixed(2)} MB\n`);

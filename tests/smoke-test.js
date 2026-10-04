/**
 * tests/smoke-test.js
 *
 * Standalone smoke test verifying that did0 loads the native binding properly
 * and executes primary W3C DID, Substrate SCALE, JCS, and BIP-39 cryptographic operations.
 */

const assert = require('assert');
const did0 = require('../index.js');

console.log('🧪 Starting did0 native engine smoke test...');

// 1. BIP-39 Keypair & Wallet Derivation
console.log('  Testing wallet derivation...');
const wallet = did0.createWallet();
assert.ok(wallet.did.startsWith('did:peaq:5'), 'DID must start with did:peaq:5');
assert.strictEqual(wallet.mnemonic.split(' ').length, 12, 'Default mnemonic should have 12 words');
assert.strictEqual(typeof wallet.publicKeyMultibase, 'string');
assert.ok(wallet.publicKeyMultibase.startsWith('z6Mk'), 'Multibase public key must be z6Mk...');
console.log(`  ✅ DID Generated: ${wallet.did}`);

// 2. RFC 8785 JSON Canonicalization Scheme (JCS)
console.log('  Testing RFC 8785 JCS canonicalization...');
const samplePayload = {
  b: 2,
  a: 1,
  nested: { y: true, x: false },
};
const canonical = did0.canonicalize(samplePayload);
assert.strictEqual(
  canonical,
  '{"a":1,"b":2,"nested":{"x":false,"y":true}}',
  'JCS must sort keys deterministically'
);
console.log('  ✅ Canonicalization verified');

// 3. Verifiable Credential Issuance & Signature Verification
console.log('  Testing credential issuance and Ed25519 signature verification...');
const credPayload = {
  id: wallet.did,
  type: ['VerifiableCredential', 'DePINDatePointCredential'],
  issuer: wallet.did,
  dataPoint: 42.195,
};
const sigHex = did0.issueCredential(credPayload, wallet.privateKeyHex);
assert.strictEqual(sigHex.length, 128, 'Ed25519 signature hex must be 128 characters');

const isValid = did0.verifyCredential(credPayload, sigHex, wallet.publicKeyMultibase);
assert.strictEqual(isValid, true, 'Cryptographic signature verification must succeed');
console.log('  ✅ Ed25519 signature successfully verified');

// 4. Substrate SCALE Codec
console.log('  Testing Substrate SCALE encoding...');
const callData = did0.encodeAddAttributeCall(
  10, // Pallet index
  1,  // Call index
  wallet.publicKeyHex,
  'peaq-did:telemetry',
  'ping',
  1000
);
assert.ok(Buffer.isBuffer(callData), 'SCALE output must be a Buffer');
assert.ok(callData.length > 32, 'SCALE extrinsic buffer should contain full call payload');
console.log(`  ✅ SCALE extrinsic call encoded (${callData.length} bytes)`);

console.log('\n✨ All smoke tests passed successfully!');

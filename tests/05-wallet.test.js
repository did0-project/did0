const assert = require('node:assert');
const test = require('node:test');
const did0 = require('../index.js');

test('Phase 4: BIP-39 Mnemonic Generation & Validation', () => {
  const mnemonic12 = did0.generateMnemonic(12);
  assert.strictEqual(mnemonic12.split(' ').length, 12, "Should generate 12 words");
  assert.strictEqual(did0.validateMnemonic(mnemonic12), true, "12-word mnemonic must be valid");

  const mnemonic24 = did0.generateMnemonic(24);
  assert.strictEqual(mnemonic24.split(' ').length, 24, "Should generate 24 words");
  assert.strictEqual(did0.validateMnemonic(mnemonic24), true, "24-word mnemonic must be valid");

  const corrupted = mnemonic12.split(' ').slice(0, 11).join(' ') + " abandon";
  assert.strictEqual(did0.validateMnemonic(corrupted), false, "Corrupted checksum must fail validation");
  assert.strictEqual(did0.validateMnemonic("notaword in the list"), false, "Invalid vocabulary must fail validation");
});

test('Phase 4: BIP-39 Official Reference Vector 1 Seed Derivation', () => {
  const vector1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  assert.strictEqual(did0.validateMnemonic(vector1), true, "Vector 1 mnemonic must be valid");

  const wallet = did0.createWallet({ mnemonic: vector1, passphrase: "" });
  const expectedSeedPrefix = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1";

  assert.strictEqual(
    wallet.seedHex.slice(0, 64),
    expectedSeedPrefix,
    "Master seed prefix must match official BIP-39 vector"
  );
  assert.strictEqual(wallet.ss58Address.startsWith("5"), true, "SS58 address must start with '5'");
  assert.strictEqual(wallet.did, "did:peaq:" + wallet.ss58Address, "DID must format as did:peaq:<ss58Address>");
});

test('Phase 4: Full Cross-Phase End-to-End DePIN Lifecycle Integration', () => {
  // Step 1: Wallet generation
  const wallet = did0.createWallet();
  assert.ok(wallet.did.startsWith("did:peaq:5"));
  assert.ok(wallet.publicKeyMultibase.startsWith("z"));

  // Step 2: Sign Verifiable Credential
  const credential = {
    type: ["VerifiableCredential", "DePINGatewayHeartbeat"],
    issuer: wallet.did,
    issuanceDate: "2026-10-04T10:20:00Z",
    credentialSubject: {
      id: wallet.did,
      uptimeSeconds: 86400,
      activeSensors: 8
    }
  };
  const sigHex = did0.issueCredential(credential, wallet.privateKeyHex);

  // Step 3: Verify signature using derived multibase public key
  const canonical = did0.canonicalize(credential);
  const isValid = did0.verifySignature(wallet.publicKeyMultibase, canonical, sigHex);
  assert.strictEqual(isValid, true, "Signature must verify using derived multibase public key");

  // Step 4: Format Substrate SCALE attribute
  const scaleAttr = did0.encodeDidAttribute(wallet.publicKeyHex, "did/pubkey", wallet.did, 5000000);
  assert.ok(Buffer.isBuffer(scaleAttr));
  assert.strictEqual(scaleAttr.subarray(0, 32).toString('hex'), wallet.publicKeyHex);
});

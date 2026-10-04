import test from 'node:test';
import assert from 'node:assert';
import did0Default, { createWallet, canonicalize, issueCredential, parseDID, verifySignature, verifyDigestSignature, verifyCredential } from '../index.mjs';

test('ESM: Named and default exports operate seamlessly', () => {
  assert.ok(typeof did0Default.createWallet === 'function');
  assert.ok(typeof createWallet === 'function');
  assert.ok(typeof canonicalize === 'function');
  assert.ok(typeof issueCredential === 'function');
  assert.ok(typeof parseDID === 'function');
  assert.ok(typeof verifySignature === 'function');
  assert.ok(typeof verifyDigestSignature === 'function');
  assert.ok(typeof verifyCredential === 'function');

  const wallet = createWallet();
  assert.ok(wallet.did.startsWith('did:peaq:5'), 'DID should start with did:peaq:5');
  assert.strictEqual(wallet.mnemonic.split(' ').length, 12, 'Default mnemonic should have 12 words');
  assert.strictEqual(typeof wallet.publicKeyMultibase, 'string');
});

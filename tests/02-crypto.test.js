const assert = require('node:assert');
const test = require('node:test');
const did0 = require('../index.js');

test('Phase 1: Native Ed25519 Cryptographic Verification', () => {
  const publicKeyMultibase = "zE4gVRcdFo7JmQMQ8yTrBctGSc9md3qd64RiexQktDgCd";
  const message = "Device-001:Auth-Challenge:998877";
  const signatureHex = "8fa2f7ef4fc60ce01bfeb8c381e8eddef423440d9a5eee494b1ec0a3ed030b451651cde769700c65a155cd554f034621d803106f9e3914a360a47ae4eab3b00a";

  const isValid = did0.verifySignature(publicKeyMultibase, message, signatureHex);
  assert.strictEqual(isValid, true, "Signature must be cryptographically valid for authentic message");

  const tamperedMessage = "Device-001:Auth-Challenge:998878";
  const isTamperedValid = did0.verifySignature(publicKeyMultibase, tamperedMessage, signatureHex);
  assert.strictEqual(isTamperedValid, false, "Signature must fail verification for tampered message");
});

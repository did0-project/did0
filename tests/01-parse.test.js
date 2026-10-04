const assert = require('node:assert');
const test = require('node:test');
const did0 = require('../index.js');

test('Phase 1: W3C DID Document Parsing', () => {
  const payload = JSON.stringify({
    id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    verificationMethod: [
      {
        id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY#keys-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        publicKeyMultibase: "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
      }
    ]
  });

  const parsed = did0.parseDID(payload);

  assert.ok(parsed, "Result should not be null or undefined");
  assert.strictEqual(
    parsed.id,
    "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    "DID subject must match input"
  );
  assert.strictEqual(
    parsed.publicKeyMultibase,
    "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
    "Multibase public key must match input"
  );
});

test('Phase 1: DID parsing rejects malformed input', () => {
  assert.throws(() => did0.parseDID('not json'), /Failed to parse/);
  assert.throws(() => did0.parseDID('{}'), /Failed to parse/, 'id is required');
  assert.throws(() => did0.parseDID('{"id":'), /Failed to parse/);
  assert.throws(() => did0.parseDID(JSON.stringify({ id: 'did:peaq:' + 'a'.repeat(5000) })), /at most 4095/);
  assert.throws(() => did0.parseDID(), /Expected/);
  assert.throws(() => did0.parseDID(123), /at most 4095|JSON string/);
});

test('Phase 1: DID parsing tolerates unknown fields and absent keys', () => {
  const parsed = did0.parseDID(JSON.stringify({ id: 'did:peaq:5abc', '@context': ['x'], extra: { deep: [1, 2] } }));
  assert.strictEqual(parsed.id, 'did:peaq:5abc');
  assert.strictEqual('publicKeyMultibase' in parsed, false);
});

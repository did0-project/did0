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

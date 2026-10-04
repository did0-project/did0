const assert = require('node:assert');
const test = require('node:test');
const did0 = require('../index.js');

test('Phase 2: Substrate SCALE Encoding for peaq DID attributes and calls', () => {
  const didAccountHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const name = "peaq-did-doc";
  const value = JSON.stringify({
    id: "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    pubKey: "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  });
  const validity = 1000000;

  // 1. Test Attribute Encoding
  const encodedAttribute = did0.encodeDidAttribute(didAccountHex, name, value, validity);
  assert.ok(Buffer.isBuffer(encodedAttribute), "Attribute result must be a Node.js Buffer");
  assert.strictEqual(
    encodedAttribute.subarray(0, 32).toString('hex'),
    didAccountHex,
    "First 32 bytes must match the AccountId"
  );

  // 2. Test Call Extrinsic Encoding
  const palletIndex = 12;
  const callIndex = 0;
  const encodedCall = did0.encodeAddAttributeCall(palletIndex, callIndex, didAccountHex, name, value, validity);

  assert.ok(Buffer.isBuffer(encodedCall), "Call result must be a Node.js Buffer");
  assert.strictEqual(encodedCall[0], palletIndex, "Byte 0 must be palletIndex");
  assert.strictEqual(encodedCall[1], callIndex, "Byte 1 must be callIndex");
  assert.strictEqual(
    encodedCall.subarray(2, 34).toString('hex'),
    didAccountHex,
    "Bytes 2..34 must match AccountId"
  );
  assert.strictEqual(
    encodedCall.length,
    encodedAttribute.length + 2,
    "Call length must be attribute length + 2 (palletIndex + callIndex)"
  );

  // 3. Test Update Attribute Call
  const encodedUpdate = did0.encodeUpdateAttributeCall(palletIndex, 1, didAccountHex, name, value, validity);
  assert.ok(Buffer.isBuffer(encodedUpdate), "Update call must be a Node.js Buffer");
  assert.strictEqual(encodedUpdate[0], palletIndex);
  assert.strictEqual(encodedUpdate[1], 1);

  // 4. Test Remove Attribute Call
  const encodedRemove = did0.encodeRemoveAttributeCall(palletIndex, 2, didAccountHex, name);
  assert.ok(Buffer.isBuffer(encodedRemove), "Remove call must be a Node.js Buffer");
  assert.strictEqual(encodedRemove[0], palletIndex);
  assert.strictEqual(encodedRemove[1], 2);
  assert.strictEqual(encodedRemove.subarray(2, 34).toString('hex'), didAccountHex);
});

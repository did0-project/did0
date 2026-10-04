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

test('Phase 2: validity is an Option<u32> matching the peaq-did pallet (valid_for)', () => {
  const account = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  // name "n" and value "v" are compact-length-prefixed: 0x04 'n', 0x04 'v'
  const none = did0.encodeDidAttribute(account, 'n', 'v', null);
  assert.strictEqual(none.subarray(32).toString('hex'), '046e' + '0476' + '00');
  assert.strictEqual(did0.encodeDidAttribute(account, 'n', 'v', undefined).toString('hex'), none.toString('hex'));

  // Some(1_000_000) = 0x01 ++ 0x000f4240 little-endian
  const some = did0.encodeDidAttribute(account, 'n', 'v', 1_000_000);
  assert.strictEqual(some.subarray(32).toString('hex'), '046e' + '0476' + '01' + '40420f00');

  // Some(0) is distinct from None
  assert.strictEqual(did0.encodeDidAttribute(account, 'n', 'v', 0).subarray(32).toString('hex'), '046e04760100000000');
});

test('Phase 2: SCALE compact length boundaries', () => {
  const account = "00".repeat(32);
  // single-byte mode: len 63 -> prefix 0xfc; two-byte mode: len 64 -> 0x0101
  const v63 = did0.encodeDidAttribute(account, 'n', 'a'.repeat(63), null);
  assert.strictEqual(v63[32 + 2], 0xfc);
  const v64 = did0.encodeDidAttribute(account, 'n', 'a'.repeat(64), null);
  assert.deepStrictEqual([...v64.subarray(34, 36)], [0x01, 0x01]);
});

test('Phase 2: invalid arguments are rejected instead of truncated or wrapped', () => {
  const account = "00".repeat(32);
  const call = (...a) => did0.encodeAddAttributeCall(...a);

  assert.throws(() => call(256, 0, account, 'n', 'v', 1), /palletIndex/);
  assert.throws(() => call(-1, 0, account, 'n', 'v', 1), /palletIndex/);
  assert.throws(() => call(1.5, 0, account, 'n', 'v', 1), /palletIndex/);
  assert.throws(() => call(1, 256, account, 'n', 'v', 1), /callIndex/);
  assert.throws(() => call(1, 0, account, 'n', 'v', -1), /validityBlocks/);
  assert.throws(() => call(1, 0, account, 'n', 'v', 2 ** 32), /validityBlocks/);
  assert.throws(() => call(1, 0, account, 'n', 'v', 'soon'), /validityBlocks/);
  assert.throws(() => call(1, 0, 'zz'.repeat(32), 'n', 'v', 1), /Account ID/);
  assert.throws(() => call(1, 0, '00'.repeat(31), 'n', 'v', 1), /Account ID/);
  assert.throws(() => call(1, 0, account, 'n'.repeat(256), 'v', 1), /name/);
  assert.throws(() => call(1, 0, account, 'n', 'v'.repeat(8192), 1), /value/);
  assert.throws(() => call(1, 0, account, 5, 'v', 1), /name/);
  assert.throws(() => did0.encodeRemoveAttributeCall(1, 3, account, 'n'.repeat(256)), /name/);

  // Boundary values that must succeed
  assert.ok(call(255, 255, account, 'n'.repeat(255), 'v'.repeat(8191), 2 ** 32 - 1));
});

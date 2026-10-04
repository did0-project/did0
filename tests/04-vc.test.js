const assert = require('node:assert');
const test = require('node:test');
const did0 = require('../index.js');

test('Phase 3: RFC 8785 JSON Canonicalization Scheme (JCS) Vectors', () => {
  // Test Vector A: Primitives, Floats, Escapes, and Whitespace Removal (RFC 8785 §3.2.2 & §3.2.3)
  const vectorA_input = JSON.stringify({
    numbers: [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
    string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\\\"\/",
    literals: [null, true, false]
  });
  
  const vectorA_expected = String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\\\"/"}`;
  const vectorA_result = did0.canonicalize(vectorA_input);
  assert.strictEqual(vectorA_result, vectorA_expected, "RFC 8785 Vector A must match expected canonical serialization");
  console.log("✔ RFC 8785 Vector A (Primitives & Escapes): PASSED");
  
  // Test Vector B: UTF-16 Code Unit Property Key Sorting (RFC 8785 §3.2.3)
  const vectorB_input = {
    "\u20ac": "Euro Sign",
    "\r": "Carriage Return",
    "\ufb33": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "\ud83d\ude00": "Emoji: Grinning Face",
    "\u0080": "Control",
    "\u00f6": "Latin Small Letter O With Diaeresis"
  };
  
  const vectorB_expected = String.raw`{"\r":"Carriage Return","1":"One","` + "\u0080" + String.raw`":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}`;
  const vectorB_result = did0.canonicalize(vectorB_input);
  assert.strictEqual(vectorB_result, vectorB_expected, "RFC 8785 Vector B must sort keys according to UTF-16 code units");
  console.log("✔ RFC 8785 Vector B (UTF-16 Code Unit Sorting): PASSED\n");
});

test('Phase 3: W3C Verifiable Credential Issuance & Verification', () => {
  const stationWallet = did0.createWallet();

  const credential = {
    type: ["VerifiableCredential", "DePINChargingReceipt"],
    issuanceDate: "2026-10-03T03:50:00Z",
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://peaq.network/credentials/depin/v1"
    ],
    id: "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
    issuer: stationWallet.did,
    credentialSubject: {
      stationId: "peaq-station-eu-berlin-04",
      batteryFinalPercent: 95,
      energyDeliveredKWh: 14.85,
      batteryInitialPercent: 12,
      id: "did:peaq:5DroneAutopilotDelta443322",
      chargingDurationMinutes: 28,
      sessionCompleted: true,
      maxChargingPowerKW: 50.0
    }
  };

  // Sign Credential
  const sigHex = did0.issueCredential(credential, stationWallet.privateKeyHex);
  assert.strictEqual(sigHex.length, 128, "Signature must be 128 hex chars (64 bytes)");

  // Verify Credential
  assert.strictEqual(did0.verifyCredential(credential, sigHex, stationWallet.publicKeyMultibase), true,
    "Credential signature must verify against station public key");

  // Key order in the input must not matter (JCS canonicalizes before hashing)
  const reordered = Object.fromEntries(Object.entries(credential).reverse());
  assert.strictEqual(did0.verifyCredential(reordered, sigHex, stationWallet.publicKeyMultibase), true);

  // Tamper detection
  const tampered = { ...credential, credentialSubject: { ...credential.credentialSubject, energyDeliveredKWh: 148.5 } };
  assert.strictEqual(did0.verifyCredential(tampered, sigHex, stationWallet.publicKeyMultibase), false,
    "Tampered credential payload must fail verification");

  // Wrong key
  const other = did0.createWallet();
  assert.strictEqual(did0.verifyCredential(credential, sigHex, other.publicKeyMultibase), false);

  // A credential signature is over the SHA-256 digest, so raw verification must reject it
  assert.strictEqual(
    did0.verifySignature(stationWallet.publicKeyMultibase, did0.canonicalize(credential), sigHex),
    false,
    "Raw verification must not accept a digest signature"
  );
});

test('Phase 3: issueCredential accepts documented key formats and rejects bad ones', () => {
  const wallet = did0.createWallet();
  const payload = { a: 1 };
  const seed = Buffer.from(wallet.privateKeyHex, 'hex');
  const pub = Buffer.from(wallet.publicKeyHex, 'hex');
  const b58 = require('bs58');
  const enc = b58.encode || b58.default.encode;

  const reference = did0.issueCredential(payload, wallet.privateKeyHex);
  assert.strictEqual(did0.issueCredential(payload, Buffer.concat([seed, pub]).toString('hex')), reference, '128-char hex');
  assert.strictEqual(did0.issueCredential(payload, enc(seed)), reference, 'base58 seed');
  assert.strictEqual(did0.issueCredential(payload, 'z' + enc(seed)), reference, 'z-prefixed base58 seed');
  assert.strictEqual(did0.issueCredential(payload, enc(Buffer.concat([seed, pub]))), reference, 'base58 seed+pub');

  for (const bad of ['', 'abcd', 'g'.repeat(64), '0'.repeat(63), 'z' + enc(Buffer.alloc(31, 1))]) {
    assert.throws(() => did0.issueCredential(payload, bad), /ERR_|private key|Expected/i, `rejects ${JSON.stringify(bad)}`);
  }
  assert.throws(() => did0.issueCredential(payload, 12345), /private key/i);
});

test('Phase 3: canonicalize rejects malformed and oversize payloads', () => {
  for (const bad of [
    '', '{', '{"a":}', '[1,]', '{"a":1,}', '[,1]', '[1 2]', 'nope', '{"a":1} trailing', '{"a":NaN}', "{'a':1}",
    '[01]', '[1.]', '[.5]', '[+1]', '[1e]', '[-]', '[--1]', '[1e999]', '[0x10]',
    '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '"unterminated', '"raw\ttab"', '"\\ud800"', '"\\udc00x"', '"\\x"',
  ]) {
    assert.throws(() => did0.canonicalize(bad), undefined, `rejects ${JSON.stringify(bad)}`);
  }
  assert.throws(() => did0.canonicalize('"' + 'x'.repeat(70000) + '"'), /JSON string or object/);

  // Deep nesting must produce an error, not exhaust the native stack
  assert.throws(() => did0.canonicalize('['.repeat(20000) + ']'.repeat(20000)), /TooDeep/);
  assert.throws(() => did0.canonicalize('{"a":'.repeat(5000) + '1' + '}'.repeat(5000)), /TooDeep/);
  const ok = '['.repeat(100) + ']'.repeat(100);
  assert.strictEqual(did0.canonicalize(ok), ok);
  assert.throws(() => did0.canonicalize(undefined), /JSON string or object|Expected/);
});

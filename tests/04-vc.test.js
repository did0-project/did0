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
  const canonicalVC = did0.canonicalize(credential);
  const isValid = did0.verifySignature(stationWallet.publicKeyMultibase, canonicalVC, sigHex);
  assert.strictEqual(isValid, true, "Credential signature must verify against station public key");

  // Tamper detection
  const tamperedVC = canonicalVC.replace("14.85", "148.50");
  const isTamperedValid = did0.verifySignature(stationWallet.publicKeyMultibase, tamperedVC, sigHex);
  assert.strictEqual(isTamperedValid, false, "Tampered credential payload must fail verification");
});

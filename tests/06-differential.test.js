// Differential tests: native output is compared against independent JS oracles.
const assert = require('node:assert');
const test = require('node:test');
const crypto = require('node:crypto');
const did0 = require('../index.js');

// Deterministic PRNG so failures are reproducible
function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Reference JCS: sort keys by UTF-16 code units (default JS string order) and use
// JSON.stringify, whose number/string formatting is what RFC 8785 specifies (ES6 / ECMA-404).
function refCanonicalize(v) {
  if (Array.isArray(v)) return '[' + v.map(refCanonicalize).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + refCanonicalize(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

test('JCS numbers: random doubles serialize exactly like ECMAScript Number-to-string', () => {
  const r = rng(1);
  const buf = Buffer.alloc(8);
  let checked = 0;
  for (let i = 0; i < 20000; i++) {
    for (let j = 0; j < 8; j++) buf[j] = Math.floor(r() * 256);
    const n = buf.readDoubleLE(0);
    if (!Number.isFinite(n)) continue;
    const input = `[${n}]`;
    assert.strictEqual(did0.canonicalize(input), JSON.stringify([n]), `number ${n}`);
    checked++;
  }
  assert.ok(checked > 19000);
});

test('JCS numbers: edge values and RFC 8785 Appendix B samples', () => {
  const cases = {
    '0': '0', '-0': '0', '1': '1', '-1': '-1', '0.5': '0.5', '1e21': '1e+21', '1e-7': '1e-7', '123456789012345680000': '123456789012345680000',
    '9007199254740991': '9007199254740991', '9007199254740992': '9007199254740992', '5e-324': '5e-324',
    '1.7976931348623157e308': '1.7976931348623157e+308', '0.000001': '0.000001', '4.5': '4.5', '100': '100', '1E2': '100',
    '333333333.33333329': '333333333.3333333', '2e-3': '0.002',
  };
  for (const [input, expected] of Object.entries(cases)) {
    assert.strictEqual(did0.canonicalize(`[${input}]`), `[${expected}]`, input);
  }
});

function randomString(r) {
  const pool = ['a', 'b', 'Z', '0', ' ', '"', '\\', '/', '\n', '\t', '\u0001', '\u001f', '\u007f', '\u0080', 'é', 'ö', '€', 'דּ', '\u{1F600}', '\u{10000}', '퟿', ''];
  let out = '';
  const len = Math.floor(r() * 6);
  for (let i = 0; i < len; i++) out += pool[Math.floor(r() * pool.length)];
  return out;
}

function randomValue(r, depth) {
  const k = Math.floor(r() * (depth > 3 ? 5 : 7));
  switch (k) {
    case 0: return null;
    case 1: return r() < 0.5;
    case 2: return Math.floor((r() - 0.5) * 2e6);
    case 3: return (r() - 0.5) * 10 ** Math.floor(r() * 30 - 10);
    case 4: return randomString(r);
    case 5: return Array.from({ length: Math.floor(r() * 4) }, () => randomValue(r, depth + 1));
    default: {
      const o = {};
      const n = Math.floor(r() * 5);
      for (let i = 0; i < n; i++) o[randomString(r)] = randomValue(r, depth + 1);
      return o;
    }
  }
}

test('JCS: 3000 random documents match the reference canonicalizer and are idempotent', () => {
  const r = rng(42);
  for (let i = 0; i < 3000; i++) {
    const doc = randomValue(r, 0);
    const text = JSON.stringify(doc, null, i % 2 ? 2 : 0);
    const expected = refCanonicalize(JSON.parse(text));
    const actual = did0.canonicalize(text);
    assert.strictEqual(actual, expected, `doc #${i}: ${text}`);
    assert.strictEqual(did0.canonicalize(actual), actual, 'idempotent');
  }
});

test('JCS: escaped input forms normalize to the same canonical output', () => {
  assert.strictEqual(did0.canonicalize('{"\\u0061":"\\u00e9\\ud83d\\ude00","b":"\\/"}'), '{"a":"é😀","b":"/"}');
  assert.strictEqual(did0.canonicalize('["\\u007f","\\u0000"]'), JSON.stringify(['\u007f', '\u0000']));
  assert.strictEqual(did0.canonicalize('  { "b" : [ 1 , 2 ] ,\n "a" : { } }  '), '{"a":{},"b":[1,2]}');
});

test('Wallet: 50 random mnemonics round-trip through validation and derive stable accounts', () => {
  for (let i = 0; i < 50; i++) {
    const m = did0.generateMnemonic(i % 2 ? 24 : 12);
    assert.ok(did0.validateMnemonic(m));
    // Swapping two distinct words breaks the checksum most of the time; a mutated word list must
    // never crash and, when it validates, must derive a (different) wallet without error.
    const words = m.split(' ');
    words[0] = words[0] === 'zoo' ? 'abandon' : 'zoo';
    const mutated = words.join(' ');
    if (did0.validateMnemonic(mutated)) assert.notStrictEqual(did0.createWallet({ mnemonic: mutated }).did, did0.createWallet({ mnemonic: m }).did);
    else assert.throws(() => did0.createWallet({ mnemonic: mutated }), /InvalidChecksum/);
  }
});

test('Credentials: sign/verify round-trips for random documents, tampering is detected', () => {
  const r = rng(7);
  const w = did0.createWallet();
  for (let i = 0; i < 200; i++) {
    const doc = { id: `urn:uuid:${i}`, data: randomValue(r, 0) };
    const sig = did0.issueCredential(doc, w.privateKeyHex);
    assert.strictEqual(did0.verifyCredential(doc, sig, w.publicKeyMultibase), true);
    assert.strictEqual(did0.verifyCredential({ ...doc, id: doc.id + 'x' }, sig, w.publicKeyMultibase), false);

    // Cross-check against node:crypto using the documented scheme: Ed25519 over SHA-256(JCS(doc))
    const digest = crypto.createHash('sha256').update(refCanonicalize(JSON.parse(JSON.stringify(doc)))).digest();
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(w.publicKeyHex, 'hex')]);
    const key = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    assert.strictEqual(crypto.verify(null, digest, key, Buffer.from(sig, 'hex')), true);
  }
});

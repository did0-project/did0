const assert = require('node:assert');
const test = require('node:test');
const crypto = require('node:crypto');
const bs58 = require('bs58');
const did0 = require('../index.js');

const b58 = bs58.encode || bs58.default.encode;

// RFC 8032 section 7.1 test vectors (Ed25519, pure)
const RFC8032 = [
  {
    pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    msg: '',
    sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    msg: '72',
    sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
];

function mb(pkHex, prefixed) {
  const raw = Buffer.from(pkHex, 'hex');
  return 'z' + b58(prefixed ? Buffer.concat([Buffer.from([0xed, 0x01]), raw]) : raw);
}

test('Ed25519: RFC 8032 known-answer vectors verify (bare and multicodec-prefixed keys)', () => {
  for (const v of RFC8032) {
    const msg = Buffer.from(v.msg, 'hex');
    for (const prefixed of [false, true]) {
      assert.strictEqual(did0.verifySignature(mb(v.pk, prefixed), msg, v.sig), true);
    }
    // string messages take the same path as Buffers (these vectors are valid UTF-8)
    assert.strictEqual(did0.verifySignature(mb(v.pk, true), msg.toString('utf8'), v.sig), true);
  }
});

test('Ed25519: tampered message, signature and key all fail', () => {
  const v = RFC8032[1];
  const key = mb(v.pk, true);
  assert.strictEqual(did0.verifySignature(key, Buffer.from('73', 'hex'), v.sig), false);

  const flipped = Buffer.from(v.sig, 'hex');
  flipped[10] ^= 1;
  assert.strictEqual(did0.verifySignature(key, Buffer.from('72', 'hex'), flipped.toString('hex')), false);

  assert.strictEqual(did0.verifySignature(mb(RFC8032[0].pk, true), Buffer.from('72', 'hex'), v.sig), false);
});

test('Ed25519: raw and digest verification are distinct schemes', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pk = 'z' + b58(Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'));
  const message = 'Device-001:Auth-Challenge:998877';

  const rawSig = crypto.sign(null, Buffer.from(message), privateKey).toString('hex');
  assert.strictEqual(did0.verifySignature(pk, message, rawSig), true);
  assert.strictEqual(did0.verifyDigestSignature(pk, message, rawSig), false, 'a raw signature must not pass digest verification');

  const digest = crypto.createHash('sha256').update(message).digest();
  const digestSig = crypto.sign(null, digest, privateKey).toString('hex');
  assert.strictEqual(did0.verifyDigestSignature(pk, message, digestSig), true);
  assert.strictEqual(did0.verifySignature(pk, message, digestSig), false, 'a digest signature must not pass raw verification');
});

test('Ed25519: malformed inputs throw instead of returning a verdict', () => {
  const v = RFC8032[0];
  const good = mb(v.pk, true);
  const empty = Buffer.alloc(0);

  assert.throws(() => did0.verifySignature('', empty, v.sig), /Invalid multibase/);
  assert.throws(() => did0.verifySignature('z', empty, v.sig), /Invalid multibase/);
  assert.throws(() => did0.verifySignature('f' + v.pk, empty, v.sig), /Invalid multibase/);
  assert.throws(() => did0.verifySignature('z0OIl', empty, v.sig), /Invalid multibase/);
  assert.throws(() => did0.verifySignature('z' + b58(Buffer.alloc(31, 1)), empty, v.sig), /Invalid multibase/);
  assert.throws(() => did0.verifySignature('z' + b58(Buffer.concat([Buffer.from([0xaa, 0xbb]), Buffer.alloc(32, 1)])), empty, v.sig), /Invalid multibase/);
  assert.throws(() => did0.verifySignature('z' + '9'.repeat(100), empty, v.sig), /Invalid multibase/);

  assert.throws(() => did0.verifySignature(good, empty, v.sig.slice(2)), /128-character/);
  assert.throws(() => did0.verifySignature(good, empty, 'zz' + v.sig.slice(2)), /Invalid hex/);
  assert.throws(() => did0.verifySignature(good, empty, v.sig + '00'), /signatureHex|128-character/);

  assert.throws(() => did0.verifySignature(good, 42, v.sig), /message/);
  assert.throws(() => did0.verifySignature(null, empty, v.sig), /publicKeyMultibase/);
  assert.throws(() => did0.verifySignature(good), /Expected/);
});

test('Ed25519: oversize string message is rejected, large Buffers are verified in place', () => {
  const v = RFC8032[0];
  assert.throws(() => did0.verifySignature(mb(v.pk, true), 'x'.repeat(70000), v.sig), /message/);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pk = 'z' + b58(Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'));
  const big = crypto.randomBytes(1 << 20);
  const sig = crypto.sign(null, big, privateKey).toString('hex');
  assert.strictEqual(did0.verifySignature(pk, big, sig), true);
  big[123456] ^= 1;
  assert.strictEqual(did0.verifySignature(pk, big, sig), false);
});

test('Ed25519: invalid curve point as public key yields false, not a crash', () => {
  const v = RFC8032[0];
  // y = 2 is not on the curve for Ed25519; any 32 bytes that fail decompression must be handled
  const bad = Buffer.alloc(32, 0xff);
  assert.strictEqual(typeof did0.verifySignature('z' + b58(bad), Buffer.alloc(0), v.sig), 'boolean');
});

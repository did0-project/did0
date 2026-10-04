const std = @import("std");
const did0 = @import("../did0.zig");
const base58 = @import("../base58.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub fn parse(allocator: std.mem.Allocator, payload: []const u8) !did0.Document {
    const parsed = try std.json.parseFromSlice(did0.Document, allocator, payload, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    });
    return parsed.value;
}

pub const PublicKeyError = error{
    InvalidMultibase,
    InvalidBase58Char,
    InvalidPublicKey,
};

/// Multicodec varint prefix for an Ed25519 public key (0xed 0x01).
pub const ed25519_multicodec = [2]u8{ 0xed, 0x01 };

/// Decodes a `z` (base58btc) multibase Ed25519 public key into its 32 raw bytes.
///
/// Accepts both the W3C `Ed25519VerificationKey2020` form (multicodec-prefixed, `z6Mk...`)
/// and the bare 32-byte form. Any other payload length is rejected.
pub fn decodePublicKey(multibase: []const u8) PublicKeyError![32]u8 {
    if (multibase.len < 2 or multibase[0] != 'z') return error.InvalidMultibase;

    var buf: [64]u8 = undefined;
    const decoded = base58.decode(&buf, multibase[1..]) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidBase58Char,
        error.BufferTooSmall => return error.InvalidPublicKey,
    };

    var key: [32]u8 = undefined;
    switch (decoded.len) {
        32 => @memcpy(&key, decoded),
        34 => {
            if (!std.mem.eql(u8, decoded[0..2], &ed25519_multicodec)) return error.InvalidPublicKey;
            @memcpy(&key, decoded[2..34]);
        },
        else => return error.InvalidPublicKey,
    }
    return key;
}

/// Encodes a 32-byte Ed25519 public key as a `z6Mk...` multibase string (multicodec-prefixed).
pub fn encodePublicKey(out: []u8, public_key: [32]u8) base58.Error![]const u8 {
    if (out.len < 1) return error.BufferTooSmall;
    var raw: [34]u8 = undefined;
    @memcpy(raw[0..2], &ed25519_multicodec);
    @memcpy(raw[2..], &public_key);
    out[0] = 'z';
    const b58 = try base58.encode(out[1..], &raw);
    return out[0 .. 1 + b58.len];
}

/// Verifies an Ed25519 signature over the raw `message` bytes.
pub fn verifySignature(public_key_bytes: [32]u8, signature: [64]u8, message: []const u8) !void {
    const pub_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
    const sig = Ed25519.Signature.fromBytes(signature);
    try sig.verify(message, pub_key);
}

/// Verifies an Ed25519 signature over SHA-256(`message`).
/// This is the scheme used by `jcs.signCanonical` for verifiable credentials.
pub fn verifyDigestSignature(public_key_bytes: [32]u8, signature: [64]u8, message: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
    return verifySignature(public_key_bytes, signature, &digest);
}

test "decodePublicKey accepts bare and multicodec-prefixed keys" {
    var alice: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&alice, "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");

    var mb_buf: [64]u8 = undefined;
    const prefixed = try encodePublicKey(&mb_buf, alice);
    try std.testing.expect(std.mem.startsWith(u8, prefixed, "z6Mk"));
    try std.testing.expectEqualSlices(u8, &alice, &(try decodePublicKey(prefixed)));

    var bare_buf: [64]u8 = undefined;
    bare_buf[0] = 'z';
    const b58 = try base58.encode(bare_buf[1..], &alice);
    try std.testing.expectEqualSlices(u8, &alice, &(try decodePublicKey(bare_buf[0 .. 1 + b58.len])));
}

test "decodePublicKey rejects malformed input" {
    try std.testing.expectError(error.InvalidMultibase, decodePublicKey(""));
    try std.testing.expectError(error.InvalidMultibase, decodePublicKey("z"));
    try std.testing.expectError(error.InvalidMultibase, decodePublicKey("uAAAA"));
    try std.testing.expectError(error.InvalidBase58Char, decodePublicKey("z0OIl"));
    // Too short, and far too long for a 32/34-byte key.
    try std.testing.expectError(error.InvalidPublicKey, decodePublicKey("z2g"));
    try std.testing.expectError(error.InvalidPublicKey, decodePublicKey("z" ++ "9" ** 80));
}

test "RFC 8032 test vector 1: raw verification only" {
    var pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    var sig: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    try verifySignature(pk, sig, "");
    try std.testing.expectError(error.SignatureVerificationFailed, verifySignature(pk, sig, "x"));
    // A raw signature must not be accepted as a digest signature.
    try std.testing.expectError(error.SignatureVerificationFailed, verifyDigestSignature(pk, sig, ""));
}

test "digest verification does not accept raw signatures over the digest bytes' preimage" {
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    const pk = kp.public_key.toBytes();
    const msg = "canonical-json";

    const raw_sig = (try kp.sign(msg, null)).toBytes();
    try verifySignature(pk, raw_sig, msg);
    try std.testing.expectError(error.SignatureVerificationFailed, verifyDigestSignature(pk, raw_sig, msg));

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
    const digest_sig = (try kp.sign(&digest, null)).toBytes();
    try verifyDigestSignature(pk, digest_sig, msg);
    try std.testing.expectError(error.SignatureVerificationFailed, verifySignature(pk, digest_sig, msg));
}

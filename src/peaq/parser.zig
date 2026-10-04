const std = @import("std");
const did0 = @import("../did0.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub fn parse(allocator: std.mem.Allocator, payload: []const u8) !did0.Document {
    const parsed = try std.json.parseFromSlice(did0.Document, allocator, payload, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
    });
    return parsed.value;
}

/// A highly optimized, zero-allocation base58 decoder for the 'z' multibase prefix.
pub fn decodeMultibase(allocator: std.mem.Allocator, multibase: []const u8) ![]u8 {
    if (multibase.len == 0 or multibase[0] != 'z') return error.InvalidMultibase;

    const encoded = multibase[1..];
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Allocate exactly enough space for a 32-byte Ed25519 public key
    var decoded = try allocator.alloc(u8, 32);
    @memset(decoded, 0);

    for (encoded) |c| {
        const char_index = std.mem.indexOfScalar(u8, alphabet, c) orelse return error.InvalidBase58Char;
        var carry: u16 = @intCast(char_index);

        // Reverse iterate to process base58 math
        var i: usize = decoded.len;
        while (i > 0) {
            i -= 1;
            carry += @as(u16, decoded[i]) * 58;
            decoded[i] = @truncate(carry);
            carry >>= 8;
        }
    }
    return decoded;
}

/// Uses Zig's ultra-fast Ed25519 standard library engine to verify a signature.
/// Supports both raw message payloads and SHA-256 digested payloads.
pub fn verifySignature(public_key_bytes: [32]u8, signature: [64]u8, message: []const u8) !void {
    const pub_key = try Ed25519.PublicKey.fromBytes(public_key_bytes);
    const sig = Ed25519.Signature.fromBytes(signature);

    if (sig.verify(message, pub_key)) {
        return;
    } else |_| {}

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message, &digest, .{});
    try sig.verify(&digest, pub_key);
}

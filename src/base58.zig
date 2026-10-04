//! Bitcoin-alphabet Base58 codec operating on caller-provided buffers (no heap).

const std = @import("std");

pub const Error = error{
    InvalidCharacter,
    BufferTooSmall,
};

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn digitValue(c: u8) ?u8 {
    const idx = std.mem.indexOfScalar(u8, alphabet, c) orelse return null;
    return @intCast(idx);
}

/// Encodes `bytes` into `out`, returning the used prefix. Leading zero bytes become '1'.
pub fn encode(out: []u8, bytes: []const u8) Error![]const u8 {
    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) : (zeros += 1) {}

    // Digits are accumulated little-endian directly in `out`, then reversed.
    var len: usize = 0;
    for (bytes[zeros..]) |byte| {
        var carry: u32 = byte;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            carry += @as(u32, out[zeros + i]) << 8;
            out[zeros + i] = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry != 0) {
            if (zeros + len >= out.len) return Error.BufferTooSmall;
            out[zeros + len] = @intCast(carry % 58);
            len += 1;
            carry /= 58;
        }
    }

    if (zeros + len > out.len) return Error.BufferTooSmall;

    std.mem.reverse(u8, out[zeros .. zeros + len]);
    for (out[zeros .. zeros + len]) |*d| d.* = alphabet[d.*];
    @memset(out[0..zeros], '1');
    return out[0 .. zeros + len];
}

/// Decodes `input` into `out`, returning the used prefix. Leading '1' characters become zero bytes.
/// Fails with `BufferTooSmall` if the decoded value does not fit (never truncates silently).
pub fn decode(out: []u8, input: []const u8) Error![]u8 {
    var zeros: usize = 0;
    while (zeros < input.len and input[zeros] == '1') : (zeros += 1) {}

    // Bytes are accumulated little-endian in out[0..len], then shifted behind the zero prefix.
    var len: usize = 0;
    for (input[zeros..]) |c| {
        var carry: u32 = digitValue(c) orelse return Error.InvalidCharacter;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            carry += @as(u32, out[i]) * 58;
            out[i] = @truncate(carry);
            carry >>= 8;
        }
        while (carry != 0) {
            if (len >= out.len) return Error.BufferTooSmall;
            out[len] = @truncate(carry);
            len += 1;
            carry >>= 8;
        }
    }

    if (zeros + len > out.len) return Error.BufferTooSmall;

    std.mem.reverse(u8, out[0..len]);
    std.mem.copyBackwards(u8, out[zeros .. zeros + len], out[0..len]);
    @memset(out[0..zeros], 0);
    return out[0 .. zeros + len];
}

test "base58 known vectors" {
    var buf: [64]u8 = undefined;

    try std.testing.expectEqualStrings("", try encode(&buf, ""));
    try std.testing.expectEqualStrings("2g", try encode(&buf, "a"));
    try std.testing.expectEqualStrings("StV1DL6CwTryKyV", try encode(&buf, "hello world"));
    try std.testing.expectEqualStrings("111", try encode(&buf, &[_]u8{ 0, 0, 0 }));
    try std.testing.expectEqualStrings("1112", try encode(&buf, &[_]u8{ 0, 0, 0, 1 }));
}

test "base58 round trip preserves leading zeros and rejects bad input" {
    var enc_buf: [64]u8 = undefined;
    var dec_buf: [64]u8 = undefined;

    const samples = [_][]const u8{
        &[_]u8{0},
        &[_]u8{ 0, 0, 1, 2, 3 },
        &[_]u8{ 0xff, 0xff, 0xff, 0xff },
        &([_]u8{0xed} ** 34),
    };
    for (samples) |sample| {
        const e = try encode(&enc_buf, sample);
        const d = try decode(&dec_buf, e);
        try std.testing.expectEqualSlices(u8, sample, d);
    }

    try std.testing.expectError(Error.InvalidCharacter, decode(&dec_buf, "0OIl"));

    var tiny: [2]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, decode(&tiny, "StV1DL6CwTryKyV"));
}

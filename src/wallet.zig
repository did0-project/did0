const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const bip39_words = @import("bip39_words.zig");

pub const Error = error{
    BufferTooSmall,
    InvalidEntropyLength,
    InvalidWordCount,
    UnknownWord,
    InvalidChecksum,
    WeakParameters,
    OutputTooLong,
    IdentityElement,
    NonCanonical,
    OutOfMemory,
};

/// Represents an enterprise DePIN wallet with native HD key derivation.
pub const Wallet = struct {
    mnemonic: []const u8,
    seed: [64]u8,
    private_key_hex: [64]u8,
    public_key_bytes: [32]u8,
    public_key_hex: [64]u8,
    public_key_multibase: []const u8,
    ss58_address: []const u8,
    did: []const u8,
};

// ----------------------------------------------------------------------------
// Base58 & Substrate SS58 Address Encoding
// ----------------------------------------------------------------------------

pub fn encodeBase58(out_buf: []u8, bytes: []const u8) Error![]const u8 {
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) : (zeros += 1) {}

    var digits: [128]u8 = undefined;
    @memset(&digits, 0);
    var digits_len: usize = 0;

    for (bytes[zeros..]) |byte| {
        var carry: u32 = byte;
        var j: usize = 0;
        while (j < digits_len or carry != 0) {
            if (j >= digits.len) return Error.BufferTooSmall;
            carry += @as(u32, digits[j]) * 256;
            digits[j] = @as(u8, @truncate(carry % 58));
            carry /= 58;
            j += 1;
        }
        if (j > digits_len) digits_len = j;
    }

    const total_len = zeros + digits_len;
    if (out_buf.len < total_len) return Error.BufferTooSmall;

    for (0..zeros) |i| {
        out_buf[i] = '1';
    }

    var i: usize = 0;
    while (i < digits_len) : (i += 1) {
        out_buf[zeros + i] = alphabet[digits[digits_len - 1 - i]];
    }

    return out_buf[0..total_len];
}

/// Encodes a 32-byte Substrate AccountId into an SS58 address (prefix 42 for peaq/Substrate).
pub fn encodeSS58(out_buf: []u8, public_key: [32]u8, prefix: u8) Error![]const u8 {
    var pre_hasher = Blake2b512.init(.{});
    pre_hasher.update("SS58PRE");
    pre_hasher.update(&[_]u8{prefix});
    pre_hasher.update(&public_key);

    var full_hash: [64]u8 = undefined;
    pre_hasher.final(&full_hash);

    var raw_payload: [35]u8 = undefined;
    raw_payload[0] = prefix;
    @memcpy(raw_payload[1..33], &public_key);
    @memcpy(raw_payload[33..35], full_hash[0..2]);

    return try encodeBase58(out_buf, &raw_payload);
}

// ----------------------------------------------------------------------------
// BIP-39 Mnemonic Generation & Seed Derivation (RFC / BIP-0039)
// ----------------------------------------------------------------------------

fn get11Bits(data: []const u8, checksum_byte: u8, bit_offset: usize) u11 {
    const byte_idx = bit_offset / 8;
    const bit_rem = @as(u3, @intCast(bit_offset % 8));

    const b0 = if (byte_idx < data.len) data[byte_idx] else checksum_byte;
    const b1 = if (byte_idx + 1 < data.len) data[byte_idx + 1] else if (byte_idx + 1 == data.len) checksum_byte else 0;
    const b2 = if (byte_idx + 2 < data.len) data[byte_idx + 2] else if (byte_idx + 2 == data.len) checksum_byte else 0;

    const combined: u24 = (@as(u24, b0) << 16) | (@as(u24, b1) << 8) | @as(u24, b2);
    const shift: u5 = 13 - @as(u5, bit_rem);
    return @as(u11, @truncate(combined >> shift));
}

/// Generates a BIP-39 mnemonic string from 16 bytes (12 words) or 32 bytes (24 words) of entropy.
pub fn generateMnemonic(out_buf: []u8, entropy: []const u8) Error![]const u8 {
    if (entropy.len != 16 and entropy.len != 32) {
        return Error.InvalidEntropyLength;
    }

    var hash: [32]u8 = undefined;
    Sha256.hash(entropy, &hash, .{});
    const checksum_byte = hash[0];

    const word_count: usize = if (entropy.len == 16) 12 else 24;

    var out_offset: usize = 0;
    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        const word_idx = get11Bits(entropy, checksum_byte, i * 11);
        const word = bip39_words.words[word_idx];

        if (out_offset + word.len + (if (i > 0) @as(usize, 1) else 0) > out_buf.len) {
            return Error.BufferTooSmall;
        }

        if (i > 0) {
            out_buf[out_offset] = ' ';
            out_offset += 1;
        }

        @memcpy(out_buf[out_offset..][0..word.len], word);
        out_offset += word.len;
    }

    return out_buf[0..out_offset];
}

/// Generates a random BIP-39 mnemonic phrase (12 words or 24 words).
pub fn generateRandomMnemonic(out_buf: []u8, word_count: usize) Error![]const u8 {
    if (word_count == 12) {
        var entropy: [16]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        std.c.arc4random_buf(entropy[0..].ptr, entropy.len);
        return generateMnemonic(out_buf, &entropy);
    } else if (word_count == 24) {
        var entropy: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        std.c.arc4random_buf(entropy[0..].ptr, entropy.len);
        return generateMnemonic(out_buf, &entropy);
    } else {
        return Error.InvalidWordCount;
    }
}

/// Validates a BIP-39 mnemonic string.
pub fn validateMnemonic(mnemonic: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, mnemonic, ' ');
    var word_count: usize = 0;
    var word_indices: [24]u11 = undefined;

    while (it.next()) |word| {
        if (word_count >= 24) return false;

        var found_idx: ?u11 = null;
        for (bip39_words.words, 0..) |w, idx| {
            if (std.mem.eql(u8, w, word)) {
                found_idx = @as(u11, @intCast(idx));
                break;
            }
        }

        const idx = found_idx orelse return false;
        word_indices[word_count] = idx;
        word_count += 1;
    }

    if (word_count != 12 and word_count != 24) return false;

    // Verify Checksum
    const ent_len: usize = if (word_count == 12) 16 else 32;
    var reconstructed_entropy: [32]u8 = undefined;
    @memset(&reconstructed_entropy, 0);

    const total_bits = word_count * 11;
    var bit_idx: usize = 0;
    while (bit_idx < total_bits) : (bit_idx += 1) {
        const w_idx = bit_idx / 11;
        const w_bit = @as(u4, @intCast(10 - (bit_idx % 11)));
        const bit = (word_indices[w_idx] >> w_bit) & 1;

        if (bit_idx < ent_len * 8) {
            const byte_pos = bit_idx / 8;
            const bit_pos = @as(u3, @intCast(7 - (bit_idx % 8)));
            reconstructed_entropy[byte_pos] |= @as(u8, @intCast(bit)) << bit_pos;
        }
    }

    var hash: [32]u8 = undefined;
    Sha256.hash(reconstructed_entropy[0..ent_len], &hash, .{});

    const cs_len: u4 = if (word_count == 12) 4 else 8;
    const expected_cs = if (cs_len == 4) hash[0] >> 4 else hash[0];

    var actual_cs: u8 = 0;
    var cs_bit: u4 = 0;
    while (cs_bit < cs_len) : (cs_bit += 1) {
        const cur_bit = ent_len * 8 + cs_bit;
        const w_idx = cur_bit / 11;
        const w_bit = @as(u4, @intCast(10 - (cur_bit % 11)));
        const bit = (word_indices[w_idx] >> w_bit) & 1;
        actual_cs = (actual_cs << 1) | @as(u8, @intCast(bit));
    }

    return actual_cs == expected_cs;
}

/// Derives a 512-bit (64-byte) master binary seed from a BIP-39 mnemonic and optional passphrase
/// using standard PBKDF2-HMAC-SHA512 with 2048 iterations (zero heap allocation).
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: []const u8, out_seed: *[64]u8) Error!void {
    var salt_buf: [256]u8 = undefined;
    const salt_prefix = "mnemonic";
    if (salt_prefix.len + passphrase.len > salt_buf.len) return Error.BufferTooSmall;

    @memcpy(salt_buf[0..salt_prefix.len], salt_prefix);
    @memcpy(salt_buf[salt_prefix.len..][0..passphrase.len], passphrase);
    const salt = salt_buf[0 .. salt_prefix.len + passphrase.len];

    std.crypto.pwhash.pbkdf2(
        out_seed,
        mnemonic,
        salt,
        2048,
        HmacSha512,
    ) catch return Error.WeakParameters;
}

// ----------------------------------------------------------------------------
// Peaq DePIN Identity & Ed25519 Keypair Derivation
// ----------------------------------------------------------------------------

pub fn deriveWalletFromSeed(
    allocator: std.mem.Allocator,
    seed: [64]u8,
    mnemonic_str: []const u8,
) Error!Wallet {
    // 1. Mini-secret (first 32 bytes of the BIP-39 derived seed)
    var mini_secret = seed[0..32].*;
    defer std.crypto.secureZero(u8, &mini_secret);

    // 2. Generate native Ed25519 keypair deterministically off the JS heap
    const key_pair = Ed25519.KeyPair.generateDeterministic(mini_secret) catch return Error.IdentityElement;
    const pub_key = key_pair.public_key.toBytes();

    // 3. Hex encodings
    const priv_hex = std.fmt.bytesToHex(mini_secret, .lower);
    const pub_hex = std.fmt.bytesToHex(pub_key, .lower);

    // 4. Multibase Public Key: "z" + Base58(32-byte public key)
    var mb_buf: [64]u8 = undefined;
    mb_buf[0] = 'z';
    const b58_pub = try encodeBase58(mb_buf[1..], &pub_key);
    const multibase_slice = try allocator.dupe(u8, mb_buf[0 .. 1 + b58_pub.len]);

    // 5. Substrate SS58 Address (Prefix 42 for standard Substrate / peaq)
    var ss58_buf: [64]u8 = undefined;
    const ss58 = try encodeSS58(&ss58_buf, pub_key, 42);
    const ss58_slice = try allocator.dupe(u8, ss58);

    // 6. W3C DID: "did:peaq:" + ss58_address
    var did_buf: [128]u8 = undefined;
    const did_prefix = "did:peaq:";
    @memcpy(did_buf[0..did_prefix.len], did_prefix);
    @memcpy(did_buf[did_prefix.len..][0..ss58.len], ss58);
    const did_slice = try allocator.dupe(u8, did_buf[0 .. did_prefix.len + ss58.len]);

    const mnemonic_slice = try allocator.dupe(u8, mnemonic_str);

    return Wallet{
        .mnemonic = mnemonic_slice,
        .seed = seed,
        .private_key_hex = priv_hex,
        .public_key_bytes = pub_key,
        .public_key_hex = pub_hex,
        .public_key_multibase = multibase_slice,
        .ss58_address = ss58_slice,
        .did = did_slice,
    };
}

/// Creates a new wallet from scratch using cryptographically secure random entropy.
pub fn createWallet(
    allocator: std.mem.Allocator,
    passphrase: []const u8,
    word_count: usize,
) Error!Wallet {
    var m_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &m_buf);
    const mnemonic = try generateRandomMnemonic(&m_buf, word_count);

    var seed: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try mnemonicToSeed(mnemonic, passphrase, &seed);

    return deriveWalletFromSeed(allocator, seed, mnemonic);
}

/// Restores a wallet from an existing BIP-39 mnemonic phrase.
pub fn createWalletFromMnemonic(
    allocator: std.mem.Allocator,
    mnemonic: []const u8,
    passphrase: []const u8,
) Error!Wallet {
    if (!validateMnemonic(mnemonic)) {
        return Error.InvalidChecksum;
    }

    var seed: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    try mnemonicToSeed(mnemonic, passphrase, &seed);

    return deriveWalletFromSeed(allocator, seed, mnemonic);
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "BIP-39 Test Vector 1: 128-bit Zero Entropy" {
    const zero_entropy = [_]u8{0} ** 16;
    var m_buf: [256]u8 = undefined;
    const mnemonic = try generateMnemonic(&m_buf, &zero_entropy);

    const expected_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    try std.testing.expectEqualStrings(expected_mnemonic, mnemonic);
    try std.testing.expect(validateMnemonic(mnemonic));

    var seed: [64]u8 = undefined;
    try mnemonicToSeed(mnemonic, "", &seed);

    const seed_hex = std.fmt.bytesToHex(seed, .lower);
    const expected_seed_prefix = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1";
    try std.testing.expectEqualStrings(expected_seed_prefix, seed_hex[0..64]);
}

test "Substrate SS58 Address Generation for Alice" {
    // Alice's known public key
    var alice_pub: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&alice_pub, "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");

    var ss58_buf: [64]u8 = undefined;
    const address = try encodeSS58(&ss58_buf, alice_pub, 42);
    try std.testing.expectEqualStrings("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", address);
}

test "Full Wallet Derivation in Stack Memory" {
    var stack_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const wallet = try createWalletFromMnemonic(allocator, mnemonic, "");

    try std.testing.expect(wallet.did.len > 10);
    try std.testing.expect(std.mem.startsWith(u8, wallet.did, "did:peaq:5"));
    try std.testing.expect(std.mem.startsWith(u8, wallet.public_key_multibase, "z"));
}

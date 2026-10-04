const std = @import("std");
const builtin = @import("builtin");
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const bip39_words = @import("bip39_words.zig");
const base58 = @import("base58.zig");
const parser = @import("peaq/parser.zig");

fn fillRandomBytes(buf: []u8) void {
    if (comptime builtin.os.tag.isDarwin()) {
        std.c.arc4random_buf(buf.ptr, buf.len);
    } else if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.getrandom(buf.ptr, buf.len, 0);
    } else {
        const file = std.fs.openFileAbsolute("/dev/urandom", .{}) catch return;
        defer file.close();
        _ = file.readAll(buf) catch return;
    }
}

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
    InvalidSS58Prefix,
    OutOfMemory,
};

/// A DePIN identity wallet: an Ed25519 keypair derived from a BIP-39 mnemonic the way
/// Substrate tooling does (see `miniSecretFromEntropy`), plus its SS58 address and did:peaq DID.
pub const Wallet = struct {
    mnemonic: []const u8,
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
    return base58.encode(out_buf, bytes) catch Error.BufferTooSmall;
}

/// Encodes a 32-byte Substrate AccountId into an SS58 address.
///
/// `prefix` is the network identifier from the SS58 registry (0..16383, excluding the reserved
/// 46 and 47). Prefixes below 64 use one prefix byte; larger ones use the two-byte form.
pub fn encodeSS58(out_buf: []u8, public_key: [32]u8, prefix: u16) Error![]const u8 {
    if (prefix >= 16384 or prefix == 46 or prefix == 47) return Error.InvalidSS58Prefix;

    var prefix_bytes: [2]u8 = undefined;
    var prefix_len: usize = 1;
    if (prefix < 64) {
        prefix_bytes[0] = @intCast(prefix);
    } else {
        prefix_len = 2;
        prefix_bytes[0] = @intCast(((prefix & 0b0000_0000_1111_1100) >> 2) | 0b0100_0000);
        prefix_bytes[1] = @intCast((prefix >> 8) | ((prefix & 0b0000_0011) << 6));
    }

    var pre_hasher = Blake2b512.init(.{});
    pre_hasher.update("SS58PRE");
    pre_hasher.update(prefix_bytes[0..prefix_len]);
    pre_hasher.update(&public_key);

    var full_hash: [64]u8 = undefined;
    pre_hasher.final(&full_hash);

    var raw_payload: [36]u8 = undefined;
    @memcpy(raw_payload[0..prefix_len], prefix_bytes[0..prefix_len]);
    @memcpy(raw_payload[prefix_len..][0..32], &public_key);
    @memcpy(raw_payload[prefix_len + 32 ..][0..2], full_hash[0..2]);

    return try encodeBase58(out_buf, raw_payload[0 .. prefix_len + 34]);
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
        fillRandomBytes(&entropy);
        return generateMnemonic(out_buf, &entropy);
    } else if (word_count == 24) {
        var entropy: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        fillRandomBytes(&entropy);
        return generateMnemonic(out_buf, &entropy);
    } else {
        return Error.InvalidWordCount;
    }
}

/// Entropy recovered from a BIP-39 mnemonic.
pub const Entropy = struct {
    bytes: [32]u8,
    len: usize,

    pub fn slice(self: *const Entropy) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// Parses a BIP-39 mnemonic (12 or 24 English words) and verifies its checksum.
pub fn mnemonicToEntropy(mnemonic: []const u8) Error!Entropy {
    var it = std.mem.tokenizeScalar(u8, mnemonic, ' ');
    var word_count: usize = 0;
    var word_indices: [24]u11 = undefined;

    while (it.next()) |word| {
        if (word_count >= 24) return Error.InvalidWordCount;

        var found_idx: ?u11 = null;
        for (bip39_words.words, 0..) |w, idx| {
            if (std.mem.eql(u8, w, word)) {
                found_idx = @as(u11, @intCast(idx));
                break;
            }
        }

        word_indices[word_count] = found_idx orelse return Error.UnknownWord;
        word_count += 1;
    }

    if (word_count != 12 and word_count != 24) return Error.InvalidWordCount;

    const ent_len: usize = if (word_count == 12) 16 else 32;
    var result = Entropy{ .bytes = [_]u8{0} ** 32, .len = ent_len };

    var bit_idx: usize = 0;
    while (bit_idx < ent_len * 8) : (bit_idx += 1) {
        const w_idx = bit_idx / 11;
        const w_bit = @as(u4, @intCast(10 - (bit_idx % 11)));
        const bit = (word_indices[w_idx] >> w_bit) & 1;
        const byte_pos = bit_idx / 8;
        const bit_pos = @as(u3, @intCast(7 - (bit_idx % 8)));
        result.bytes[byte_pos] |= @as(u8, @intCast(bit)) << bit_pos;
    }

    var hash: [32]u8 = undefined;
    Sha256.hash(result.slice(), &hash, .{});

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

    if (actual_cs != expected_cs) {
        std.crypto.secureZero(u8, &result.bytes);
        return Error.InvalidChecksum;
    }
    return result;
}

/// Validates a BIP-39 mnemonic string.
pub fn validateMnemonic(mnemonic: []const u8) bool {
    var entropy = mnemonicToEntropy(mnemonic) catch return false;
    std.crypto.secureZero(u8, &entropy.bytes);
    return true;
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

/// Derives the 32-byte Ed25519 mini-secret exactly as Substrate tooling (`substrate-bip39`,
/// polkadot-js `mnemonicToMiniSecret`) does: PBKDF2-HMAC-SHA512 keyed with the mnemonic's
/// *entropy* (not its text), salt `"mnemonic" ++ passphrase`, 2048 rounds, first 32 bytes.
///
/// This intentionally differs from the BIP-39 seed (which keys PBKDF2 with the mnemonic string),
/// so the same phrase yields the same account in Polkadot.js, Talisman, SubWallet, etc.
pub fn miniSecretFromEntropy(entropy: []const u8, passphrase: []const u8, out: *[32]u8) Error!void {
    var salt_buf: [256]u8 = undefined;
    const salt_prefix = "mnemonic";
    if (salt_prefix.len + passphrase.len > salt_buf.len) return Error.BufferTooSmall;

    @memcpy(salt_buf[0..salt_prefix.len], salt_prefix);
    @memcpy(salt_buf[salt_prefix.len..][0..passphrase.len], passphrase);
    const salt = salt_buf[0 .. salt_prefix.len + passphrase.len];

    var full: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &full);
    std.crypto.pwhash.pbkdf2(&full, entropy, salt, 2048, HmacSha512) catch return Error.WeakParameters;
    @memcpy(out, full[0..32]);
}

// ----------------------------------------------------------------------------
// Peaq DePIN Identity & Ed25519 Keypair Derivation
// ----------------------------------------------------------------------------

/// Generic Substrate format. peaq's registered prefix is 1221; pass it explicitly if you want it.
pub const default_ss58_prefix: u16 = 42;

pub fn deriveWalletFromMiniSecret(
    allocator: std.mem.Allocator,
    mini_secret: [32]u8,
    mnemonic_str: []const u8,
    ss58_prefix: u16,
) Error!Wallet {
    // 1. Deterministic Ed25519 keypair from the mini-secret
    const key_pair = Ed25519.KeyPair.generateDeterministic(mini_secret) catch return Error.IdentityElement;
    const pub_key = key_pair.public_key.toBytes();

    // 2. Hex encodings
    const priv_hex = std.fmt.bytesToHex(mini_secret, .lower);
    const pub_hex = std.fmt.bytesToHex(pub_key, .lower);

    // 3. Multibase public key in the W3C Ed25519VerificationKey2020 form (z6Mk...)
    var mb_buf: [64]u8 = undefined;
    const mb = parser.encodePublicKey(&mb_buf, pub_key) catch return Error.BufferTooSmall;
    const multibase_slice = try allocator.dupe(u8, mb);

    // 4. Substrate SS58 address
    var ss58_buf: [64]u8 = undefined;
    const ss58 = try encodeSS58(&ss58_buf, pub_key, ss58_prefix);
    const ss58_slice = try allocator.dupe(u8, ss58);

    // 5. W3C DID: "did:peaq:" + ss58_address
    var did_buf: [128]u8 = undefined;
    const did_prefix = "did:peaq:";
    @memcpy(did_buf[0..did_prefix.len], did_prefix);
    @memcpy(did_buf[did_prefix.len..][0..ss58.len], ss58);
    const did_slice = try allocator.dupe(u8, did_buf[0 .. did_prefix.len + ss58.len]);

    const mnemonic_slice = try allocator.dupe(u8, mnemonic_str);

    return Wallet{
        .mnemonic = mnemonic_slice,
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
    ss58_prefix: u16,
) Error!Wallet {
    var m_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &m_buf);
    const mnemonic = try generateRandomMnemonic(&m_buf, word_count);
    return createWalletFromMnemonic(allocator, mnemonic, passphrase, ss58_prefix);
}

/// Restores a wallet from an existing BIP-39 mnemonic phrase.
pub fn createWalletFromMnemonic(
    allocator: std.mem.Allocator,
    mnemonic: []const u8,
    passphrase: []const u8,
    ss58_prefix: u16,
) Error!Wallet {
    var entropy = try mnemonicToEntropy(mnemonic);
    defer std.crypto.secureZero(u8, &entropy.bytes);

    var mini_secret: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &mini_secret);
    try miniSecretFromEntropy(entropy.slice(), passphrase, &mini_secret);

    return deriveWalletFromMiniSecret(allocator, mini_secret, mnemonic, ss58_prefix);
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

test "SS58 known addresses for Alice on other networks" {
    var alice_pub: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&alice_pub, "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");

    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5", try encodeSS58(&buf, alice_pub, 0)); // Polkadot
    try std.testing.expectEqualStrings("HNZata7iMYWmk5RvZRTiAsSDhV8366zq2YGb3tLH5Upf74F", try encodeSS58(&buf, alice_pub, 2)); // Kusama
    try std.testing.expectError(Error.InvalidSS58Prefix, encodeSS58(&buf, alice_pub, 47));
}

test "Full Wallet Derivation in Stack Memory" {
    var stack_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const wallet = try createWalletFromMnemonic(allocator, mnemonic, "", default_ss58_prefix);

    try std.testing.expect(wallet.did.len > 10);
    try std.testing.expect(std.mem.startsWith(u8, wallet.did, "did:peaq:5"));
    try std.testing.expect(std.mem.startsWith(u8, wallet.public_key_multibase, "z6Mk"));
}

test "Substrate-compatible mini-secret and account for the zero-entropy mnemonic" {
    var stack_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const entropy = try mnemonicToEntropy(mnemonic);
    try std.testing.expectEqual(@as(usize, 16), entropy.len);

    // Matches polkadot-js `mnemonicToMiniSecret` for this phrase.
    var mini: [32]u8 = undefined;
    try miniSecretFromEntropy(entropy.slice(), "", &mini);
    const mini_hex = std.fmt.bytesToHex(mini, .lower);
    try std.testing.expectEqualStrings("4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e2", &mini_hex);

    const w = try createWalletFromMnemonic(allocator, mnemonic, "", default_ss58_prefix);
    try std.testing.expectEqualStrings("9125f505bdef2cb5825b9931769316d3e2f22150786489a04f39b434ec9fb294", &w.public_key_hex);
    try std.testing.expectEqualStrings("z6MkpDrjMkZu8tXxfgFvREHAwvSAgy7ZE9Wo4u9cL1mkFfQf", w.public_key_multibase);
    try std.testing.expectEqualStrings("5FM25N8HGtacre9TnWQGRK32d1kUp1Gs6Dd7YiYpSPZLjmj6", w.ss58_address);
    try std.testing.expectEqualStrings("did:peaq:5FM25N8HGtacre9TnWQGRK32d1kUp1Gs6Dd7YiYpSPZLjmj6", w.did);

    // The same key encodes to a different address under peaq's registered prefix (two-byte form).
    const peaq = try createWalletFromMnemonic(allocator, mnemonic, "", 1221);
    try std.testing.expectEqualSlices(u8, &w.public_key_bytes, &peaq.public_key_bytes);
    try std.testing.expect(!std.mem.eql(u8, w.ss58_address, peaq.ss58_address));
    try std.testing.expect(std.mem.startsWith(u8, peaq.did, "did:peaq:"));
    try std.testing.expectError(Error.InvalidSS58Prefix, createWalletFromMnemonic(allocator, mnemonic, "", 16384));
    try std.testing.expectError(Error.InvalidSS58Prefix, createWalletFromMnemonic(allocator, mnemonic, "", 46));

    // A passphrase must change the account.
    const w2 = try createWalletFromMnemonic(allocator, mnemonic, "secret", default_ss58_prefix);
    try std.testing.expect(!std.mem.eql(u8, w.ss58_address, w2.ss58_address));
}

test "mnemonicToEntropy rejects bad phrases with specific errors" {
    try std.testing.expectError(Error.InvalidWordCount, mnemonicToEntropy("abandon abandon"));
    try std.testing.expectError(Error.UnknownWord, mnemonicToEntropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzzz"));
    try std.testing.expectError(Error.InvalidChecksum, mnemonicToEntropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));
    try std.testing.expect(!validateMnemonic(""));
}

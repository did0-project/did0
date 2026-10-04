//! did0: Zero-Allocation Decentralized Identifier (DID) and Cryptographic Engine.
//!
//! Designed for high-throughput DePIN microservices, hardware gateways, and IoT nodes.
//! Provides native W3C DID document resolution, Substrate SCALE serialization,
//! RFC 8785 JSON Canonicalization Scheme (JCS) verifiable credentials, and
//! BIP-39 / SS58 deterministic wallet key derivation off the JavaScript heap.

const std = @import("std");

pub const peaq = @import("peaq/parser.zig");
pub const scale = @import("scale.zig");
pub const jcs = @import("jcs.zig");
pub const wallet = @import("wallet.zig");

/// Represents a cryptographic key associated with the DID
pub const VerificationMethod = struct {
    id: []const u8,
    type: []const u8,
    controller: []const u8,
    publicKeyMultibase: ?[]const u8 = null,
    publicKeyHex: ?[]const u8 = null,
};

/// Represents an endpoint for interacting with the DID subject
pub const Service = struct {
    id: []const u8,
    type: []const u8,
    serviceEndpoint: []const u8,
};

/// The core W3C DID Document standard
pub const Document = struct {
    id: []const u8,
    controller: ?[]const u8 = null,
    verificationMethod: ?[]const VerificationMethod = null,

    // For Phase 1, we treat authentication as an array of string references
    // pointing back to the verificationMethod IDs
    authentication: ?[]const []const u8 = null,

    service: ?[]const Service = null,
};

test "W3C structs compile successfully" {
    // A simple sanity check for the test runner
    const doc = Document{
        .id = "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    };
    try std.testing.expectEqualStrings("did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", doc.id);
}

test "W3C Document can be zero-allocation SCALE encoded" {
    var buffer: [512]u8 = undefined;
    var enc = scale.Encoder.init(&buffer);

    const doc = Document{
        .id = "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
    };

    try enc.encode(doc);
    const written = enc.getWritten();
    try std.testing.expect(written.len > doc.id.len);
}

test "JCS canonicalization export check" {
    var stack_buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    var out_buf: [1024]u8 = undefined;
    const res = try jcs.canonicalize(allocator, "{\"b\":2,\"a\":1}", &out_buf);
    try std.testing.expectEqualStrings("{\"a\":1,\"b\":2}", res);
}

test "Wallet export check" {
    var stack_buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const w = try wallet.createWalletFromMnemonic(allocator, mnemonic, "");
    try std.testing.expect(std.mem.startsWith(u8, w.did, "did:peaq:5"));
}

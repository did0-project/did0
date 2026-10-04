const std = @import("std");

/// Errors that can occur during SCALE encoding
pub const Error = error{
    BufferTooSmall,
    ValueTooLarge,
    UnsupportedType,
};

/// A zero-allocation Substrate SCALE (Simple Concatenated Aggregate Little-Endian) serializer.
/// Writes directly to a caller-provided memory slice without heap allocations.
pub const Encoder = struct {
    buffer: []u8,
    offset: usize = 0,

    /// Initializes a new Encoder backed by the provided buffer.
    pub fn init(buffer: []u8) Encoder {
        return .{
            .buffer = buffer,
            .offset = 0,
        };
    }

    /// Returns the slice of encoded bytes written so far.
    pub fn getWritten(self: *const Encoder) []const u8 {
        return self.buffer[0..self.offset];
    }

    /// Resets the encoder offset back to zero.
    pub fn reset(self: *Encoder) void {
        self.offset = 0;
    }

    /// Returns the remaining available byte capacity in the buffer.
    pub fn remaining(self: *const Encoder) usize {
        return self.buffer.len - self.offset;
    }

    /// Encodes a single unsigned 8-bit integer.
    pub fn writeU8(self: *Encoder, val: u8) Error!void {
        if (self.remaining() < 1) return Error.BufferTooSmall;
        self.buffer[self.offset] = val;
        self.offset += 1;
    }

    /// Encodes a signed 8-bit integer.
    pub fn writeI8(self: *Encoder, val: i8) Error!void {
        return self.writeU8(@bitCast(val));
    }

    /// Encodes an unsigned 16-bit integer in little-endian.
    pub fn writeU16(self: *Encoder, val: u16) Error!void {
        if (self.remaining() < 2) return Error.BufferTooSmall;
        std.mem.writeInt(u16, self.buffer[self.offset..][0..2], val, .little);
        self.offset += 2;
    }

    /// Encodes a signed 16-bit integer in little-endian.
    pub fn writeI16(self: *Encoder, val: i16) Error!void {
        return self.writeU16(@bitCast(val));
    }

    /// Encodes an unsigned 32-bit integer in little-endian.
    pub fn writeU32(self: *Encoder, val: u32) Error!void {
        if (self.remaining() < 4) return Error.BufferTooSmall;
        std.mem.writeInt(u32, self.buffer[self.offset..][0..4], val, .little);
        self.offset += 4;
    }

    /// Encodes a signed 32-bit integer in little-endian.
    pub fn writeI32(self: *Encoder, val: i32) Error!void {
        return self.writeU32(@bitCast(val));
    }

    /// Encodes an unsigned 64-bit integer in little-endian.
    pub fn writeU64(self: *Encoder, val: u64) Error!void {
        if (self.remaining() < 8) return Error.BufferTooSmall;
        std.mem.writeInt(u64, self.buffer[self.offset..][0..8], val, .little);
        self.offset += 8;
    }

    /// Encodes a signed 64-bit integer in little-endian.
    pub fn writeI64(self: *Encoder, val: i64) Error!void {
        return self.writeU64(@bitCast(val));
    }

    /// Encodes an unsigned 128-bit integer in little-endian.
    pub fn writeU128(self: *Encoder, val: u128) Error!void {
        if (self.remaining() < 16) return Error.BufferTooSmall;
        std.mem.writeInt(u128, self.buffer[self.offset..][0..16], val, .little);
        self.offset += 16;
    }

    /// Encodes a signed 128-bit integer in little-endian.
    pub fn writeI128(self: *Encoder, val: i128) Error!void {
        return self.writeU128(@bitCast(val));
    }

    /// Encodes a boolean as 0x01 (true) or 0x00 (false).
    pub fn writeBool(self: *Encoder, val: bool) Error!void {
        return self.writeU8(if (val) 0x01 else 0x00);
    }

    /// Encodes an Option(bool) per Substrate specification:
    /// 0x00 for None, 0x01 for Some(true), 0x02 for Some(false).
    pub fn writeOptionBool(self: *Encoder, val: ?bool) Error!void {
        if (val) |b| {
            return self.writeU8(if (b) 0x01 else 0x02);
        } else {
            return self.writeU8(0x00);
        }
    }

    /// Encodes a Substrate compact integer (Compact<u64>).
    /// Mode 00: 0 ..= 63 (1 byte)
    /// Mode 01: 64 ..= 16383 (2 bytes, little-endian)
    /// Mode 10: 16384 ..= 1073741823 (4 bytes, little-endian)
    /// Mode 11: >= 1073741824 (header byte + little-endian bytes)
    pub fn writeCompact(self: *Encoder, val: u64) Error!void {
        if (val <= 63) {
            const byte: u8 = @as(u8, @intCast(val << 2)); // lower 2 bits are 00
            try self.writeU8(byte);
        } else if (val <= 16383) {
            const encoded: u16 = @as(u16, @intCast((val << 2) | 0b01));
            try self.writeU16(encoded);
        } else if (val <= 1073741823) {
            const encoded: u32 = @as(u32, @intCast((val << 2) | 0b10));
            try self.writeU32(encoded);
        } else {
            // Big integer mode (0b11)
            // Calculate how many bytes are needed to store val
            var temp = val;
            var num_bytes: u8 = 0;
            while (temp > 0) : (temp >>= 8) {
                num_bytes += 1;
            }
            if (num_bytes < 4) num_bytes = 4;

            if (self.remaining() < 1 + num_bytes) return Error.BufferTooSmall;

            // Header byte: ((num_bytes - 4) << 2) | 0b11
            const header: u8 = ((num_bytes - 4) << 2) | 0b11;
            try self.writeU8(header);

            temp = val;
            var i: usize = 0;
            while (i < num_bytes) : (i += 1) {
                try self.writeU8(@as(u8, @truncate(temp)));
                temp >>= 8;
            }
        }
    }

    /// Writes raw bytes without length prefix (e.g. for fixed-size arrays).
    /// Encodes an `Option<u32>`: `0x00` for none, `0x01` followed by the little-endian value otherwise.
    pub fn writeOptionU32(self: *Encoder, val: ?u32) Error!void {
        if (val) |v| {
            try self.writeU8(1);
            try self.writeU32(v);
        } else {
            try self.writeU8(0);
        }
    }

    pub fn writeRawBytes(self: *Encoder, bytes: []const u8) Error!void {
        if (self.remaining() < bytes.len) return Error.BufferTooSmall;
        @memcpy(self.buffer[self.offset..][0..bytes.len], bytes);
        self.offset += bytes.len;
    }

    /// Writes a compact length prefix followed by raw bytes (e.g., String, Vector).
    pub fn writeSlice(self: *Encoder, slice: []const u8) Error!void {
        try self.writeCompact(@as(u64, slice.len));
        try self.writeRawBytes(slice);
    }

    /// Alias for writeSlice for UTF-8 strings.
    pub fn writeString(self: *Encoder, str: []const u8) Error!void {
        return self.writeSlice(str);
    }

    /// Recursively encodes arbitrary Zig values (structs, slices, arrays, optionals, primitives)
    /// using zero heap allocations.
    pub fn encode(self: *Encoder, value: anytype) Error!void {
        const T = @TypeOf(value);
        const info = @typeInfo(T);

        switch (info) {
            .int => |int_info| {
                if (int_info.signedness == .unsigned) {
                    switch (int_info.bits) {
                        8 => try self.writeU8(value),
                        16 => try self.writeU16(value),
                        32 => try self.writeU32(value),
                        64 => try self.writeU64(value),
                        128 => try self.writeU128(value),
                        else => return Error.UnsupportedType,
                    }
                } else {
                    switch (int_info.bits) {
                        8 => try self.writeI8(value),
                        16 => try self.writeI16(value),
                        32 => try self.writeI32(value),
                        64 => try self.writeI64(value),
                        128 => try self.writeI128(value),
                        else => return Error.UnsupportedType,
                    }
                }
            },
            .bool => {
                try self.writeBool(value);
            },
            .optional => |opt_info| {
                if (opt_info.child == bool) {
                    try self.writeOptionBool(value);
                } else {
                    if (value) |val| {
                        try self.writeU8(0x01);
                        try self.encode(val);
                    } else {
                        try self.writeU8(0x00);
                    }
                }
            },
            .array => |arr_info| {
                if (arr_info.child == u8) {
                    try self.writeRawBytes(&value);
                } else {
                    for (value) |elem| {
                        try self.encode(elem);
                    }
                }
            },
            .pointer => |ptr_info| {
                switch (ptr_info.size) {
                    .slice => {
                        if (ptr_info.child == u8) {
                            try self.writeSlice(value);
                        } else {
                            try self.writeCompact(@as(u64, value.len));
                            for (value) |elem| {
                                try self.encode(elem);
                            }
                        }
                    },
                    .one => {
                        try self.encode(value.*);
                    },
                    else => return Error.UnsupportedType,
                }
            },
            .@"struct" => |struct_info| {
                inline for (struct_info.fields) |field| {
                    try self.encode(@field(value, field.name));
                }
            },
            else => return Error.UnsupportedType,
        }
    }
};

// ----------------------------------------------------------------------------
// peaq Network DID Attributes & Pallet Extrinsics
// ----------------------------------------------------------------------------

/// Represents a peaq DID attribute stored on the blockchain
pub const DidAttribute = struct {
    did_account: [32]u8,
    name: []const u8,
    value: []const u8,
    /// `valid_for: Option<BlockNumber>` in the peaq-did pallet (BlockNumber is u32).
    validity: ?u32,
};

/// Encodes a peaq DID attribute into SCALE bytecode using a stack/fixed buffer.
pub fn encodeDidAttribute(buffer: []u8, attr: DidAttribute) Error![]const u8 {
    var encoder = Encoder.init(buffer);
    try encoder.writeRawBytes(&attr.did_account);
    try encoder.writeSlice(attr.name);
    try encoder.writeSlice(attr.value);
    try encoder.writeOptionU32(attr.validity);
    return encoder.getWritten();
}

/// Encodes a Substrate dispatchable call for peaq-did `add_attribute(did_account, name, value, valid_for: Option<BlockNumber>)`.
pub fn encodeAddAttributeCall(
    buffer: []u8,
    pallet_index: u8,
    call_index: u8,
    did_account: [32]u8,
    name: []const u8,
    value: []const u8,
    validity: ?u32,
) Error![]const u8 {
    var encoder = Encoder.init(buffer);
    try encoder.writeU8(pallet_index);
    try encoder.writeU8(call_index);
    try encoder.writeRawBytes(&did_account);
    try encoder.writeSlice(name);
    try encoder.writeSlice(value);
    try encoder.writeOptionU32(validity);
    return encoder.getWritten();
}

/// Encodes a Substrate dispatchable call for peaq-did `update_attribute(did_account, name, value, valid_for: Option<BlockNumber>)`.
pub fn encodeUpdateAttributeCall(
    buffer: []u8,
    pallet_index: u8,
    call_index: u8,
    did_account: [32]u8,
    name: []const u8,
    value: []const u8,
    validity: ?u32,
) Error![]const u8 {
    return encodeAddAttributeCall(buffer, pallet_index, call_index, did_account, name, value, validity);
}

/// Encodes a Substrate dispatchable call for peaq-did `remove_attribute(did_account, name)`.
pub fn encodeRemoveAttributeCall(
    buffer: []u8,
    pallet_index: u8,
    call_index: u8,
    did_account: [32]u8,
    name: []const u8,
) Error![]const u8 {
    var encoder = Encoder.init(buffer);
    try encoder.writeU8(pallet_index);
    try encoder.writeU8(call_index);
    try encoder.writeRawBytes(&did_account);
    try encoder.writeSlice(name);
    return encoder.getWritten();
}

// ----------------------------------------------------------------------------
// Tests: Verified against Substrate SCALE Codec Standard Test Vectors
// ----------------------------------------------------------------------------

test "SCALE compact integer encoding - Substrate test vectors" {
    var buf: [16]u8 = undefined;

    // 0 -> 0x00
    var enc = Encoder.init(&buf);
    try enc.writeCompact(0);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, enc.getWritten());

    // 1 -> 0x04
    enc.reset();
    try enc.writeCompact(1);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x04}, enc.getWritten());

    // 42 -> 0xa8
    enc.reset();
    try enc.writeCompact(42);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xa8}, enc.getWritten());

    // 63 -> 0xfc
    enc.reset();
    try enc.writeCompact(63);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xfc}, enc.getWritten());

    // 64 -> [0x01, 0x01]
    enc.reset();
    try enc.writeCompact(64);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x01 }, enc.getWritten());

    // 16383 -> [0xfd, 0xff]
    enc.reset();
    try enc.writeCompact(16383);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfd, 0xff }, enc.getWritten());

    // 16384 -> [0x02, 0x00, 0x01, 0x00]
    enc.reset();
    try enc.writeCompact(16384);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x00, 0x01, 0x00 }, enc.getWritten());

    // 1073741823 -> [0xfe, 0xff, 0xff, 0xff]
    enc.reset();
    try enc.writeCompact(1073741823);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfe, 0xff, 0xff, 0xff }, enc.getWritten());

    // 1073741824 -> [0x03, 0x00, 0x00, 0x00, 0x40]
    enc.reset();
    try enc.writeCompact(1073741824);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x00, 0x00, 0x00, 0x40 }, enc.getWritten());
}

test "SCALE basic primitive encoding" {
    var buf: [32]u8 = undefined;

    // Integers
    var enc = Encoder.init(&buf);
    try enc.writeU8(0x42);
    try enc.writeU16(0x1234);
    try enc.writeU32(0x56789abc);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x42,
        0x34,
        0x12,
        0xbc,
        0x9a,
        0x78,
        0x56,
    }, enc.getWritten());

    // Booleans
    enc.reset();
    try enc.writeBool(true);
    try enc.writeBool(false);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, enc.getWritten());

    // Option(bool)
    enc.reset();
    try enc.writeOptionBool(null);
    try enc.writeOptionBool(true);
    try enc.writeOptionBool(false);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x02 }, enc.getWritten());
}

test "SCALE string and byte slice encoding" {
    var buf: [32]u8 = undefined;
    var enc = Encoder.init(&buf);

    // "TEST" (len 4 -> compact 0x10)
    try enc.writeString("TEST");
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x10, 'T', 'E', 'S', 'T' }, enc.getWritten());
}

test "SCALE struct and generic reflection encoding" {
    const TestStruct = struct {
        id: u16,
        active: bool,
        name: []const u8,
    };

    var buf: [64]u8 = undefined;
    var enc = Encoder.init(&buf);
    const item = TestStruct{
        .id = 1,
        .active = true,
        .name = "peaq",
    };

    try enc.encode(item);
    // id (1 as u16 little-endian: 0x01, 0x00)
    // active (true: 0x01)
    // name ("peaq", len 4: compact 0x10, 'p', 'e', 'a', 'q')
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x01, 0x00,
        0x01, 0x10,
        'p',  'e',
        'a',  'q',
    }, enc.getWritten());
}

test "SCALE peaq DID attribute and extrinsic encoding" {
    var pub_key = [_]u8{0xaa} ** 32;
    var buf: [256]u8 = undefined;

    const attr = DidAttribute{
        .did_account = pub_key,
        .name = "peaq-did-doc",
        .value = "{\"id\":\"did:peaq:0xaa\"}",
        .validity = 1000000,
    };

    const encoded = try encodeDidAttribute(&buf, attr);
    try std.testing.expect(encoded.len > 32);

    // Check account id
    try std.testing.expectEqualSlices(u8, &pub_key, encoded[0..32]);

    // Check call encoding
    var call_buf: [256]u8 = undefined;
    const call_bytes = try encodeAddAttributeCall(
        &call_buf,
        0x14, // Pallet index
        0x00, // Call index (add_attribute)
        pub_key,
        "peaq-did-doc",
        "{\"id\":\"did:peaq:0xaa\"}",
        1000000,
    );

    // valid_for = Some(1_000_000) is encoded as 0x01 ++ u32 LE
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x40, 0x42, 0x0f, 0x00 }, call_bytes[call_bytes.len - 5 ..]);

    // valid_for = None is a single 0x00 byte
    const none_bytes = try encodeAddAttributeCall(&call_buf, 0x14, 0x00, pub_key, "n", "v", null);
    try std.testing.expectEqual(@as(u8, 0x00), none_bytes[none_bytes.len - 1]);
    try std.testing.expectEqual(@as(usize, 2 + 32 + 2 + 2 + 1), none_bytes.len);

    try std.testing.expectEqual(@as(u8, 0x14), call_bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x00), call_bytes[1]);
    try std.testing.expectEqualSlices(u8, &pub_key, call_bytes[2..34]);
}

test "SCALE peaq remove_attribute extrinsic encoding" {
    const pub_key = [_]u8{0xbb} ** 32;
    var call_buf: [128]u8 = undefined;
    const call_bytes = try encodeRemoveAttributeCall(
        &call_buf,
        0x14, // Pallet index
        0x02, // Call index (remove_attribute)
        pub_key,
        "peaq-did-doc",
    );

    try std.testing.expectEqual(@as(u8, 0x14), call_bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x02), call_bytes[1]);
    try std.testing.expectEqualSlices(u8, &pub_key, call_bytes[2..34]);
}

test "BufferTooSmall error handling" {
    var buf: [2]u8 = undefined;
    var enc = Encoder.init(&buf);
    try std.testing.expectError(Error.BufferTooSmall, enc.writeU32(12345));
}

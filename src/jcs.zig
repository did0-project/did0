const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{
    BufferTooSmall,
    InvalidJson,
    InvalidUnicode,
    InvalidNumber,
    UnexpectedToken,
    DuplicateKey,
    TooDeep,
    OutOfMemory,
};

/// Maximum nesting depth accepted by the parser (guards the native stack against hostile input).
pub const max_depth = 128;

/// Lightweight AST for JSON values parsed into a caller-owned FixedBufferAllocator.
pub const Value = union(enum) {
    null_val: void,
    bool_val: bool,
    number: f64,
    string: []const u8,
    array: []Value,
    object: []Member,
};

pub const Member = struct {
    name: []const u8,
    value: Value,
};

// ----------------------------------------------------------------------------
// UTF-16 Code Unit Iterator & Lexicographical Key Comparison (RFC 8785 §3.2.3)
// ----------------------------------------------------------------------------

pub const Utf16Iterator = struct {
    utf8_iter: std.unicode.Utf8Iterator,
    pending_low: ?u16 = null,

    pub fn init(slice: []const u8) ?Utf16Iterator {
        const view = std.unicode.Utf8View.init(slice) catch return null;
        return .{ .utf8_iter = view.iterator(), .pending_low = null };
    }

    pub fn next(self: *Utf16Iterator) ?u16 {
        if (self.pending_low) |low| {
            self.pending_low = null;
            return low;
        }
        const cp = self.utf8_iter.nextCodepoint() orelse return null;
        if (cp <= 0xFFFF) {
            return @as(u16, @intCast(cp));
        } else {
            const v = cp - 0x10000;
            const high: u16 = @as(u16, @intCast(0xD800 + (v >> 10)));
            self.pending_low = @as(u16, @intCast(0xDC00 + (v & 0x3FF)));
            return high;
        }
    }
};

/// Compares two UTF-8 strings according to UTF-16 code unit values (RFC 8785 Section 3.2.3).
pub fn compareUtf16(a: []const u8, b: []const u8) std.math.Order {
    var it_a = Utf16Iterator.init(a) orelse return std.mem.order(u8, a, b);
    var it_b = Utf16Iterator.init(b) orelse return std.mem.order(u8, a, b);
    while (true) {
        const u_a = it_a.next();
        const u_b = it_b.next();
        if (u_a == null and u_b == null) return .eq;
        if (u_a == null) return .lt;
        if (u_b == null) return .gt;
        if (u_a.? < u_b.?) return .lt;
        if (u_a.? > u_b.?) return .gt;
    }
}

pub fn sortMembers(members: []Member) void {
    std.mem.sort(Member, members, {}, struct {
        fn lessThan(_: void, a: Member, b: Member) bool {
            return compareUtf16(a.name, b.name) == .lt;
        }
    }.lessThan);
}

// ----------------------------------------------------------------------------
// Number Formatting (RFC 8785 §3.2.2.3 & ECMAScript 6 §7.1.12.1 ToString)
// ----------------------------------------------------------------------------

pub fn formatEcmaNumber(buf: []u8, val: f64) Error![]const u8 {
    if (std.math.isNan(val) or std.math.isInf(val)) {
        return Error.InvalidNumber;
    }
    // -0.0 and +0.0 both serialize as "0"
    if (val == 0.0) {
        if (buf.len < 1) return Error.BufferTooSmall;
        buf[0] = '0';
        return buf[0..1];
    }

    var w: usize = 0;
    var v = val;
    if (v < 0) {
        if (buf.len < 1) return Error.BufferTooSmall;
        buf[0] = '-';
        w = 1;
        v = -v;
    }

    // Shortest round-trip digits in scientific form, e.g. "4.7287639067508275e-6".
    var temp: [64]u8 = undefined;
    const e_str = std.fmt.bufPrint(&temp, "{e}", .{v}) catch return Error.BufferTooSmall;
    const e_idx = std.mem.indexOfScalar(u8, e_str, 'e') orelse return Error.InvalidNumber;
    const exp = std.fmt.parseInt(i32, e_str[e_idx + 1 ..], 10) catch return Error.InvalidNumber;

    var digits_buf: [32]u8 = undefined;
    var k: usize = 0;
    for (e_str[0..e_idx]) |c| {
        if (c == '.') continue;
        if (k >= digits_buf.len) return Error.InvalidNumber;
        digits_buf[k] = c;
        k += 1;
    }
    const digits = digits_buf[0..k];
    // ECMAScript Number::toString: value = 0.d1d2...dk * 10^n
    const n: i32 = exp + 1;
    const kk: i32 = @intCast(k);

    const Writer = struct {
        buf: []u8,
        pos: *usize,
        fn put(self: @This(), bytes: []const u8) Error!void {
            if (self.pos.* + bytes.len > self.buf.len) return Error.BufferTooSmall;
            @memcpy(self.buf[self.pos.*..][0..bytes.len], bytes);
            self.pos.* += bytes.len;
        }
        fn zeros(self: @This(), count: usize) Error!void {
            if (self.pos.* + count > self.buf.len) return Error.BufferTooSmall;
            @memset(self.buf[self.pos.*..][0..count], '0');
            self.pos.* += count;
        }
    };
    const wr = Writer{ .buf = buf, .pos = &w };

    if (kk <= n and n <= 21) {
        try wr.put(digits);
        try wr.zeros(@intCast(n - kk));
    } else if (0 < n and n <= 21) {
        const un: usize = @intCast(n);
        try wr.put(digits[0..un]);
        try wr.put(".");
        try wr.put(digits[un..]);
    } else if (-6 < n and n <= 0) {
        try wr.put("0.");
        try wr.zeros(@intCast(-n));
        try wr.put(digits);
    } else {
        const e = n - 1;
        try wr.put(digits[0..1]);
        if (k > 1) {
            try wr.put(".");
            try wr.put(digits[1..]);
        }
        var eb: [16]u8 = undefined;
        const e_txt = std.fmt.bufPrint(&eb, "e{s}{d}", .{ if (e < 0) "-" else "+", @abs(e) }) catch return Error.BufferTooSmall;
        try wr.put(e_txt);
    }

    return buf[0..w];
}

// ----------------------------------------------------------------------------
// Zero-Allocation JSON Parser (Constructs AST in FixedBufferAllocator)
// ----------------------------------------------------------------------------

pub const Parser = struct {
    allocator: std.mem.Allocator,
    input: []const u8,
    pos: usize = 0,
    depth: usize = 0,

    pub fn init(allocator: std.mem.Allocator, input: []const u8) Parser {
        return .{
            .allocator = allocator,
            .input = input,
            .pos = 0,
        };
    }

    fn skipWhitespace(self: *Parser) void {
        while (self.pos < self.input.len) {
            const c = self.input[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peekChar(self: *Parser) ?u8 {
        self.skipWhitespace();
        if (self.pos >= self.input.len) return null;
        return self.input[self.pos];
    }

    pub fn parseValue(self: *Parser) Error!Value {
        const c = self.peekChar() orelse return Error.UnexpectedToken;
        switch (c) {
            'n' => return self.parseNull(),
            't', 'f' => return self.parseBool(),
            '"' => {
                const str = try self.parseString();
                return Value{ .string = str };
            },
            '-', '0'...'9' => return self.parseNumber(),
            '[', '{' => {
                if (self.depth >= max_depth) return Error.TooDeep;
                self.depth += 1;
                defer self.depth -= 1;
                return if (c == '[') self.parseArray() else self.parseObject();
            },
            else => return Error.UnexpectedToken,
        }
    }

    fn parseNull(self: *Parser) Error!Value {
        self.skipWhitespace();
        if (self.pos + 4 <= self.input.len and std.mem.eql(u8, self.input[self.pos..][0..4], "null")) {
            self.pos += 4;
            return Value{ .null_val = {} };
        }
        return Error.InvalidJson;
    }

    fn parseBool(self: *Parser) Error!Value {
        self.skipWhitespace();
        if (self.pos + 4 <= self.input.len and std.mem.eql(u8, self.input[self.pos..][0..4], "true")) {
            self.pos += 4;
            return Value{ .bool_val = true };
        }
        if (self.pos + 5 <= self.input.len and std.mem.eql(u8, self.input[self.pos..][0..5], "false")) {
            self.pos += 5;
            return Value{ .bool_val = false };
        }
        return Error.InvalidJson;
    }

    fn parseHex4(slice: []const u8) ?u16 {
        if (slice.len < 4) return null;
        var val: u16 = 0;
        for (slice[0..4]) |c| {
            val <<= 4;
            if (c >= '0' and c <= '9') {
                val |= (c - '0');
            } else if (c >= 'a' and c <= 'f') {
                val |= (c - 'a' + 10);
            } else if (c >= 'A' and c <= 'F') {
                val |= (c - 'A' + 10);
            } else {
                return null;
            }
        }
        return val;
    }

    fn parseString(self: *Parser) Error![]const u8 {
        self.skipWhitespace();
        if (self.pos >= self.input.len or self.input[self.pos] != '"') return Error.UnexpectedToken;
        self.pos += 1; // skip opening quote

        var unescaped_list: std.ArrayListUnmanaged(u8) = .empty;
        errdefer unescaped_list.deinit(self.allocator);

        while (self.pos < self.input.len) {
            const c = self.input[self.pos];
            if (c == '"') {
                self.pos += 1;
                return unescaped_list.toOwnedSlice(self.allocator) catch return Error.OutOfMemory;
            } else if (c == '\\') {
                self.pos += 1;
                if (self.pos >= self.input.len) return Error.InvalidJson;
                const esc = self.input[self.pos];
                self.pos += 1;
                switch (esc) {
                    '"' => try unescaped_list.append(self.allocator, '"'),
                    '\\' => try unescaped_list.append(self.allocator, '\\'),
                    '/' => try unescaped_list.append(self.allocator, '/'),
                    'b' => try unescaped_list.append(self.allocator, 0x08),
                    'f' => try unescaped_list.append(self.allocator, 0x0C),
                    'n' => try unescaped_list.append(self.allocator, 0x0A),
                    'r' => try unescaped_list.append(self.allocator, 0x0D),
                    't' => try unescaped_list.append(self.allocator, 0x09),
                    'u' => {
                        if (self.pos + 4 > self.input.len) return Error.InvalidUnicode;
                        const hex1 = parseHex4(self.input[self.pos..][0..4]) orelse return Error.InvalidUnicode;
                        self.pos += 4;

                        // Check surrogate pair
                        if (hex1 >= 0xD800 and hex1 <= 0xDBFF) {
                            if (self.pos + 6 > self.input.len or self.input[self.pos] != '\\' or self.input[self.pos + 1] != 'u') {
                                return Error.InvalidUnicode;
                            }
                            self.pos += 2;
                            const hex2 = parseHex4(self.input[self.pos..][0..4]) orelse return Error.InvalidUnicode;
                            self.pos += 4;
                            if (hex2 < 0xDC00 or hex2 > 0xDFFF) return Error.InvalidUnicode;

                            const cp: u21 = 0x10000 + ((@as(u21, hex1) - 0xD800) << 10) + (@as(u21, hex2) - 0xDC00);
                            var utf8_buf: [4]u8 = undefined;
                            const len = std.unicode.utf8Encode(cp, &utf8_buf) catch return Error.InvalidUnicode;
                            try unescaped_list.appendSlice(self.allocator, utf8_buf[0..len]);
                        } else if (hex1 >= 0xDC00 and hex1 <= 0xDFFF) {
                            // Lone low surrogate
                            return Error.InvalidUnicode;
                        } else {
                            var utf8_buf: [4]u8 = undefined;
                            const len = std.unicode.utf8Encode(hex1, &utf8_buf) catch return Error.InvalidUnicode;
                            try unescaped_list.appendSlice(self.allocator, utf8_buf[0..len]);
                        }
                    },
                    else => return Error.InvalidJson,
                }
            } else if (c < 0x20) {
                // Raw control characters must be escaped in JSON strings
                return Error.InvalidJson;
            } else {
                try unescaped_list.append(self.allocator, c);
                self.pos += 1;
            }
        }
        return Error.InvalidJson;
    }

    /// Strict RFC 8259 number grammar: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?
    fn parseNumber(self: *Parser) Error!Value {
        self.skipWhitespace();
        const start = self.pos;
        const in = self.input;
        var p = self.pos;

        if (p < in.len and in[p] == '-') p += 1;
        if (p >= in.len) return Error.InvalidNumber;
        if (in[p] == '0') {
            p += 1;
        } else if (in[p] >= '1' and in[p] <= '9') {
            while (p < in.len and in[p] >= '0' and in[p] <= '9') p += 1;
        } else {
            return Error.InvalidNumber;
        }
        if (p < in.len and in[p] == '.') {
            p += 1;
            const frac_start = p;
            while (p < in.len and in[p] >= '0' and in[p] <= '9') p += 1;
            if (p == frac_start) return Error.InvalidNumber;
        }
        if (p < in.len and (in[p] == 'e' or in[p] == 'E')) {
            p += 1;
            if (p < in.len and (in[p] == '+' or in[p] == '-')) p += 1;
            const exp_start = p;
            while (p < in.len and in[p] >= '0' and in[p] <= '9') p += 1;
            if (p == exp_start) return Error.InvalidNumber;
        }

        self.pos = p;
        const val = std.fmt.parseFloat(f64, in[start..p]) catch return Error.InvalidNumber;
        if (std.math.isInf(val)) return Error.InvalidNumber;
        return Value{ .number = val };
    }

    fn parseArray(self: *Parser) Error!Value {
        self.skipWhitespace();
        if (self.pos >= self.input.len or self.input[self.pos] != '[') return Error.UnexpectedToken;
        self.pos += 1;

        var list: std.ArrayListUnmanaged(Value) = .empty;
        errdefer list.deinit(self.allocator);

        self.skipWhitespace();
        if (self.pos < self.input.len and self.input[self.pos] == ']') {
            self.pos += 1;
            return Value{ .array = list.toOwnedSlice(self.allocator) catch return Error.OutOfMemory };
        }

        while (true) {
            const elem = try self.parseValue();
            try list.append(self.allocator, elem);

            self.skipWhitespace();
            if (self.pos < self.input.len and self.input[self.pos] == ',') {
                self.pos += 1;
            } else if (self.pos < self.input.len and self.input[self.pos] == ']') {
                self.pos += 1;
                break;
            } else {
                return Error.InvalidJson;
            }
        }

        return Value{ .array = list.toOwnedSlice(self.allocator) catch return Error.OutOfMemory };
    }

    fn parseObject(self: *Parser) Error!Value {
        self.skipWhitespace();
        if (self.pos >= self.input.len or self.input[self.pos] != '{') return Error.UnexpectedToken;
        self.pos += 1;

        var members: std.ArrayListUnmanaged(Member) = .empty;
        errdefer members.deinit(self.allocator);

        self.skipWhitespace();
        if (self.pos < self.input.len and self.input[self.pos] == '}') {
            self.pos += 1;
            return Value{ .object = members.toOwnedSlice(self.allocator) catch return Error.OutOfMemory };
        }

        while (true) {
            const key = try self.parseString();

            self.skipWhitespace();
            if (self.pos >= self.input.len or self.input[self.pos] != ':') return Error.InvalidJson;
            self.pos += 1; // skip ':'

            const val = try self.parseValue();
            try members.append(self.allocator, .{ .name = key, .value = val });

            self.skipWhitespace();
            if (self.pos < self.input.len and self.input[self.pos] == ',') {
                self.pos += 1;
            } else if (self.pos < self.input.len and self.input[self.pos] == '}') {
                self.pos += 1;
                break;
            } else {
                return Error.InvalidJson;
            }
        }

        const slice = members.toOwnedSlice(self.allocator) catch return Error.OutOfMemory;
        sortMembers(slice);
        // Duplicate names make the signed document ambiguous between parsers; reject them.
        if (slice.len > 1) {
            for (slice[1..], 0..) |m, i| {
                if (std.mem.eql(u8, m.name, slice[i].name)) return Error.DuplicateKey;
            }
        }
        return Value{ .object = slice };
    }
};

// ----------------------------------------------------------------------------
// Canonical Serializer (RFC 8785)
// ----------------------------------------------------------------------------

pub const Serializer = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn init(buffer: []u8) Serializer {
        return .{
            .buffer = buffer,
            .offset = 0,
        };
    }

    fn writeByte(self: *Serializer, byte: u8) Error!void {
        if (self.offset >= self.buffer.len) return Error.BufferTooSmall;
        self.buffer[self.offset] = byte;
        self.offset += 1;
    }

    fn writeSlice(self: *Serializer, slice: []const u8) Error!void {
        if (self.offset + slice.len > self.buffer.len) return Error.BufferTooSmall;
        @memcpy(self.buffer[self.offset..][0..slice.len], slice);
        self.offset += slice.len;
    }

    pub fn serialize(self: *Serializer, val: Value) Error!void {
        switch (val) {
            .null_val => try self.writeSlice("null"),
            .bool_val => |b| {
                if (b) {
                    try self.writeSlice("true");
                } else {
                    try self.writeSlice("false");
                }
            },
            .number => |num| {
                var num_buf: [128]u8 = undefined;
                const formatted = try formatEcmaNumber(&num_buf, num);
                try self.writeSlice(formatted);
            },
            .string => |str| {
                try self.serializeString(str);
            },
            .array => |arr| {
                try self.writeByte('[');
                for (arr, 0..) |elem, i| {
                    if (i > 0) try self.writeByte(',');
                    try self.serialize(elem);
                }
                try self.writeByte(']');
            },
            .object => |members| {
                try self.writeByte('{');
                for (members, 0..) |m, i| {
                    if (i > 0) try self.writeByte(',');
                    try self.serializeString(m.name);
                    try self.writeByte(':');
                    try self.serialize(m.value);
                }
                try self.writeByte('}');
            },
        }
    }

    fn serializeString(self: *Serializer, str: []const u8) Error!void {
        try self.writeByte('"');
        var i: usize = 0;
        while (i < str.len) : (i += 1) {
            const b = str[i];
            switch (b) {
                '"' => try self.writeSlice("\\\""),
                '\\' => try self.writeSlice("\\\\"),
                0x08 => try self.writeSlice("\\b"),
                0x0C => try self.writeSlice("\\f"),
                0x0A => try self.writeSlice("\\n"),
                0x0D => try self.writeSlice("\\r"),
                0x09 => try self.writeSlice("\\t"),
                0x00...0x07, 0x0B, 0x0E...0x1F => {
                    var hex_buf: [6]u8 = undefined;
                    const hex_str = std.fmt.bufPrint(&hex_buf, "\\u00{x:0>2}", .{b}) catch return Error.BufferTooSmall;
                    try self.writeSlice(hex_str);
                },
                else => try self.writeByte(b),
            }
        }
        try self.writeByte('"');
    }
};

/// Fully zero-allocation Canonicalization function.
/// Parses and sorts JSON in stack-allocated FixedBufferAllocator and outputs canonical UTF-8 bytes.
pub fn canonicalize(allocator: std.mem.Allocator, input_json: []const u8, out_buf: []u8) Error![]const u8 {
    if (!std.unicode.utf8ValidateSlice(input_json)) return Error.InvalidUnicode;
    var parser = Parser.init(allocator, input_json);
    const ast = try parser.parseValue();
    parser.skipWhitespace();
    if (parser.pos != input_json.len) return Error.UnexpectedToken;
    var serializer = Serializer.init(out_buf);
    try serializer.serialize(ast);
    return serializer.buffer[0..serializer.offset];
}

/// Hashes the canonical JSON using SHA-256 and signs the 32-byte digest using Ed25519.
pub fn signCanonical(
    canonical_json: []const u8,
    secret_key_bytes: [32]u8,
) ![64]u8 {
    // 1. SHA-256 hash of the canonical JSON string
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_json, &hash, .{});

    // 2. Derive Ed25519 KeyPair deterministically from 32-byte secret seed
    const key_pair = try Ed25519.KeyPair.generateDeterministic(secret_key_bytes);

    // 3. Sign the 32-byte digest deterministically
    const sig = try key_pair.sign(&hash, null);

    return sig.toBytes();
}

// ----------------------------------------------------------------------------
// Tests: Verified against RFC 8785 Standard Test Vectors
// ----------------------------------------------------------------------------

test "RFC 8785 Section 3.2.2 & 3.2.3 canonicalization test vector" {
    var stack_buf: [32768]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    const input =
        \\{
        \\  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
        \\  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\\\"\/",
        \\  "literals": [null, true, false]
        \\}
    ;

    var out_buf: [4096]u8 = undefined;
    const result = try canonicalize(allocator, input, &out_buf);

    const expected =
        \\{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\\\"/"}
    ;

    try std.testing.expectEqualStrings(expected, result);
}

test "RFC 8785 Section 3.2.3 UTF-16 code unit property sorting test vector" {
    var stack_buf: [32768]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    const input =
        \\{
        \\  "\u20ac": "Euro Sign",
        \\  "\r": "Carriage Return",
        \\  "\ufb33": "Hebrew Letter Dalet With Dagesh",
        \\  "1": "One",
        \\  "\ud83d\ude00": "Emoji: Grinning Face",
        \\  "\u0080": "Control",
        \\  "\u00f6": "Latin Small Letter O With Diaeresis"
        \\}
    ;

    var out_buf: [4096]u8 = undefined;
    const result = try canonicalize(allocator, input, &out_buf);

    // Expected order: \r, 1, \u0080, \u00f6, \u20ac, 😀 (\ud83d\ude00), \ufb33
    // Note per RFC 8785 §3.2.2.2, U+0080 is outside U+0000..U+001F so it is serialized as raw UTF-8 (0xC2, 0x80)
    const expected =
        "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{0080}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}";

    try std.testing.expectEqualStrings(expected, result);
}

test "JCS signCanonical and verify" {
    const canonical_json = "{\"credentialSubject\":{\"id\":\"did:peaq:drone-01\",\"stationId\":\"station-99\"},\"type\":\"VerifiableCredential\"}";
    const seed: [32]u8 = [_]u8{0x77} ** 32;

    const sig_bytes = try signCanonical(canonical_json, seed);
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);

    // Verify against SHA-256 hash of canonical_json
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_json, &digest, .{});

    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    try sig.verify(&digest, key_pair.public_key);
}

test "formatEcmaNumber follows ECMAScript Number::toString" {
    var buf: [64]u8 = undefined;
    const cases = [_]struct { v: f64, s: []const u8 }{
        .{ .v = 0.0, .s = "0" },
        .{ .v = -0.0, .s = "0" },
        .{ .v = 1.0, .s = "1" },
        .{ .v = -1.5, .s = "-1.5" },
        .{ .v = 0.000001, .s = "0.000001" },
        .{ .v = 0.0000001, .s = "1e-7" },
        .{ .v = -4.7287639067508275e-6, .s = "-0.0000047287639067508275" },
        .{ .v = 123456789012345680000.0, .s = "123456789012345680000" },
        .{ .v = 1e21, .s = "1e+21" },
        .{ .v = 1.5e300, .s = "1.5e+300" },
        .{ .v = 5e-324, .s = "5e-324" },
        .{ .v = 9007199254740992.0, .s = "9007199254740992" },
        .{ .v = 333333333.33333329, .s = "333333333.3333333" },
    };
    for (cases) |c| try std.testing.expectEqualStrings(c.s, try formatEcmaNumber(&buf, c.v));
    try std.testing.expectError(Error.InvalidNumber, formatEcmaNumber(&buf, std.math.inf(f64)));
}

test "canonicalize rejects ambiguous or malformed documents" {
    var stack_buf: [8192]u8 = undefined;
    var out: [1024]u8 = undefined;
    const bad = [_][]const u8{ "[1,]", "{\"a\":1,}", "{\"a\":1,\"a\":2}", "[01]", "[1.]", "{} x", "\"a\tb\"", "\"\\ud800\"" };
    for (bad) |doc| {
        var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
        try std.testing.expect(std.meta.isError(canonicalize(fba.allocator(), doc, &out)));
    }
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    try std.testing.expectError(Error.InvalidUnicode, canonicalize(fba.allocator(), "\"\xff\"", &out));
}

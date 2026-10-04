const std = @import("std");
const did0 = @import("did0.zig");

const napi_env = ?*opaque {};
const napi_value = ?*opaque {};
const napi_callback_info = ?*opaque {};

const napi_valuetype = enum(c_int) {
    napi_undefined,
    napi_null,
    napi_boolean,
    napi_number,
    napi_string,
    napi_symbol,
    napi_object,
    napi_function,
    napi_external,
    napi_bigint,
};

extern "c" fn napi_get_cb_info(env: napi_env, info: napi_callback_info, argc: *usize, argv: [*]napi_value, this_arg: ?*napi_value, data: ?*anyopaque) c_int;
extern "c" fn napi_get_value_string_utf8(env: napi_env, value: napi_value, buf: ?[*]u8, bufsize: usize, result: *usize) c_int;
extern "c" fn napi_get_value_double(env: napi_env, value: napi_value, result: *f64) c_int;
extern "c" fn napi_create_string_utf8(env: napi_env, str: [*]const u8, length: usize, result: *napi_value) c_int;
extern "c" fn napi_create_object(env: napi_env, result: *napi_value) c_int;
extern "c" fn napi_create_function(env: napi_env, utf8name: ?[*]const u8, length: usize, cb: *const fn (napi_env, napi_callback_info) callconv(.c) napi_value, data: ?*anyopaque, result: *napi_value) c_int;
extern "c" fn napi_set_named_property(env: napi_env, object: napi_value, utf8name: [*]const u8, value: napi_value) c_int;
extern "c" fn napi_get_named_property(env: napi_env, object: napi_value, utf8name: [*]const u8, result: *napi_value) c_int;
extern "c" fn napi_throw_error(env: napi_env, code: ?[*]const u8, msg: [*]const u8) c_int;
extern "c" fn napi_get_boolean(env: napi_env, value: bool, result: *napi_value) c_int;
extern "c" fn napi_create_buffer_copy(env: napi_env, length: usize, data: [*]const u8, result_data: ?*?*anyopaque, result: *napi_value) c_int;
extern "c" fn napi_typeof(env: napi_env, value: napi_value, result: *napi_valuetype) c_int;
extern "c" fn napi_get_global(env: napi_env, result: *napi_value) c_int;
extern "c" fn napi_call_function(env: napi_env, recv: napi_value, func: napi_value, argc: usize, argv: [*]const napi_value, result: *napi_value) c_int;
extern "c" fn napi_is_buffer(env: napi_env, value: napi_value, result: *bool) c_int;
extern "c" fn napi_get_buffer_info(env: napi_env, value: napi_value, data: *?*anyopaque, length: *usize) c_int;

const base58 = did0.base58;

fn throw(env: napi_env, code: [:0]const u8, msg: [:0]const u8) napi_value {
    _ = napi_throw_error(env, code.ptr, msg.ptr);
    return null;
}

fn typeOf(env: napi_env, val: napi_value) napi_valuetype {
    var t: napi_valuetype = .napi_undefined;
    if (napi_typeof(env, val, &t) != 0) return .napi_undefined;
    return t;
}

/// Reads a JS string into `buf`. Returns null if the value is not a string or if it does not
/// fit (never truncates silently, which would corrupt payloads and on-chain attributes).
fn readString(env: napi_env, val: napi_value, buf: []u8) ?[]u8 {
    if (typeOf(env, val) != .napi_string) return null;
    var needed: usize = 0;
    if (napi_get_value_string_utf8(env, val, null, 0, &needed) != 0) return null;
    if (needed >= buf.len) return null;
    var n: usize = 0;
    if (napi_get_value_string_utf8(env, val, buf.ptr, buf.len, &n) != 0 or n != needed) return null;
    return buf[0..n];
}

/// Reads a JS number that is an exact integer in 0..2^32-1 (no wrapping of negatives or fractions).
fn readU32(env: napi_env, val: napi_value) ?u32 {
    if (typeOf(env, val) != .napi_number) return null;
    var d: f64 = 0;
    if (napi_get_value_double(env, val, &d) != 0) return null;
    if (!(d >= 0 and d <= 4294967295.0) or d != @floor(d)) return null;
    return @intFromFloat(d);
}

/// `null`/`undefined` map to `None`; a number maps to `Some(n)`; anything else is an error.
fn readOptionalU32(env: napi_env, val: napi_value) error{InvalidArgument}!?u32 {
    switch (typeOf(env, val)) {
        .napi_undefined, .napi_null => return null,
        else => return readU32(env, val) orelse error.InvalidArgument,
    }
}

fn readU8(env: napi_env, val: napi_value) ?u8 {
    const v = readU32(env, val) orelse return null;
    if (v > 255) return null;
    return @intCast(v);
}

/// Reads a 64-character hex string as a 32-byte AccountId.
fn readAccountId(env: napi_env, val: napi_value) ?[32]u8 {
    var hex: [65]u8 = undefined;
    const s = readString(env, val, &hex) orelse return null;
    if (s.len != 64) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch return null;
    return out;
}

fn extractJsonString(env: napi_env, val: napi_value, buf: []u8) ![]const u8 {
    var target_str_val = val;

    if (typeOf(env, val) == .napi_object) {
        var global: napi_value = null;
        if (napi_get_global(env, &global) != 0) return error.NapiError;

        var json_obj: napi_value = null;
        if (napi_get_named_property(env, global, "JSON", &json_obj) != 0) return error.NapiError;

        var stringify_fn: napi_value = null;
        if (napi_get_named_property(env, json_obj, "stringify", &stringify_fn) != 0) return error.NapiError;

        const args = [1]napi_value{val};
        if (napi_call_function(env, json_obj, stringify_fn, 1, &args, &target_str_val) != 0) return error.NapiError;
    }

    return readString(env, target_str_val, buf) orelse error.NapiError;
}

/// Decodes a private key given as 64-char hex (seed), 128-char hex (seed ++ pubkey),
/// or base58 (optionally `z`-prefixed) of 32 or 64 bytes. Only the first 32 bytes (the seed) are used.
fn decodePrivateKeyBytes(input: []const u8) ![32]u8 {
    var seed: [32]u8 = undefined;

    if (input.len == 64) {
        _ = std.fmt.hexToBytes(&seed, input) catch return error.InvalidPrivateKey;
        return seed;
    }

    if (input.len == 128) {
        var sk64: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &sk64);
        _ = std.fmt.hexToBytes(&sk64, input) catch return error.InvalidPrivateKey;
        @memcpy(&seed, sk64[0..32]);
        return seed;
    }

    var buf: [96]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    const candidates = [2][]const u8{ input, if (input.len > 1 and input[0] == 'z') input[1..] else input };
    for (candidates) |cand| {
        const raw = base58.decode(&buf, cand) catch continue;
        if (raw.len == 32 or raw.len == 64) {
            @memcpy(&seed, raw[0..32]);
            return seed;
        }
    }
    return error.InvalidPrivateKey;
}

export fn parseDID_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 1) {
        return throw(env, "ERR_INVALID_ARGS", "Expected a JSON string argument");
    }

    var raw_input: [4096]u8 = undefined;
    const payload = readString(env, argv[0], &raw_input) orelse {
        return throw(env, "ERR_INVALID_ARGS", "Expected a JSON string of at most 4095 bytes");
    };

    var parser_buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&parser_buffer);
    const stack_allocator = fba.allocator();

    const doc = did0.peaq.parse(stack_allocator, payload) catch {
        return throw(env, "ERR_PARSE_FAILED", "Failed to parse W3C DID document");
    };

    var js_doc: napi_value = null;
    _ = napi_create_object(env, &js_doc);

    var id_val: napi_value = null;
    _ = napi_create_string_utf8(env, doc.id.ptr, doc.id.len, &id_val);
    _ = napi_set_named_property(env, js_doc, "id", id_val);

    if (doc.verificationMethod) |methods| {
        if (methods.len > 0 and methods[0].publicKeyMultibase != null) {
            const pk = methods[0].publicKeyMultibase.?;
            var pk_val: napi_value = null;
            _ = napi_create_string_utf8(env, pk.ptr, pk.len, &pk_val);
            _ = napi_set_named_property(env, js_doc, "publicKeyMultibase", pk_val);
        }
    }

    return js_doc;
}

const VerifyMode = enum { raw, digest };

fn verifyBinding(env: napi_env, info: napi_callback_info, comptime mode: VerifyMode) napi_value {
    var argc: usize = 3;
    var argv: [3]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 3) {
        return throw(env, "ERR_INVALID_ARGS", "Expected (publicKeyMultibase, message, signatureHex)");
    }

    var pk_buf: [128]u8 = undefined;
    const pk_str = readString(env, argv[0], &pk_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "publicKeyMultibase must be a string");
    };

    // The message may be a string or a Buffer. Strings are copied into a bounded buffer;
    // Buffers are read in place.
    var msg_buf: [65536]u8 = undefined;
    var message: []const u8 = undefined;
    var is_buf = false;
    _ = napi_is_buffer(env, argv[1], &is_buf);
    if (is_buf) {
        var raw_data: ?*anyopaque = null;
        var msg_len: usize = 0;
        if (napi_get_buffer_info(env, argv[1], &raw_data, &msg_len) != 0) {
            return throw(env, "ERR_INVALID_ARGS", "Failed to read message buffer");
        }
        if (msg_len == 0) {
            message = "";
        } else {
            const ptr: [*]const u8 = @ptrCast(raw_data orelse return throw(env, "ERR_INVALID_ARGS", "Failed to read message buffer"));
            message = ptr[0..msg_len];
        }
    } else {
        message = readString(env, argv[1], &msg_buf) orelse {
            return throw(env, "ERR_INVALID_ARGS", "message must be a string under 64 KiB or a Buffer");
        };
    }

    var sig_hex_buf: [129]u8 = undefined;
    const sig_hex = readString(env, argv[2], &sig_hex_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "signatureHex must be a string");
    };

    const pub_key = did0.peaq.decodePublicKey(pk_str) catch {
        return throw(env, "ERR_CRYPTO", "Invalid multibase Ed25519 public key (expected 32 bytes, optionally with the 0xed01 multicodec prefix)");
    };

    if (sig_hex.len != 128) {
        return throw(env, "ERR_CRYPTO", "Expected 128-character hex string for 64-byte signature");
    }
    var sig_bytes: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&sig_bytes, sig_hex) catch {
        return throw(env, "ERR_CRYPTO", "Invalid hex in signature");
    };

    var is_valid = true;
    const verify_fn = switch (mode) {
        .raw => did0.peaq.verifySignature,
        .digest => did0.peaq.verifyDigestSignature,
    };
    verify_fn(pub_key, sig_bytes, message) catch {
        is_valid = false;
    };

    var result: napi_value = null;
    _ = napi_get_boolean(env, is_valid, &result);
    return result;
}

/// Verifies an Ed25519 signature over the raw message bytes.
export fn verifySignature_binding(env: napi_env, info: napi_callback_info) napi_value {
    return verifyBinding(env, info, .raw);
}

/// Verifies an Ed25519 signature over SHA-256(message), the scheme used by `issueCredential`.
export fn verifyDigestSignature_binding(env: napi_env, info: napi_callback_info) napi_value {
    return verifyBinding(env, info, .digest);
}

export fn encodeDidAttribute_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 4;
    var argv: [4]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 4) {
        return throw(env, "ERR_INVALID_ARGS", "Expected (didAccountHex, name, value, validityBlocks)");
    }

    const account_bytes = readAccountId(env, argv[0]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "Expected 64-character hex string for 32-byte Account ID");
    };

    var name_buf: [256]u8 = undefined;
    const name = readString(env, argv[1], &name_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "name must be a string of at most 255 bytes");
    };

    var val_buf: [8192]u8 = undefined;
    const value = readString(env, argv[2], &val_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "value must be a string of at most 8191 bytes");
    };

    const validity = readOptionalU32(env, argv[3]) catch {
        return throw(env, "ERR_INVALID_ARGS", "validityBlocks must be a uint32, or null/undefined for no expiry");
    };

    var stack_buf: [16384]u8 = undefined;
    const attr = did0.scale.DidAttribute{
        .did_account = account_bytes,
        .name = name,
        .value = value,
        .validity = validity,
    };

    const encoded = did0.scale.encodeDidAttribute(&stack_buf, attr) catch {
        return throw(env, "ERR_ENCODE_FAILED", "Buffer overflow during SCALE encoding");
    };

    var result: napi_value = null;
    _ = napi_create_buffer_copy(env, encoded.len, encoded.ptr, null, &result);
    return result;
}

export fn encodeAddAttributeCall_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 6;
    var argv: [6]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 6) {
        return throw(env, "ERR_INVALID_ARGS", "Expected (palletIndex, callIndex, didAccountHex, name, value, validityBlocks)");
    }

    const pallet_index = readU8(env, argv[0]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "palletIndex must be an integer in 0..255");
    };
    const call_index = readU8(env, argv[1]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "callIndex must be an integer in 0..255");
    };

    const account_bytes = readAccountId(env, argv[2]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "Expected 64-character hex string for 32-byte Account ID");
    };

    var name_buf: [256]u8 = undefined;
    const name = readString(env, argv[3], &name_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "name must be a string of at most 255 bytes");
    };

    var val_buf: [8192]u8 = undefined;
    const value = readString(env, argv[4], &val_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "value must be a string of at most 8191 bytes");
    };

    const validity = readOptionalU32(env, argv[5]) catch {
        return throw(env, "ERR_INVALID_ARGS", "validityBlocks must be a uint32, or null/undefined for no expiry");
    };

    var stack_buf: [16384]u8 = undefined;
    const call_bytes = did0.scale.encodeAddAttributeCall(
        &stack_buf,
        pallet_index,
        call_index,
        account_bytes,
        name,
        value,
        validity,
    ) catch {
        return throw(env, "ERR_ENCODE_FAILED", "Buffer overflow during SCALE extrinsic call encoding");
    };

    var result: napi_value = null;
    _ = napi_create_buffer_copy(env, call_bytes.len, call_bytes.ptr, null, &result);
    return result;
}

export fn encodeUpdateAttributeCall_binding(env: napi_env, info: napi_callback_info) napi_value {
    return encodeAddAttributeCall_binding(env, info);
}

export fn encodeRemoveAttributeCall_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 4;
    var argv: [4]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 4) {
        return throw(env, "ERR_INVALID_ARGS", "Expected (palletIndex, callIndex, didAccountHex, name)");
    }

    const pallet_index = readU8(env, argv[0]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "palletIndex must be an integer in 0..255");
    };
    const call_index = readU8(env, argv[1]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "callIndex must be an integer in 0..255");
    };

    const account_bytes = readAccountId(env, argv[2]) orelse {
        return throw(env, "ERR_INVALID_ARGS", "Expected 64-character hex string for 32-byte Account ID");
    };

    var name_buf: [256]u8 = undefined;
    const name = readString(env, argv[3], &name_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "name must be a string of at most 255 bytes");
    };

    var stack_buf: [16384]u8 = undefined;
    const call_bytes = did0.scale.encodeRemoveAttributeCall(
        &stack_buf,
        pallet_index,
        call_index,
        account_bytes,
        name,
    ) catch {
        return throw(env, "ERR_ENCODE_FAILED", "Buffer overflow during SCALE extrinsic call encoding");
    };

    var result: napi_value = null;
    _ = napi_create_buffer_copy(env, call_bytes.len, call_bytes.ptr, null, &result);
    return result;
}

export fn canonicalize_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 1) {
        return throw(env, "ERR_INVALID_ARGS", "Expected (payload)");
    }

    var raw_input: [65536]u8 = undefined;
    const json_str = extractJsonString(env, argv[0], &raw_input) catch {
        return throw(env, "ERR_INVALID_ARGS", "Payload must be a JSON string or object under 64 KiB");
    };

    var stack_buf: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const stack_allocator = fba.allocator();

    var out_buf: [65536]u8 = undefined;
    const canon = did0.jcs.canonicalize(stack_allocator, json_str, &out_buf) catch |err| {
        return throw(env, "ERR_CANONICALIZE", @errorName(err));
    };

    var result: napi_value = null;
    _ = napi_create_string_utf8(env, canon.ptr, canon.len, &result);
    return result;
}

export fn issueCredential_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 2;
    var argv: [2]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 2) {
        return throw(env, "ERR_INVALID_ARGS", "Expected (payload, privateKeyHexOrBase58)");
    }

    var raw_input: [65536]u8 = undefined;
    const json_str = extractJsonString(env, argv[0], &raw_input) catch {
        return throw(env, "ERR_INVALID_ARGS", "Payload must be a JSON string or object under 64 KiB");
    };

    var key_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_buf);
    const key_str = readString(env, argv[1], &key_buf) orelse {
        return throw(env, "ERR_INVALID_ARGS", "Expected private key string");
    };
    if (key_str.len == 0) return throw(env, "ERR_INVALID_ARGS", "Expected private key string");

    var priv_key = decodePrivateKeyBytes(key_str) catch {
        return throw(env, "ERR_INVALID_KEY", "Invalid private key format (expected 32/64-byte hex or base58)");
    };
    defer std.crypto.secureZero(u8, &priv_key);

    var stack_buf: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const stack_allocator = fba.allocator();

    var out_buf: [65536]u8 = undefined;
    const canon = did0.jcs.canonicalize(stack_allocator, json_str, &out_buf) catch |err| {
        return throw(env, "ERR_CANONICALIZE", @errorName(err));
    };

    const sig_bytes = did0.jcs.signCanonical(canon, priv_key) catch |err| {
        return throw(env, "ERR_SIGN", @errorName(err));
    };

    const sig_hex = std.fmt.bytesToHex(sig_bytes, .lower);

    var result: napi_value = null;
    _ = napi_create_string_utf8(env, &sig_hex, sig_hex.len, &result);
    return result;
}

export fn generateMnemonic_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;
    _ = napi_get_cb_info(env, info, &argc, &argv, null, null);

    var word_count: usize = 12;
    if (argc >= 1 and typeOf(env, argv[0]) != .napi_undefined) {
        const wc = readU32(env, argv[0]) orelse 0;
        if (wc != 12 and wc != 24) {
            return throw(env, "ERR_INVALID_ARGS", "wordCount must be 12 or 24");
        }
        word_count = wc;
    }

    var m_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &m_buf);
    const mnemonic = did0.wallet.generateRandomMnemonic(&m_buf, word_count) catch {
        return throw(env, "ERR_ENTROPY", "Failed to generate random mnemonic");
    };

    var result: napi_value = null;
    _ = napi_create_string_utf8(env, mnemonic.ptr, mnemonic.len, &result);
    return result;
}

export fn validateMnemonic_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;
    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 1) {
        return throw(env, "ERR_INVALID_ARGS", "Expected mnemonic string");
    }

    var m_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &m_buf);
    // An over-long or non-string value is simply not a valid mnemonic.
    const is_valid = if (readString(env, argv[0], &m_buf)) |m| did0.wallet.validateMnemonic(m) else false;

    var result: napi_value = null;
    _ = napi_get_boolean(env, is_valid, &result);
    return result;
}

export fn createWallet_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 3;
    var argv: [3]napi_value = undefined;
    _ = napi_get_cb_info(env, info, &argc, &argv, null, null);

    var stack_buf: [16384]u8 = undefined;
    defer std.crypto.secureZero(u8, &stack_buf);
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    var pass_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &pass_buf);
    var passphrase: []const u8 = "";
    if (argc >= 1 and typeOf(env, argv[0]) != .napi_undefined) {
        passphrase = readString(env, argv[0], &pass_buf) orelse {
            return throw(env, "ERR_INVALID_ARGS", "passphrase must be a string of at most 247 bytes");
        };
    }

    var m_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &m_buf);
    var mnemonic: []const u8 = "";
    if (argc >= 2 and typeOf(env, argv[1]) != .napi_undefined) {
        mnemonic = readString(env, argv[1], &m_buf) orelse {
            return throw(env, "ERR_INVALID_ARGS", "mnemonic must be a string of at most 511 bytes");
        };
    }

    var ss58_prefix: u16 = did0.wallet.default_ss58_prefix;
    if (argc >= 3 and typeOf(env, argv[2]) != .napi_undefined) {
        const p = readU32(env, argv[2]) orelse 0xffff_ffff;
        if (p >= 16384) return throw(env, "ERR_INVALID_ARGS", "ss58Prefix must be an integer in 0..16383");
        ss58_prefix = @intCast(p);
    }

    var w = (if (mnemonic.len > 0)
        did0.wallet.createWalletFromMnemonic(allocator, mnemonic, passphrase, ss58_prefix)
    else
        did0.wallet.createWallet(allocator, passphrase, 12, ss58_prefix)) catch |err| {
        return throw(env, "ERR_WALLET", @errorName(err));
    };
    defer std.crypto.secureZero(u8, &w.private_key_hex);

    var js_obj: napi_value = null;
    _ = napi_create_object(env, &js_obj);

    var m_val: napi_value = null;
    _ = napi_create_string_utf8(env, w.mnemonic.ptr, w.mnemonic.len, &m_val);
    _ = napi_set_named_property(env, js_obj, "mnemonic", m_val);

    var priv_val: napi_value = null;
    _ = napi_create_string_utf8(env, &w.private_key_hex, w.private_key_hex.len, &priv_val);
    _ = napi_set_named_property(env, js_obj, "privateKeyHex", priv_val);

    var pub_val: napi_value = null;
    _ = napi_create_string_utf8(env, &w.public_key_hex, w.public_key_hex.len, &pub_val);
    _ = napi_set_named_property(env, js_obj, "publicKeyHex", pub_val);

    var mb_val: napi_value = null;
    _ = napi_create_string_utf8(env, w.public_key_multibase.ptr, w.public_key_multibase.len, &mb_val);
    _ = napi_set_named_property(env, js_obj, "publicKeyMultibase", mb_val);

    var addr_val: napi_value = null;
    _ = napi_create_string_utf8(env, w.ss58_address.ptr, w.ss58_address.len, &addr_val);
    _ = napi_set_named_property(env, js_obj, "ss58Address", addr_val);

    var did_val: napi_value = null;
    _ = napi_create_string_utf8(env, w.did.ptr, w.did.len, &did_val);
    _ = napi_set_named_property(env, js_obj, "did", did_val);

    return js_obj;
}

fn register(env: napi_env, exports: napi_value, comptime name: [:0]const u8, cb: *const fn (napi_env, napi_callback_info) callconv(.c) napi_value) void {
    var f: napi_value = null;
    _ = napi_create_function(env, name.ptr, name.len, cb, null, &f);
    _ = napi_set_named_property(env, exports, name.ptr, f);
}

export fn napi_register_module_v1(env: napi_env, exports: napi_value) napi_value {
    register(env, exports, "parseDID", parseDID_binding);
    register(env, exports, "verifySignature", verifySignature_binding);
    register(env, exports, "verifyDigestSignature", verifyDigestSignature_binding);
    register(env, exports, "encodeDidAttribute", encodeDidAttribute_binding);
    register(env, exports, "encodeAddAttributeCall", encodeAddAttributeCall_binding);
    register(env, exports, "encodeUpdateAttributeCall", encodeUpdateAttributeCall_binding);
    register(env, exports, "encodeRemoveAttributeCall", encodeRemoveAttributeCall_binding);
    register(env, exports, "canonicalize", canonicalize_binding);
    register(env, exports, "issueCredential", issueCredential_binding);
    register(env, exports, "generateMnemonic", generateMnemonic_binding);
    register(env, exports, "validateMnemonic", validateMnemonic_binding);
    register(env, exports, "createWallet", createWallet_binding);
    return exports;
}

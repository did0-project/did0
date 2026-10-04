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
extern "c" fn napi_get_value_string_utf8(env: napi_env, value: napi_value, buf: [*]u8, bufsize: usize, result: *usize) c_int;
extern "c" fn napi_get_value_uint32(env: napi_env, value: napi_value, result: *u32) c_int;
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

fn extractJsonString(env: napi_env, val: napi_value, buf: []u8) ![]const u8 {
    var v_type: napi_valuetype = .napi_undefined;
    _ = napi_typeof(env, val, &v_type);

    var target_str_val = val;

    if (v_type == .napi_object) {
        var global: napi_value = null;
        if (napi_get_global(env, &global) != 0) return error.NapiError;

        var json_obj: napi_value = null;
        if (napi_get_named_property(env, global, "JSON", &json_obj) != 0) return error.NapiError;

        var stringify_fn: napi_value = null;
        if (napi_get_named_property(env, json_obj, "stringify", &stringify_fn) != 0) return error.NapiError;

        const args = [1]napi_value{val};
        if (napi_call_function(env, json_obj, stringify_fn, 1, &args, &target_str_val) != 0) return error.NapiError;
    }

    var str_len: usize = 0;
    if (napi_get_value_string_utf8(env, target_str_val, buf.ptr, buf.len, &str_len) != 0) {
        return error.NapiError;
    }
    return buf[0..str_len];
}

fn decodeBase58(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoded = if (input.len > 0 and input[0] == 'z') input[1..] else input;
    const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var decoded = try allocator.alloc(u8, 32);
    @memset(decoded, 0);

    for (encoded) |c| {
        const char_index = std.mem.indexOfScalar(u8, alphabet, c) orelse return error.InvalidBase58Char;
        var carry: u16 = @intCast(char_index);
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

fn decodePrivateKeyBytes(allocator: std.mem.Allocator, input: []const u8) ![32]u8 {
    var seed: [32]u8 = undefined;

    // 1. Hex 64 chars -> 32 bytes
    if (input.len == 64) {
        _ = std.fmt.hexToBytes(&seed, input[0..64]) catch return error.InvalidPrivateKey;
        return seed;
    }

    // 2. Hex 128 chars -> 64 bytes (first 32 bytes are seed)
    if (input.len == 128) {
        var sk64: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(&sk64, input[0..128]) catch return error.InvalidPrivateKey;
        @memcpy(&seed, sk64[0..32]);
        return seed;
    }

    // 3. Base58 (with or without 'z' prefix)
    const raw = decodeBase58(allocator, input) catch return error.InvalidPrivateKey;
    if (raw.len >= 32) {
        @memcpy(&seed, raw[0..32]);
        return seed;
    }

    return error.InvalidPrivateKey;
}

export fn parseDID_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 1) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected a JSON string argument");
        return null;
    }

    var raw_input: [4096]u8 = undefined;
    var input_len: usize = 0;
    if (napi_get_value_string_utf8(env, argv[0], &raw_input, raw_input.len, &input_len) != 0) {
        _ = napi_throw_error(env, "ERR_DECODE", "Failed to read string argument");
        return null;
    }

    const payload = raw_input[0..input_len];

    var parser_buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&parser_buffer);
    const stack_allocator = fba.allocator();

    const doc = did0.peaq.parse(stack_allocator, payload) catch {
        _ = napi_throw_error(env, "ERR_PARSE_FAILED", "Failed to parse W3C DID document");
        return null;
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

export fn verifySignature_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 3;
    var argv: [3]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 3) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected (publicKeyMultibase, message, signatureHex)");
        return null;
    }

    var pk_buf: [128]u8 = undefined;
    var pk_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[0], &pk_buf, pk_buf.len, &pk_len);

    var is_buf = false;
    _ = napi_is_buffer(env, argv[1], &is_buf);

    var msg_buf: [65536]u8 = undefined;
    var msg_len: usize = 0;

    if (is_buf) {
        var raw_data: ?*anyopaque = null;
        _ = napi_get_buffer_info(env, argv[1], &raw_data, &msg_len);
        if (raw_data != null and msg_len <= msg_buf.len) {
            const ptr: [*]const u8 = @ptrCast(raw_data.?);
            @memcpy(msg_buf[0..msg_len], ptr[0..msg_len]);
        }
    } else {
        _ = napi_get_value_string_utf8(env, argv[1], &msg_buf, msg_buf.len, &msg_len);
    }

    var sig_hex: [256]u8 = undefined;
    var sig_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[2], &sig_hex, sig_hex.len, &sig_len);

    var stack_buf: [2048]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const stack_allocator = fba.allocator();

    // 1. Decode multibase public key into 32 raw bytes
    const pub_key_raw = did0.peaq.decodeMultibase(stack_allocator, pk_buf[0..pk_len]) catch {
        _ = napi_throw_error(env, "ERR_CRYPTO", "Invalid multibase public key");
        return null;
    };
    if (pub_key_raw.len != 32) {
        _ = napi_throw_error(env, "ERR_CRYPTO", "Expected 32-byte public key");
        return null;
    }
    var pub_key_bytes: [32]u8 = undefined;
    @memcpy(&pub_key_bytes, pub_key_raw[0..32]);

    // 2. Decode hex signature into 64 raw bytes
    if (sig_len != 128) {
        _ = napi_throw_error(env, "ERR_CRYPTO", "Expected 128-character hex string for 64-byte signature");
        return null;
    }
    var sig_bytes: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&sig_bytes, sig_hex[0..128]) catch {
        _ = napi_throw_error(env, "ERR_CRYPTO", "Invalid hex in signature");
        return null;
    };

    // 3. Verify via Zig's native Ed25519 engine (supports both raw message and sha256 digest)
    var is_valid = true;
    did0.peaq.verifySignature(pub_key_bytes, sig_bytes, msg_buf[0..msg_len]) catch {
        is_valid = false;
    };

    var result: napi_value = null;
    _ = napi_get_boolean(env, is_valid, &result);
    return result;
}

export fn encodeDidAttribute_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 4;
    var argv: [4]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 4) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected (didAccountHex, name, value, validityBlocks)");
        return null;
    }

    var account_hex: [128]u8 = undefined;
    var account_hex_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[0], &account_hex, account_hex.len, &account_hex_len);

    if (account_hex_len != 64) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected 64-character hex string for 32-byte Account ID");
        return null;
    }

    var account_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&account_bytes, account_hex[0..64]) catch {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Invalid hex in Account ID");
        return null;
    };

    var name_buf: [256]u8 = undefined;
    var name_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[1], &name_buf, name_buf.len, &name_len);

    var val_buf: [8192]u8 = undefined;
    var val_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[2], &val_buf, val_buf.len, &val_len);

    var validity: u32 = 0;
    _ = napi_get_value_uint32(env, argv[3], &validity);

    var stack_buf: [16384]u8 = undefined;
    const attr = did0.scale.DidAttribute{
        .did_account = account_bytes,
        .name = name_buf[0..name_len],
        .value = val_buf[0..val_len],
        .validity = validity,
    };

    const encoded = did0.scale.encodeDidAttribute(&stack_buf, attr) catch {
        _ = napi_throw_error(env, "ERR_ENCODE_FAILED", "Buffer overflow during SCALE encoding");
        return null;
    };

    var result: napi_value = null;
    _ = napi_create_buffer_copy(env, encoded.len, encoded.ptr, null, &result);
    return result;
}

export fn encodeAddAttributeCall_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 6;
    var argv: [6]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 6) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected (palletIndex, callIndex, didAccountHex, name, value, validityBlocks)");
        return null;
    }

    var pallet_index: u32 = 0;
    _ = napi_get_value_uint32(env, argv[0], &pallet_index);

    var call_index: u32 = 0;
    _ = napi_get_value_uint32(env, argv[1], &call_index);

    var account_hex: [128]u8 = undefined;
    var account_hex_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[2], &account_hex, account_hex.len, &account_hex_len);

    if (account_hex_len != 64) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected 64-character hex string for 32-byte Account ID");
        return null;
    }

    var account_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&account_bytes, account_hex[0..64]) catch {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Invalid hex in Account ID");
        return null;
    };

    var name_buf: [256]u8 = undefined;
    var name_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[3], &name_buf, name_buf.len, &name_len);

    var val_buf: [8192]u8 = undefined;
    var val_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[4], &val_buf, val_buf.len, &val_len);

    var validity: u32 = 0;
    _ = napi_get_value_uint32(env, argv[5], &validity);

    var stack_buf: [16384]u8 = undefined;
    const call_bytes = did0.scale.encodeAddAttributeCall(
        &stack_buf,
        @as(u8, @truncate(pallet_index)),
        @as(u8, @truncate(call_index)),
        account_bytes,
        name_buf[0..name_len],
        val_buf[0..val_len],
        validity,
    ) catch {
        _ = napi_throw_error(env, "ERR_ENCODE_FAILED", "Buffer overflow during SCALE extrinsic call encoding");
        return null;
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
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected (palletIndex, callIndex, didAccountHex, name)");
        return null;
    }

    var pallet_index: u32 = 0;
    _ = napi_get_value_uint32(env, argv[0], &pallet_index);

    var call_index: u32 = 0;
    _ = napi_get_value_uint32(env, argv[1], &call_index);

    var account_hex: [128]u8 = undefined;
    var account_hex_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[2], &account_hex, account_hex.len, &account_hex_len);

    if (account_hex_len != 64) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected 64-character hex string for 32-byte Account ID");
        return null;
    }

    var account_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&account_bytes, account_hex[0..64]) catch {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Invalid hex in Account ID");
        return null;
    };

    var name_buf: [256]u8 = undefined;
    var name_len: usize = 0;
    _ = napi_get_value_string_utf8(env, argv[3], &name_buf, name_buf.len, &name_len);

    var stack_buf: [16384]u8 = undefined;
    const call_bytes = did0.scale.encodeRemoveAttributeCall(
        &stack_buf,
        @as(u8, @truncate(pallet_index)),
        @as(u8, @truncate(call_index)),
        account_bytes,
        name_buf[0..name_len],
    ) catch {
        _ = napi_throw_error(env, "ERR_ENCODE_FAILED", "Buffer overflow during SCALE extrinsic call encoding");
        return null;
    };

    var result: napi_value = null;
    _ = napi_create_buffer_copy(env, call_bytes.len, call_bytes.ptr, null, &result);
    return result;
}

export fn canonicalize_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 1) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected (payload)");
        return null;
    }

    var raw_input: [65536]u8 = undefined;
    const json_str = extractJsonString(env, argv[0], &raw_input) catch {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Failed to extract JSON payload");
        return null;
    };

    var stack_buf: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const stack_allocator = fba.allocator();

    var out_buf: [65536]u8 = undefined;
    const canon = did0.jcs.canonicalize(stack_allocator, json_str, &out_buf) catch |err| {
        _ = napi_throw_error(env, "ERR_CANONICALIZE", @errorName(err).ptr);
        return null;
    };

    var result: napi_value = null;
    _ = napi_create_string_utf8(env, canon.ptr, canon.len, &result);
    return result;
}

export fn issueCredential_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 2;
    var argv: [2]napi_value = undefined;

    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 2) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected (payload, privateKeyHexOrBase58)");
        return null;
    }

    var raw_input: [65536]u8 = undefined;
    const json_str = extractJsonString(env, argv[0], &raw_input) catch {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Failed to extract JSON payload");
        return null;
    };

    var key_buf: [256]u8 = undefined;
    var key_len: usize = 0;
    if (napi_get_value_string_utf8(env, argv[1], &key_buf, key_buf.len, &key_len) != 0 or key_len == 0) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected private key string");
        return null;
    }

    var stack_buf: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const stack_allocator = fba.allocator();

    var priv_key = decodePrivateKeyBytes(stack_allocator, key_buf[0..key_len]) catch {
        _ = napi_throw_error(env, "ERR_INVALID_KEY", "Invalid private key format (expected 32/64-byte hex or base58)");
        return null;
    };
    defer std.crypto.secureZero(u8, &priv_key);
    defer std.crypto.secureZero(u8, &key_buf);

    var out_buf: [65536]u8 = undefined;
    const canon = did0.jcs.canonicalize(stack_allocator, json_str, &out_buf) catch |err| {
        _ = napi_throw_error(env, "ERR_CANONICALIZE", @errorName(err).ptr);
        return null;
    };

    const sig_bytes = did0.jcs.signCanonical(canon, priv_key) catch |err| {
        _ = napi_throw_error(env, "ERR_SIGN", @errorName(err).ptr);
        return null;
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
    if (argc >= 1) {
        var wc_u32: u32 = 12;
        if (napi_get_value_uint32(env, argv[0], &wc_u32) == 0) {
            if (wc_u32 == 24) word_count = 24;
        }
    }

    var m_buf: [256]u8 = undefined;
    const mnemonic = did0.wallet.generateRandomMnemonic(&m_buf, word_count) catch {
        _ = napi_throw_error(env, "ERR_ENTROPY", "Failed to generate random mnemonic");
        return null;
    };

    var result: napi_value = null;
    _ = napi_create_string_utf8(env, mnemonic.ptr, mnemonic.len, &result);
    return result;
}

export fn validateMnemonic_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 1;
    var argv: [1]napi_value = undefined;
    if (napi_get_cb_info(env, info, &argc, &argv, null, null) != 0 or argc < 1) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Expected mnemonic string");
        return null;
    }

    var m_buf: [512]u8 = undefined;
    var m_len: usize = 0;
    if (napi_get_value_string_utf8(env, argv[0], &m_buf, m_buf.len, &m_len) != 0) {
        _ = napi_throw_error(env, "ERR_INVALID_ARGS", "Failed to read mnemonic string");
        return null;
    }

    const is_valid = did0.wallet.validateMnemonic(m_buf[0..m_len]);
    var result: napi_value = null;
    _ = napi_get_boolean(env, is_valid, &result);
    return result;
}

export fn createWallet_binding(env: napi_env, info: napi_callback_info) napi_value {
    var argc: usize = 2;
    var argv: [2]napi_value = undefined;
    _ = napi_get_cb_info(env, info, &argc, &argv, null, null);

    var stack_buf: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buf);
    const allocator = fba.allocator();

    var pass_buf: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &pass_buf);
    var pass_len: usize = 0;
    if (argc >= 1) {
        _ = napi_get_value_string_utf8(env, argv[0], &pass_buf, pass_buf.len, &pass_len);
    }
    const passphrase = pass_buf[0..pass_len];

    var m_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &m_buf);
    var m_len: usize = 0;
    var has_mnemonic = false;
    if (argc >= 2) {
        if (napi_get_value_string_utf8(env, argv[1], &m_buf, m_buf.len, &m_len) == 0 and m_len > 0) {
            has_mnemonic = true;
        }
    }

    const w = if (has_mnemonic)
        did0.wallet.createWalletFromMnemonic(allocator, m_buf[0..m_len], passphrase) catch |err| {
            _ = napi_throw_error(env, "ERR_WALLET", @errorName(err).ptr);
            return null;
        }
    else
        did0.wallet.createWallet(allocator, passphrase, 12) catch |err| {
            _ = napi_throw_error(env, "ERR_WALLET", @errorName(err).ptr);
            return null;
        };

    var js_obj: napi_value = null;
    _ = napi_create_object(env, &js_obj);

    var m_val: napi_value = null;
    _ = napi_create_string_utf8(env, w.mnemonic.ptr, w.mnemonic.len, &m_val);
    _ = napi_set_named_property(env, js_obj, "mnemonic", m_val);

    const seed_hex = std.fmt.bytesToHex(w.seed, .lower);
    var seed_val: napi_value = null;
    _ = napi_create_string_utf8(env, &seed_hex, seed_hex.len, &seed_val);
    _ = napi_set_named_property(env, js_obj, "seedHex", seed_val);

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

export fn napi_register_module_v1(env: napi_env, exports: napi_value) napi_value {
    var fn_parse: napi_value = null;
    _ = napi_create_function(env, "parseDID", 8, parseDID_binding, null, &fn_parse);
    _ = napi_set_named_property(env, exports, "parseDID", fn_parse);

    var fn_verify: napi_value = null;
    _ = napi_create_function(env, "verifySignature", 15, verifySignature_binding, null, &fn_verify);
    _ = napi_set_named_property(env, exports, "verifySignature", fn_verify);

    var fn_encode_attr: napi_value = null;
    _ = napi_create_function(env, "encodeDidAttribute", 18, encodeDidAttribute_binding, null, &fn_encode_attr);
    _ = napi_set_named_property(env, exports, "encodeDidAttribute", fn_encode_attr);

    var fn_encode_call: napi_value = null;
    _ = napi_create_function(env, "encodeAddAttributeCall", 21, encodeAddAttributeCall_binding, null, &fn_encode_call);
    _ = napi_set_named_property(env, exports, "encodeAddAttributeCall", fn_encode_call);

    var fn_update_call: napi_value = null;
    _ = napi_create_function(env, "encodeUpdateAttributeCall", 24, encodeUpdateAttributeCall_binding, null, &fn_update_call);
    _ = napi_set_named_property(env, exports, "encodeUpdateAttributeCall", fn_update_call);

    var fn_remove_call: napi_value = null;
    _ = napi_create_function(env, "encodeRemoveAttributeCall", 24, encodeRemoveAttributeCall_binding, null, &fn_remove_call);
    _ = napi_set_named_property(env, exports, "encodeRemoveAttributeCall", fn_remove_call);

    var fn_canonicalize: napi_value = null;
    _ = napi_create_function(env, "canonicalize", 12, canonicalize_binding, null, &fn_canonicalize);
    _ = napi_set_named_property(env, exports, "canonicalize", fn_canonicalize);

    var fn_issue: napi_value = null;
    _ = napi_create_function(env, "issueCredential", 15, issueCredential_binding, null, &fn_issue);
    _ = napi_set_named_property(env, exports, "issueCredential", fn_issue);

    var fn_mnemonic: napi_value = null;
    _ = napi_create_function(env, "generateMnemonic", 16, generateMnemonic_binding, null, &fn_mnemonic);
    _ = napi_set_named_property(env, exports, "generateMnemonic", fn_mnemonic);

    var fn_val_m: napi_value = null;
    _ = napi_create_function(env, "validateMnemonic", 16, validateMnemonic_binding, null, &fn_val_m);
    _ = napi_set_named_property(env, exports, "validateMnemonic", fn_val_m);

    var fn_wallet: napi_value = null;
    _ = napi_create_function(env, "createWallet", 12, createWallet_binding, null, &fn_wallet);
    _ = napi_set_named_property(env, exports, "createWallet", fn_wallet);

    return exports;
}

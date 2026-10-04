const std = @import("std");
const did0 = @import("did0");

pub fn main(init: std.process.Init) !void {
    _ = init;

    const BOLD = "\x1b[1m";
    const CYAN = "\x1b[36m";
    const GREEN = "\x1b[32m";
    const RESET = "\x1b[0m";

    std.debug.print("{s}{s}did0 v0.2.0{s} - Zero-Allocation DID Resolver\n\n", .{ BOLD, CYAN, RESET });

    // Simulated JSON payload from a peaq network RPC node
    const payload =
        \\{
        \\  "id": "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        \\  "verificationMethod": [
        \\    {
        \\      "id": "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY#keys-1",
        \\      "type": "Ed25519VerificationKey2020",
        \\      "controller": "did:peaq:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        \\      "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
        \\    }
        \\  ]
        \\}
    ;

    // THE MAGIC: A FixedBufferAllocator living entirely on the stack.
    // 4KB is more than enough overhead to map the array structures,
    // meaning this entire extraction happens with ZERO heap allocations.
    var stack_buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_buffer);
    const stack_allocator = fba.allocator();

    std.debug.print("Extracting payload on the stack...\n", .{});

    const doc = did0.peaq.parse(stack_allocator, payload) catch |err| {
        std.debug.print("Failed to parse DID Document: {}\n", .{err});
        return;
    };

    // Print the extracted zero-copy data
    std.debug.print("├─ {s}DID Subject :{s} {s}\n", .{ BOLD, RESET, doc.id });

    if (doc.verificationMethod) |methods| {
        for (methods, 0..) |method, i| {
            std.debug.print("├─ {s}Key [{d}]     :{s} {s}\n", .{ BOLD, i, RESET, method.id });

            if (method.publicKeyMultibase) |pk_mb| {
                std.debug.print("├─ {s}Multibase   :{s} {s}{s}{s}\n", .{ BOLD, RESET, CYAN, pk_mb, RESET });

                // Decode the multibase string into the raw 32-byte public key
                if (did0.peaq.decodePublicKey(pk_mb)) |raw_bytes| {
                    std.debug.print("╰─ {s}Raw Ed25519 :{s} {s}", .{ BOLD, RESET, GREEN });
                    for (&raw_bytes) |b| std.debug.print("{x:0>2}", .{b});
                    std.debug.print("{s}\n", .{RESET});

                    // Note: If we had a challenge payload and signature from the device,
                    // we would pass them into did0.peaq.verifySignature() right here.

                } else |err| {
                    std.debug.print("╰─ {s}Decode Err  :{s} {}\n", .{ BOLD, RESET, err });
                }
            }
        }
    }
}

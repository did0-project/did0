const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 1. Export the core library module for other developers to import
    // (addModule still accepts root_source_file)
    const did0_mod = b.addModule("did0", .{
        .root_source_file = b.path("src/did0.zig"),
        .target = target,
        .optimize = optimize,
    });

    // 2. Build the CLI Executable using the new root_module pattern
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "did0",
        .root_module = exe_mod,
    });

    // Link the core library to the executable
    exe.root_module.addImport("did0", did0_mod);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the did0 CLI tool");
    run_step.dependOn(&run_cmd.step);

    // 3. Setup the test runner for the library (also requires a root_module)
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/did0.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library unit tests");
    test_step.dependOn(&run_lib_tests.step);

    // 5. Setup documentation generation
    const docs_step = b.step("docs", "Generate library HTML documentation");
    const docs_install = b.addInstallDirectory(.{
        .source_dir = lib_tests.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&docs_install.step);

    // 4. Build the Node.js Native Addon
    const napi_mod = b.createModule(.{
        .root_source_file = b.path("src/napi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "did0",
        .root_module = napi_mod,
    });

    // Node-API resolves symbols dynamically at runtime
    lib.linker_allow_shlib_undefined = true;

    const install_node_addon = b.addInstallArtifact(lib, .{});

    // Create a custom build step: `zig build addon`
    const addon_step = b.step("addon", "Build the Node.js native addon");
    addon_step.dependOn(&install_node_addon.step);
}

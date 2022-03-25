const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const cflags = [_][]const u8{ "-Wall", "-Wextra", "-Werror" };

    const exe = b.addExecutable("gemini-zig", "src/main.zig");
    exe.setTarget(target);
    exe.linkLibC();
    exe.linkSystemLibrary("mbedtls");
    exe.linkSystemLibrary("mbedcrypto");
    exe.linkSystemLibrary("mbedx509");
    exe.addIncludeDir("src");
    exe.addCSourceFile("src/shim.c", &cflags);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest("src/main.zig");
    tests.setBuildMode(mode);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&tests.step);
}

const std = @import("std");
const sbom_lib = @import("zig-build-sbom");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "c-project",
        .root_module = exe_mod,
    });

    exe.addCSourceFile(.{
        .file = b.path("vendor/lwip/src/core/tcp.c"),
    });

    b.installArtifact(exe);

    _ = sbom_lib.addSbomStep(b, exe, .{
        .format = .cyclonedx_json,
        .output_path = "sbom.cdx.json",
        .version = "1.0.0",
        .include_c_sources = true,
    });
}

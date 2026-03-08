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
        .name = "transitive-app",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    _ = sbom_lib.addSbomStep(b, exe, .{
        .format = .cyclonedx_json,
        .output_path = "sbom.cdx.json",
        .version = "2.0.0",
        .include_transitive = true,
    });
}

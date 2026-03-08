const std = @import("std");
const sbom_step_mod = @import("src/sbom_step.zig");
const microzig_mod = @import("src/integrations/microzig.zig");

const BuildZig = @This();

pub const SbomStep = sbom_step_mod.SbomStep;

pub const microzig = struct {
    pub const MicroZigSbomOptions = microzig_mod.MicroZigSbomOptions;

    /// Adds an SBOM step for a MicroZig firmware, resolving the serializer
    /// automatically from zig-build-sbom's dependency graph.
    pub fn addFirmwareSbomStep(
        b: *std.Build,
        fw: anytype,
        options: MicroZigSbomOptions,
    ) *SbomStep {
        const dep = b.dependencyFromBuildZig(BuildZig, .{});
        const serializer = dep.artifact("sbom-serializer");
        return microzig_mod.addFirmwareSbomStep(b, fw, options, serializer);
    }
};

/// Adds an SBOM generation step for a Zig executable or library.
/// The step is reachable via `zig build sbom`.
pub fn addSbomStep(
    b: *std.Build,
    compile: *std.Build.Step.Compile,
    options: SbomStep.Options,
) *SbomStep {
    const dep = b.dependencyFromBuildZig(@This(), .{});
    const serializer = dep.artifact("sbom-serializer");
    const sbom_step = SbomStep.create(b, compile, options, serializer);
    const top = b.step("sbom", "Generate SBOM for firmware");
    top.dependOn(&sbom_step.run_step.step);
    return sbom_step;
}

/// Adds an SBOM step AND attaches it to the default install step.
/// The SBOM is generated automatically on every `zig build`.
pub fn addSbomToInstall(
    b: *std.Build,
    compile: *std.Build.Step.Compile,
    options: SbomStep.Options,
) *SbomStep {
    const dep = b.dependencyFromBuildZig(@This(), .{});
    const serializer = dep.artifact("sbom-serializer");
    const sbom_step = SbomStep.create(b, compile, options, serializer);
    b.getInstallStep().dependOn(&sbom_step.run_step.step);
    return sbom_step;
}

/// Returns a LazyPath to the generated SBOM file for chaining.
pub fn getOutput(sbom_step: *SbomStep) std.Build.LazyPath {
    return sbom_step.getOutput();
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const serde_dep = b.dependency("serde", .{
        .target = target,
        .optimize = optimize,
    });
    const serde_mod = serde_dep.module("serde");

    // Serializer executable — compiled as a build tool with serde available.
    // Uses the library module to access sbom model and serializers.
    const serializer_lib_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    serializer_lib_mod.addImport("serde", serde_mod);

    const serializer_mod = b.createModule(.{
        .root_source_file = b.path("src/bin/sbom_serializer.zig"),
        .target = target,
        .optimize = optimize,
    });
    serializer_mod.addImport("zig-build-sbom", serializer_lib_mod);

    const serializer = b.addExecutable(.{
        .name = "sbom-serializer",
        .root_module = serializer_mod,
    });
    b.installArtifact(serializer);

    const lib_mod = b.addModule("zig-build-sbom", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("serde", serde_mod);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("serde", serde_mod);

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

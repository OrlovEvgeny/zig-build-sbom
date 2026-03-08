const std = @import("std");
const sbom_lib = @import("zig-build-sbom");

// Mock MicroZig types matching the duck-typing contract in microzig.zig.
// Real MicroZig projects use MicroBuild and Firmware; this fixture simulates
// the interface without pulling in the full MicroZig dependency.

const MemoryRegion = struct {
    tag: Tag,
    offset: u64,
    length: u64,

    const Tag = enum { flash, ram };
};

const MockCpu = struct {
    arch: std.Target.Cpu.Arch,
    name: []const u8,
};

const MockChip = struct {
    name: []const u8,
    cpu: MockCpu,
    memory_regions: []const MemoryRegion,
};

const MockTarget = struct {
    chip: MockChip,
};

const MockFirmware = struct {
    artifact: *std.Build.Step.Compile,
    target: MockTarget,
};

pub fn build(b: *std.Build) void {
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    });

    const exe = b.addExecutable(.{
        .name = "blinky",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // RP2040: dual Cortex-M0+, 2MB flash, 264KB SRAM.
    const fw = MockFirmware{
        .artifact = exe,
        .target = .{
            .chip = .{
                .name = "RP2040",
                .cpu = .{
                    .arch = .thumb,
                    .name = "cortex_m0plus",
                },
                .memory_regions = &.{
                    .{ .tag = .flash, .offset = 0x10000000, .length = 0x200000 },
                    .{ .tag = .ram, .offset = 0x20000000, .length = 0x42000 },
                },
            },
        },
    };

    _ = sbom_lib.microzig.addFirmwareSbomStep(b, fw, .{
        .base = .{
            .format = .cyclonedx_json,
            .output_path = "sbom.cdx.json",
            .version = "1.0.0",
            .manufacturer = .{ .name = "Acme IoT GmbH", .url = "https://acme-iot.de" },
        },
        .include_hardware_component = true,
        .include_memory_layout = true,
        .include_cpu_info = true,
    });
}

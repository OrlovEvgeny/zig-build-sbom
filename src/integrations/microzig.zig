const std = @import("std");
const sbom_model = @import("../sbom.zig");
const SbomStep = @import("../sbom_step.zig").SbomStep;

pub const MicroZigSbomOptions = struct {
    base: SbomStep.Options = .{},
    include_hardware_component: bool = true,
    include_memory_layout: bool = true,
    include_cpu_info: bool = true,
};

/// Adds an SBOM step for a MicroZig firmware.
/// Extracts chip, board, HAL, and CPU information in addition to software deps.
///
/// `fw` is accepted as `anytype` because MicroZig's Firmware is a
/// comptime-parameterized type (parameterized by PortSelect). There is no
/// stable concrete type to import without creating a circular dependency.
/// Duck-typing contract: `fw` must have `.artifact` (*std.Build.Step.Compile)
/// and `.target` (with `.chip.name`, `.chip.cpu.arch`, `.chip.cpu.name`,
/// `.chip.memory_regions`).
pub fn addFirmwareSbomStep(
    b: *std.Build,
    fw: anytype,
    options: MicroZigSbomOptions,
    serializer: *std.Build.Step.Compile,
) *SbomStep {
    const compile: *std.Build.Step.Compile = fw.artifact;
    var enhanced_options = options.base;

    const hw_props = buildHardwareProperties(b, fw, options);
    enhanced_options.custom_properties = hw_props;

    const sbom_step = SbomStep.create(b, compile, enhanced_options, serializer);

    if (options.include_hardware_component) {
        const device_comp = makeDeviceComponent(b, fw);
        sbom_step.extra_components.append(b.allocator, device_comp) catch @panic("OOM");
    }

    const top = b.step("sbom", "Generate SBOM for firmware");
    top.dependOn(&sbom_step.run_step.step);
    return sbom_step;
}

fn buildHardwareProperties(
    b: *std.Build,
    fw: anytype,
    options: MicroZigSbomOptions,
) []const sbom_model.Property {
    var props: std.ArrayListUnmanaged(sbom_model.Property) = .{};

    const target = fw.target;

    if (options.include_cpu_info) {
        props.append(b.allocator, .{
            .name = "firmware:cpu.arch",
            .value = @tagName(target.chip.cpu.arch),
        }) catch @panic("OOM");

        props.append(b.allocator, .{
            .name = "firmware:cpu.model",
            .value = target.chip.cpu.name,
        }) catch @panic("OOM");

        props.append(b.allocator, .{
            .name = "firmware:chip.name",
            .value = target.chip.name,
        }) catch @panic("OOM");
    }

    if (options.include_memory_layout) {
        for (target.chip.memory_regions, 0..) |region, i| {
            props.append(b.allocator, .{
                .name = b.fmt("firmware:memory.region.{d}.type", .{i}),
                .value = @tagName(region.tag),
            }) catch @panic("OOM");
            props.append(b.allocator, .{
                .name = b.fmt("firmware:memory.region.{d}.offset", .{i}),
                .value = b.fmt("0x{X}", .{region.offset}),
            }) catch @panic("OOM");
            props.append(b.allocator, .{
                .name = b.fmt("firmware:memory.region.{d}.length", .{i}),
                .value = b.fmt("0x{X}", .{region.length}),
            }) catch @panic("OOM");
        }
    }

    return props.toOwnedSlice(b.allocator) catch @panic("OOM");
}

fn makeDeviceComponent(b: *std.Build, fw: anytype) sbom_model.Component {
    const chip = fw.target.chip;

    var total_flash: u64 = 0;
    for (chip.memory_regions) |region| {
        if (std.mem.eql(u8, @tagName(region.tag), "flash")) {
            total_flash += region.length;
        }
    }

    // Allocate properties on the builder's arena. Comptime slice literals (&.{...})
    // can become dangling when the Component is copied across build step boundaries.
    const props = b.allocator.alloc(sbom_model.Property, 2) catch @panic("OOM");
    props[0] = .{ .name = "cdx:device:type", .value = "mcu" };
    props[1] = .{ .name = "firmware:target.arch", .value = @tagName(chip.cpu.arch) };

    return sbom_model.Component{
        .type = .device,
        .bom_ref = b.fmt("device-{s}", .{chip.name}),
        .name = chip.name,
        .description = b.fmt("{s} ({s} core, {d} bytes flash)", .{
            chip.name,
            chip.cpu.name,
            total_flash,
        }),
        .properties = props,
    };
}

// Testable helpers that accept raw data instead of `*std.Build` / `anytype`.
// The build-time functions above delegate to these for the core logic.

pub const MemoryRegionTag = enum { flash, ram, io };

pub const MemoryRegion = struct {
    tag: MemoryRegionTag,
    offset: u64,
    length: u64,
};

pub const ChipInfo = struct {
    name: []const u8,
    cpu_arch: []const u8,
    cpu_name: []const u8,
    memory_regions: []const MemoryRegion,
};

/// Builds hardware property list from chip info. Caller owns returned slice.
pub fn buildHardwarePropertiesFromInfo(
    allocator: std.mem.Allocator,
    chip: ChipInfo,
    include_cpu_info: bool,
    include_memory_layout: bool,
) ![]const sbom_model.Property {
    var props: std.ArrayListUnmanaged(sbom_model.Property) = .{};
    errdefer props.deinit(allocator);

    if (include_cpu_info) {
        try props.append(allocator, .{ .name = "firmware:cpu.arch", .value = chip.cpu_arch });
        try props.append(allocator, .{ .name = "firmware:cpu.model", .value = chip.cpu_name });
        try props.append(allocator, .{ .name = "firmware:chip.name", .value = chip.name });
    }

    if (include_memory_layout) {
        for (chip.memory_regions, 0..) |region, i| {
            try props.append(allocator, .{
                .name = try std.fmt.allocPrint(allocator, "firmware:memory.region.{d}.type", .{i}),
                .value = @tagName(region.tag),
            });
            try props.append(allocator, .{
                .name = try std.fmt.allocPrint(allocator, "firmware:memory.region.{d}.offset", .{i}),
                .value = try std.fmt.allocPrint(allocator, "0x{X}", .{region.offset}),
            });
            try props.append(allocator, .{
                .name = try std.fmt.allocPrint(allocator, "firmware:memory.region.{d}.length", .{i}),
                .value = try std.fmt.allocPrint(allocator, "0x{X}", .{region.length}),
            });
        }
    }

    return props.toOwnedSlice(allocator);
}

/// Builds a device component from chip info. Caller owns returned strings.
pub fn makeDeviceComponentFromInfo(
    allocator: std.mem.Allocator,
    chip: ChipInfo,
) !sbom_model.Component {
    var total_flash: u64 = 0;
    for (chip.memory_regions) |region| {
        if (region.tag == .flash) {
            total_flash += region.length;
        }
    }

    const props = try allocator.alloc(sbom_model.Property, 2);
    props[0] = .{ .name = "cdx:device:type", .value = "mcu" };
    props[1] = .{ .name = "firmware:target.arch", .value = chip.cpu_arch };

    return sbom_model.Component{
        .type = .device,
        .bom_ref = try std.fmt.allocPrint(allocator, "device-{s}", .{chip.name}),
        .name = chip.name,
        .description = try std.fmt.allocPrint(allocator, "{s} ({s} core, {d} bytes flash)", .{
            chip.name,
            chip.cpu_name,
            total_flash,
        }),
        .properties = props,
    };
}

/// Computes total flash from memory regions.
pub fn totalFlash(regions: []const MemoryRegion) u64 {
    var total: u64 = 0;
    for (regions) |region| {
        if (region.tag == .flash) total += region.length;
    }
    return total;
}

const testing = std.testing;

const test_rp2040 = ChipInfo{
    .name = "RP2040",
    .cpu_arch = "thumb",
    .cpu_name = "cortex_m0plus",
    .memory_regions = &.{
        .{ .tag = .flash, .offset = 0x10000000, .length = 2 * 1024 * 1024 },
        .{ .tag = .ram, .offset = 0x20000000, .length = 264 * 1024 },
    },
};

test "buildHardwarePropertiesFromInfo: cpu info enabled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const props = try buildHardwarePropertiesFromInfo(aa, test_rp2040, true, false);

    try testing.expectEqual(@as(usize, 3), props.len);
    try testing.expectEqualStrings("firmware:cpu.arch", props[0].name);
    try testing.expectEqualStrings("thumb", props[0].value);
    try testing.expectEqualStrings("firmware:cpu.model", props[1].name);
    try testing.expectEqualStrings("cortex_m0plus", props[1].value);
    try testing.expectEqualStrings("firmware:chip.name", props[2].name);
    try testing.expectEqualStrings("RP2040", props[2].value);
}

test "buildHardwarePropertiesFromInfo: cpu info disabled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const props = try buildHardwarePropertiesFromInfo(arena.allocator(), test_rp2040, false, false);
    try testing.expectEqual(@as(usize, 0), props.len);
}

test "buildHardwarePropertiesFromInfo: memory layout enabled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const props = try buildHardwarePropertiesFromInfo(aa, test_rp2040, false, true);

    // 2 regions × 3 properties each = 6
    try testing.expectEqual(@as(usize, 6), props.len);
    try testing.expectEqualStrings("firmware:memory.region.0.type", props[0].name);
    try testing.expectEqualStrings("flash", props[0].value);
    try testing.expectEqualStrings("firmware:memory.region.1.type", props[3].name);
    try testing.expectEqualStrings("ram", props[3].value);
}

test "makeDeviceComponentFromInfo: correct fields" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const comp = try makeDeviceComponentFromInfo(aa, test_rp2040);

    try testing.expectEqual(sbom_model.ComponentType.device, comp.type);
    try testing.expectEqualStrings("RP2040", comp.name);
    try testing.expectEqualStrings("device-RP2040", comp.bom_ref);
    try testing.expectEqual(@as(usize, 2), comp.properties.len);
    try testing.expectEqualStrings("cdx:device:type", comp.properties[0].name);
    try testing.expectEqualStrings("mcu", comp.properties[0].value);
    try testing.expectEqualStrings("firmware:target.arch", comp.properties[1].name);
    try testing.expectEqualStrings("thumb", comp.properties[1].value);

    // Description includes flash size.
    try testing.expect(std.mem.indexOf(u8, comp.description.?, "2097152 bytes flash") != null);
}

test "totalFlash: multiple flash regions summed" {
    const regions = &[_]MemoryRegion{
        .{ .tag = .flash, .offset = 0, .length = 1024 },
        .{ .tag = .ram, .offset = 0x2000, .length = 512 },
        .{ .tag = .flash, .offset = 0x1000, .length = 2048 },
    };
    try testing.expectEqual(@as(u64, 3072), totalFlash(regions));
}

test "totalFlash: no flash regions" {
    const regions = &[_]MemoryRegion{
        .{ .tag = .ram, .offset = 0, .length = 4096 },
        .{ .tag = .io, .offset = 0x4000, .length = 256 },
    };
    try testing.expectEqual(@as(u64, 0), totalFlash(regions));
}

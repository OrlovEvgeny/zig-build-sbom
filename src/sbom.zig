const std = @import("std");

// Zig 0.14.0 has std.json.stringifyAlloc; 0.15+ replaced it with
// std.json.Stringify.valueAlloc. Pick whichever is available.
fn jsonStringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    if (@hasDecl(std.json, "stringifyAlloc")) {
        return std.json.stringifyAlloc(allocator, value, .{});
    } else {
        return std.json.Stringify.valueAlloc(allocator, value, .{});
    }
}

pub const Bom = struct {
    serial_number: []const u8,
    version: u32 = 1,
    metadata: Metadata,
    components: []const Component,
    dependencies: []const Dependency,
    compositions: []const Composition,
};

pub const Metadata = struct {
    timestamp: []const u8,
    tools: []const Tool,
    component: ?Component = null,
    manufacturer: ?OrganizationalEntity = null,
};

pub const ComponentType = enum {
    firmware,
    library,
    application,
    device,
    device_driver,
    tool,
    file,
};

pub const Component = struct {
    type: ComponentType,
    bom_ref: []const u8,
    name: []const u8,
    version: ?[]const u8 = null,
    purl: ?[]const u8 = null,
    hashes: []const Hash = &.{},
    licenses: []const LicenseExpression = &.{},
    source_url: ?[]const u8 = null,
    scope: Scope = .required,
    description: ?[]const u8 = null,
    properties: []const Property = &.{},
};

pub const Hash = struct {
    pub const Algorithm = enum {
        md5,
        sha1,
        sha2_256,
        sha2_384,
        sha2_512,
        sha3_256,
        blake3,

        pub fn toCycloneDxString(self: Algorithm) []const u8 {
            return switch (self) {
                .md5 => "MD5",
                .sha1 => "SHA-1",
                .sha2_256 => "SHA-256",
                .sha2_384 => "SHA-384",
                .sha2_512 => "SHA-512",
                .sha3_256 => "SHA3-256",
                .blake3 => "BLAKE3",
            };
        }

        pub fn toSpdxString(self: Algorithm) []const u8 {
            return switch (self) {
                .sha2_256 => "SHA256",
                .sha1 => "SHA1",
                .md5 => "MD5",
                else => "OTHER",
            };
        }
    };

    alg: Algorithm,
    content: []const u8,
};

pub const LicenseExpression = union(enum) {
    spdx: []const u8,
    named: []const u8,
    no_assertion,
};

pub const Scope = enum {
    required,
    optional,
    excluded,
};

pub const Dependency = struct {
    ref: []const u8,
    depends_on: []const []const u8,
};

pub const Composition = struct {
    pub const Aggregate = enum {
        complete,
        incomplete,
        unknown,
        incomplete_first_party_only,
    };

    aggregate: Aggregate,
    assemblies: []const []const u8,
};

pub const Property = struct {
    name: []const u8,
    value: []const u8,
};

pub const Tool = struct {
    vendor: []const u8,
    name: []const u8,
    version: []const u8,
};

pub const OrganizationalEntity = struct {
    name: []const u8,
    url: ?[]const u8 = null,
    contact: ?[]const OrganizationalContact = null,
};

pub const OrganizationalContact = struct {
    name: ?[]const u8 = null,
    email: ?[]const u8 = null,
};

const testing = std.testing;

test "ComponentType: all variants exist" {
    const types = [_]ComponentType{
        .firmware, .library, .application, .device, .device_driver, .tool, .file,
    };
    try testing.expectEqual(@as(usize, 7), types.len);
}

test "Hash.Algorithm: CycloneDX strings" {
    try testing.expectEqualStrings("SHA-256", Hash.Algorithm.sha2_256.toCycloneDxString());
    try testing.expectEqualStrings("SHA-1", Hash.Algorithm.sha1.toCycloneDxString());
    try testing.expectEqualStrings("BLAKE3", Hash.Algorithm.blake3.toCycloneDxString());
}

test "Hash.Algorithm: SPDX strings" {
    try testing.expectEqualStrings("SHA256", Hash.Algorithm.sha2_256.toSpdxString());
    try testing.expectEqualStrings("SHA1", Hash.Algorithm.sha1.toSpdxString());
    try testing.expectEqualStrings("OTHER", Hash.Algorithm.blake3.toSpdxString());
}

test "LicenseExpression: union variants" {
    const spdx_lic: LicenseExpression = .{ .spdx = "MIT" };
    const named_lic: LicenseExpression = .{ .named = "Custom License" };
    const no_assert: LicenseExpression = .no_assertion;

    switch (spdx_lic) {
        .spdx => |id| try testing.expectEqualStrings("MIT", id),
        else => unreachable,
    }
    switch (named_lic) {
        .named => |n| try testing.expectEqualStrings("Custom License", n),
        else => unreachable,
    }
    switch (no_assert) {
        .no_assertion => {},
        else => unreachable,
    }
}

test "Composition.Aggregate: all variants" {
    const aggs = [_]Composition.Aggregate{
        .complete, .incomplete, .unknown, .incomplete_first_party_only,
    };
    try testing.expectEqual(@as(usize, 4), aggs.len);
}

test "Bom: construct minimal instance" {
    const bom = Bom{
        .serial_number = "urn:uuid:test",
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{
                .vendor = "test",
                .name = "test-tool",
                .version = "0.1.0",
            }},
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    try testing.expectEqual(@as(u32, 1), bom.version);
    try testing.expectEqualStrings("urn:uuid:test", bom.serial_number);
}

test "Bom: std.json serialize with hardware properties and manufacturer" {
    // Reproduces the microzig fixture scenario.
    const bom = Bom{
        .serial_number = "urn:uuid:test-microzig",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{
                .vendor = "zig-embedded-group",
                .name = "zig-build-sbom",
                .version = "0.1.0",
            }},
            .component = .{
                .type = .firmware,
                .bom_ref = "blinky",
                .name = "blinky",
                .version = "1.0.0",
                .properties = &.{
                    .{ .name = "firmware:cpu.arch", .value = "thumb" },
                    .{ .name = "firmware:cpu.model", .value = "cortex_m0plus" },
                    .{ .name = "firmware:chip.name", .value = "RP2040" },
                },
            },
            .manufacturer = .{ .name = "Acme IoT GmbH", .url = "https://acme-iot.de" },
        },
        .components = &.{
            .{
                .type = .device,
                .bom_ref = "device-RP2040",
                .name = "RP2040",
                .description = "RP2040 (cortex_m0plus core, 2097152 bytes flash)",
                .properties = &.{
                    .{ .name = "cdx:device:type", .value = "mcu" },
                    .{ .name = "firmware:target.arch", .value = "thumb" },
                },
            },
        },
        .dependencies = &.{},
        .compositions = &.{
            .{
                .aggregate = .complete,
                .assemblies = &.{ "blinky", "device-RP2040" },
            },
        },
    };

    const json_bytes = try jsonStringifyAlloc(testing.allocator, bom);
    defer testing.allocator.free(json_bytes);

    try testing.expect(json_bytes.len > 0);
    try testing.expect(std.mem.indexOf(u8, json_bytes, "RP2040") != null);
    try testing.expect(std.mem.indexOf(u8, json_bytes, "Acme IoT GmbH") != null);
}

test "Bom: std.json round-trip with all field variants" {
    const original = Bom{
        .serial_number = "urn:uuid:round-trip-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-06-15T12:00:00Z",
            .tools = &.{.{
                .vendor = "zig-embedded-group",
                .name = "zig-build-sbom",
                .version = "0.1.0",
            }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root-fw",
                .name = "blinky",
                .version = "1.0.0",
                .purl = "pkg:zig/blinky@1.0.0",
                .description = "Test firmware",
                .hashes = &.{.{ .alg = .sha2_256, .content = "abc123" }},
                .licenses = &.{
                    .{ .spdx = "MIT" },
                    .{ .named = "Custom License" },
                    .no_assertion,
                },
                .scope = .optional,
                .properties = &.{.{ .name = "firmware:chip", .value = "rp2040" }},
            },
            .manufacturer = .{
                .name = "Test Corp",
                .url = "https://example.com",
                .contact = &.{.{ .name = "Alice", .email = "alice@example.com" }},
            },
        },
        .components = &.{
            .{
                .type = .library,
                .bom_ref = "1220aabbccdd",
                .name = "microzig",
                .version = "0.13.0",
                .hashes = &.{.{ .alg = .sha2_256, .content = "aabbccdd" }},
                .source_url = "https://github.com/ZigEmbeddedGroup/microzig",
            },
            .{
                .type = .device,
                .bom_ref = "device-rp2040",
                .name = "rp2040",
                .description = "RP2040 MCU",
            },
        },
        .dependencies = &.{
            .{ .ref = "root-fw", .depends_on = &.{"1220aabbccdd"} },
            .{ .ref = "1220aabbccdd", .depends_on = &.{} },
        },
        .compositions = &.{
            .{ .aggregate = .complete, .assemblies = &.{ "root-fw", "1220aabbccdd" } },
            .{ .aggregate = .incomplete, .assemblies = &.{"device-rp2040"} },
        },
    };

    // Serialize to JSON.
    const json_bytes = try jsonStringifyAlloc(testing.allocator, original);
    defer testing.allocator.free(json_bytes);

    // Parse back.
    const parsed = try std.json.parseFromSlice(Bom, testing.allocator, json_bytes, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const rt = parsed.value;

    try testing.expectEqualStrings("urn:uuid:round-trip-test", rt.serial_number);
    try testing.expectEqual(@as(u32, 1), rt.version);
    try testing.expectEqualStrings("2024-06-15T12:00:00Z", rt.metadata.timestamp);
    try testing.expectEqual(@as(usize, 1), rt.metadata.tools.len);
    try testing.expectEqualStrings("zig-build-sbom", rt.metadata.tools[0].name);

    // Root component.
    const root = rt.metadata.component.?;
    try testing.expectEqual(ComponentType.firmware, root.type);
    try testing.expectEqualStrings("blinky", root.name);
    try testing.expectEqualStrings("1.0.0", root.version.?);
    try testing.expectEqualStrings("pkg:zig/blinky@1.0.0", root.purl.?);
    try testing.expectEqual(Scope.optional, root.scope);
    try testing.expectEqual(@as(usize, 1), root.hashes.len);
    try testing.expectEqual(@as(usize, 3), root.licenses.len);
    try testing.expectEqual(@as(usize, 1), root.properties.len);

    // License variants round-trip.
    switch (root.licenses[0]) {
        .spdx => |id| try testing.expectEqualStrings("MIT", id),
        else => return error.TestUnexpectedResult,
    }
    switch (root.licenses[1]) {
        .named => |n| try testing.expectEqualStrings("Custom License", n),
        else => return error.TestUnexpectedResult,
    }
    switch (root.licenses[2]) {
        .no_assertion => {},
        else => return error.TestUnexpectedResult,
    }

    // Manufacturer.
    const mfr = rt.metadata.manufacturer.?;
    try testing.expectEqualStrings("Test Corp", mfr.name);
    try testing.expectEqualStrings("https://example.com", mfr.url.?);
    try testing.expectEqual(@as(usize, 1), mfr.contact.?.len);

    // Components.
    try testing.expectEqual(@as(usize, 2), rt.components.len);
    try testing.expectEqualStrings("microzig", rt.components[0].name);
    try testing.expectEqual(ComponentType.device, rt.components[1].type);

    // Dependencies.
    try testing.expectEqual(@as(usize, 2), rt.dependencies.len);
    try testing.expectEqualStrings("root-fw", rt.dependencies[0].ref);
    try testing.expectEqual(@as(usize, 1), rt.dependencies[0].depends_on.len);

    // Compositions.
    try testing.expectEqual(@as(usize, 2), rt.compositions.len);
    try testing.expectEqual(Composition.Aggregate.complete, rt.compositions[0].aggregate);
    try testing.expectEqual(Composition.Aggregate.incomplete, rt.compositions[1].aggregate);
}

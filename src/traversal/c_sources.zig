const std = @import("std");
const sbom_model = @import("../sbom.zig");
const purl_mod = @import("../util/purl.zig");

pub const CFileInfo = struct {
    path: []const u8,
    flags: []const []const u8 = &.{},
};

/// Known C libraries identified by path fragment heuristics.
pub const known_c_libraries = [_]struct {
    path_fragment: []const u8,
    name: []const u8,
    license: []const u8,
    purl_namespace: []const u8,
}{
    .{ .path_fragment = "lwip", .name = "lwIP", .license = "BSD-3-Clause", .purl_namespace = "lwip" },
    .{ .path_fragment = "mbedtls", .name = "Mbed TLS", .license = "Apache-2.0", .purl_namespace = "mbedtls" },
    .{ .path_fragment = "freertos", .name = "FreeRTOS", .license = "MIT", .purl_namespace = "freertos" },
    .{ .path_fragment = "cmsis", .name = "CMSIS", .license = "Apache-2.0", .purl_namespace = "arm-cmsis" },
    .{ .path_fragment = "fatfs", .name = "FatFs", .license = "BSD-1-Clause", .purl_namespace = "fatfs" },
    .{ .path_fragment = "tinycbor", .name = "tinycbor", .license = "MIT", .purl_namespace = "tinycbor" },
    .{ .path_fragment = "sqlite", .name = "SQLite", .license = "blessing", .purl_namespace = "sqlite" },
};

pub const ExtractError = error{
    OutOfMemory,
};

/// Extracts C source files from a compile step and groups them into components.
pub fn extractCSourceFiles(
    ctx: *@import("graph.zig").ExtractionContext,
    compile: *std.Build.Step.Compile,
) ExtractError!void {
    const allocator = ctx.allocator;

    var c_paths: std.ArrayListUnmanaged([]const u8) = .{};
    defer c_paths.deinit(allocator);

    for (compile.root_module.link_objects.items) |link_obj| {
        switch (link_obj) {
            .c_source_file => |csf| {
                const path = csf.file.getPath2(compile.root_module.owner, null);
                c_paths.append(allocator, path) catch return ExtractError.OutOfMemory;
            },
            .c_source_files => |csfs| {
                for (csfs.files) |file_path| {
                    const root = csfs.root.getPath2(compile.root_module.owner, null);
                    const full = std.fs.path.join(allocator, &.{ root, file_path }) catch
                        return ExtractError.OutOfMemory;
                    c_paths.append(allocator, full) catch return ExtractError.OutOfMemory;
                }
            },
            else => {},
        }
    }

    if (c_paths.items.len == 0) return;

    if (!ctx.options.identify_vendored_libs) {
        // Emit a single catch-all component without library identification.
        const component = buildCLibraryComponent(allocator, "unknown-c-sources") catch return ExtractError.OutOfMemory;
        ctx.components.append(ctx.allocator, component) catch return ExtractError.OutOfMemory;
        return;
    }

    // Group files by known library or "unknown-c-sources".
    var groups = std.StringHashMap(void).init(allocator);
    defer groups.deinit();

    for (c_paths.items) |path| {
        const lib_name = identifyLibrary(path) orelse "unknown-c-sources";
        groups.put(lib_name, {}) catch return ExtractError.OutOfMemory;
    }

    var group_it = groups.keyIterator();
    while (group_it.next()) |key_ptr| {
        const lib_name = key_ptr.*;
        const component = buildCLibraryComponent(allocator, lib_name) catch return ExtractError.OutOfMemory;
        ctx.components.append(ctx.allocator, component) catch return ExtractError.OutOfMemory;
    }
}

fn identifyLibrary(path: []const u8) ?[]const u8 {
    for (&known_c_libraries) |lib| {
        if (containsCaseInsensitive(path, lib.path_fragment)) {
            return lib.name;
        }
    }
    return null;
}

fn buildCLibraryComponent(allocator: std.mem.Allocator, name: []const u8) !sbom_model.Component {
    var purl_ns: []const u8 = "generic";
    var license: ?[]const u8 = null;

    for (&known_c_libraries) |lib| {
        if (std.mem.eql(u8, lib.name, name)) {
            purl_ns = lib.purl_namespace;
            license = lib.license;
            break;
        }
    }

    const bom_ref = try std.fmt.allocPrint(allocator, "c-lib-{s}", .{name});
    const purl_str = try purl_mod.forCLibrary(allocator, name, purl_ns, null);

    const licenses: []const sbom_model.LicenseExpression = if (license) |lic| blk: {
        const arr = try allocator.alloc(sbom_model.LicenseExpression, 1);
        arr[0] = .{ .spdx = lic };
        break :blk arr;
    } else &.{};

    return sbom_model.Component{
        .type = .library,
        .bom_ref = bom_ref,
        .name = name,
        .purl = purl_str,
        .licenses = licenses,
        .scope = .required,
    };
}

/// Matches a path against the known libraries table (case-insensitive).
pub fn matchKnownLibrary(path: []const u8) ?struct { name: []const u8, license: []const u8 } {
    for (&known_c_libraries) |lib| {
        if (containsCaseInsensitive(path, lib.path_fragment)) {
            return .{ .name = lib.name, .license = lib.license };
        }
    }
    return null;
}

// Path fragments in the known_c_libraries table are lowercase. Real filesystem
// paths may use any casing (e.g. "FreeRTOS", "CMSIS"). Compare lowercased.
fn containsCaseInsensitive(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    const end = haystack.len - needle.len + 1;
    var i: usize = 0;
    while (i < end) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

const testing = std.testing;

test "matchKnownLibrary: lwip" {
    const result = matchKnownLibrary("vendor/lwip/src/core/tcp.c").?;
    try testing.expectEqualStrings("lwIP", result.name);
    try testing.expectEqualStrings("BSD-3-Clause", result.license);
}

test "matchKnownLibrary: mbedtls" {
    const result = matchKnownLibrary("third_party/mbedtls/library/aes.c").?;
    try testing.expectEqualStrings("Mbed TLS", result.name);
    try testing.expectEqualStrings("Apache-2.0", result.license);
}

test "matchKnownLibrary: unknown" {
    try testing.expect(matchKnownLibrary("src/main.c") == null);
}

test "known_c_libraries: all entries have required fields" {
    for (&known_c_libraries) |lib| {
        try testing.expect(lib.path_fragment.len > 0);
        try testing.expect(lib.name.len > 0);
        try testing.expect(lib.license.len > 0);
        try testing.expect(lib.purl_namespace.len > 0);
    }
}

test "matchKnownLibrary: case-insensitive FreeRTOS" {
    const result = matchKnownLibrary("vendor/FreeRTOS/src/tasks.c").?;
    try testing.expectEqualStrings("FreeRTOS", result.name);
    try testing.expectEqualStrings("MIT", result.license);
}

test "matchKnownLibrary: case-insensitive CMSIS" {
    const result = matchKnownLibrary("CMSIS/Core/Include/core_cm4.h").?;
    try testing.expectEqualStrings("CMSIS", result.name);
    try testing.expectEqualStrings("Apache-2.0", result.license);
}

test "buildCLibraryComponent: license attached for known library" {
    const comp = try buildCLibraryComponent(testing.allocator, "lwIP");
    defer {
        testing.allocator.free(comp.bom_ref);
        testing.allocator.free(comp.purl.?);
        if (comp.licenses.len > 0) testing.allocator.free(comp.licenses);
    }
    try testing.expectEqual(@as(usize, 1), comp.licenses.len);
    switch (comp.licenses[0]) {
        .spdx => |expr| try testing.expectEqualStrings("BSD-3-Clause", expr),
        else => return error.TestUnexpectedResult,
    }
}

test "buildCLibraryComponent: unknown library has empty licenses" {
    const comp = try buildCLibraryComponent(testing.allocator, "custom-lib");
    defer {
        testing.allocator.free(comp.bom_ref);
        testing.allocator.free(comp.purl.?);
    }
    try testing.expectEqual(@as(usize, 0), comp.licenses.len);
}

test "containsCaseInsensitive: exact match" {
    try testing.expect(containsCaseInsensitive("lwip/src/core.c", "lwip"));
}

test "containsCaseInsensitive: mixed case" {
    try testing.expect(containsCaseInsensitive("vendor/LWIP/src/core.c", "lwip"));
}

test "containsCaseInsensitive: no match" {
    try testing.expect(!containsCaseInsensitive("vendor/something/src.c", "lwip"));
}

test "matchKnownLibrary: first match wins on multi-match path" {
    // Path containing both "lwip" and "fatfs" — first match in table order wins.
    const result = matchKnownLibrary("vendor/lwip-fatfs/combined.c").?;
    try testing.expectEqualStrings("lwIP", result.name);
}

test "identifyLibrary: returns null for unknown" {
    try testing.expect(identifyLibrary("src/app/main.c") == null);
}

test "identifyLibrary: finds sqlite" {
    const result = identifyLibrary("third_party/sqlite/sqlite3.c").?;
    try testing.expectEqualStrings("SQLite", result);
}

const std = @import("std");

pub const PurlError = error{
    OutOfMemory,
};

/// Package metadata sufficient for purl generation.
pub const PackageInfo = struct {
    name: []const u8,
    version: ?[]const u8 = null,
    url: ?[]const u8 = null,
    hash: []const u8 = "",
};

pub const PurlOptions = struct {
    /// When true, uses `pkg:generic/` instead of the unofficial `pkg:zig/` type.
    strict_purl: bool = false,
};

/// Generates a purl for a Zig package.
/// Format: `pkg:zig/{name}@{version}` or `pkg:zig/{name}@{version}#{host}`
///
/// `pkg:zig/` is not an official PURL type yet. Pass `opts.strict_purl = true`
/// to use `pkg:generic/` for strict compliance.
pub fn forZigPackage(allocator: std.mem.Allocator, info: PackageInfo) PurlError!?[]const u8 {
    return forZigPackageWithOpts(allocator, info, .{});
}

pub fn forZigPackageWithOpts(allocator: std.mem.Allocator, info: PackageInfo, opts: PurlOptions) PurlError!?[]const u8 {
    const pkg_type: []const u8 = if (opts.strict_purl) "pkg:generic" else "pkg:zig";
    const version_str = info.version orelse if (info.hash.len >= 16) info.hash[0..16] else info.hash;
    if (version_str.len == 0) return null;

    const encoded_name = try purlPercentEncode(allocator, info.name);
    defer allocator.free(encoded_name);

    if (info.url) |url| {
        const host = extractHostFromUrl(url);
        if (host.len > 0) {
            const result = try std.fmt.allocPrint(allocator, "{s}/{s}@{s}#{s}", .{ pkg_type, encoded_name, version_str, host });
            return result;
        }
    }

    const result = try std.fmt.allocPrint(allocator, "{s}/{s}@{s}", .{ pkg_type, encoded_name, version_str });
    return result;
}

/// Generates a purl for a known C library identified from vendored sources.
/// Format: `pkg:generic/{namespace}/{name}@{version}`
pub fn forCLibrary(
    allocator: std.mem.Allocator,
    name: []const u8,
    purl_namespace: []const u8,
    version: ?[]const u8,
) PurlError![]const u8 {
    const ver = version orelse "unknown";
    const encoded_name = try purlPercentEncode(allocator, name);
    defer allocator.free(encoded_name);
    const encoded_ns = try purlPercentEncode(allocator, purl_namespace);
    defer allocator.free(encoded_ns);
    return std.fmt.allocPrint(allocator, "pkg:generic/{s}/{s}@{s}", .{ encoded_ns, encoded_name, ver });
}

/// Generates a purl for the Zig compiler as a build tool.
/// Format: `pkg:generic/zig@{version}`
pub fn forZigCompiler(allocator: std.mem.Allocator, zig_version: []const u8) PurlError![]const u8 {
    const encoded_ver = try purlPercentEncode(allocator, zig_version);
    defer allocator.free(encoded_ver);
    return std.fmt.allocPrint(allocator, "pkg:generic/zig@{s}", .{encoded_ver});
}

/// Percent-encodes PURL-reserved characters: `@`, `/`, `#`, `?`, `%`.
/// Returns a newly-allocated string; caller must free.
fn purlPercentEncode(allocator: std.mem.Allocator, input: []const u8) PurlError![]const u8 {
    var needs_encoding = false;
    for (input) |c| {
        if (c == '@' or c == '/' or c == '#' or c == '?' or c == '%') {
            needs_encoding = true;
            break;
        }
    }
    if (!needs_encoding) {
        return allocator.dupe(u8, input) catch return PurlError.OutOfMemory;
    }

    var out: std.ArrayList(u8) = .{};
    errdefer out.deinit(allocator);
    const hex = "0123456789ABCDEF";
    for (input) |c| {
        if (c == '@' or c == '/' or c == '#' or c == '?' or c == '%') {
            out.append(allocator, '%') catch return PurlError.OutOfMemory;
            out.append(allocator, hex[c >> 4]) catch return PurlError.OutOfMemory;
            out.append(allocator, hex[c & 0x0f]) catch return PurlError.OutOfMemory;
        } else {
            out.append(allocator, c) catch return PurlError.OutOfMemory;
        }
    }
    return out.toOwnedSlice(allocator) catch return PurlError.OutOfMemory;
}

/// Extracts the host+path portion from a URL, stripping the scheme.
/// `https://github.com/ZigEmbeddedGroup/microzig/archive/...` → `github.com/ZigEmbeddedGroup/microzig`
/// Also strips `#fragment` and `?query` before extracting segments.
fn extractHostFromUrl(url: []const u8) []const u8 {
    var rest = url;

    // Strip scheme (handles both `https://` and `git+https://`).
    if (std.mem.indexOf(u8, rest, "://")) |idx| {
        rest = rest[idx + 3 ..];
    }

    // Strip fragment and query — git URLs use `#ref` for branch/commit.
    if (std.mem.indexOf(u8, rest, "#")) |idx| rest = rest[0..idx];
    if (std.mem.indexOf(u8, rest, "?")) |idx| rest = rest[0..idx];

    // Take up to the third path segment (host/org/repo).
    var segments: usize = 0;
    for (rest, 0..) |c, i| {
        if (c == '/') {
            segments += 1;
            if (segments == 3) return rest[0..i];
        }
    }
    return rest;
}

const testing = std.testing;

test "forZigPackage: name and version" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "microzig",
        .version = "0.13.0",
    });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/microzig@0.13.0", result.?);
}

test "forZigPackage: with URL qualifier" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "microzig",
        .version = "0.13.0",
        .url = "https://github.com/ZigEmbeddedGroup/microzig/archive/v0.13.0.tar.gz",
    });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/microzig@0.13.0#github.com/ZigEmbeddedGroup/microzig", result.?);
}

test "forZigPackage: falls back to hash prefix when no version" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "rp2xxx",
        .hash = "1220abcdef0123456789",
    });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/rp2xxx@1220abcdef012345", result.?);
}

test "forZigPackage: returns null when no version and no hash" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "unknown",
    });
    try testing.expect(result == null);
}

test "forCLibrary: basic" {
    const result = try forCLibrary(testing.allocator, "lwIP", "lwip", "2.1.3");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("pkg:generic/lwip/lwIP@2.1.3", result);
}

test "forCLibrary: unknown version" {
    const result = try forCLibrary(testing.allocator, "FreeRTOS", "freertos", null);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("pkg:generic/freertos/FreeRTOS@unknown", result);
}

test "forZigCompiler: basic" {
    const result = try forZigCompiler(testing.allocator, "0.14.0");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("pkg:generic/zig@0.14.0", result);
}

test "forZigPackage: name with reserved chars" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "my/lib@v2",
        .version = "1.0",
    });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/my%2Flib%40v2@1.0", result.?);
}

test "forZigPackage: name with hash char" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "lib#dev",
        .version = "1.0",
    });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/lib%23dev@1.0", result.?);
}

test "forZigPackage: empty name" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "",
        .version = "1.0",
    });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/@1.0", result.?);
}

test "forZigPackage: empty version and empty hash returns null" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "mylib",
        .hash = "",
    });
    try testing.expect(result == null);
}

test "purlPercentEncode: no reserved chars" {
    const result = try purlPercentEncode(testing.allocator, "simple-name");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("simple-name", result);
}

test "purlPercentEncode: all reserved chars" {
    const result = try purlPercentEncode(testing.allocator, "@/#?%");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("%40%2F%23%3F%25", result);
}

test "extractHostFromUrl: git+https URL" {
    const host = extractHostFromUrl("git+https://github.com/foo/bar#abc123");
    try testing.expectEqualStrings("github.com/foo/bar", host);
}

test "extractHostFromUrl: URL with no path" {
    const host = extractHostFromUrl("https://example.com");
    try testing.expectEqualStrings("example.com", host);
}

test "extractHostFromUrl: plain host only" {
    const host = extractHostFromUrl("example.com");
    try testing.expectEqualStrings("example.com", host);
}

test "forZigPackage: very long name (256+ chars)" {
    const long_name = "a" ** 300;
    const result = try forZigPackage(testing.allocator, .{
        .name = long_name,
        .version = "1.0",
    });
    defer testing.allocator.free(result.?);
    try testing.expect(std.mem.startsWith(u8, result.?, "pkg:zig/"));
    try testing.expect(std.mem.indexOf(u8, result.?, "@1.0") != null);
    // Full name preserved — PURL spec does not limit name length.
    try testing.expect(result.?.len > 300);
}

test "forZigPackage: unicode package name" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "日本語パッケージ",
        .version = "2.0",
    });
    defer testing.allocator.free(result.?);
    try testing.expect(std.mem.startsWith(u8, result.?, "pkg:zig/"));
    try testing.expect(std.mem.indexOf(u8, result.?, "@2.0") != null);
}

test "forZigPackage: empty URL with non-empty hash" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "mylib",
        .version = "1.0",
        .url = "",
        .hash = "1220abcdef0123456789",
    });
    defer testing.allocator.free(result.?);
    // Empty URL should not produce a fragment.
    try testing.expect(std.mem.indexOf(u8, result.?, "#") == null);
    try testing.expectEqualStrings("pkg:zig/mylib@1.0", result.?);
}

test "forZigPackageWithOpts: strict mode uses pkg:generic" {
    const result = try forZigPackageWithOpts(testing.allocator, .{
        .name = "microzig",
        .version = "0.13.0",
    }, .{ .strict_purl = true });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:generic/microzig@0.13.0", result.?);
}

test "forZigPackageWithOpts: strict mode with URL" {
    const result = try forZigPackageWithOpts(testing.allocator, .{
        .name = "microzig",
        .version = "0.13.0",
        .url = "https://github.com/ZigEmbeddedGroup/microzig/archive/v0.13.0.tar.gz",
    }, .{ .strict_purl = true });
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:generic/microzig@0.13.0#github.com/ZigEmbeddedGroup/microzig", result.?);
}

test "forZigPackageWithOpts: default (non-strict) uses pkg:zig" {
    const result = try forZigPackageWithOpts(testing.allocator, .{
        .name = "mylib",
        .version = "1.0",
    }, .{});
    defer testing.allocator.free(result.?);
    try testing.expectEqualStrings("pkg:zig/mylib@1.0", result.?);
}

test "forCLibrary: name with reserved chars" {
    const result = try forCLibrary(testing.allocator, "lib@v2/special", "ns#1", "1.0");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("pkg:generic/ns%231/lib%40v2%2Fspecial@1.0", result);
}

test "forZigCompiler: version with plus (build metadata)" {
    const result = try forZigCompiler(testing.allocator, "0.14.0+abcdef");
    defer testing.allocator.free(result);
    // '+' is not in the PURL-reserved set we encode, so it passes through.
    try testing.expectEqualStrings("pkg:generic/zig@0.14.0+abcdef", result);
}

test "extractHostFromUrl: URL with query params and fragment" {
    const host = extractHostFromUrl("https://github.com/org/repo?token=abc&ref=main#L42");
    try testing.expectEqualStrings("github.com/org/repo", host);
}

test "extractHostFromUrl: URL with only query, no fragment" {
    const host = extractHostFromUrl("https://example.com/a/b?q=1");
    try testing.expectEqualStrings("example.com/a/b", host);
}

test "forZigPackage: version with reserved chars" {
    const result = try forZigPackage(testing.allocator, .{
        .name = "mylib",
        .version = "1.0.0-beta+build",
    });
    defer testing.allocator.free(result.?);
    // Version is placed as-is (PURL spec treats version literally).
    try testing.expectEqualStrings("pkg:zig/mylib@1.0.0-beta+build", result.?);
}

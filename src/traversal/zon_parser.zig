const std = @import("std");
const Ast = std.zig.Ast;

pub const ZonParseError = error{
    OutOfMemory,
    ParseFailed,
    FileNotFound,
    ReadFailed,
};

pub const ZonMetadata = struct {
    name: ?[]const u8 = null,
    version: ?[]const u8 = null,
    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *ZonMetadata) void {
        const alloc = self.allocator orelse return;
        if (self.name) |n| alloc.free(n);
        if (self.version) |v| alloc.free(v);
        self.* = .{};
    }
};

/// Parses `.name` and `.version` fields from a build.zig.zon file.
/// Uses std.zig.Ast — no custom ZON parser.
/// Caller must call `deinit()` on the returned metadata.
pub fn parseZonFile(allocator: std.mem.Allocator, path: []const u8) ZonParseError!ZonMetadata {
    const source = std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return ZonParseError.FileNotFound,
        else => return ZonParseError.ReadFailed,
    };
    defer allocator.free(source);
    return parseZonSource(allocator, source);
}

/// Parses `.name` and `.version` fields from ZON source text.
/// Caller must call `deinit()` on the returned metadata.
pub fn parseZonSource(allocator: std.mem.Allocator, source: []const u8) ZonParseError!ZonMetadata {
    // Ast.parse requires a sentinel-terminated slice.
    const buf = allocator.alloc(u8, source.len + 1) catch return ZonParseError.OutOfMemory;
    defer allocator.free(buf);
    @memcpy(buf[0..source.len], source);
    buf[source.len] = 0;
    const source_z: [:0]const u8 = buf[0..source.len :0];

    var ast = Ast.parse(allocator, source_z, .zon) catch return ZonParseError.ParseFailed;
    defer ast.deinit(allocator);

    if (ast.errors.len > 0) return ZonParseError.ParseFailed;

    var result = ZonMetadata{ .allocator = allocator };
    errdefer result.deinit();

    const root_decls = ast.rootDecls();
    if (root_decls.len == 0) return result;
    const root_node = root_decls[0];

    var field_buf: [2]Ast.Node.Index = undefined;
    const fields_init = ast.fullStructInit(&field_buf, root_node) orelse return result;

    for (fields_init.ast.fields) |field_init| {
        const field_name = fieldName(ast, field_init) orelse continue;

        if (std.mem.eql(u8, field_name, "name")) {
            const raw = extractStringOrDotLiteral(ast, field_init) orelse continue;
            result.name = allocator.dupe(u8, raw) catch return ZonParseError.OutOfMemory;
        } else if (std.mem.eql(u8, field_name, "version")) {
            const raw = extractStringLiteral(ast, field_init) orelse continue;
            result.version = allocator.dupe(u8, raw) catch return ZonParseError.OutOfMemory;
        }
    }

    return result;
}

fn fieldName(ast: Ast, field_node: Ast.Node.Index) ?[]const u8 {
    const first = ast.firstToken(field_node);
    if (first < 2) return null;
    const name_token: Ast.TokenIndex = first - 2;
    const raw = ast.tokenSlice(name_token);
    if (raw.len > 1 and raw[0] == '.') return raw[1..];
    return raw;
}

// 0.15+ has nodeTag/nodeMainToken helpers; 0.14.0 only has multi-array access.
fn getNodeTag(ast: Ast, node: Ast.Node.Index) Ast.Node.Tag {
    if (@hasDecl(Ast, "nodeTag")) return ast.nodeTag(node);
    return ast.nodes.items(.tag)[node];
}

fn getNodeMainToken(ast: Ast, node: Ast.Node.Index) Ast.TokenIndex {
    if (@hasDecl(Ast, "nodeMainToken")) return ast.nodeMainToken(node);
    return ast.nodes.items(.main_token)[node];
}

fn extractStringLiteral(ast: Ast, node: Ast.Node.Index) ?[]const u8 {
    const tag = getNodeTag(ast, node);
    if (tag != .string_literal) return null;
    const token = getNodeMainToken(ast, node);
    const raw = ast.tokenSlice(token);
    if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
        return raw[1 .. raw.len - 1];
    }
    return raw;
}

fn extractStringOrDotLiteral(ast: Ast, node: Ast.Node.Index) ?[]const u8 {
    const tag = getNodeTag(ast, node);
    if (tag == .enum_literal) {
        const token = getNodeMainToken(ast, node);
        return ast.tokenSlice(token);
    }
    return extractStringLiteral(ast, node);
}

pub const ZonDependencyInfo = struct {
    url: ?[]const u8 = null,
};

/// Parses `.dependencies` from ZON source and extracts dep_name → url mappings.
/// Caller must call `deinitDependencies()` on the returned map.
pub fn parseZonDependencies(allocator: std.mem.Allocator, source: []const u8) ZonParseError!std.StringHashMap(ZonDependencyInfo) {
    const buf = allocator.alloc(u8, source.len + 1) catch return ZonParseError.OutOfMemory;
    defer allocator.free(buf);
    @memcpy(buf[0..source.len], source);
    buf[source.len] = 0;
    const source_z: [:0]const u8 = buf[0..source.len :0];

    var ast = Ast.parse(allocator, source_z, .zon) catch return ZonParseError.ParseFailed;
    defer ast.deinit(allocator);

    if (ast.errors.len > 0) return ZonParseError.ParseFailed;

    var result = std.StringHashMap(ZonDependencyInfo).init(allocator);
    errdefer deinitDependencies(&result, allocator);

    const root_decls = ast.rootDecls();
    if (root_decls.len == 0) return result;
    const root_node = root_decls[0];

    var field_buf: [2]Ast.Node.Index = undefined;
    const fields_init = ast.fullStructInit(&field_buf, root_node) orelse return result;

    for (fields_init.ast.fields) |field_init| {
        const name = fieldName(ast, field_init) orelse continue;
        if (!std.mem.eql(u8, name, "dependencies")) continue;

        var dep_field_buf: [2]Ast.Node.Index = undefined;
        const deps_init = ast.fullStructInit(&dep_field_buf, field_init) orelse continue;

        for (deps_init.ast.fields) |dep_field| {
            const dep_name = fieldName(ast, dep_field) orelse continue;

            var inner_buf: [2]Ast.Node.Index = undefined;
            const inner_init = ast.fullStructInit(&inner_buf, dep_field) orelse continue;

            var url: ?[]const u8 = null;
            for (inner_init.ast.fields) |inner_field| {
                const inner_name = fieldName(ast, inner_field) orelse continue;
                if (std.mem.eql(u8, inner_name, "url")) {
                    url = extractStringLiteral(ast, inner_field);
                }
            }

            const owned_name = allocator.dupe(u8, dep_name) catch return ZonParseError.OutOfMemory;
            errdefer allocator.free(owned_name);
            const owned_url: ?[]const u8 = if (url) |u|
                (allocator.dupe(u8, u) catch return ZonParseError.OutOfMemory)
            else
                null;

            result.put(owned_name, .{ .url = owned_url }) catch return ZonParseError.OutOfMemory;
        }
    }

    return result;
}

pub fn deinitDependencies(map: *std.StringHashMap(ZonDependencyInfo), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.url) |u| allocator.free(u);
        allocator.free(entry.key_ptr.*);
    }
    map.deinit();
}

const testing = std.testing;

test "parseZonSource: basic name and version" {
    const source =
        \\.{
        \\    .name = "my-project",
        \\    .version = "1.2.3",
        \\    .dependencies = .{},
        \\}
    ;
    var meta = try parseZonSource(testing.allocator, source);
    defer meta.deinit();
    try testing.expectEqualStrings("my-project", meta.name.?);
    try testing.expectEqualStrings("1.2.3", meta.version.?);
}

test "parseZonSource: dot-literal name" {
    const source =
        \\.{
        \\    .name = .zig_build_sbom,
        \\    .version = "0.1.0",
        \\    .fingerprint = 0xabc,
        \\    .paths = .{},
        \\    .dependencies = .{},
        \\}
    ;
    var meta = try parseZonSource(testing.allocator, source);
    defer meta.deinit();
    try testing.expectEqualStrings("zig_build_sbom", meta.name.?);
    try testing.expectEqualStrings("0.1.0", meta.version.?);
}

test "parseZonSource: missing fields" {
    const source =
        \\.{
        \\    .dependencies = .{},
        \\}
    ;
    var meta = try parseZonSource(testing.allocator, source);
    defer meta.deinit();
    try testing.expect(meta.name == null);
    try testing.expect(meta.version == null);
}

test "parseZonSource: empty source fails" {
    const result = parseZonSource(testing.allocator, "");
    try testing.expectError(ZonParseError.ParseFailed, result);
}

test "parseZonDependencies: extracts url" {
    const source =
        \\.{
        \\    .name = "my-project",
        \\    .version = "1.0.0",
        \\    .dependencies = .{
        \\        .serde = .{
        \\            .url = "git+https://github.com/example/serde.zig#abc123",
        \\            .hash = "serde-0.1.0-abc123",
        \\        },
        \\    },
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);

    try testing.expectEqual(@as(usize, 1), deps.count());
    const serde_info = deps.get("serde").?;
    try testing.expectEqualStrings(
        "git+https://github.com/example/serde.zig#abc123",
        serde_info.url.?,
    );
}

test "parseZonDependencies: multiple deps" {
    const source =
        \\.{
        \\    .name = "multi",
        \\    .version = "0.1.0",
        \\    .dependencies = .{
        \\        .lib_a = .{
        \\            .url = "https://example.com/a.tar.gz",
        \\            .hash = "a-hash",
        \\        },
        \\        .lib_b = .{
        \\            .url = "https://example.com/b.tar.gz",
        \\            .hash = "b-hash",
        \\        },
        \\    },
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);

    try testing.expectEqual(@as(usize, 2), deps.count());
    try testing.expect(deps.get("lib_a") != null);
    try testing.expect(deps.get("lib_b") != null);
}

test "parseZonDependencies: path dependency has no url" {
    const source =
        \\.{
        \\    .name = "path-dep",
        \\    .version = "0.1.0",
        \\    .dependencies = .{
        \\        .local = .{
        \\            .path = "../local-lib",
        \\        },
        \\    },
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);

    try testing.expectEqual(@as(usize, 1), deps.count());
    const local_info = deps.get("local").?;
    try testing.expect(local_info.url == null);
}

test "parseZonDependencies: no dependencies field" {
    const source =
        \\.{
        \\    .name = "nodeps",
        \\    .version = "1.0.0",
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);
    try testing.expectEqual(@as(usize, 0), deps.count());
}

test "parseZonSource: string with escape sequences" {
    const source =
        \\.{
        \\    .name = "escape-test",
        \\    .version = "1.0.0",
        \\    .fingerprint = 0xabc,
        \\    .paths = .{},
        \\}
    ;
    var meta = try parseZonSource(testing.allocator, source);
    defer meta.deinit();
    try testing.expectEqualStrings("escape-test", meta.name.?);
    try testing.expectEqualStrings("1.0.0", meta.version.?);
}

test "parseZonSource: only whitespace and comments fails" {
    const result = parseZonSource(testing.allocator, "  // just a comment\n  ");
    try testing.expectError(ZonParseError.ParseFailed, result);
}

test "parseZonDependencies: empty dependencies struct" {
    const source =
        \\.{
        \\    .name = "empty-deps",
        \\    .version = "1.0.0",
        \\    .dependencies = .{},
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);
    try testing.expectEqual(@as(usize, 0), deps.count());
}

test "parseZonDependencies: dependency with neither url nor path" {
    const source =
        \\.{
        \\    .name = "bare-dep",
        \\    .version = "1.0.0",
        \\    .dependencies = .{
        \\        .weird = .{
        \\            .hash = "some-hash",
        \\        },
        \\    },
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);

    try testing.expectEqual(@as(usize, 1), deps.count());
    const info = deps.get("weird").?;
    try testing.expect(info.url == null);
}

test "parseZonSource: name with hyphen and digits" {
    const source =
        \\.{
        \\    .name = "my-lib-2024",
        \\    .version = "0.0.1-rc.1",
        \\}
    ;
    var meta = try parseZonSource(testing.allocator, source);
    defer meta.deinit();
    try testing.expectEqualStrings("my-lib-2024", meta.name.?);
    try testing.expectEqualStrings("0.0.1-rc.1", meta.version.?);
}

test "parseZonDependencies: multiple deps with mixed url and path" {
    const source =
        \\.{
        \\    .name = "mixed",
        \\    .version = "1.0.0",
        \\    .dependencies = .{
        \\        .remote = .{
        \\            .url = "https://example.com/remote.tar.gz",
        \\            .hash = "abc123",
        \\        },
        \\        .local = .{
        \\            .path = "../local-lib",
        \\        },
        \\        .bare = .{
        \\            .hash = "def456",
        \\        },
        \\    },
        \\}
    ;
    var deps = try parseZonDependencies(testing.allocator, source);
    defer deinitDependencies(&deps, testing.allocator);

    try testing.expectEqual(@as(usize, 3), deps.count());
    try testing.expectEqualStrings("https://example.com/remote.tar.gz", deps.get("remote").?.url.?);
    try testing.expect(deps.get("local").?.url == null);
    try testing.expect(deps.get("bare").?.url == null);
}

test "parseZonSource: fingerprint and paths ignored" {
    const source =
        \\.{
        \\    .name = "multi-field",
        \\    .version = "2.0.0",
        \\    .fingerprint = 0xdeadbeef,
        \\    .paths = .{ "build.zig", "src" },
        \\    .dependencies = .{},
        \\}
    ;
    var meta = try parseZonSource(testing.allocator, source);
    defer meta.deinit();
    try testing.expectEqualStrings("multi-field", meta.name.?);
    try testing.expectEqualStrings("2.0.0", meta.version.?);
}

const std = @import("std");
const sbom_model = @import("../sbom.zig");
const zon_parser = @import("zon_parser.zig");
const purl_mod = @import("../util/purl.zig");

pub const ExtractionOptions = struct {
    include_transitive: bool = true,
    include_c_sources: bool = true,
    identify_vendored_libs: bool = true,
    include_zig_stdlib: bool = true,
    include_toolchain: bool = true,
    infer_licenses: bool = false,
    strict_purl: bool = false,
};

pub const PackageMetadata = struct {
    name: []const u8,
    version: ?[]const u8 = null,
    url: ?[]const u8 = null,
    hash: []const u8,
    build_root: []const u8,
};

pub const ExtractionContext = struct {
    allocator: std.mem.Allocator,
    options: ExtractionOptions,
    visited: std.StringHashMap(void),
    visited_modules: std.AutoHashMap(*std.Build.Module, void),
    components: std.ArrayListUnmanaged(sbom_model.Component),
    dependencies: std.ArrayListUnmanaged(sbom_model.Dependency),

    pub fn init(allocator: std.mem.Allocator, options: ExtractionOptions) ExtractionContext {
        return .{
            .allocator = allocator,
            .options = options,
            .visited = std.StringHashMap(void).init(allocator),
            .visited_modules = std.AutoHashMap(*std.Build.Module, void).init(allocator),
            .components = .{},
            .dependencies = .{},
        };
    }

    pub fn deinit(self: *ExtractionContext) void {
        self.visited.deinit();
        self.visited_modules.deinit();
        self.components.deinit(self.allocator);
        for (self.dependencies.items) |dep| {
            self.allocator.free(dep.depends_on);
        }
        self.dependencies.deinit(self.allocator);
    }

    /// Frees the visited tracking maps without touching component/dependency data.
    /// Use when extraction is complete but components are still referenced downstream.
    pub fn deinitVisitedOnly(self: *ExtractionContext) void {
        self.visited.deinit();
        self.visited_modules.deinit();
    }
};

pub const ExtractError = error{
    OutOfMemory,
};

/// Entry point: extract all components reachable from a compile step.
pub fn extractFromCompile(
    ctx: *ExtractionContext,
    compile: *std.Build.Step.Compile,
) ExtractError!void {
    const owner = compile.root_module.owner;
    try extractZigPackage(ctx, owner, .root, null);

    if (ctx.options.include_c_sources) {
        const c_sources = @import("c_sources.zig");
        try c_sources.extractCSourceFiles(ctx, compile);
    }

    try extractModuleImports(ctx, compile.root_module, owner.dep_prefix);

    if (ctx.options.include_toolchain) {
        try addToolchainComponent(ctx);
    }
}

fn addToolchainComponent(ctx: *ExtractionContext) ExtractError!void {
    const zig_version = @import("builtin").zig_version_string;
    const purl_str = purl_mod.forZigCompiler(ctx.allocator, zig_version) catch
        return ExtractError.OutOfMemory;

    const component = sbom_model.Component{
        .type = .application,
        .bom_ref = "zig-compiler",
        .name = "zig",
        .version = zig_version,
        .purl = purl_str,
        .scope = .required,
    };
    ctx.components.append(ctx.allocator, component) catch return ExtractError.OutOfMemory;

    // Link the root component to the compiler so the dependency graph
    // reflects the build tool relationship.
    if (ctx.components.items.len > 0) {
        const root_ref = ctx.components.items[0].bom_ref;
        const dep_slice = ctx.allocator.alloc([]const u8, 1) catch return ExtractError.OutOfMemory;
        dep_slice[0] = "zig-compiler";
        ctx.dependencies.append(ctx.allocator, .{
            .ref = root_ref,
            .depends_on = dep_slice,
        }) catch return ExtractError.OutOfMemory;
    }
}

/// Extracts a Zig package as an SBOM component.
fn extractZigPackage(
    ctx: *ExtractionContext,
    builder: *std.Build,
    role: enum { root, dependency },
    source_url: ?[]const u8,
) ExtractError!void {
    const pkg_id = builder.dep_prefix;

    if (pkg_id.len > 0) {
        const gop = ctx.visited.getOrPut(pkg_id) catch return ExtractError.OutOfMemory;
        if (gop.found_existing) return;
    }

    const meta = resolvePackageMetadata(ctx.allocator, builder, source_url) catch |err| switch (err) {
        error.OutOfMemory => return ExtractError.OutOfMemory,
        else => PackageMetadata{
            .name = "<unknown>",
            .hash = pkg_id,
            .build_root = builder.build_root.path orelse ".",
            .url = source_url,
        },
    };

    // dep_prefix has a trailing dot separator (e.g. "zig-build-sbom.") — strip it.
    const clean_id = if (pkg_id.len > 0 and pkg_id[pkg_id.len - 1] == '.')
        pkg_id[0 .. pkg_id.len - 1]
    else
        pkg_id;

    const bom_ref = if (clean_id.len > 0) clean_id else meta.name;

    // Only content-addressed hashes (starting with "1220") are real.
    // Path dependencies use the dep name, not a hash.
    const is_content_hash = std.mem.startsWith(u8, clean_id, "1220");
    const hashes: []const sbom_model.Hash = if (is_content_hash) blk: {
        const raw_hash = clean_id[4..];
        const h = ctx.allocator.alloc(sbom_model.Hash, 1) catch return ExtractError.OutOfMemory;
        h[0] = .{ .alg = .sha2_256, .content = raw_hash };
        break :blk h;
    } else &.{};

    const purl_result = purl_mod.forZigPackageWithOpts(ctx.allocator, .{
        .name = meta.name,
        .version = meta.version,
        .url = meta.url,
        .hash = if (is_content_hash) clean_id else "",
    }, .{ .strict_purl = ctx.options.strict_purl }) catch null;

    const licenses: []const sbom_model.LicenseExpression = if (ctx.options.infer_licenses) blk: {
        if (inferLicense(ctx.allocator, meta.build_root)) |spdx_id| {
            const arr = ctx.allocator.alloc(sbom_model.LicenseExpression, 1) catch break :blk &.{};
            arr[0] = .{ .spdx = spdx_id };
            break :blk arr;
        } else break :blk &.{};
    } else &.{};

    const component = sbom_model.Component{
        .type = if (role == .root) .firmware else .library,
        .bom_ref = bom_ref,
        .name = meta.name,
        .version = meta.version,
        .purl = purl_result,
        .hashes = hashes,
        .licenses = licenses,
        .source_url = meta.url,
        .scope = .required,
    };

    ctx.components.append(ctx.allocator, component) catch return ExtractError.OutOfMemory;

    if (ctx.options.include_transitive) {
        try extractTransitiveDeps(ctx, builder, bom_ref);
    }
}

fn stripTrailingDot(s: []const u8) []const u8 {
    if (s.len > 0 and s[s.len - 1] == '.') return s[0 .. s.len - 1];
    return s;
}

fn extractTransitiveDeps(
    ctx: *ExtractionContext,
    builder: *std.Build,
    parent_ref: []const u8,
) ExtractError!void {
    // Parse the parent's ZON to get dependency download URLs for children.
    var dep_urls_opt = resolveDepUrls(ctx.allocator, builder);
    defer if (dep_urls_opt) |*m| zon_parser.deinitDependencies(m, ctx.allocator);

    var dep_refs: std.ArrayListUnmanaged([]const u8) = .{};
    defer dep_refs.deinit(ctx.allocator);

    for (builder.available_deps) |dep_pair| {
        const dep_name = dep_pair[0];
        const dep = builder.dependency(dep_name, .{});
        const child_ref = stripTrailingDot(dep.builder.dep_prefix);

        const dep_url: ?[]const u8 = if (dep_urls_opt) |urls|
            (if (urls.get(dep_name)) |info| info.url else null)
        else
            null;

        try extractZigPackage(ctx, dep.builder, .dependency, dep_url);
        dep_refs.append(ctx.allocator, child_ref) catch return ExtractError.OutOfMemory;
    }

    if (dep_refs.items.len > 0) {
        const owned = ctx.allocator.dupe([]const u8, dep_refs.items) catch return ExtractError.OutOfMemory;
        ctx.dependencies.append(ctx.allocator, .{
            .ref = parent_ref,
            .depends_on = owned,
        }) catch return ExtractError.OutOfMemory;
    }
}

/// Walk a Module's import table, following cross-package imports.
fn extractModuleImports(
    ctx: *ExtractionContext,
    module: *std.Build.Module,
    parent_prefix: []const u8,
) ExtractError!void {
    const gop = ctx.visited_modules.getOrPut(module) catch return ExtractError.OutOfMemory;
    if (gop.found_existing) return;

    var it = module.import_table.iterator();
    while (it.next()) |entry| {
        const imported_module = entry.value_ptr.*;
        const mod_prefix = imported_module.owner.dep_prefix;

        if (mod_prefix.len > 0 and !std.mem.eql(u8, mod_prefix, parent_prefix)) {
            try extractZigPackage(ctx, imported_module.owner, .dependency, null);
        }
        try extractModuleImports(ctx, imported_module, mod_prefix);
    }
}

pub const ResolveError = error{
    OutOfMemory,
    FileNotFound,
    ParseFailed,
    ReadFailed,
};

pub fn resolvePackageMetadata(
    allocator: std.mem.Allocator,
    builder: *std.Build,
    source_url: ?[]const u8,
) ResolveError!PackageMetadata {
    const build_root = builder.build_root.path orelse ".";
    const zon_path = std.fs.path.join(allocator, &.{ build_root, "build.zig.zon" }) catch
        return ResolveError.OutOfMemory;
    defer allocator.free(zon_path);

    const zon_meta = zon_parser.parseZonFile(allocator, zon_path) catch |err| switch (err) {
        error.OutOfMemory => return ResolveError.OutOfMemory,
        error.FileNotFound => return ResolveError.FileNotFound,
        error.ParseFailed => return ResolveError.ParseFailed,
        error.ReadFailed => return ResolveError.ReadFailed,
    };
    // Ownership of strings transfers to the caller via PackageMetadata.
    // Do not deinit zon_meta — caller manages lifetime via arena or explicit free.

    return PackageMetadata{
        .name = zon_meta.name orelse "<unknown>",
        .version = zon_meta.version,
        .url = source_url,
        .hash = builder.dep_prefix,
        .build_root = build_root,
    };
}

fn resolveDepUrls(allocator: std.mem.Allocator, builder: *std.Build) ?std.StringHashMap(zon_parser.ZonDependencyInfo) {
    const build_root = builder.build_root.path orelse return null;
    const zon_path = std.fs.path.join(allocator, &.{ build_root, "build.zig.zon" }) catch return null;
    // Arena allocator makes this free a no-op, but it's correct for GPA too.
    defer allocator.free(zon_path);

    const source = std.fs.cwd().readFileAlloc(allocator, zon_path, 1024 * 1024) catch return null;
    defer allocator.free(source);

    return zon_parser.parseZonDependencies(allocator, source) catch null;
}

// License file detection. Checks for common license files in the package root
// and matches their content against well-known license text patterns.
fn inferLicense(allocator: std.mem.Allocator, build_root: []const u8) ?[]const u8 {
    const license_filenames = [_][]const u8{
        "LICENSE",     "LICENSE.md",  "LICENSE.txt",
        "LICENCE",     "LICENCE.md",  "LICENCE.txt",
        "COPYING",     "COPYING.md",  "COPYING.txt",
        "LICENSE-MIT", "LICENSE-APACHE",
    };

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    for (license_filenames) |filename| {
        const joined = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ build_root, filename }) catch continue;
        const content = std.fs.cwd().readFileAlloc(allocator, joined, 4096) catch continue;
        defer allocator.free(content);

        if (matchLicenseContent(content)) |spdx_id| return spdx_id;
    }
    return null;
}

fn matchLicenseContent(content: []const u8) ?[]const u8 {
    const sample = content[0..@min(content.len, 2048)];

    if (std.mem.indexOf(u8, sample, "MIT License") != null or
        std.mem.indexOf(u8, sample, "Permission is hereby granted, free of charge") != null)
        return "MIT";

    if (std.mem.indexOf(u8, sample, "Apache License") != null and
        std.mem.indexOf(u8, sample, "Version 2.0") != null)
        return "Apache-2.0";

    if (std.mem.indexOf(u8, sample, "BSD 1-Clause") != null) return "BSD-1-Clause";
    if (std.mem.indexOf(u8, sample, "BSD 2-Clause") != null) return "BSD-2-Clause";
    if (std.mem.indexOf(u8, sample, "BSD 3-Clause") != null) return "BSD-3-Clause";
    if (std.mem.indexOf(u8, sample, "ISC License") != null) return "ISC";

    if (std.mem.indexOf(u8, sample, "Mozilla Public License Version 2.0") != null or
        std.mem.indexOf(u8, sample, "Mozilla Public License, v. 2.0") != null)
        return "MPL-2.0";

    if (std.mem.indexOf(u8, sample, "GNU GENERAL PUBLIC LICENSE") != null) {
        if (std.mem.indexOf(u8, sample, "Version 3") != null) return "GPL-3.0-only";
        if (std.mem.indexOf(u8, sample, "Version 2") != null) return "GPL-2.0-only";
    }
    if (std.mem.indexOf(u8, sample, "GNU LESSER GENERAL PUBLIC LICENSE") != null) {
        if (std.mem.indexOf(u8, sample, "Version 3") != null) return "LGPL-3.0-only";
        if (std.mem.indexOf(u8, sample, "Version 2.1") != null) return "LGPL-2.1-only";
    }

    if (std.mem.indexOf(u8, sample, "Boost Software License") != null) return "BSL-1.0";
    if (std.mem.indexOf(u8, sample, "The Unlicense") != null) return "Unlicense";

    if (std.mem.indexOf(u8, sample, "Creative Commons") != null and
        std.mem.indexOf(u8, sample, "CC0") != null)
        return "CC0-1.0";

    if (std.mem.indexOf(u8, sample, "zlib License") != null or
        std.mem.indexOf(u8, sample, "zlib/libpng") != null)
        return "Zlib";

    return null;
}

const testing = std.testing;

test "ExtractionContext: init and deinit" {
    var ctx = ExtractionContext.init(testing.allocator, .{});
    defer ctx.deinit();
    try testing.expectEqual(@as(usize, 0), ctx.components.items.len);
    try testing.expectEqual(@as(usize, 0), ctx.dependencies.items.len);
}

test "ExtractionContext: manual component insertion" {
    var ctx = ExtractionContext.init(testing.allocator, .{});
    defer ctx.deinit();

    try ctx.components.append(ctx.allocator, .{
        .type = .firmware,
        .bom_ref = "test-ref",
        .name = "test-fw",
        .version = "1.0.0",
    });
    try testing.expectEqual(@as(usize, 1), ctx.components.items.len);
    try testing.expectEqualStrings("test-fw", ctx.components.items[0].name);
}

test "PackageMetadata: fields" {
    const meta = PackageMetadata{
        .name = "mylib",
        .version = "2.0.0",
        .hash = "1220abcdef",
        .build_root = "/tmp/mylib",
    };
    try testing.expectEqualStrings("mylib", meta.name);
    try testing.expectEqualStrings("2.0.0", meta.version.?);
}

test "matchLicenseContent: MIT" {
    try testing.expectEqualStrings("MIT", matchLicenseContent("MIT License\n\nCopyright (c) 2024").?);
}

test "matchLicenseContent: MIT via grant text" {
    try testing.expectEqualStrings("MIT", matchLicenseContent("Permission is hereby granted, free of charge, to any person").?);
}

test "matchLicenseContent: Apache-2.0" {
    try testing.expectEqualStrings("Apache-2.0", matchLicenseContent("Apache License\nVersion 2.0, January 2004").?);
}

test "matchLicenseContent: BSD-3-Clause" {
    try testing.expectEqualStrings("BSD-3-Clause", matchLicenseContent("BSD 3-Clause License\n\nRedistribution").?);
}

test "matchLicenseContent: GPL-3.0" {
    try testing.expectEqualStrings("GPL-3.0-only", matchLicenseContent("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007").?);
}

test "matchLicenseContent: unknown returns null" {
    try testing.expect(matchLicenseContent("This is some proprietary license text.") == null);
}

test "matchLicenseContent: empty returns null" {
    try testing.expect(matchLicenseContent("") == null);
}

test "matchLicenseContent: BSD-1-Clause" {
    try testing.expectEqualStrings("BSD-1-Clause", matchLicenseContent("BSD 1-Clause License\n\nRedistribution").?);
}

test "matchLicenseContent: bare 'BSD' without clause number returns null" {
    try testing.expect(matchLicenseContent("This software is available under the BSD license.") == null);
}

test "matchLicenseContent: 'MIT License' in non-license context returns MIT" {
    // matchLicenseContent does text matching — it cannot distinguish context.
    // A file mentioning "MIT License" in documentation will match.
    // This test documents the known behavior.
    const result = matchLicenseContent("This code was originally released under the MIT License by the author.");
    try testing.expectEqualStrings("MIT", result.?);
}

test "ExtractionOptions: infer_licenses defaults false" {
    const opts = ExtractionOptions{};
    try testing.expect(!opts.infer_licenses);
}

test "matchLicenseContent: multiple patterns present — first match wins" {
    // MIT appears before Apache in the matching logic, so MIT wins
    // even if Apache text also appears.
    const content = "MIT License\n\nApache License\nVersion 2.0";
    try testing.expectEqualStrings("MIT", matchLicenseContent(content).?);
}

test "matchLicenseContent: text beyond 2048 bytes is ignored" {
    // Pad 2049 bytes of filler before the license text.
    const padding = "." ** 2049;
    const content = padding ++ "MIT License";
    try testing.expect(matchLicenseContent(content) == null);
}

test "matchLicenseContent: ISC" {
    try testing.expectEqualStrings("ISC", matchLicenseContent("ISC License\n\nCopyright (c)").?);
}

test "matchLicenseContent: MPL-2.0 via full name" {
    try testing.expectEqualStrings("MPL-2.0", matchLicenseContent("Mozilla Public License Version 2.0").?);
}

test "matchLicenseContent: MPL-2.0 via short form" {
    try testing.expectEqualStrings("MPL-2.0", matchLicenseContent("Mozilla Public License, v. 2.0").?);
}

test "matchLicenseContent: Unlicense" {
    try testing.expectEqualStrings("Unlicense", matchLicenseContent("This is free and unencumbered software released into the public domain.\n\nThe Unlicense").?);
}

test "matchLicenseContent: Zlib" {
    try testing.expectEqualStrings("Zlib", matchLicenseContent("zlib License\n\nThis software is provided 'as-is'").?);
}

test "matchLicenseContent: BSL-1.0" {
    try testing.expectEqualStrings("BSL-1.0", matchLicenseContent("Boost Software License - Version 1.0").?);
}

test "matchLicenseContent: CC0-1.0" {
    try testing.expectEqualStrings("CC0-1.0", matchLicenseContent("Creative Commons CC0 1.0 Universal").?);
}

test "matchLicenseContent: LGPL-2.1" {
    try testing.expectEqualStrings("LGPL-2.1-only", matchLicenseContent("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999").?);
}

test "matchLicenseContent: GPL-2.0" {
    try testing.expectEqualStrings("GPL-2.0-only", matchLicenseContent("GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991").?);
}

const std = @import("std");
const sbom_model = @import("sbom.zig");
const graph = @import("traversal/graph.zig");
const uuid_mod = @import("util/uuid.zig");
const timestamp_mod = @import("util/timestamp.zig");

pub const SbomStep = struct {
    // Phase 1: graph extraction + intermediate JSON.
    extraction_step: std.Build.Step,
    compile: *std.Build.Step.Compile,
    options: Options,
    intermediate_file: std.Build.GeneratedFile,

    // Phase 2: serializer executable produces final SBOM.
    run_step: *std.Build.Step.Run,
    output_file: std.Build.LazyPath,

    // Additional components injected by MicroZig integration or other extensions.
    extra_components: std.ArrayList(sbom_model.Component),
    extra_properties: []const sbom_model.Property,

    pub const base_id: std.Build.Step.Id = .custom;

    pub const Options = struct {
        format: Format = .cyclonedx_json,
        output_path: []const u8 = "sbom.cdx.json",
        version: []const u8 = "0.0.0",
        manufacturer: ?sbom_model.OrganizationalEntity = null,
        include_c_sources: bool = true,
        include_transitive: bool = true,
        infer_licenses: bool = true,
        require_licenses: bool = false,
        custom_properties: []const sbom_model.Property = &.{},
        /// Use `pkg:generic/` instead of the unofficial `pkg:zig/` PURL type.
        strict_purl: bool = false,
    };

    pub const Format = enum {
        cyclonedx_json,
        cyclonedx_xml,
        spdx_json,

        fn toCliArg(self: Format) []const u8 {
            return switch (self) {
                .cyclonedx_json => "cyclonedx-json",
                .cyclonedx_xml => "cyclonedx-xml",
                .spdx_json => "spdx-json",
            };
        }
    };

    pub fn create(
        b: *std.Build,
        compile: *std.Build.Step.Compile,
        options: Options,
        serializer: *std.Build.Step.Compile,
    ) *SbomStep {
        const self = b.allocator.create(SbomStep) catch @panic("OOM");
        self.* = .{
            .extraction_step = std.Build.Step.init(.{
                .id = base_id,
                .name = b.fmt("sbom extract {s}", .{compile.name}),
                .owner = b,
                .makeFn = makeIntermediate,
            }),
            .compile = compile,
            .options = options,
            .intermediate_file = .{ .step = &self.extraction_step },
            .run_step = undefined,
            .output_file = undefined,
            .extra_components = .{},
            .extra_properties = options.custom_properties,
        };

        // Phase 2: run the serializer executable on the intermediate JSON.
        const run = b.addRunArtifact(serializer);
        run.addFileArg(.{ .generated = .{ .file = &self.intermediate_file } });
        const output = run.addOutputFileArg(options.output_path);
        run.addArg(options.format.toCliArg());
        run.step.dependOn(&self.extraction_step);

        self.run_step = run;
        self.output_file = output;
        return self;
    }

    /// Returns a LazyPath to the generated SBOM file for chaining.
    pub fn getOutput(self: *SbomStep) std.Build.LazyPath {
        return self.output_file;
    }

    // Phase 1: extract build graph and write intermediate JSON.
    fn makeIntermediate(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const self: *SbomStep = @fieldParentPtr("extraction_step", step);
        const b = step.owner;
        const allocator = b.allocator;

        var ctx = graph.ExtractionContext.init(allocator, .{
            .include_c_sources = self.options.include_c_sources,
            .include_transitive = self.options.include_transitive,
            .infer_licenses = self.options.infer_licenses,
            .strict_purl = self.options.strict_purl,
        });

        graph.extractFromCompile(&ctx, self.compile) catch |err| {
            try step.addError("SBOM graph extraction failed: {}", .{err});
            return;
        };

        // Components and dependencies are still referenced, but the visited
        // sets are only needed during traversal.
        ctx.deinitVisitedOnly();

        for (self.extra_components.items) |comp| {
            ctx.components.append(allocator, comp) catch {
                try step.addError("SBOM: failed to add extra component", .{});
                return;
            };
        }

        const bom = assembleBom(allocator, &ctx, self) catch |err| {
            try step.addError("SBOM assembly failed: {}", .{err});
            return;
        };

        if (self.options.require_licenses) {
            var missing_count: usize = 0;
            for (bom.components) |comp| {
                if (comp.licenses.len == 0) {
                    try step.addError("SBOM: component '{s}' has no license", .{comp.name});
                    missing_count += 1;
                }
            }
            if (bom.metadata.component) |root| {
                if (root.licenses.len == 0) {
                    try step.addError("SBOM: root component '{s}' has no license", .{root.name});
                    missing_count += 1;
                }
            }
            if (missing_count > 0) return;
        }

        // Serialize Bom to intermediate JSON using a flat (non-recursive) writer.
        // std.json.Stringify uses anytype-based comptime dispatch that causes
        // stack overflow in build runner worker threads (~512KB stack on macOS).
        var out: std.ArrayList(u8) = .{};
        defer out.deinit(allocator);
        serializeBomJson(&out, allocator, bom) catch |err| {
            try step.addError("SBOM: intermediate JSON serialization failed: {}", .{err});
            return;
        };

        const cache_dir_path = b.cache_root.path orelse ".";
        // Include the compile step name to avoid collisions in multi-firmware builds.
        const intermediate_name = std.fmt.allocPrint(allocator, "sbom_intermediate_{s}.json", .{self.compile.name}) catch {
            try step.addError("SBOM: intermediate name alloc failed", .{});
            return;
        };
        const intermediate_path = std.fs.path.join(allocator, &.{ cache_dir_path, intermediate_name }) catch {
            try step.addError("SBOM: path join failed", .{});
            return;
        };

        if (std.fs.path.dirname(intermediate_path)) |dir| {
            std.fs.cwd().makePath(dir) catch {};
        }

        const file = std.fs.cwd().createFile(intermediate_path, .{}) catch |err| {
            try step.addError("SBOM: failed to create intermediate file {s}: {}", .{ intermediate_path, err });
            return;
        };
        defer file.close();
        file.writeAll(out.items) catch |err| {
            try step.addError("SBOM: failed to write intermediate file: {}", .{err});
            return;
        };

        self.intermediate_file.path = intermediate_path;
    }

    fn assembleBom(
        allocator: std.mem.Allocator,
        ctx: *graph.ExtractionContext,
        self: *SbomStep,
    ) !sbom_model.Bom {
        const serial = try uuid_mod.generateV4(allocator);
        const ts = try timestamp_mod.now(allocator);

        const root_component: ?sbom_model.Component = if (ctx.components.items.len > 0) blk: {
            var root = ctx.components.items[0];
            root.version = self.options.version;
            root.properties = self.extra_properties;
            break :blk root;
        } else null;

        // Partition components: Zig packages get "complete", C heuristics get "incomplete".
        var zig_refs: std.ArrayList([]const u8) = .{};
        defer zig_refs.deinit(allocator);
        var c_refs: std.ArrayList([]const u8) = .{};
        defer c_refs.deinit(allocator);

        for (ctx.components.items) |comp| {
            if (std.mem.startsWith(u8, comp.bom_ref, "c-lib-")) {
                try c_refs.append(allocator, comp.bom_ref);
            } else {
                try zig_refs.append(allocator, comp.bom_ref);
            }
        }

        const num_compositions: usize = (if (zig_refs.items.len > 0) @as(usize, 1) else 0) +
            (if (c_refs.items.len > 0) @as(usize, 1) else 0);
        const compositions = try allocator.alloc(sbom_model.Composition, num_compositions);
        var comp_idx: usize = 0;

        if (zig_refs.items.len > 0) {
            compositions[comp_idx] = .{
                .aggregate = .complete,
                .assemblies = try allocator.dupe([]const u8, zig_refs.items),
            };
            comp_idx += 1;
        }
        if (c_refs.items.len > 0) {
            compositions[comp_idx] = .{
                .aggregate = .incomplete,
                .assemblies = try allocator.dupe([]const u8, c_refs.items),
            };
        }

        return sbom_model.Bom{
            .serial_number = serial,
            .version = 1,
            .metadata = .{
                .timestamp = ts,
                .tools = &.{.{
                    .vendor = "zig-embedded-group",
                    .name = "zig-build-sbom",
                    .version = "0.1.0",
                }},
                .component = root_component,
                .manufacturer = self.options.manufacturer,
            },
            // Skip the root component (index 0) — it's in metadata.component.
            .components = if (ctx.components.items.len > 1) ctx.components.items[1..] else &.{},
            .dependencies = ctx.dependencies.items,
            .compositions = compositions,
        };
    }
};

// Flat JSON serializer for Bom → intermediate format.
// Uses ArrayList(u8) directly to avoid anytype/comptime dispatch depth
// that causes stack overflow in build runner worker threads.

fn serializeBomJson(out: *std.ArrayList(u8), a: std.mem.Allocator, bom: sbom_model.Bom) !void {
    try out.appendSlice(a, "{");
    try appendStr(out, a, "\"serial_number\":");
    try appendQuoted(out, a, bom.serial_number);
    try appendStr(out, a, ",\"version\":");
    try appendInt(out, a, bom.version);
    try appendStr(out, a, ",\"metadata\":");
    try serializeMetadata(out, a, bom.metadata);
    try appendStr(out, a, ",\"components\":[");
    for (bom.components, 0..) |comp, i| {
        if (i > 0) try out.append(a, ',');
        try serializeComponent(out, a, comp);
    }
    try appendStr(out, a, "],\"dependencies\":[");
    for (bom.dependencies, 0..) |dep, i| {
        if (i > 0) try out.append(a, ',');
        try serializeDependency(out, a, dep);
    }
    try appendStr(out, a, "],\"compositions\":[");
    for (bom.compositions, 0..) |comp, i| {
        if (i > 0) try out.append(a, ',');
        try serializeComposition(out, a, comp);
    }
    try appendStr(out, a, "]}");
}

fn serializeMetadata(out: *std.ArrayList(u8), a: std.mem.Allocator, meta: sbom_model.Metadata) !void {
    try out.append(a, '{');
    try appendStr(out, a, "\"timestamp\":");
    try appendQuoted(out, a, meta.timestamp);
    try appendStr(out, a, ",\"tools\":[");
    for (meta.tools, 0..) |tool, i| {
        if (i > 0) try out.append(a, ',');
        try serializeTool(out, a, tool);
    }
    try out.append(a, ']');
    try appendStr(out, a, ",\"component\":");
    if (meta.component) |comp| {
        try serializeComponent(out, a, comp);
    } else {
        try appendStr(out, a, "null");
    }
    try appendStr(out, a, ",\"manufacturer\":");
    if (meta.manufacturer) |mfr| {
        try serializeManufacturer(out, a, mfr);
    } else {
        try appendStr(out, a, "null");
    }
    try out.append(a, '}');
}

fn serializeTool(out: *std.ArrayList(u8), a: std.mem.Allocator, tool: sbom_model.Tool) !void {
    try out.append(a, '{');
    try appendStr(out, a, "\"vendor\":");
    try appendQuoted(out, a, tool.vendor);
    try appendStr(out, a, ",\"name\":");
    try appendQuoted(out, a, tool.name);
    try appendStr(out, a, ",\"version\":");
    try appendQuoted(out, a, tool.version);
    try out.append(a, '}');
}

fn serializeComponent(out: *std.ArrayList(u8), a: std.mem.Allocator, comp: sbom_model.Component) !void {
    try out.append(a, '{');
    try appendStr(out, a, "\"type\":");
    try appendQuoted(out, a, @tagName(comp.type));
    try appendStr(out, a, ",\"bom_ref\":");
    try appendQuoted(out, a, comp.bom_ref);
    try appendStr(out, a, ",\"name\":");
    try appendQuoted(out, a, comp.name);

    try appendStr(out, a, ",\"version\":");
    if (comp.version) |v| try appendQuoted(out, a, v) else try appendStr(out, a, "null");

    try appendStr(out, a, ",\"purl\":");
    if (comp.purl) |p| try appendQuoted(out, a, p) else try appendStr(out, a, "null");

    try appendStr(out, a, ",\"hashes\":[");
    for (comp.hashes, 0..) |h, i| {
        if (i > 0) try out.append(a, ',');
        try out.append(a, '{');
        try appendStr(out, a, "\"alg\":");
        try appendQuoted(out, a, @tagName(h.alg));
        try appendStr(out, a, ",\"content\":");
        try appendQuoted(out, a, h.content);
        try out.append(a, '}');
    }

    try appendStr(out, a, "],\"licenses\":[");
    for (comp.licenses, 0..) |lic, i| {
        if (i > 0) try out.append(a, ',');
        switch (lic) {
            .spdx => |expr| {
                try appendStr(out, a, "{\"spdx\":");
                try appendQuoted(out, a, expr);
                try out.append(a, '}');
            },
            .named => |name| {
                try appendStr(out, a, "{\"named\":");
                try appendQuoted(out, a, name);
                try out.append(a, '}');
            },
            .no_assertion => try appendStr(out, a, "{\"no_assertion\":{}}"),
        }
    }

    try appendStr(out, a, "],\"source_url\":");
    if (comp.source_url) |u| try appendQuoted(out, a, u) else try appendStr(out, a, "null");

    try appendStr(out, a, ",\"scope\":");
    try appendQuoted(out, a, @tagName(comp.scope));

    try appendStr(out, a, ",\"description\":");
    if (comp.description) |d| try appendQuoted(out, a, d) else try appendStr(out, a, "null");

    try appendStr(out, a, ",\"properties\":[");
    for (comp.properties, 0..) |prop, i| {
        if (i > 0) try out.append(a, ',');
        try out.append(a, '{');
        try appendStr(out, a, "\"name\":");
        try appendQuoted(out, a, prop.name);
        try appendStr(out, a, ",\"value\":");
        try appendQuoted(out, a, prop.value);
        try out.append(a, '}');
    }
    try appendStr(out, a, "]}");
}

fn serializeDependency(out: *std.ArrayList(u8), a: std.mem.Allocator, dep: sbom_model.Dependency) !void {
    try out.append(a, '{');
    try appendStr(out, a, "\"ref\":");
    try appendQuoted(out, a, dep.ref);
    try appendStr(out, a, ",\"depends_on\":[");
    for (dep.depends_on, 0..) |d, i| {
        if (i > 0) try out.append(a, ',');
        try appendQuoted(out, a, d);
    }
    try appendStr(out, a, "]}");
}

fn serializeComposition(out: *std.ArrayList(u8), a: std.mem.Allocator, comp: sbom_model.Composition) !void {
    try out.append(a, '{');
    try appendStr(out, a, "\"aggregate\":");
    try appendQuoted(out, a, @tagName(comp.aggregate));
    try appendStr(out, a, ",\"assemblies\":[");
    for (comp.assemblies, 0..) |ref, i| {
        if (i > 0) try out.append(a, ',');
        try appendQuoted(out, a, ref);
    }
    try appendStr(out, a, "]}");
}

fn serializeManufacturer(out: *std.ArrayList(u8), a: std.mem.Allocator, mfr: sbom_model.OrganizationalEntity) !void {
    try out.append(a, '{');
    try appendStr(out, a, "\"name\":");
    try appendQuoted(out, a, mfr.name);
    try appendStr(out, a, ",\"url\":");
    if (mfr.url) |u| try appendQuoted(out, a, u) else try appendStr(out, a, "null");
    try appendStr(out, a, ",\"contact\":");
    if (mfr.contact) |contacts| {
        try out.append(a, '[');
        for (contacts, 0..) |c, i| {
            if (i > 0) try out.append(a, ',');
            try out.append(a, '{');
            try appendStr(out, a, "\"name\":");
            if (c.name) |n| try appendQuoted(out, a, n) else try appendStr(out, a, "null");
            try appendStr(out, a, ",\"email\":");
            if (c.email) |e| try appendQuoted(out, a, e) else try appendStr(out, a, "null");
            try out.append(a, '}');
        }
        try out.append(a, ']');
    } else {
        try appendStr(out, a, "null");
    }
    try out.append(a, '}');
}

fn appendStr(out: *std.ArrayList(u8), a: std.mem.Allocator, s: []const u8) !void {
    try out.appendSlice(a, s);
}

fn appendQuoted(out: *std.ArrayList(u8), a: std.mem.Allocator, s: []const u8) !void {
    try out.append(a, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(a, "\\\""),
            '\\' => try out.appendSlice(a, "\\\\"),
            '\n' => try out.appendSlice(a, "\\n"),
            '\r' => try out.appendSlice(a, "\\r"),
            '\t' => try out.appendSlice(a, "\\t"),
            else => {
                // RFC 8259: all U+0000–U+001F must be escaped.
                if (c < 0x20) {
                    try out.appendSlice(a, "\\u00");
                    const hex = "0123456789abcdef";
                    try out.append(a, hex[c >> 4]);
                    try out.append(a, hex[c & 0x0f]);
                } else {
                    try out.append(a, c);
                }
            },
        }
    }
    try out.append(a, '"');
}

fn appendInt(out: *std.ArrayList(u8), a: std.mem.Allocator, value: u32) !void {
    var buf: [10]u8 = undefined;
    var pos: usize = 0;
    var v = value;
    if (v == 0) {
        try out.append(a, '0');
        return;
    }
    while (v > 0) : (pos += 1) {
        buf[pos] = @intCast('0' + (v % 10));
        v /= 10;
    }
    var i: usize = 0;
    while (i < pos / 2) : (i += 1) {
        const tmp = buf[i];
        buf[i] = buf[pos - 1 - i];
        buf[pos - 1 - i] = tmp;
    }
    try out.appendSlice(a, buf[0..pos]);
}

const testing = std.testing;

test "appendQuoted: control characters escaped per RFC 8259" {
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);

    try appendQuoted(&out, testing.allocator, "a\x00b\x08c\x0Bd\x1F");
    const result = out.items;

    // Must produce valid JSON string. Parse it back.
    const parsed = try std.json.parseFromSlice([]const u8, testing.allocator, result, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("a\x00b\x08c\x0Bd\x1F", parsed.value);
}

test "appendQuoted: standard escapes" {
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);

    try appendQuoted(&out, testing.allocator, "hello \"world\"\nline2\\end");
    const result = out.items;
    try testing.expectEqualStrings("\"hello \\\"world\\\"\\nline2\\\\end\"", result);
}

test "appendInt: zero" {
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try appendInt(&out, testing.allocator, 0);
    try testing.expectEqualStrings("0", out.items);
}

test "appendInt: max u32" {
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try appendInt(&out, testing.allocator, std.math.maxInt(u32));
    try testing.expectEqualStrings("4294967295", out.items);
}

test "serializeBomJson: unicode in component names" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:unicode-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root",
                .name = "firmware-日本語",
                .version = "1.0.0",
            },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try serializeBomJson(&out, testing.allocator, bom);

    // Must be valid JSON with multi-byte UTF-8 preserved.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{});
    defer parsed.deinit();
    const meta = parsed.value.object.get("metadata").?.object;
    const comp = meta.get("component").?.object;
    try testing.expectEqualStrings("firmware-日本語", comp.get("name").?.string);
}

test "serializeBomJson: deeply nested special chars" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:special-chars",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root",
                .name = "fw",
                .version = "1.0.0",
                .description = "desc with \"quotes\" and \\backslash\\ and\ttab",
                .properties = &.{
                    .{ .name = "key\"with\"quotes", .value = "val\nwith\nnewlines" },
                },
            },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try serializeBomJson(&out, testing.allocator, bom);

    // Round-trip through std.json to verify escaping is correct.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{});
    defer parsed.deinit();
    const meta = parsed.value.object.get("metadata").?.object;
    const comp = meta.get("component").?.object;
    try testing.expectEqualStrings("desc with \"quotes\" and \\backslash\\ and\ttab", comp.get("description").?.string);

    const props = comp.get("properties").?.array.items;
    try testing.expectEqualStrings("key\"with\"quotes", props[0].object.get("name").?.string);
    try testing.expectEqualStrings("val\nwith\nnewlines", props[0].object.get("value").?.string);
}

test "serializeBomJson: round-trip all license variants" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:license-variants",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root",
                .name = "fw",
                .version = "1.0.0",
            },
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "lic-lib",
            .name = "lic-test",
            .licenses = &.{
                .{ .spdx = "MIT" },
                .{ .named = "Proprietary-v2" },
                .no_assertion,
            },
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try serializeBomJson(&out, testing.allocator, bom);

    // Parse back through std.json into sbom_model.Bom — the same path the
    // serializer binary uses. This catches format mismatches like {} vs [].
    const parsed = try std.json.parseFromSlice(sbom_model.Bom, testing.allocator, out.items, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const rt = parsed.value;

    try testing.expectEqual(@as(usize, 1), rt.components.len);
    const lics = rt.components[0].licenses;
    try testing.expectEqual(@as(usize, 3), lics.len);

    switch (lics[0]) {
        .spdx => |id| try testing.expectEqualStrings("MIT", id),
        else => return error.TestUnexpectedResult,
    }
    switch (lics[1]) {
        .named => |n| try testing.expectEqualStrings("Proprietary-v2", n),
        else => return error.TestUnexpectedResult,
    }
    switch (lics[2]) {
        .no_assertion => {},
        else => return error.TestUnexpectedResult,
    }
}

test "appendQuoted: all control characters 0x00-0x1F" {
    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);

    // Build a string with every control character.
    var input: [0x20]u8 = undefined;
    for (0..0x20) |i| {
        input[i] = @intCast(i);
    }

    try appendQuoted(&out, testing.allocator, &input);

    // Must produce valid JSON. Parse it back and verify round-trip.
    const parsed = try std.json.parseFromSlice([]const u8, testing.allocator, out.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(&input, parsed.value);
}

test "serializeBomJson: round-trip through std.json" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:test-roundtrip",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "test-tool", .version = "0.1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root",
                .name = "fw",
                .version = "1.0.0",
            },
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "lib1",
            .name = "mylib",
            .version = "2.0.0",
            .licenses = &.{.{ .spdx = "MIT" }},
        }},
        .dependencies = &.{.{
            .ref = "root",
            .depends_on = &.{"lib1"},
        }},
        .compositions = &.{.{
            .aggregate = .complete,
            .assemblies = &.{ "root", "lib1" },
        }},
    };

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try serializeBomJson(&out, testing.allocator, bom);

    // Must be valid JSON.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, out.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("urn:uuid:test-roundtrip", obj.get("serial_number").?.string);
    try testing.expectEqual(@as(i64, 1), obj.get("version").?.integer);
    try testing.expectEqual(@as(usize, 1), obj.get("components").?.array.items.len);
    try testing.expectEqual(@as(usize, 1), obj.get("dependencies").?.array.items.len);
}

test "serializeBomJson: comprehensive round-trip with all field variants" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:comprehensive-rt",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-06-15T12:00:00Z",
            .tools = &.{.{ .vendor = "zig-embedded-group", .name = "zig-build-sbom", .version = "0.1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root-fw",
                .name = "test-fw",
                .version = "2.0.0",
                .purl = "pkg:zig/test-fw@2.0.0",
                .description = "Full-featured test firmware",
                .hashes = &.{.{ .alg = .sha2_256, .content = "deadbeef" }},
                .licenses = &.{
                    .{ .spdx = "MIT" },
                    .{ .named = "Proprietary-v2" },
                    .no_assertion,
                },
                .scope = .optional,
                .source_url = "https://example.com/fw.tar.gz",
                .properties = &.{
                    .{ .name = "firmware:chip", .value = "rp2040" },
                    .{ .name = "firmware:arch", .value = "thumb" },
                },
            },
            .manufacturer = .{
                .name = "Acme Corp",
                .url = "https://acme.example",
                .contact = &.{
                    .{ .name = "Alice", .email = "alice@acme.example" },
                    .{ .name = null, .email = "info@acme.example" },
                },
            },
        },
        .components = &.{
            .{
                .type = .library,
                .bom_ref = "lib-a",
                .name = "dep-a",
                .version = "1.0.0",
                .hashes = &.{.{ .alg = .sha2_256, .content = "aabb" }},
                .licenses = &.{.{ .spdx = "Apache-2.0" }},
            },
            .{
                .type = .device,
                .bom_ref = "device-rp2040",
                .name = "RP2040",
                .description = "RP2040 MCU",
                .properties = &.{.{ .name = "cdx:device:type", .value = "mcu" }},
            },
        },
        .dependencies = &.{
            .{ .ref = "root-fw", .depends_on = &.{ "lib-a", "device-rp2040" } },
            .{ .ref = "lib-a", .depends_on = &.{} },
        },
        .compositions = &.{
            .{ .aggregate = .complete, .assemblies = &.{ "root-fw", "lib-a" } },
            .{ .aggregate = .incomplete, .assemblies = &.{"device-rp2040"} },
        },
    };

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try serializeBomJson(&out, testing.allocator, bom);

    const parsed = try std.json.parseFromSlice(sbom_model.Bom, testing.allocator, out.items, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();
    const rt = parsed.value;

    // Top-level fields.
    try testing.expectEqualStrings("urn:uuid:comprehensive-rt", rt.serial_number);
    try testing.expectEqual(@as(u32, 1), rt.version);

    // Metadata.
    try testing.expectEqualStrings("2024-06-15T12:00:00Z", rt.metadata.timestamp);
    try testing.expectEqual(@as(usize, 1), rt.metadata.tools.len);

    // Root component.
    const root = rt.metadata.component.?;
    try testing.expectEqualStrings("test-fw", root.name);
    try testing.expectEqualStrings("2.0.0", root.version.?);
    try testing.expectEqualStrings("pkg:zig/test-fw@2.0.0", root.purl.?);
    try testing.expectEqualStrings("Full-featured test firmware", root.description.?);
    try testing.expectEqual(@as(usize, 1), root.hashes.len);
    try testing.expectEqual(@as(usize, 3), root.licenses.len);
    try testing.expectEqual(@as(usize, 2), root.properties.len);
    try testing.expectEqualStrings("https://example.com/fw.tar.gz", root.source_url.?);

    // Manufacturer.
    const mfr = rt.metadata.manufacturer.?;
    try testing.expectEqualStrings("Acme Corp", mfr.name);
    try testing.expectEqualStrings("https://acme.example", mfr.url.?);
    try testing.expectEqual(@as(usize, 2), mfr.contact.?.len);
    try testing.expectEqualStrings("Alice", mfr.contact.?[0].name.?);
    try testing.expectEqualStrings("info@acme.example", mfr.contact.?[1].email.?);

    // Components.
    try testing.expectEqual(@as(usize, 2), rt.components.len);
    try testing.expectEqualStrings("dep-a", rt.components[0].name);
    try testing.expectEqualStrings("RP2040", rt.components[1].name);

    // Dependencies.
    try testing.expectEqual(@as(usize, 2), rt.dependencies.len);
    try testing.expectEqual(@as(usize, 2), rt.dependencies[0].depends_on.len);
    try testing.expectEqual(@as(usize, 0), rt.dependencies[1].depends_on.len);

    // Compositions.
    try testing.expectEqual(@as(usize, 2), rt.compositions.len);
    try testing.expectEqual(sbom_model.Composition.Aggregate.complete, rt.compositions[0].aggregate);
    try testing.expectEqual(sbom_model.Composition.Aggregate.incomplete, rt.compositions[1].aggregate);
}

test "serializeBomJson: composition serializes assemblies correctly" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:comp-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root",
                .name = "fw",
                .version = "1.0.0",
            },
        },
        .components = &.{
            .{ .type = .library, .bom_ref = "zig-lib", .name = "zig-lib" },
            .{ .type = .library, .bom_ref = "c-lib-lwip", .name = "lwIP" },
        },
        .dependencies = &.{},
        .compositions = &.{
            .{ .aggregate = .complete, .assemblies = &.{ "root", "zig-lib" } },
            .{ .aggregate = .incomplete, .assemblies = &.{"c-lib-lwip"} },
        },
    };

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(testing.allocator);
    try serializeBomJson(&out, testing.allocator, bom);

    const parsed = try std.json.parseFromSlice(sbom_model.Bom, testing.allocator, out.items, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 2), parsed.value.compositions.len);
    try testing.expectEqual(sbom_model.Composition.Aggregate.complete, parsed.value.compositions[0].aggregate);
    try testing.expectEqual(@as(usize, 2), parsed.value.compositions[0].assemblies.len);
    try testing.expectEqual(sbom_model.Composition.Aggregate.incomplete, parsed.value.compositions[1].aggregate);
    try testing.expectEqual(@as(usize, 1), parsed.value.compositions[1].assemblies.len);
    try testing.expectEqualStrings("c-lib-lwip", parsed.value.compositions[1].assemblies[0]);
}

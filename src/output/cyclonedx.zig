const std = @import("std");
const sbom_model = @import("../sbom.zig");
const serde_lib = @import("serde");

pub const OutputFormat = enum { json, xml };

pub const SerializeError = error{
    OutOfMemory,
};

// CycloneDX 1.6 JSON schema structs.
// Field names use serde rename to match the spec's camelCase/hyphenated keys.

const CdxBom = struct {
    bom_format: []const u8,
    spec_version: []const u8,
    serial_number: []const u8,
    version: u32,
    metadata: CdxMetadata,
    components: []const CdxComponent,
    dependencies: []const CdxDependency,
    compositions: []const CdxComposition,

    pub const serde = .{
        .rename = .{
            .bom_format = "bomFormat",
            .spec_version = "specVersion",
            .serial_number = "serialNumber",
        },
    };
};

const CdxMetadata = struct {
    timestamp: []const u8,
    tools: CdxToolsWrapper,
    component: ?CdxComponent = null,
    manufacturer: ?CdxManufacturer = null,

    pub const serde = .{
        .skip = .{
            .component = serde_lib.SkipMode.@"null",
            .manufacturer = serde_lib.SkipMode.@"null",
        },
    };
};

const CdxToolsWrapper = struct {
    components: []const CdxToolComponent,
};

const CdxToolComponent = struct {
    type: []const u8,
    name: []const u8,
    version: []const u8,
    group: ?[]const u8 = null,

    pub const serde = .{
        .skip = .{
            .group = serde_lib.SkipMode.@"null",
        },
    };
};

const CdxComponent = struct {
    type: []const u8,
    bom_ref: []const u8,
    name: []const u8,
    version: ?[]const u8 = null,
    purl: ?[]const u8 = null,
    description: ?[]const u8 = null,
    hashes: ?[]const CdxHash = null,
    licenses: ?[]const CdxLicenseEntry = null,
    scope: ?[]const u8 = null,
    external_references: ?[]const CdxExternalReference = null,
    properties: ?[]const CdxProperty = null,

    pub const serde = .{
        .rename = .{
            .bom_ref = "bom-ref",
            .external_references = "externalReferences",
        },
        .skip = .{
            .version = serde_lib.SkipMode.@"null",
            .purl = serde_lib.SkipMode.@"null",
            .description = serde_lib.SkipMode.@"null",
            .hashes = serde_lib.SkipMode.@"null",
            .licenses = serde_lib.SkipMode.@"null",
            .scope = serde_lib.SkipMode.@"null",
            .external_references = serde_lib.SkipMode.@"null",
            .properties = serde_lib.SkipMode.@"null",
        },
    };
};

const CdxHash = struct {
    alg: []const u8,
    content: []const u8,
};

const CdxLicenseEntry = struct {
    expression: ?[]const u8 = null,
    license: ?CdxLicenseName = null,

    pub const serde = .{
        .skip = .{
            .expression = serde_lib.SkipMode.@"null",
            .license = serde_lib.SkipMode.@"null",
        },
    };
};

const CdxLicenseName = struct {
    name: []const u8,
};

const CdxDependency = struct {
    ref: []const u8,
    depends_on: []const []const u8,

    pub const serde = .{
        .rename = .{
            .depends_on = "dependsOn",
        },
    };
};

const CdxComposition = struct {
    aggregate: []const u8,
    assemblies: []const []const u8,
};

const CdxProperty = struct {
    name: []const u8,
    value: []const u8,
};

const CdxManufacturer = struct {
    name: []const u8,
    url: ?[]const []const u8 = null,
    contact: ?[]const CdxContact = null,

    pub const serde = .{
        .skip = .{
            .url = serde_lib.SkipMode.@"null",
            .contact = serde_lib.SkipMode.@"null",
        },
    };
};

const CdxContact = struct {
    name: ?[]const u8 = null,
    email: ?[]const u8 = null,

    pub const serde = .{
        .skip = .{
            .name = serde_lib.SkipMode.@"null",
            .email = serde_lib.SkipMode.@"null",
        },
    };
};

const CdxExternalReference = struct {
    type: []const u8,
    url: []const u8,
};

/// Serializes a Bom to CycloneDX 1.6 format, writing to the provided writer.
pub fn serialize(
    allocator: std.mem.Allocator,
    bom: sbom_model.Bom,
    format: OutputFormat,
    writer: anytype,
) !void {
    switch (format) {
        .json => {
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            const aa = arena.allocator();

            const cdx = try buildCdxBom(aa, bom);
            const bytes = serde_lib.json.toSliceWith(aa, cdx, .{ .pretty = true, .indent = 2 }) catch
                return SerializeError.OutOfMemory;
            try writer.writeAll(bytes);
            try writer.writeAll("\n");
        },
        .xml => {
            try serializeXml(allocator, bom, writer);
        },
    }
}

/// Serializes a Bom to CycloneDX 1.6 JSON and returns the bytes.
pub fn serializeJsonAlloc(allocator: std.mem.Allocator, bom: sbom_model.Bom) SerializeError![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    serialize(allocator, bom, .json, buf.writer(allocator)) catch return SerializeError.OutOfMemory;
    return buf.toOwnedSlice(allocator) catch return SerializeError.OutOfMemory;
}

fn buildCdxBom(allocator: std.mem.Allocator, bom: sbom_model.Bom) SerializeError!CdxBom {
    const tool_comps = allocator.alloc(CdxToolComponent, bom.metadata.tools.len) catch
        return SerializeError.OutOfMemory;
    for (bom.metadata.tools, 0..) |tool, i| {
        tool_comps[i] = .{
            .type = "application",
            .name = tool.name,
            .version = tool.version,
            .group = if (tool.vendor.len > 0) tool.vendor else null,
        };
    }

    const meta_comp: ?CdxComponent = if (bom.metadata.component) |comp|
        buildCdxComponent(allocator, comp) catch return SerializeError.OutOfMemory
    else
        null;

    const manufacturer: ?CdxManufacturer = if (bom.metadata.manufacturer) |mfr| blk: {
        const url_arr: ?[]const []const u8 = if (mfr.url) |u| brk: {
            const arr = allocator.alloc([]const u8, 1) catch return SerializeError.OutOfMemory;
            arr[0] = u;
            break :brk arr;
        } else null;

        const contacts: ?[]const CdxContact = if (mfr.contact) |src_contacts| brk: {
            const arr = allocator.alloc(CdxContact, src_contacts.len) catch return SerializeError.OutOfMemory;
            for (src_contacts, 0..) |c, i| {
                arr[i] = .{ .name = c.name, .email = c.email };
            }
            break :brk arr;
        } else null;

        break :blk .{
            .name = mfr.name,
            .url = url_arr,
            .contact = contacts,
        };
    } else null;

    const components = allocator.alloc(CdxComponent, bom.components.len) catch
        return SerializeError.OutOfMemory;
    for (bom.components, 0..) |comp, i| {
        components[i] = buildCdxComponent(allocator, comp) catch return SerializeError.OutOfMemory;
    }

    const deps = allocator.alloc(CdxDependency, bom.dependencies.len) catch
        return SerializeError.OutOfMemory;
    for (bom.dependencies, 0..) |dep, i| {
        deps[i] = .{
            .ref = dep.ref,
            .depends_on = dep.depends_on,
        };
    }

    const comps = allocator.alloc(CdxComposition, bom.compositions.len) catch
        return SerializeError.OutOfMemory;
    for (bom.compositions, 0..) |comp, i| {
        comps[i] = .{
            .aggregate = aggregateString(comp.aggregate),
            .assemblies = comp.assemblies,
        };
    }

    return CdxBom{
        .bom_format = "CycloneDX",
        .spec_version = "1.6",
        .serial_number = bom.serial_number,
        .version = bom.version,
        .metadata = .{
            .timestamp = bom.metadata.timestamp,
            .tools = .{ .components = tool_comps },
            .component = meta_comp,
            .manufacturer = manufacturer,
        },
        .components = components,
        .dependencies = deps,
        .compositions = comps,
    };
}

fn buildCdxComponent(allocator: std.mem.Allocator, comp: sbom_model.Component) !CdxComponent {
    const hashes: ?[]const CdxHash = if (comp.hashes.len > 0) blk: {
        const h = try allocator.alloc(CdxHash, comp.hashes.len);
        for (comp.hashes, 0..) |hash, i| {
            h[i] = .{
                .alg = hash.alg.toCycloneDxString(),
                .content = hash.content,
            };
        }
        break :blk h;
    } else null;

    const licenses: ?[]const CdxLicenseEntry = if (comp.licenses.len > 0) blk: {
        const l = try allocator.alloc(CdxLicenseEntry, comp.licenses.len);
        for (comp.licenses, 0..) |lic, i| {
            l[i] = switch (lic) {
                .spdx => |expr| .{ .expression = expr },
                .named => |name| .{ .license = .{ .name = name } },
                .no_assertion => .{ .expression = "NOASSERTION" },
            };
        }
        break :blk l;
    } else null;

    const props: ?[]const CdxProperty = if (comp.properties.len > 0) blk: {
        const p = try allocator.alloc(CdxProperty, comp.properties.len);
        for (comp.properties, 0..) |prop, i| {
            p[i] = .{ .name = prop.name, .value = prop.value };
        }
        break :blk p;
    } else null;

    const scope: ?[]const u8 = if (comp.scope != .required) @tagName(comp.scope) else null;

    const ext_refs: ?[]const CdxExternalReference = if (comp.source_url) |url| blk: {
        const refs = try allocator.alloc(CdxExternalReference, 1);
        refs[0] = .{ .type = "distribution", .url = url };
        break :blk refs;
    } else null;

    return CdxComponent{
        .type = componentTypeString(comp.type),
        .bom_ref = comp.bom_ref,
        .name = comp.name,
        .version = comp.version,
        .purl = comp.purl,
        .description = comp.description,
        .hashes = hashes,
        .licenses = licenses,
        .scope = scope,
        .external_references = ext_refs,
        .properties = props,
    };
}

fn serializeXml(
    allocator: std.mem.Allocator,
    bom: sbom_model.Bom,
    writer: anytype,
) !void {
    _ = allocator;

    try writer.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try writer.writeAll("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\"");
    try writer.writeAll(" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"");
    try writer.writeAll(" xsi:schemaLocation=\"http://cyclonedx.org/schema/bom/1.6 http://cyclonedx.org/schema/bom-1.6.xsd\"");
    try writer.writeAll(" serialNumber=\"");
    try writeXmlEscaped(writer, bom.serial_number);
    try writer.print("\" version=\"{d}\">\n", .{bom.version});

    try writer.writeAll("  <metadata>\n");
    try writer.writeAll("    <timestamp>");
    try writeXmlEscaped(writer, bom.metadata.timestamp);
    try writer.writeAll("</timestamp>\n");
    try writer.writeAll("    <tools>\n      <components>\n");
    for (bom.metadata.tools) |tool| {
        try writer.writeAll("        <component type=\"application\">\n");
        if (tool.vendor.len > 0) {
            try writer.writeAll("          <group>");
            try writeXmlEscaped(writer, tool.vendor);
            try writer.writeAll("</group>\n");
        }
        try writer.writeAll("          <name>");
        try writeXmlEscaped(writer, tool.name);
        try writer.writeAll("</name>\n");
        try writer.writeAll("          <version>");
        try writeXmlEscaped(writer, tool.version);
        try writer.writeAll("</version>\n");
        try writer.writeAll("        </component>\n");
    }
    try writer.writeAll("      </components>\n    </tools>\n");

    if (bom.metadata.manufacturer) |mfr| {
        try writer.writeAll("    <manufacturer>\n");
        try writer.writeAll("      <name>");
        try writeXmlEscaped(writer, mfr.name);
        try writer.writeAll("</name>\n");
        if (mfr.url) |url| {
            try writer.writeAll("      <url>");
            try writeXmlEscaped(writer, url);
            try writer.writeAll("</url>\n");
        }
        if (mfr.contact) |contacts| {
            for (contacts) |c| {
                try writer.writeAll("      <contact>\n");
                if (c.name) |n| {
                    try writer.writeAll("        <name>");
                    try writeXmlEscaped(writer, n);
                    try writer.writeAll("</name>\n");
                }
                if (c.email) |e| {
                    try writer.writeAll("        <email>");
                    try writeXmlEscaped(writer, e);
                    try writer.writeAll("</email>\n");
                }
                try writer.writeAll("      </contact>\n");
            }
        }
        try writer.writeAll("    </manufacturer>\n");
    }

    if (bom.metadata.component) |comp| {
        try writeXmlComponentOpen(writer, comp, "    ");
        try writeXmlComponentBody(writer, comp, "    ");
        try writer.writeAll("    </component>\n");
    }
    try writer.writeAll("  </metadata>\n");

    try writer.writeAll("  <components>\n");
    for (bom.components) |comp| {
        try writeXmlComponentOpen(writer, comp, "    ");
        try writeXmlComponentBody(writer, comp, "    ");
        try writer.writeAll("    </component>\n");
    }
    try writer.writeAll("  </components>\n");

    try writer.writeAll("  <dependencies>\n");
    for (bom.dependencies) |dep| {
        try writer.writeAll("    <dependency ref=\"");
        try writeXmlEscaped(writer, dep.ref);
        try writer.writeAll("\">\n");
        for (dep.depends_on) |d| {
            try writer.writeAll("      <dependency ref=\"");
            try writeXmlEscaped(writer, d);
            try writer.writeAll("\"/>\n");
        }
        try writer.writeAll("    </dependency>\n");
    }
    try writer.writeAll("  </dependencies>\n");

    try writer.writeAll("  <compositions>\n");
    for (bom.compositions) |comp| {
        try writer.writeAll("    <composition>\n");
        try writer.writeAll("      <aggregate>");
        try writeXmlEscaped(writer, aggregateString(comp.aggregate));
        try writer.writeAll("</aggregate>\n");
        try writer.writeAll("      <assemblies>\n");
        for (comp.assemblies) |ref| {
            try writer.writeAll("        <assembly ref=\"");
            try writeXmlEscaped(writer, ref);
            try writer.writeAll("\"/>\n");
        }
        try writer.writeAll("      </assemblies>\n");
        try writer.writeAll("    </composition>\n");
    }
    try writer.writeAll("  </compositions>\n");

    try writer.writeAll("</bom>\n");
}

// XML component opening: type attribute, bom-ref, name, version, description, scope, hashes.
fn writeXmlComponentOpen(writer: anytype, comp: sbom_model.Component, indent: []const u8) !void {
    try writer.writeAll(indent);
    try writer.writeAll("<component type=\"");
    try writeXmlEscaped(writer, componentTypeString(comp.type));
    try writer.writeAll("\" bom-ref=\"");
    try writeXmlEscaped(writer, comp.bom_ref);
    try writer.writeAll("\">\n");
    try writer.writeAll(indent);
    try writer.writeAll("  <name>");
    try writeXmlEscaped(writer, comp.name);
    try writer.writeAll("</name>\n");
    if (comp.version) |v| {
        try writer.writeAll(indent);
        try writer.writeAll("  <version>");
        try writeXmlEscaped(writer, v);
        try writer.writeAll("</version>\n");
    }
    if (comp.description) |d| {
        try writer.writeAll(indent);
        try writer.writeAll("  <description>");
        try writeXmlEscaped(writer, d);
        try writer.writeAll("</description>\n");
    }
    if (comp.scope != .required) {
        try writer.writeAll(indent);
        try writer.writeAll("  <scope>");
        try writeXmlEscaped(writer, @tagName(comp.scope));
        try writer.writeAll("</scope>\n");
    }
    if (comp.hashes.len > 0) {
        try writer.writeAll(indent);
        try writer.writeAll("  <hashes>\n");
        for (comp.hashes) |h| {
            try writer.writeAll(indent);
            try writer.writeAll("    <hash alg=\"");
            try writeXmlEscaped(writer, h.alg.toCycloneDxString());
            try writer.writeAll("\">");
            try writeXmlEscaped(writer, h.content);
            try writer.writeAll("</hash>\n");
        }
        try writer.writeAll(indent);
        try writer.writeAll("  </hashes>\n");
    }
}

// XML component body: licenses, purl, externalReferences, properties.
// Called after writeXmlComponentOpen for both metadata and regular components.
fn writeXmlComponentBody(writer: anytype, comp: sbom_model.Component, indent: []const u8) !void {
    if (comp.licenses.len > 0) {
        try writer.writeAll(indent);
        try writer.writeAll("  <licenses>\n");
        for (comp.licenses) |lic| {
            switch (lic) {
                .spdx => |expr| {
                    try writer.writeAll(indent);
                    try writer.writeAll("    <expression>");
                    try writeXmlEscaped(writer, expr);
                    try writer.writeAll("</expression>\n");
                },
                .named => |name| {
                    try writer.writeAll(indent);
                    try writer.writeAll("    <license><name>");
                    try writeXmlEscaped(writer, name);
                    try writer.writeAll("</name></license>\n");
                },
                .no_assertion => {
                    try writer.writeAll(indent);
                    try writer.writeAll("    <expression>NOASSERTION</expression>\n");
                },
            }
        }
        try writer.writeAll(indent);
        try writer.writeAll("  </licenses>\n");
    }
    if (comp.purl) |p| {
        try writer.writeAll(indent);
        try writer.writeAll("  <purl>");
        try writeXmlEscaped(writer, p);
        try writer.writeAll("</purl>\n");
    }
    if (comp.source_url) |url| {
        try writer.writeAll(indent);
        try writer.writeAll("  <externalReferences>\n");
        try writer.writeAll(indent);
        try writer.writeAll("    <reference type=\"distribution\">\n");
        try writer.writeAll(indent);
        try writer.writeAll("      <url>");
        try writeXmlEscaped(writer, url);
        try writer.writeAll("</url>\n");
        try writer.writeAll(indent);
        try writer.writeAll("    </reference>\n");
        try writer.writeAll(indent);
        try writer.writeAll("  </externalReferences>\n");
    }
    if (comp.properties.len > 0) {
        try writer.writeAll(indent);
        try writer.writeAll("  <properties>\n");
        for (comp.properties) |prop| {
            try writer.writeAll(indent);
            try writer.writeAll("    <property name=\"");
            try writeXmlEscaped(writer, prop.name);
            try writer.writeAll("\">");
            try writeXmlEscaped(writer, prop.value);
            try writer.writeAll("</property>\n");
        }
        try writer.writeAll(indent);
        try writer.writeAll("  </properties>\n");
    }
}

/// Writes text with XML entity escaping for `<`, `>`, `&`, `"`, `'`.
fn writeXmlEscaped(writer: anytype, text: []const u8) !void {
    for (text) |c| {
        switch (c) {
            '<' => try writer.writeAll("&lt;"),
            '>' => try writer.writeAll("&gt;"),
            '&' => try writer.writeAll("&amp;"),
            '"' => try writer.writeAll("&quot;"),
            '\'' => try writer.writeAll("&apos;"),
            else => try writer.writeByte(c),
        }
    }
}

pub fn componentTypeString(t: sbom_model.ComponentType) []const u8 {
    return switch (t) {
        .firmware => "firmware",
        .library => "library",
        .application => "application",
        .device => "device",
        .device_driver => "device-driver",
        .tool => "application",
        .file => "file",
    };
}

fn aggregateString(a: sbom_model.Composition.Aggregate) []const u8 {
    return switch (a) {
        .complete => "complete",
        .incomplete => "incomplete",
        .unknown => "unknown",
        .incomplete_first_party_only => "incomplete_first_party_only",
    };
}

const testing = std.testing;

fn makeTestBom() sbom_model.Bom {
    return .{
        .serial_number = "urn:uuid:test-uuid",
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
                .bom_ref = "root-fw",
                .name = "blinky",
                .version = "1.0.0",
            },
        },
        .components = &.{
            .{
                .type = .library,
                .bom_ref = "1220abcdef",
                .name = "microzig",
                .version = "0.13.0",
                .hashes = &.{.{
                    .alg = .sha2_256,
                    .content = "abcdef0123456789",
                }},
            },
        },
        .dependencies = &.{
            .{
                .ref = "root-fw",
                .depends_on = &.{"1220abcdef"},
            },
        },
        .compositions = &.{
            .{
                .aggregate = .complete,
                .assemblies = &.{ "root-fw", "1220abcdef" },
            },
        },
    };
}

test "CycloneDX JSON: bomFormat and specVersion" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "\"CycloneDX\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"1.6\"") != null);
}

test "CycloneDX JSON: firmware component type" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "\"firmware\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"blinky\"") != null);
}

test "CycloneDX JSON: hashes present" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "SHA-256") != null);
    try testing.expect(std.mem.indexOf(u8, output, "abcdef0123456789") != null);
}

test "CycloneDX JSON: compositions aggregate" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "\"complete\"") != null);
}

test "CycloneDX JSON: tools metadata" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "\"zig-build-sbom\"") != null);
}

test "CycloneDX JSON: dependencies" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "\"dependsOn\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"root-fw\"") != null);
}

test "CycloneDX XML: basic structure" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "<?xml version") != null);
    try testing.expect(std.mem.indexOf(u8, output, "cyclonedx.org/schema/bom/1.6") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<name>blinky</name>") != null);
}

test "componentTypeString: all types" {
    try testing.expectEqualStrings("firmware", componentTypeString(.firmware));
    try testing.expectEqualStrings("library", componentTypeString(.library));
    try testing.expectEqualStrings("device", componentTypeString(.device));
    try testing.expectEqualStrings("device-driver", componentTypeString(.device_driver));
    try testing.expectEqualStrings("file", componentTypeString(.file));
}

test "writeXmlEscaped: special characters" {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try writeXmlEscaped(buf.writer(testing.allocator), "<script>alert('x\"&y')</script>");
    try testing.expectEqualStrings("&lt;script&gt;alert(&apos;x&quot;&amp;y&apos;)&lt;/script&gt;", buf.items);
}

test "CycloneDX XML: escapes special chars in name" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "ref-with-\"&-chars",
                .name = "<script>alert(1)</script>",
                .version = "1.0",
            },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // Name must be escaped.
    try testing.expect(std.mem.indexOf(u8, output, "&lt;script&gt;") != null);
    // bom-ref must be escaped.
    try testing.expect(std.mem.indexOf(u8, output, "&quot;&amp;") != null);
    // Raw angle brackets must not appear in data values.
    try testing.expect(std.mem.indexOf(u8, output, "<script>") == null);
}

test "CycloneDX JSON: manufacturer with contact" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:mfr-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .manufacturer = .{
                .name = "Acme Corp",
                .url = "https://acme.example",
                .contact = &.{.{ .name = "Alice", .email = "alice@acme.example" }},
            },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;
    try testing.expect(std.mem.indexOf(u8, output, "\"Acme Corp\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "alice@acme.example") != null);
}

test "CycloneDX JSON: empty components list" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:empty",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;
    try testing.expect(std.mem.indexOf(u8, output, "\"components\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"CycloneDX\"") != null);
}

test "CycloneDX JSON: component with no version" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:nover",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "no-version-lib",
            .name = "mylib",
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;
    try testing.expect(std.mem.indexOf(u8, output, "\"mylib\"") != null);
}

test "CycloneDX XML: licenses and properties" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:lic-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "lic-comp",
            .name = "licensed-lib",
            .licenses = &.{.{ .spdx = "MIT" }},
            .properties = &.{.{ .name = "custom:key", .value = "val" }},
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;
    try testing.expect(std.mem.indexOf(u8, output, "<expression>MIT</expression>") != null);
    try testing.expect(std.mem.indexOf(u8, output, "custom:key") != null);
}

test "CycloneDX XML: metadata component includes licenses and properties" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:meta-comp-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root-fw",
                .name = "blinky",
                .version = "1.0.0",
                .description = "LED blinker firmware",
                .licenses = &.{.{ .spdx = "MIT" }},
                .properties = &.{.{ .name = "firmware:chip", .value = "rp2040" }},
            },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // Metadata component must have licenses, properties, and description.
    try testing.expect(std.mem.indexOf(u8, output, "<expression>MIT</expression>") != null);
    try testing.expect(std.mem.indexOf(u8, output, "firmware:chip") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<description>LED blinker firmware</description>") != null);
}

test "CycloneDX XML: manufacturer section" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:mfr-xml-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .manufacturer = .{
                .name = "Acme Corp",
                .url = "https://acme.example",
                .contact = &.{.{ .name = "Alice", .email = "alice@acme.example" }},
            },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "<manufacturer>") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<name>Acme Corp</name>") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<url>https://acme.example</url>") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<email>alice@acme.example</email>") != null);
}

test "CycloneDX XML: description on device component" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:desc-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .device,
            .bom_ref = "device-rp2040",
            .name = "RP2040",
            .description = "RP2040 (cortex_m0plus core, 2097152 bytes flash)",
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "<description>RP2040 (cortex_m0plus core, 2097152 bytes flash)</description>") != null);
}

test "CycloneDX: component with all optional fields" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:all-fields",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "full-lib",
            .name = "full-library",
            .version = "3.2.1",
            .purl = "pkg:zig/full-library@3.2.1",
            .description = "A fully described library",
            .hashes = &.{.{ .alg = .sha2_256, .content = "deadbeef" }},
            .licenses = &.{.{ .spdx = "Apache-2.0" }},
            .scope = .optional,
            .source_url = "https://example.com/full-library.tar.gz",
            .properties = &.{.{ .name = "custom:foo", .value = "bar" }},
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };

    // JSON output.
    var json_buf: std.ArrayListUnmanaged(u8) = .{};
    defer json_buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, json_buf.writer(testing.allocator));
    const json_out = json_buf.items;

    try testing.expect(std.mem.indexOf(u8, json_out, "\"full-library\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"3.2.1\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"A fully described library\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"optional\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"externalReferences\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"distribution\"") != null);

    // XML output.
    var xml_buf: std.ArrayListUnmanaged(u8) = .{};
    defer xml_buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, xml_buf.writer(testing.allocator));
    const xml_out = xml_buf.items;

    try testing.expect(std.mem.indexOf(u8, xml_out, "<description>A fully described library</description>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<scope>optional</scope>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<purl>pkg:zig/full-library@3.2.1</purl>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "type=\"distribution\"") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<url>https://example.com/full-library.tar.gz</url>") != null);
}

test "CycloneDX: multiple license types in one component" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:multi-lic",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "multi-lic-lib",
            .name = "multi-lic",
            .licenses = &.{
                .{ .spdx = "MIT" },
                .{ .named = "Custom Proprietary" },
                .no_assertion,
            },
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };

    // JSON.
    var json_buf: std.ArrayListUnmanaged(u8) = .{};
    defer json_buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, json_buf.writer(testing.allocator));
    const json_out = json_buf.items;
    try testing.expect(std.mem.indexOf(u8, json_out, "\"MIT\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"Custom Proprietary\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "NOASSERTION") != null);

    // XML.
    var xml_buf: std.ArrayListUnmanaged(u8) = .{};
    defer xml_buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, xml_buf.writer(testing.allocator));
    const xml_out = xml_buf.items;
    try testing.expect(std.mem.indexOf(u8, xml_out, "<expression>MIT</expression>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<license><name>Custom Proprietary</name></license>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<expression>NOASSERTION</expression>") != null);
}

test "CycloneDX JSON: required top-level fields present" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("CycloneDX", obj.get("bomFormat").?.string);
    try testing.expectEqualStrings("1.6", obj.get("specVersion").?.string);
    try testing.expect(obj.get("serialNumber") != null);
    try testing.expect(obj.get("version") != null);
    try testing.expect(obj.get("metadata") != null);
    try testing.expect(obj.get("components") != null);
    try testing.expect(obj.get("dependencies") != null);
    try testing.expect(obj.get("compositions") != null);
}

test "CycloneDX XML: structural validity" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.startsWith(u8, output, "<?xml"));
    try testing.expect(std.mem.indexOf(u8, output, "<bom ") != null);
    try testing.expect(std.mem.indexOf(u8, output, "</bom>") != null);

    // Every <component must have a matching </component>.
    var open_count: usize = 0;
    var close_count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, output, pos, "<component ")) |idx| {
        open_count += 1;
        pos = idx + 1;
    }
    pos = 0;
    while (std.mem.indexOfPos(u8, output, pos, "</component>")) |idx| {
        close_count += 1;
        pos = idx + 1;
    }
    try testing.expectEqual(open_count, close_count);
}

test "CycloneDX XML: tools include vendor group" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "<group>zig-embedded-group</group>") != null);
}

test "CycloneDX: device component with description and properties in JSON and XML" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:device-full",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .device,
            .bom_ref = "device-stm32f4",
            .name = "STM32F407",
            .description = "STM32F407 (cortex_m4 core, 1048576 bytes flash)",
            .properties = &.{
                .{ .name = "cdx:device:type", .value = "mcu" },
                .{ .name = "firmware:target.arch", .value = "thumb" },
            },
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };

    // JSON.
    var json_buf: std.ArrayListUnmanaged(u8) = .{};
    defer json_buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, json_buf.writer(testing.allocator));
    const json_out = json_buf.items;

    try testing.expect(std.mem.indexOf(u8, json_out, "\"device\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "\"STM32F407\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "cortex_m4") != null);
    try testing.expect(std.mem.indexOf(u8, json_out, "cdx:device:type") != null);

    // XML.
    var xml_buf: std.ArrayListUnmanaged(u8) = .{};
    defer xml_buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, xml_buf.writer(testing.allocator));
    const xml_out = xml_buf.items;

    try testing.expect(std.mem.indexOf(u8, xml_out, "type=\"device\"") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<name>STM32F407</name>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "<description>STM32F407 (cortex_m4 core, 1048576 bytes flash)</description>") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "cdx:device:type") != null);
    try testing.expect(std.mem.indexOf(u8, xml_out, "firmware:target.arch") != null);
}

test "CycloneDX JSON: round-trip serialize then parse" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:cdx-roundtrip",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root-fw",
                .name = "my-firmware",
                .version = "2.0.0",
                .licenses = &.{.{ .spdx = "MIT" }},
            },
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "dep-lib",
            .name = "dep",
            .version = "1.0.0",
            .hashes = &.{.{ .alg = .sha2_256, .content = "feedface" }},
        }},
        .dependencies = &.{.{
            .ref = "root-fw",
            .depends_on = &.{"dep-lib"},
        }},
        .compositions = &.{.{
            .aggregate = .complete,
            .assemblies = &.{ "root-fw", "dep-lib" },
        }},
    };

    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));

    // Parse back as generic JSON and verify structure.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("CycloneDX", obj.get("bomFormat").?.string);
    try testing.expectEqualStrings("1.6", obj.get("specVersion").?.string);

    const meta = obj.get("metadata").?.object;
    const meta_comp = meta.get("component").?.object;
    try testing.expectEqualStrings("my-firmware", meta_comp.get("name").?.string);

    const components = obj.get("components").?.array.items;
    try testing.expectEqual(@as(usize, 1), components.len);
    try testing.expectEqualStrings("dep", components[0].object.get("name").?.string);
}

test "CycloneDX XML: dependency with zero dependsOn" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:empty-dep",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "leaf-lib",
            .name = "leaf",
        }},
        .dependencies = &.{.{
            .ref = "leaf-lib",
            .depends_on = &.{},
        }},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // Empty dependency element (no child <dependency> refs).
    try testing.expect(std.mem.indexOf(u8, output, "ref=\"leaf-lib\"") != null);
}

test "CycloneDX XML: namespace and schema attributes" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "xsi:schemaLocation=\"http://cyclonedx.org/schema/bom/1.6 http://cyclonedx.org/schema/bom-1.6.xsd\"") != null);
}

test "CycloneDX XML: nested special chars in properties" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:prop-escape",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "prop-lib",
            .name = "prop-test",
            .properties = &.{
                .{ .name = "key<with>angles", .value = "val&\"quotes'" },
            },
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "key&lt;with&gt;angles") != null);
    try testing.expect(std.mem.indexOf(u8, output, "val&amp;&quot;quotes&apos;") != null);
}

test "CycloneDX XML: multiple compositions" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:multi-comp",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{
            .{ .type = .library, .bom_ref = "zig-lib", .name = "zig-lib" },
            .{ .type = .library, .bom_ref = "c-lib-lwip", .name = "lwIP" },
        },
        .dependencies = &.{},
        .compositions = &.{
            .{ .aggregate = .complete, .assemblies = &.{"zig-lib"} },
            .{ .aggregate = .incomplete, .assemblies = &.{"c-lib-lwip"} },
        },
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // Both composition aggregates must appear.
    try testing.expect(std.mem.indexOf(u8, output, "<aggregate>complete</aggregate>") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<aggregate>incomplete</aggregate>") != null);

    // Count <composition> elements.
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, output, pos, "<composition>")) |idx| {
        count += 1;
        pos = idx + 1;
    }
    try testing.expectEqual(@as(usize, 2), count);
}

test "CycloneDX XML: dependency with zero dependsOn produces valid structure" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:zero-deps",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "leaf",
            .name = "leaf-lib",
        }},
        .dependencies = &.{.{
            .ref = "leaf",
            .depends_on = &.{},
        }},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serializeXml(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // Parent dependency element exists with no child dependency refs.
    try testing.expect(std.mem.indexOf(u8, output, "ref=\"leaf\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "<dependency ref=\"leaf\">\n    </dependency>") != null);
}

test "CycloneDX JSON: externalReferences for component with source_url" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:extref-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "ext-lib",
            .name = "external-lib",
            .source_url = "https://github.com/example/lib/archive/v1.0.tar.gz",
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, .json, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "\"externalReferences\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"distribution\"") != null);
    try testing.expect(std.mem.indexOf(u8, output, "github.com/example/lib/archive/v1.0.tar.gz") != null);
}

const std = @import("std");
const sbom_model = @import("../sbom.zig");
const serde_lib = @import("serde");

pub const SerializeError = error{
    OutOfMemory,
};

// SPDX 2.3 JSON schema structs.

const SpdxDocument = struct {
    spdx_id: []const u8,
    spdx_version: []const u8,
    data_license: []const u8,
    name: []const u8,
    document_namespace: []const u8,
    creation_info: SpdxCreationInfo,
    packages: []const SpdxPackage,
    relationships: []const SpdxRelationship,

    pub const serde = .{
        .rename = .{
            .spdx_id = "SPDXID",
            .spdx_version = "spdxVersion",
            .data_license = "dataLicense",
            .document_namespace = "documentNamespace",
            .creation_info = "creationInfo",
        },
    };
};

const SpdxCreationInfo = struct {
    created: []const u8,
    creators: []const []const u8,
};

const SpdxPackage = struct {
    spdx_id: []const u8,
    name: []const u8,
    version_info: ?[]const u8 = null,
    supplier: []const u8,
    download_location: []const u8,
    files_analyzed: bool,
    license_concluded: []const u8,
    license_declared: []const u8,
    copyright_text: []const u8,
    external_refs: ?[]const SpdxExternalRef = null,
    checksums: ?[]const SpdxChecksum = null,

    pub const serde = .{
        .rename = .{
            .spdx_id = "SPDXID",
            .version_info = "versionInfo",
            .download_location = "downloadLocation",
            .files_analyzed = "filesAnalyzed",
            .license_concluded = "licenseConcluded",
            .license_declared = "licenseDeclared",
            .copyright_text = "copyrightText",
            .external_refs = "externalRefs",
        },
        .skip = .{
            .version_info = serde_lib.SkipMode.@"null",
            .external_refs = serde_lib.SkipMode.@"null",
            .checksums = serde_lib.SkipMode.@"null",
        },
    };
};

const SpdxExternalRef = struct {
    reference_category: []const u8,
    reference_type: []const u8,
    reference_locator: []const u8,

    pub const serde = .{
        .rename = .{
            .reference_category = "referenceCategory",
            .reference_type = "referenceType",
            .reference_locator = "referenceLocator",
        },
    };
};

const SpdxChecksum = struct {
    algorithm: []const u8,
    checksum_value: []const u8,

    pub const serde = .{
        .rename = .{
            .checksum_value = "checksumValue",
        },
    };
};

const SpdxRelationship = struct {
    spdx_element_id: []const u8,
    relationship_type: []const u8,
    related_spdx_element: []const u8,

    pub const serde = .{
        .rename = .{
            .spdx_element_id = "spdxElementId",
            .relationship_type = "relationshipType",
            .related_spdx_element = "relatedSpdxElement",
        },
    };
};

/// Serializes a Bom to SPDX 2.3 JSON format.
pub fn serialize(
    allocator: std.mem.Allocator,
    bom: sbom_model.Bom,
    writer: anytype,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const doc = try buildSpdxDocument(aa, bom);
    const bytes = serde_lib.json.toSliceWith(aa, doc, .{ .pretty = true, .indent = 2 }) catch
        return SerializeError.OutOfMemory;
    try writer.writeAll(bytes);
    try writer.writeAll("\n");
}

fn buildSpdxDocument(allocator: std.mem.Allocator, bom: sbom_model.Bom) SerializeError!SpdxDocument {
    const doc_name = if (bom.metadata.component) |c| c.name else "firmware-sbom";

    const doc_ns = std.fmt.allocPrint(allocator, "https://spdx.org/spdxdocs/{s}-{s}", .{
        doc_name, bom.serial_number,
    }) catch return SerializeError.OutOfMemory;

    const creators = allocator.alloc([]const u8, bom.metadata.tools.len) catch
        return SerializeError.OutOfMemory;
    for (bom.metadata.tools, 0..) |tool, i| {
        creators[i] = std.fmt.allocPrint(allocator, "Tool: {s}-{s}", .{ tool.name, tool.version }) catch
            return SerializeError.OutOfMemory;
    }

    // First pass: build bom_ref → unique SPDX ID mapping with collision resolution.
    var id_map = std.StringHashMap([]const u8).init(allocator);
    defer id_map.deinit();

    if (bom.metadata.component) |root_comp| {
        const uid = bomRefToUniqueSpdxId(allocator, &id_map, root_comp.bom_ref) catch
            return SerializeError.OutOfMemory;
        id_map.put(root_comp.bom_ref, uid) catch return SerializeError.OutOfMemory;
    }
    for (bom.components) |comp| {
        if (id_map.contains(comp.bom_ref)) continue;
        const uid = bomRefToUniqueSpdxId(allocator, &id_map, comp.bom_ref) catch
            return SerializeError.OutOfMemory;
        id_map.put(comp.bom_ref, uid) catch return SerializeError.OutOfMemory;
    }
    // Pre-populate IDs referenced only in dependency edges.
    for (bom.dependencies) |dep| {
        if (!id_map.contains(dep.ref)) {
            const uid = bomRefToUniqueSpdxId(allocator, &id_map, dep.ref) catch
                return SerializeError.OutOfMemory;
            id_map.put(dep.ref, uid) catch return SerializeError.OutOfMemory;
        }
        for (dep.depends_on) |dep_on| {
            if (!id_map.contains(dep_on)) {
                const uid = bomRefToUniqueSpdxId(allocator, &id_map, dep_on) catch
                    return SerializeError.OutOfMemory;
                id_map.put(dep_on, uid) catch return SerializeError.OutOfMemory;
            }
        }
    }

    // Second pass: build packages and relationships using the mapping.
    const has_root = bom.metadata.component != null;
    const pkg_count = (if (has_root) @as(usize, 1) else @as(usize, 0)) + bom.components.len;
    const packages = allocator.alloc(SpdxPackage, pkg_count) catch
        return SerializeError.OutOfMemory;

    const root_supplier: []const u8 = if (bom.metadata.manufacturer) |mfr|
        std.fmt.allocPrint(allocator, "Organization: {s}", .{mfr.name}) catch return SerializeError.OutOfMemory
    else
        "NOASSERTION";

    var idx: usize = 0;
    if (bom.metadata.component) |root_comp| {
        packages[idx] = buildSpdxPackageWithId(allocator, root_comp, root_supplier, id_map.get(root_comp.bom_ref).?) catch return SerializeError.OutOfMemory;
        idx += 1;
    }
    for (bom.components) |comp| {
        packages[idx] = buildSpdxPackageWithId(allocator, comp, "NOASSERTION", id_map.get(comp.bom_ref).?) catch return SerializeError.OutOfMemory;
        idx += 1;
    }

    var rel_count: usize = 0;
    if (has_root) rel_count += 1;
    for (bom.dependencies) |dep| {
        rel_count += dep.depends_on.len;
    }

    const relationships = allocator.alloc(SpdxRelationship, rel_count) catch
        return SerializeError.OutOfMemory;
    var rel_idx: usize = 0;

    if (bom.metadata.component) |root_comp| {
        relationships[rel_idx] = .{
            .spdx_element_id = "SPDXRef-DOCUMENT",
            .relationship_type = "DESCRIBES",
            .related_spdx_element = id_map.get(root_comp.bom_ref).?,
        };
        rel_idx += 1;
    }

    for (bom.dependencies) |dep| {
        for (dep.depends_on) |dep_on| {
            relationships[rel_idx] = .{
                .spdx_element_id = id_map.get(dep.ref).?,
                .relationship_type = "DEPENDS_ON",
                .related_spdx_element = id_map.get(dep_on).?,
            };
            rel_idx += 1;
        }
    }

    return SpdxDocument{
        .spdx_id = "SPDXRef-DOCUMENT",
        .spdx_version = "SPDX-2.3",
        .data_license = "CC0-1.0",
        .name = doc_name,
        .document_namespace = doc_ns,
        .creation_info = .{
            .created = bom.metadata.timestamp,
            .creators = creators,
        },
        .packages = packages,
        .relationships = relationships,
    };
}

fn buildSpdxPackageWithId(allocator: std.mem.Allocator, component: sbom_model.Component, supplier: []const u8, spdx_id: []const u8) !SpdxPackage {
    const download_location: []const u8 = component.source_url orelse "NOASSERTION";

    const license_concluded: []const u8 = if (component.licenses.len > 0)
        switch (component.licenses[0]) {
            .spdx => |expr| expr,
            .named => |name| name,
            .no_assertion => "NOASSERTION",
        }
    else
        "NOASSERTION";

    const ext_refs: ?[]const SpdxExternalRef = if (component.purl) |p| blk: {
        const refs = try allocator.alloc(SpdxExternalRef, 1);
        refs[0] = .{
            .reference_category = "PACKAGE-MANAGER",
            .reference_type = "purl",
            .reference_locator = p,
        };
        break :blk refs;
    } else null;

    const checksums: ?[]const SpdxChecksum = if (component.hashes.len > 0) blk: {
        const cs = try allocator.alloc(SpdxChecksum, component.hashes.len);
        for (component.hashes, 0..) |h, i| {
            cs[i] = .{
                .algorithm = h.alg.toSpdxString(),
                .checksum_value = h.content,
            };
        }
        break :blk cs;
    } else null;

    return SpdxPackage{
        .spdx_id = spdx_id,
        .name = component.name,
        .version_info = component.version,
        .supplier = supplier,
        .download_location = download_location,
        .files_analyzed = false,
        .license_concluded = license_concluded,
        .license_declared = license_concluded,
        .copyright_text = "NOASSERTION",
        .external_refs = ext_refs,
        .checksums = checksums,
    };
}

/// SPDX IDs must match `[a-zA-Z0-9.-]+`. Truncate long hashes and sanitize.
pub fn bomRefToSpdxId(allocator: std.mem.Allocator, bom_ref: []const u8) ![]const u8 {
    const max_len = 64;
    const truncated = bom_ref[0..@min(bom_ref.len, max_len)];

    const prefix = "SPDXRef-";
    var result = try allocator.alloc(u8, prefix.len + truncated.len);
    @memcpy(result[0..prefix.len], prefix);

    for (truncated, 0..) |c, i| {
        result[prefix.len + i] = if (std.ascii.isAlphanumeric(c) or c == '.' or c == '-')
            c
        else
            '-';
    }

    return result;
}

/// Wraps bomRefToSpdxId with collision detection. Appends `-N` suffix when the
/// base ID already appears in the mapping (e.g. due to truncation collisions).
fn bomRefToUniqueSpdxId(
    allocator: std.mem.Allocator,
    id_map: *const std.StringHashMap([]const u8),
    bom_ref: []const u8,
) ![]const u8 {
    const base_id = try bomRefToSpdxId(allocator, bom_ref);

    if (!idValueExists(id_map, base_id)) return base_id;

    // Collision — append incrementing suffix until unique.
    var suffix: u32 = 1;
    while (suffix < 10000) : (suffix += 1) {
        const candidate = std.fmt.allocPrint(allocator, "{s}-{d}", .{ base_id, suffix }) catch
            return error.OutOfMemory;

        if (!idValueExists(id_map, candidate)) {
            allocator.free(base_id);
            return candidate;
        }
        allocator.free(candidate);
    }

    allocator.free(base_id);
    return error.OutOfMemory;
}

fn idValueExists(id_map: *const std.StringHashMap([]const u8), needle: []const u8) bool {
    var it = id_map.valueIterator();
    while (it.next()) |existing| {
        if (std.mem.eql(u8, existing.*, needle)) return true;
    }
    return false;
}

/// Serializes a Bom to SPDX 2.3 JSON and returns the bytes.
pub fn serializeAlloc(allocator: std.mem.Allocator, bom: sbom_model.Bom) SerializeError![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    serialize(allocator, bom, buf.writer(allocator)) catch return SerializeError.OutOfMemory;
    return buf.toOwnedSlice(allocator) catch return SerializeError.OutOfMemory;
}

const testing = std.testing;

fn makeTestBom() sbom_model.Bom {
    return .{
        .serial_number = "urn:uuid:test-uuid-1234",
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
        .compositions = &.{},
    };
}

test "SPDX JSON: document header" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "SPDXRef-DOCUMENT") != null);
    try testing.expect(std.mem.indexOf(u8, output, "SPDX-2.3") != null);
    try testing.expect(std.mem.indexOf(u8, output, "CC0-1.0") != null);
}

test "SPDX JSON: documentNamespace unique" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "https://spdx.org/spdxdocs/blinky-urn:uuid:test-uuid-1234") != null);
}

test "SPDX JSON: DESCRIBES relationship" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "DESCRIBES") != null);
}

test "SPDX JSON: DEPENDS_ON relationship" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "DEPENDS_ON") != null);
}

test "SPDX JSON: packages present" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "microzig") != null);
    try testing.expect(std.mem.indexOf(u8, output, "blinky") != null);
}

test "bomRefToSpdxId: basic sanitization" {
    const result = try bomRefToSpdxId(testing.allocator, "root-fw");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("SPDXRef-root-fw", result);
}

test "bomRefToSpdxId: hash with special chars" {
    const result = try bomRefToSpdxId(testing.allocator, "1220abc/def");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("SPDXRef-1220abc-def", result);
}

test "bomRefToSpdxId: truncation" {
    const long_ref = "a" ** 128;
    const result = try bomRefToSpdxId(testing.allocator, long_ref);
    defer testing.allocator.free(result);
    // "SPDXRef-" (8) + 64 truncated chars = 72
    try testing.expectEqual(@as(usize, 72), result.len);
}

test "SPDX JSON: supplier field present" {
    const bom = makeTestBom();
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);

    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // All packages should have supplier (NOASSERTION when no manufacturer).
    try testing.expect(std.mem.indexOf(u8, output, "NOASSERTION") != null);
    try testing.expect(std.mem.indexOf(u8, output, "\"supplier\"") != null);
}

test "SPDX JSON: supplier derived from manufacturer" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:supplier-test",
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
            .manufacturer = .{ .name = "Acme Corp" },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    try testing.expect(std.mem.indexOf(u8, buf.items, "Organization: Acme Corp") != null);
}

test "SPDX JSON: multiple DEPENDS_ON relationships" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:multi-dep",
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
            .{ .type = .library, .bom_ref = "lib-a", .name = "liba" },
            .{ .type = .library, .bom_ref = "lib-b", .name = "libb" },
        },
        .dependencies = &.{
            .{ .ref = "root", .depends_on = &.{ "lib-a", "lib-b" } },
        },
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));

    // Count DEPENDS_ON occurrences.
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, buf.items, pos, "DEPENDS_ON")) |idx| {
        count += 1;
        pos = idx + 1;
    }
    try testing.expectEqual(@as(usize, 2), count);
}

test "SPDX JSON: component with no version" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:nover",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "nover-lib",
            .name = "mylib",
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;
    try testing.expect(std.mem.indexOf(u8, output, "\"mylib\"") != null);
    // versionInfo should be absent (skip null).
    try testing.expect(std.mem.indexOf(u8, output, "\"versionInfo\"") == null);
}

test "SPDX: licenseDeclared populated when license available" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:lic-decl-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "mit-lib",
            .name = "mit-library",
            .licenses = &.{.{ .spdx = "MIT" }},
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    // licenseDeclared should be "MIT", not "NOASSERTION".
    try testing.expect(std.mem.indexOf(u8, output, "\"licenseDeclared\": \"MIT\"") != null);
}

test "SPDX: bomRefToSpdxId uniqueness for long hashes" {
    // Two different 64-char hashes must produce distinct SPDX IDs.
    const hash_a = "1220" ++ "a" ** 60;
    const hash_b = "1220" ++ "b" ** 60;
    const id_a = try bomRefToSpdxId(testing.allocator, hash_a);
    defer testing.allocator.free(id_a);
    const id_b = try bomRefToSpdxId(testing.allocator, hash_b);
    defer testing.allocator.free(id_b);
    try testing.expect(!std.mem.eql(u8, id_a, id_b));
}

test "SPDX: empty bom with no components" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:empty-bom",
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
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "SPDX-2.3") != null);
    // No DESCRIBES relationship without a root component.
    try testing.expect(std.mem.indexOf(u8, output, "DESCRIBES") == null);
}

test "SPDX: component with multiple hashes" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:multi-hash",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "multi-hash-lib",
            .name = "hashlib",
            .hashes = &.{
                .{ .alg = .sha2_256, .content = "abc123" },
                .{ .alg = .sha1, .content = "def456" },
            },
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    const output = buf.items;

    try testing.expect(std.mem.indexOf(u8, output, "SHA256") != null);
    try testing.expect(std.mem.indexOf(u8, output, "SHA1") != null);
    try testing.expect(std.mem.indexOf(u8, output, "abc123") != null);
    try testing.expect(std.mem.indexOf(u8, output, "def456") != null);
}

test "SPDX: bomRefToSpdxId truncation collision (raw function)" {
    // Two bom_refs sharing the first 64 chars collide under raw bomRefToSpdxId.
    const prefix = "a" ** 64;
    const ref_a = prefix ++ "-alpha";
    const ref_b = prefix ++ "-bravo";
    const id_a = try bomRefToSpdxId(testing.allocator, ref_a);
    defer testing.allocator.free(id_a);
    const id_b = try bomRefToSpdxId(testing.allocator, ref_b);
    defer testing.allocator.free(id_b);
    try testing.expectEqualStrings(id_a, id_b);
}

test "SPDX: bomRefToUniqueSpdxId resolves truncation collisions" {
    var id_map = std.StringHashMap([]const u8).init(testing.allocator);
    defer id_map.deinit();

    const prefix = "a" ** 64;
    const ref_a = prefix ++ "-alpha";
    const ref_b = prefix ++ "-bravo";

    const uid_a = try bomRefToUniqueSpdxId(testing.allocator, &id_map, ref_a);
    defer testing.allocator.free(uid_a);
    id_map.put(ref_a, uid_a) catch unreachable;

    const uid_b = try bomRefToUniqueSpdxId(testing.allocator, &id_map, ref_b);
    defer testing.allocator.free(uid_b);

    // Deduplication must produce distinct IDs.
    try testing.expect(!std.mem.eql(u8, uid_a, uid_b));
    // Second ID gets a "-1" suffix.
    try testing.expect(std.mem.endsWith(u8, uid_b, "-1"));
}

test "SPDX: colliding bom_refs produce distinct IDs in full serialization" {
    const prefix = "a" ** 64;
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:collision-test",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root",
                .name = "fw",
                .version = "1.0",
            },
        },
        .components = &.{
            .{ .type = .library, .bom_ref = prefix ++ "-alpha", .name = "lib-a" },
            .{ .type = .library, .bom_ref = prefix ++ "-bravo", .name = "lib-b" },
        },
        .dependencies = &.{
            .{ .ref = "root", .depends_on = &.{ prefix ++ "-alpha", prefix ++ "-bravo" } },
        },
        .compositions = &.{},
    };

    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();

    const packages = parsed.value.object.get("packages").?.array.items;
    // root + 2 libs = 3 packages, all with distinct SPDXID values.
    try testing.expectEqual(@as(usize, 3), packages.len);
    const id0 = packages[0].object.get("SPDXID").?.string;
    const id1 = packages[1].object.get("SPDXID").?.string;
    const id2 = packages[2].object.get("SPDXID").?.string;
    try testing.expect(!std.mem.eql(u8, id1, id2));
    try testing.expect(!std.mem.eql(u8, id0, id1));
}

test "SPDX: document namespace uniqueness across serializations" {
    const bom_a = sbom_model.Bom{
        .serial_number = "urn:uuid:aaaa-1111",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{ .type = .firmware, .bom_ref = "root", .name = "fw", .version = "1.0.0" },
        },
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var bom_b = bom_a;
    bom_b.serial_number = "urn:uuid:bbbb-2222";

    var buf_a: std.ArrayListUnmanaged(u8) = .{};
    defer buf_a.deinit(testing.allocator);
    try serialize(testing.allocator, bom_a, buf_a.writer(testing.allocator));

    var buf_b: std.ArrayListUnmanaged(u8) = .{};
    defer buf_b.deinit(testing.allocator);
    try serialize(testing.allocator, bom_b, buf_b.writer(testing.allocator));

    // Parse both and compare namespaces.
    const parsed_a = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf_a.items, .{});
    defer parsed_a.deinit();
    const parsed_b = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf_b.items, .{});
    defer parsed_b.deinit();

    const ns_a = parsed_a.value.object.get("documentNamespace").?.string;
    const ns_b = parsed_b.value.object.get("documentNamespace").?.string;
    try testing.expect(!std.mem.eql(u8, ns_a, ns_b));
}

test "SPDX: bomRefToSpdxId with empty string" {
    const result = try bomRefToSpdxId(testing.allocator, "");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("SPDXRef-", result);
}

test "SPDX: bomRefToSpdxId with only special chars" {
    const result = try bomRefToSpdxId(testing.allocator, "!@#$%^&*()");
    defer testing.allocator.free(result);
    // All special chars replaced with '-'.
    try testing.expectEqualStrings("SPDXRef-----------", result);
    // Verify it's a valid SPDX ID (only alphanumeric, '.', '-').
    for (result["SPDXRef-".len..]) |c| {
        try testing.expect(std.ascii.isAlphanumeric(c) or c == '.' or c == '-');
    }
}

test "SPDX: named license produces correct licenseDeclared" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:named-lic",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "named-lic-lib",
            .name = "proprietary-lib",
            .licenses = &.{.{ .named = "Proprietary-v3" }},
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    try testing.expect(std.mem.indexOf(u8, buf.items, "\"licenseDeclared\": \"Proprietary-v3\"") != null);
}

test "SPDX: no_assertion license produces NOASSERTION" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:no-assert-lic",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "no-assert-lib",
            .name = "unknown-lic-lib",
            .licenses = &.{.no_assertion},
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));
    try testing.expect(std.mem.indexOf(u8, buf.items, "\"licenseDeclared\": \"NOASSERTION\"") != null);
}

test "SPDX: zero dependencies produces valid document" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:zero-deps",
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
        .components = &.{},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("SPDX-2.3", obj.get("spdxVersion").?.string);
    const rels = obj.get("relationships").?.array.items;
    // Only DESCRIBES, no DEPENDS_ON.
    try testing.expectEqual(@as(usize, 1), rels.len);
    try testing.expectEqualStrings("DESCRIBES", rels[0].object.get("relationshipType").?.string);
}

test "SPDX: component with purl generates externalRefs" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:purl-extref",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "purl-lib",
            .name = "purl-test",
            .purl = "pkg:zig/purl-test@1.0.0",
        }},
        .dependencies = &.{},
        .compositions = &.{},
    };
    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));

    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const pkgs = parsed.value.object.get("packages").?.array.items;
    const ext_refs = pkgs[0].object.get("externalRefs").?.array.items;
    try testing.expectEqual(@as(usize, 1), ext_refs.len);
    try testing.expectEqualStrings("purl", ext_refs[0].object.get("referenceType").?.string);
    try testing.expectEqualStrings("pkg:zig/purl-test@1.0.0", ext_refs[0].object.get("referenceLocator").?.string);
}

test "SPDX JSON: round-trip serialize then parse" {
    const bom = sbom_model.Bom{
        .serial_number = "urn:uuid:spdx-roundtrip",
        .version = 1,
        .metadata = .{
            .timestamp = "2024-01-01T00:00:00Z",
            .tools = &.{.{ .vendor = "test", .name = "tool", .version = "1.0" }},
            .component = .{
                .type = .firmware,
                .bom_ref = "root-fw",
                .name = "my-firmware",
                .version = "2.0.0",
                .licenses = &.{.{ .spdx = "Apache-2.0" }},
            },
        },
        .components = &.{.{
            .type = .library,
            .bom_ref = "dep-lib",
            .name = "dep",
            .version = "1.0.0",
            .purl = "pkg:zig/dep@1.0.0",
            .hashes = &.{.{ .alg = .sha2_256, .content = "feedface" }},
        }},
        .dependencies = &.{.{
            .ref = "root-fw",
            .depends_on = &.{"dep-lib"},
        }},
        .compositions = &.{},
    };

    var buf: std.ArrayListUnmanaged(u8) = .{};
    defer buf.deinit(testing.allocator);
    try serialize(testing.allocator, bom, buf.writer(testing.allocator));

    // Parse back as generic JSON and verify structure.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, buf.items, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;

    try testing.expectEqualStrings("SPDX-2.3", obj.get("spdxVersion").?.string);
    try testing.expectEqualStrings("CC0-1.0", obj.get("dataLicense").?.string);

    const packages = obj.get("packages").?.array.items;
    try testing.expectEqual(@as(usize, 2), packages.len);

    const relationships = obj.get("relationships").?.array.items;
    try testing.expect(relationships.len >= 2);
}

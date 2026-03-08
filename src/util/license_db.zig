const std = @import("std");

/// Common SPDX license identifiers and their canonical names.
/// Covers the most frequently encountered licenses in embedded/IoT ecosystems.
pub const Entry = struct {
    id: []const u8,
    name: []const u8,
    osi_approved: bool,
};

pub const known_licenses = [_]Entry{
    .{ .id = "MIT", .name = "MIT License", .osi_approved = true },
    .{ .id = "Apache-2.0", .name = "Apache License 2.0", .osi_approved = true },
    .{ .id = "BSD-2-Clause", .name = "BSD 2-Clause \"Simplified\" License", .osi_approved = true },
    .{ .id = "BSD-3-Clause", .name = "BSD 3-Clause \"New\" or \"Revised\" License", .osi_approved = true },
    .{ .id = "BSD-1-Clause", .name = "BSD 1-Clause License", .osi_approved = true },
    .{ .id = "ISC", .name = "ISC License", .osi_approved = true },
    .{ .id = "Zlib", .name = "zlib License", .osi_approved = true },
    .{ .id = "BSL-1.0", .name = "Boost Software License 1.0", .osi_approved = true },
    .{ .id = "MPL-2.0", .name = "Mozilla Public License 2.0", .osi_approved = true },
    .{ .id = "GPL-2.0-only", .name = "GNU General Public License v2.0 only", .osi_approved = true },
    .{ .id = "GPL-2.0-or-later", .name = "GNU General Public License v2.0 or later", .osi_approved = true },
    .{ .id = "GPL-3.0-only", .name = "GNU General Public License v3.0 only", .osi_approved = true },
    .{ .id = "GPL-3.0-or-later", .name = "GNU General Public License v3.0 or later", .osi_approved = true },
    .{ .id = "LGPL-2.1-only", .name = "GNU Lesser General Public License v2.1 only", .osi_approved = true },
    .{ .id = "LGPL-3.0-only", .name = "GNU Lesser General Public License v3.0 only", .osi_approved = true },
    .{ .id = "Unlicense", .name = "The Unlicense", .osi_approved = true },
    .{ .id = "CC0-1.0", .name = "Creative Commons Zero v1.0 Universal", .osi_approved = false },
    .{ .id = "blessing", .name = "SQLite Blessing", .osi_approved = false },
};

/// Returns the SPDX license entry for the given ID, or null if not recognized.
pub fn lookup(spdx_id: []const u8) ?*const Entry {
    for (&known_licenses) |*entry| {
        if (std.mem.eql(u8, entry.id, spdx_id)) return entry;
    }
    return null;
}

/// Checks whether a string is a valid SPDX license expression.
/// Accepts single IDs and simple `OR`/`AND` compound expressions.
///
/// In non-strict mode (default), accepts any non-empty identifier token.
/// In strict mode, each token must be a known SPDX ID, `NOASSERTION`,
/// or a `LicenseRef-*` custom identifier.
pub fn isValidExpression(expr: []const u8) bool {
    return isValidExpressionStrict(expr, false);
}

pub fn isValidExpressionStrict(expr: []const u8, strict: bool) bool {
    if (expr.len == 0) return false;

    var it = std.mem.splitSequence(u8, expr, " OR ");
    while (it.next()) |part| {
        var and_it = std.mem.splitSequence(u8, part, " AND ");
        while (and_it.next()) |id| {
            const trimmed = std.mem.trim(u8, id, " ");
            if (trimmed.len == 0) return false;
            if (strict) {
                if (std.mem.eql(u8, trimmed, "NOASSERTION")) continue;
                if (std.mem.startsWith(u8, trimmed, "LicenseRef-")) continue;
                if (lookup(trimmed) == null) return false;
            }
        }
    }
    return true;
}

const testing = std.testing;

test "lookup: known license" {
    const entry = lookup("MIT").?;
    try testing.expectEqualStrings("MIT License", entry.name);
    try testing.expect(entry.osi_approved);
}

test "lookup: unknown license" {
    try testing.expect(lookup("UNKNOWN-999") == null);
}

test "lookup: BSD-3-Clause" {
    const entry = lookup("BSD-3-Clause").?;
    try testing.expectEqualStrings("BSD-3-Clause", entry.id);
}

test "isValidExpression: single ID" {
    try testing.expect(isValidExpression("MIT"));
}

test "isValidExpression: compound OR" {
    try testing.expect(isValidExpression("Apache-2.0 OR MIT"));
}

test "isValidExpression: empty is invalid" {
    try testing.expect(!isValidExpression(""));
}

test "isValidExpression: compound AND" {
    try testing.expect(isValidExpression("Apache-2.0 AND MIT"));
}

test "isValidExpression: AND and OR combined" {
    try testing.expect(isValidExpression("MIT OR Apache-2.0 AND BSD-3-Clause"));
}

test "isValidExpression: extra whitespace" {
    try testing.expect(isValidExpression("  MIT  "));
}

test "lookup: Apache-2.0" {
    const entry = lookup("Apache-2.0").?;
    try testing.expectEqualStrings("Apache License 2.0", entry.name);
    try testing.expect(entry.osi_approved);
}

test "lookup: blessing not OSI approved" {
    const entry = lookup("blessing").?;
    try testing.expect(!entry.osi_approved);
}

test "isValidExpressionStrict: known ID accepted" {
    try testing.expect(isValidExpressionStrict("MIT", true));
    try testing.expect(isValidExpressionStrict("Apache-2.0", true));
}

test "isValidExpressionStrict: unknown ID rejected" {
    try testing.expect(!isValidExpressionStrict("UNKNOWN-999", true));
    try testing.expect(!isValidExpressionStrict("mit", true));
}

test "isValidExpressionStrict: NOASSERTION accepted" {
    try testing.expect(isValidExpressionStrict("NOASSERTION", true));
}

test "isValidExpressionStrict: LicenseRef custom ID accepted" {
    try testing.expect(isValidExpressionStrict("LicenseRef-my-custom", true));
    try testing.expect(isValidExpressionStrict("LicenseRef-proprietary-v2", true));
}

test "isValidExpressionStrict: compound with known IDs" {
    try testing.expect(isValidExpressionStrict("MIT OR Apache-2.0", true));
    try testing.expect(isValidExpressionStrict("MIT AND BSD-3-Clause", true));
}

test "isValidExpressionStrict: compound with unknown rejects" {
    try testing.expect(!isValidExpressionStrict("MIT OR FAKE-LICENSE", true));
}

test "isValidExpressionStrict: non-strict still accepts anything" {
    try testing.expect(isValidExpressionStrict("FAKE-LICENSE", false));
    try testing.expect(isValidExpressionStrict("anything-goes", false));
}

test "lookup: case sensitive — lowercase 'mit' returns null" {
    // SPDX IDs are case-sensitive per spec. "mit" is not "MIT".
    try testing.expect(lookup("mit") == null);
}

test "lookup: case sensitive — 'apache-2.0' returns null" {
    try testing.expect(lookup("apache-2.0") == null);
}

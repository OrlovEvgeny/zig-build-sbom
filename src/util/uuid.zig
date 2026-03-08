const std = @import("std");

pub const UuidError = error{
    OutOfMemory,
};

/// Generates a UUIDv4 formatted as `urn:uuid:{hex}` for CycloneDX serial numbers.
/// Uses std.crypto.random for cryptographic randomness.
pub fn generateV4(allocator: std.mem.Allocator) UuidError![]const u8 {
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);

    // RFC 4122 version 4: set version bits (0100) and variant bits (10xx).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    return std.fmt.allocPrint(allocator, "urn:uuid:{x:0>8}-{x:0>4}-{x:0>4}-{x:0>4}-{x:0>12}", .{
        std.mem.readInt(u32, bytes[0..4], .big),
        std.mem.readInt(u16, bytes[4..6], .big),
        std.mem.readInt(u16, bytes[6..8], .big),
        std.mem.readInt(u16, bytes[8..10], .big),
        std.mem.readInt(u48, bytes[10..16], .big),
    });
}

const testing = std.testing;

test "generateV4: format validation" {
    const uuid = try generateV4(testing.allocator);
    defer testing.allocator.free(uuid);

    try testing.expect(std.mem.startsWith(u8, uuid, "urn:uuid:"));
    // urn:uuid: (9) + 8-4-4-4-12 (32 hex + 4 dashes = 36) = 45
    try testing.expectEqual(@as(usize, 45), uuid.len);

    // Verify dashes at correct positions.
    try testing.expectEqual(@as(u8, '-'), uuid[17]);
    try testing.expectEqual(@as(u8, '-'), uuid[22]);
    try testing.expectEqual(@as(u8, '-'), uuid[27]);
    try testing.expectEqual(@as(u8, '-'), uuid[32]);
}

test "generateV4: version and variant bits" {
    const uuid = try generateV4(testing.allocator);
    defer testing.allocator.free(uuid);

    // Version nibble is at position 14 in the hex string (index 9+14=23).
    try testing.expectEqual(@as(u8, '4'), uuid[23]);

    // Variant nibble is at position 19 in the hex string (index 9+19=28).
    const variant_char = uuid[28];
    try testing.expect(variant_char == '8' or variant_char == '9' or
        variant_char == 'a' or variant_char == 'b');
}

test "generateV4: uniqueness" {
    const a = try generateV4(testing.allocator);
    defer testing.allocator.free(a);
    const b = try generateV4(testing.allocator);
    defer testing.allocator.free(b);
    try testing.expect(!std.mem.eql(u8, a, b));
}

test "generateV4: all hex characters are valid lowercase" {
    const uuid = try generateV4(testing.allocator);
    defer testing.allocator.free(uuid);

    // Skip "urn:uuid:" prefix and verify hex chars + dashes.
    for (uuid["urn:uuid:".len..]) |c| {
        try testing.expect(c == '-' or (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

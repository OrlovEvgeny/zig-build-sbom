const std = @import("std");

pub const TimestampError = error{
    OutOfMemory,
    InvalidTimestamp,
};

/// Returns the current time as an ISO 8601 UTC string: `2026-03-07T14:23:00Z`.
pub fn now(allocator: std.mem.Allocator) TimestampError![]const u8 {
    const epoch_secs = std.time.timestamp();
    return fromEpoch(allocator, epoch_secs);
}

/// Converts a Unix epoch timestamp to ISO 8601 UTC string.
/// Returns `InvalidTimestamp` for negative values (pre-1970).
pub fn fromEpoch(allocator: std.mem.Allocator, epoch_secs: i64) TimestampError![]const u8 {
    if (epoch_secs < 0) return error.InvalidTimestamp;
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(epoch_secs) };
    const day = es.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = es.getDaySeconds();

    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    });
}

const testing = std.testing;

test "fromEpoch: known date" {
    // 2024-01-01T00:00:00Z = 1704067200
    const ts = try fromEpoch(testing.allocator, 1704067200);
    defer testing.allocator.free(ts);
    try testing.expectEqualStrings("2024-01-01T00:00:00Z", ts);
}

test "fromEpoch: format structure" {
    const ts = try fromEpoch(testing.allocator, 1709827380);
    defer testing.allocator.free(ts);
    // Should be 20 chars: YYYY-MM-DDTHH:MM:SSZ
    try testing.expectEqual(@as(usize, 20), ts.len);
    try testing.expectEqual(@as(u8, 'T'), ts[10]);
    try testing.expectEqual(@as(u8, 'Z'), ts[19]);
}

test "now: produces non-empty string" {
    const ts = try now(testing.allocator);
    defer testing.allocator.free(ts);
    try testing.expect(ts.len == 20);
    try testing.expect(std.mem.endsWith(u8, ts, "Z"));
}

test "fromEpoch: epoch zero" {
    const ts = try fromEpoch(testing.allocator, 0);
    defer testing.allocator.free(ts);
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", ts);
}

test "fromEpoch: negative returns error" {
    const result = fromEpoch(testing.allocator, -1);
    try testing.expectError(error.InvalidTimestamp, result);
}

test "fromEpoch: far-future date" {
    // 2100-01-01T00:00:00Z = 4102444800
    const ts = try fromEpoch(testing.allocator, 4102444800);
    defer testing.allocator.free(ts);
    try testing.expectEqualStrings("2100-01-01T00:00:00Z", ts);
}

test "fromEpoch: leap year Feb 29" {
    // 2024-02-29T12:00:00Z = 1709208000
    const ts = try fromEpoch(testing.allocator, 1709208000);
    defer testing.allocator.free(ts);
    try testing.expectEqualStrings("2024-02-29T12:00:00Z", ts);
}

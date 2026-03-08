// Standalone SBOM serializer executable.
// Compiled as a build tool with serde available, invoked via Step.Run.
// Reads intermediate JSON (Bom struct), writes final CycloneDX/SPDX output.

const std = @import("std");
const lib = @import("zig-build-sbom");
const sbom_model = lib.sbom;
const cyclonedx = lib.cyclonedx;
const spdx = lib.spdx;

const Format = enum {
    @"cyclonedx-json",
    @"cyclonedx-xml",
    @"spdx-json",
};

// Exit codes for distinct failure modes.
const EXIT_USAGE = 1;
const EXIT_READ = 2;
const EXIT_PARSE = 3;
const EXIT_SERIALIZE = 4;
const EXIT_WRITE = 5;

fn fatalWithCode(code: u8, comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print(fmt ++ "\n", args);
    std.process.exit(code);
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 4) {
        fatalWithCode(EXIT_USAGE, "usage: sbom-serializer <input.json> <output-file> <format>", .{});
    }

    const input_path = args[1];
    const output_path = args[2];
    const format = std.meta.stringToEnum(Format, args[3]) orelse {
        fatalWithCode(EXIT_USAGE, "unknown format: {s}", .{args[3]});
    };

    const input_data = std.fs.cwd().readFileAlloc(allocator, input_path, 64 * 1024 * 1024) catch |err| {
        fatalWithCode(EXIT_READ, "failed to read {s}: {}", .{ input_path, err });
    };
    defer allocator.free(input_data);

    const parsed = std.json.parseFromSlice(sbom_model.Bom, allocator, input_data, .{
        .ignore_unknown_fields = true,
    }) catch |err| {
        fatalWithCode(EXIT_PARSE, "failed to parse intermediate JSON: {}", .{err});
    };
    defer parsed.deinit();

    const bom = parsed.value;

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);
    const w = buf.writer(allocator);

    switch (format) {
        .@"cyclonedx-json" => cyclonedx.serialize(allocator, bom, .json, w) catch |err| {
            fatalWithCode(EXIT_SERIALIZE, "CycloneDX JSON serialization failed: {}", .{err});
        },
        .@"cyclonedx-xml" => cyclonedx.serialize(allocator, bom, .xml, w) catch |err| {
            fatalWithCode(EXIT_SERIALIZE, "CycloneDX XML serialization failed: {}", .{err});
        },
        .@"spdx-json" => spdx.serialize(allocator, bom, w) catch |err| {
            fatalWithCode(EXIT_SERIALIZE, "SPDX JSON serialization failed: {}", .{err});
        },
    }

    if (std.fs.path.dirname(output_path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }

    const file = std.fs.cwd().createFile(output_path, .{}) catch |err| {
        fatalWithCode(EXIT_WRITE, "failed to create {s}: {}", .{ output_path, err });
    };
    defer file.close();

    file.writeAll(buf.items) catch |err| {
        fatalWithCode(EXIT_WRITE, "failed to write output: {}", .{err});
    };
}

// zig-build-sbom — Build-time SBOM generator for Zig and bare-metal firmware.

const std = @import("std");
pub const SbomStep = @import("sbom_step.zig").SbomStep;

// Utility modules.
pub const purl = @import("util/purl.zig");
pub const uuid = @import("util/uuid.zig");
pub const timestamp = @import("util/timestamp.zig");
pub const license_db = @import("util/license_db.zig");

// Model.
pub const sbom = @import("sbom.zig");

// Traversal.
pub const zon_parser = @import("traversal/zon_parser.zig");
pub const graph = @import("traversal/graph.zig");
pub const c_sources = @import("traversal/c_sources.zig");

// Serializers.
pub const cyclonedx = @import("output/cyclonedx.zig");
pub const spdx = @import("output/spdx.zig");

// MicroZig integration.
pub const microzig = @import("integrations/microzig.zig");

test {
    _ = purl;
    _ = uuid;
    _ = timestamp;
    _ = license_db;
    _ = sbom;
    _ = zon_parser;
    _ = graph;
    _ = c_sources;
    _ = cyclonedx;
    _ = spdx;
}

# zig-build-sbom

Build-time SBOM generator for Zig projects and bare-metal firmware.

[![Zig](https://img.shields.io/badge/Zig-0.14.0+-f7a41d?logo=zig&logoColor=white)](https://ziglang.org)
[![Release](https://img.shields.io/github/v/release/OrlovEvgeny/zig-build-sbom)](https://github.com/OrlovEvgeny/zig-build-sbom/releases)
[![Tests](https://github.com/OrlovEvgeny/zig-build-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/OrlovEvgeny/zig-build-sbom/actions/workflows/ci.yml)

Hooks into `std.Build` to extract the full dependency graph at compile time and produces [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/) or [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) SBOMs with zero runtime overhead. Designed for [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) compliance in embedded/IoT products.

## Why

Existing SBOM tools (Syft, cdxgen, FOSSA) work by scanning binaries or lockfiles. Zig has neither. Its build system resolves dependencies via content-addressed hashing and compiles everything from source — there is no `package-lock.json` to scrape and no dynamic linker metadata to read.

`zig-build-sbom` reads the build graph directly. Every Zig package, its transitive dependencies, content hashes, and vendored C sources are captured from the same data structures the compiler uses. No guessing, no heuristics for the Zig portion of the graph.

For MicroZig firmware it also captures hardware context: chip name, CPU architecture, memory regions — information that CycloneDX's `device` component type was designed for but no existing tool fills in.

## Install

```sh
zig fetch --save git+https://github.com/OrlovEvgeny/zig-build-sbom
```

## Usage

### `addSbomStep` — generate on demand

Adds an SBOM step reachable via `zig build sbom`:

```zig
const std = @import("std");
const sbom = @import("zig-build-sbom");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "my-app",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // Generate SBOM on `zig build sbom`
    _ = sbom.addSbomStep(b, exe, .{
        .format = .cyclonedx_json,
        .output_path = "sbom.cdx.json",
        .version = "1.0.0",
    });
}
```

```sh
zig build sbom
```

### `addSbomToInstall` — generate on every build

```zig
_ = sbom.addSbomToInstall(b, exe, .{
    .format = .cyclonedx_json,
    .output_path = "sbom.cdx.json",
    .version = "1.0.0",
});
```

### `getOutput` — chain the SBOM as a build dependency

```zig
const sbom_step = sbom.addSbomStep(b, exe, .{ ... });
const sbom_output = sbom_step.getOutput();
// Use sbom_output as a LazyPath dependency for another step.
```

## Output formats

| Format | Option | File convention |
|--------|--------|-----------------|
| CycloneDX 1.6 JSON | `.cyclonedx_json` | `*.cdx.json` |
| CycloneDX 1.6 XML | `.cyclonedx_xml` | `*.cdx.xml` |
| SPDX 2.3 JSON | `.spdx_json` | `*.spdx.json` |

## Options

```zig
_ = sbom.addSbomStep(b, exe, .{
    // Output format (default: cyclonedx_json)
    .format = .cyclonedx_json,

    // Output filename in the build cache
    .output_path = "sbom.cdx.json",

    // Version string for the root component
    .version = "1.0.0",

    // Manufacturer metadata (useful for CRA compliance)
    .manufacturer = .{
        .name = "Acme GmbH",
        .url = "https://acme.de",
    },

    // Include vendored C sources as components (default: true)
    .include_c_sources = true,

    // Walk transitive Zig dependencies (default: true)
    .include_transitive = true,

    // Infer SPDX license IDs from package names (default: true)
    .infer_licenses = true,

    // Custom properties added to the root component
    .custom_properties = &.{},
});
```

## MicroZig firmware

For MicroZig projects, use the `microzig` integration. It adds hardware context: chip name, CPU architecture, memory layout, and a CycloneDX `device` component for the MCU.

```zig
const std = @import("std");
const sbom = @import("zig-build-sbom");

pub fn build(b: *std.Build) void {
    // ... MicroZig setup, `fw` is a MicroZig Firmware value ...

    _ = sbom.microzig.addFirmwareSbomStep(b, fw, .{
        .base = .{
            .format = .cyclonedx_json,
            .output_path = "sbom.cdx.json",
            .version = "1.0.0",
            .manufacturer = .{ .name = "Acme IoT GmbH", .url = "https://acme-iot.de" },
        },
        .include_hardware_component = true,  // adds device component for the MCU
        .include_memory_layout = true,       // flash/RAM regions in properties
        .include_cpu_info = true,            // CPU arch and model in properties
    });
}
```

The firmware's `fw` value is accepted as `anytype` — it must have `.artifact` (`*std.Build.Step.Compile`) and `.target` (with `.chip.name`, `.chip.cpu.arch`, `.chip.cpu.name`, `.chip.memory_regions`). Standard MicroZig `Firmware` satisfies this contract.

### Example output (RP2040 blinky)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "firmware",
      "bom-ref": "blinky",
      "name": "blinky",
      "version": "1.0.0",
      "properties": [
        { "name": "firmware:cpu.arch", "value": "thumb" },
        { "name": "firmware:cpu.model", "value": "cortex_m0plus" },
        { "name": "firmware:chip.name", "value": "RP2040" },
        { "name": "firmware:memory.region.0.type", "value": "flash" },
        { "name": "firmware:memory.region.0.length", "value": "0x200000" },
        { "name": "firmware:memory.region.1.type", "value": "ram" },
        { "name": "firmware:memory.region.1.length", "value": "0x42000" }
      ]
    },
    "manufacturer": { "name": "Acme IoT GmbH" }
  },
  "components": [
    {
      "type": "device",
      "bom-ref": "device-RP2040",
      "name": "RP2040",
      "description": "RP2040 (cortex_m0plus core, 2097152 bytes flash)",
      "properties": [
        { "name": "cdx:device:type", "value": "mcu" },
        { "name": "firmware:target.arch", "value": "thumb" }
      ]
    }
  ],
  "compositions": [
    { "aggregate": "complete", "assemblies": ["blinky", "device-RP2040"] }
  ]
}
```

## Vendored C sources

When `include_c_sources` is enabled (the default), the traversal inspects `Step.Compile` link objects for C source files. Files are grouped by directory into logical libraries using a built-in table of known projects:

| Library | Detected path pattern |
|---------|-----------------------|
| lwIP | `lwip/` |
| mbedTLS | `mbedtls/` |
| FreeRTOS | `freertos/`, `FreeRTOS/` |
| CMSIS | `cmsis/`, `CMSIS/` |
| FatFs | `fatfs/` |
| tinycbor | `tinycbor/` |
| SQLite | `sqlite/` |

C-sourced components are marked with `compositions.aggregate = "incomplete"` — the tool cannot guarantee it found every vendored file through path heuristics alone.

## What goes into the SBOM

| Source | Component type | `bom-ref` | Completeness |
|--------|---------------|-----------|--------------|
| Root project | `firmware` | project name | `complete` |
| Zig packages (direct + transitive) | `library` | `pkg_hash` | `complete` |
| Vendored C sources | `library` | generated ID | `incomplete` |
| MCU chip (MicroZig) | `device` | `device-{chip}` | `complete` |

`pkg_hash` (Zig's content-addressed package hash) is used as `bom-ref` for all Zig dependencies. Names can collide in diamond dependency graphs; content hashes cannot.

## CRA compliance notes

The [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) requires technical documentation including an SBOM for products with digital elements (enforcement: September 2026 for reporting, December 2027 for full compliance).

`zig-build-sbom` supports CRA workflows:

- `compositions.aggregate` honestly reports `complete` (Zig packages from the build graph) vs. `incomplete` (C sources from heuristics). Auditors can distinguish proven completeness from best-effort.
- `manufacturer` metadata maps to CRA Article 13 requirements.
- CycloneDX `device` components capture hardware identity for IoT/embedded products.
- Every Zig dependency includes its content hash, providing verifiable provenance without external registries.

## How it works

SBOM generation runs in two phases:

1. **Graph extraction** (build step, runs in the Zig build runner): walks `Step.Compile` modules and their transitive imports, reads `build.zig.zon` metadata via `std.zig.Ast`, detects C sources, and writes an intermediate JSON file.

2. **Serialization** (separate executable via `Step.Run`): reads the intermediate JSON, serializes to CycloneDX or SPDX using [serde.zig](https://github.com/OrlovEvgeny/serde.zig) for standards-compliant field naming and structure.

The two-phase split exists because `serde.zig` (like any normal Zig dependency) cannot be `@import`ed inside the build runner — the build runner resolves `@import("serde")` to the dependency's `build.zig`, not its library module.

## Requirements

- Zig 0.14.0+

## License

MIT

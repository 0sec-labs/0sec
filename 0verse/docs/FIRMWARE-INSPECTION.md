# Deterministic firmware inspection

Issue `#79` adds the final R1 boundary between verified acquisition bytes and
later decompilation or emulation. The dependency-free
`zeroverse.firmware_inspection` module snapshots an opaque binary and emits a
canonical `0verse.firmware-inspection/v1` evidence report. It never opens a live
transport, invokes binwalk, unpacks a filesystem, executes code, or writes to the
source artifact.

## Inputs

Raw files can be inspected directly:

```python
from zeroverse.firmware_inspection import inspect_firmware

report = inspect_firmware(
    "firmware.bin",
    artifact_id="ecu-main",
    load_address=0x08000000,
)
print(report.canonical_bytes().decode())
```

Acquisition bundles should use the stricter path:

```python
from zeroverse.acquisition_bundle import load_acquisition_bundle
from zeroverse.firmware_inspection import inspect_bundle

bundle = load_acquisition_bundle("./acquisition")
reports = inspect_bundle(bundle, load_addresses={"firmware": 0x08000000})
```

`inspect_bundle()` admits only artifacts already selected by
`AcquisitionManifest.analysis_inputs()`: present, hash-verified, non-encrypted
firmware images or memory regions. The inspector snapshots each file again and
requires its size and SHA-256 to still match the validated bundle identity.

Raw inputs are regular non-symlink files, capped at 512 MiB. They are read once
in bounded chunks while file identity and metadata are checked before and after
the read. Inspection operates on that immutable in-memory snapshot.

## Reported observations

Every report includes the byte size and SHA-256 plus:

- whole-image and deterministic windowed Shannon entropy;
- bounded ASCII and UTF-16LE strings with offsets and original lengths;
- runs of at least 64 `0x00` or `0xff` bytes;
- repeated, aligned non-uniform blocks with digests and occurrence offsets;
- embedded ELF, PE, Mach-O, uImage, FDT, SquashFS, CramFS, gzip, XZ, ZIP, UBI,
  and JFFS2 signatures;
- supported architecture and vector-table candidates;
- non-overlapping candidate regions separated by observed padding; and
- explicit unknowns when a property cannot be established.

Large string, padding, repeated-block, and container result sets are bounded
deterministically. The report records total counts and truncation flags rather
than silently presenting a partial set as complete.
Strings can contain credentials, identifiers, endpoints, or other sensitive
firmware content; callers must apply the same export/redaction policy used for
the acquisition bundle.

`FirmwareInspectionReport.canonical_bytes()` uses sorted JSON keys, compact
separators, ASCII escaping, and one trailing newline. The report has no timestamp,
random identifier, host path, or tool-availability field, so identical bytes and
arguments produce identical output.

## Confidence and evidence

Confidence is an integer from `0` through `100`; it ranks a supported heuristic
and is not a probability. Every architecture, vector-table, container, and
region candidate carries machine-readable evidence strings. A candidate remains
an inference, never an observed architecture or executable permission.

Version 1 recognizes architecture from validated ELF, PE, and Mach-O headers. It
also recognizes a conservative little-endian ARM Cortex-M vector shape: an
aligned initial stack pointer in a common RAM range, a Thumb reset handler, and
multiple plausible handler entries. It does not guess MIPS, TriCore, PowerPC,
RISC-V, or another raw-image architecture from byte frequency. Such images keep
`architecture-not-established` until a stronger parser, user declaration, or
device profile supplies evidence.

Load-address precedence is explicit:

1. A non-negative caller-supplied address is `user-supplied` and always wins.
2. A unique address supported by an executable header or Cortex-M reset pointer
   is `inferred`.
3. Conflicting or absent evidence leaves the address `unknown` and candidate
   manifest starts as `null`.

Supplying an address changes only the derived report. The retained firmware and
source manifest remain byte-for-byte unchanged. Conflicts between a caller
address and embedded pointers reduce heuristic confidence and remain visible in
the evidence; the inspector does not rewrite pointer values to make them agree.

## Region roles

Candidate spans are bounded by observed padding or artifact edges. Version 1
assigns roles conservatively:

| Role | Required evidence |
|---|---|
| `bootloader` | the first supported vector table when a distinct later vector table indicates a multi-stage image |
| `code` | a supported vector table or validated embedded executable header |
| `calibration` | explicit calibration, fuel-map, ignition-map, or torque-map string markers |
| `data` | a non-padding span without supported executable or calibration evidence; confidence is intentionally low |

These rules do not claim semantic completeness. Compressed, encoded, proprietary,
or mixed regions may remain `data` or unknown until another evidence-producing
parser refines them.

Selected candidates can be projected into a new manifest:

```python
from zeroverse.firmware_inspection import with_inspection_regions

derived = with_inspection_regions(bundle.manifest, reports[0])
```

The function is copy-on-write. It verifies the report identity against the
manifest artifact, creates reciprocal `MemoryRegion` and `artifact.region_ids`
references, preserves existing order, and records the conservative `inferred`
basis. Confidence and detailed evidence remain in the inspection report because
`AcquisitionManifest` v1 has no per-field confidence model.

## Boundary

Inspection is not extraction or analysis. A container signature is not proof
that decompression is safe or complete; an architecture candidate is not a
decompiler configuration; a code region is not a vulnerability finding. Binwalk
carving and Qiling execution remain in `zeroverse.firmware` and are optional,
later stages. The user-facing `scout inspect` CLI remains issue `#73`.

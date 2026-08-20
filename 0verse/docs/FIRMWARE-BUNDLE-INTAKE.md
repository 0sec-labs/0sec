# Firmware acquisition bundle intake

Issue `#80` adds a hardware-free filesystem boundary around
`AcquisitionManifest` v1. It verifies retained evidence only. Loading a bundle
never opens a CAN, serial, network, debug, or storage transport.

## Layout

The loader accepts a directory whose root contains the conventionally named
manifest:

```text
acquisition/
  acquisition.json
  artifacts/
    firmware.bin
  captures/
    passive-can.log
  logs/
    transactions.jsonl
    collector.log
```

Artifact directories and names are not otherwise prescribed. Every artifact
used by 0verse must be declared by a canonical bundle-relative POSIX path in
`acquisition.json`. Undeclared support files are ignored rather than entering an
analysis lane implicitly.

## Python API

```python
from zeroverse.acquisition_bundle import load_acquisition_bundle

bundle = load_acquisition_bundle("./acquisition")
for item in bundle.analysis_artifacts():
    print(item.artifact.artifact_id, item.path, item.observed_sha256)
```

Verified analysis artifacts can next enter the deterministic
[firmware inspector](FIRMWARE-INSPECTION.md). That stage snapshots and rechecks
the artifact identity before deriving structure; bundle loading itself never
interprets firmware bytes.

`AcquisitionBundle.root` and `manifest_path` are absolute canonical paths. Artifact
paths are absolute, normalized beneath that root, and may intentionally be absent.
`AcquisitionBundle.artifacts` preserves manifest order. Validation itself runs in
path order so diagnostics are deterministic even when a producer reorders the
artifact array.

The dependency-free [Scout evidence producer and replay
boundary](FIRMWARE-SCOUT-EVIDENCE-REPLAY.md) creates this layout for passive CAN
observations. It publishes the manifest only after its raw capture, canonical
transaction log, and tool/session log have been sealed and hashed.

## State verification

The filesystem must agree with each manifest state:

| Manifest state | Required filesystem state |
|---|---|
| `present` + `recorded` | regular file matching the declared size and SHA-256; the claim remains `recorded` |
| `present` + `verified` | regular file matching both equal declared and observed identities |
| `present` + `modified` | regular file matching the explicitly recorded observed identity, which differs from the declaration |
| `missing` + `unavailable` | no object at the declared path |

Encrypted, encoded, virtual-read, calibration-only, partial, and unknown content
is hashed exactly as retained. Those dimensions describe interpretation and
coverage; they do not weaken byte-integrity checks. Missing, modified, recorded,
and encrypted firmware remains excluded from `analysis_artifacts()`.

## Fail-closed checks

The loader rejects a non-directory or symlink bundle root, an invalid or symlink
manifest, symlinks in any artifact path component, non-regular artifacts,
hard-link aliases between declared artifacts, present/missing contradictions, and
size or digest drift. Files are opened without following the final symlink where
the platform supports it, hashed in bounded chunks, and checked for inode or
metadata changes before and after reading.

Failures raise `AcquisitionBundleValidationError`. Its `issues` tuple is sorted
and each `BundleValidationIssue` carries a stable `code`, a bundle-relative
artifact or manifest `path`, optional `artifact_id`, and actionable detail. A root
failure retains the requested root path. Callers should branch on `code` rather
than parsing prose. Multiple independent artifact failures are reported in one
exception.

The committed fixtures under
`tests/fixtures/acquisition-bundles/v1/` contain no real device data. The positive
fixture covers firmware, captures, transaction logs, tool logs, and all explicit
artifact outcome states. The negative fixtures retain schema-valid manifests but
contradict one filesystem property each.

# Firmware Scout safety and acquisition contract

Status: **Accepted for R0**, 2026-07-17.

This record defines the boundary between live-device acquisition and 0verse's
offline analysis pipeline. It applies to ECUs and to other embedded targets.
Device-specific profiles may narrow this policy; they cannot silently weaken it.

## Decision

Firmware Scout is passive by default. In this project, **passive means zero
transmission**: no CAN frame, ISO-TP message, diagnostic request, serial command,
debug-port operation, wake-up pattern, or keepalive is sent. Opening an interface
for receive-only capture is not permission to transmit through it.

The stable handoff is
[`AcquisitionManifest` v1](../schemas/acquisition-manifest-v1.schema.json), parsed
by the dependency-free [`zeroverse.acquisition`](../src/zeroverse/acquisition.py)
module. A producer records observations and artifacts in the manifest; the
hardware-free [`zeroverse.acquisition_bundle`](../src/zeroverse/acquisition_bundle.py)
loader then verifies retained paths, sizes, and hashes before offline analysis
consumes them. Verified bytes may then enter the dependency-free
[`zeroverse.firmware_inspection`](../src/zeroverse/firmware_inspection.py) module,
which emits bounded observations and explicit inferences without unpacking,
execution, or mutation. Passive event producers can use the dependency-free
[`zeroverse.scout_evidence`](../src/zeroverse/scout_evidence.py) module to append,
seal, and replay byte-bound observations through a pure consumer interface. None
of these modules imports a CAN, ISO-TP, serial, JTAG/SWD, or vendor-flashing
implementation.

An acquisition manifest is evidence, not authority. Its transport mode,
ownership statement, or authorization basis describes provenance and cannot
enable a transport, service, session, or security algorithm. Authorization and
the future outbound safety governor are separate gates.

`DeviceProfile` v1 is inert, sourced target metadata: its facts never grant
permission or configure an interface. A declared fact's `observed_at` records
when its source recorded that declaration, not a physical target observation.
A future #77 safety policy is the sole outbound authorization owner; sharing a
`profile_id` cannot promote profile knowledge into permission.

## Operating modes

| Mode | Meaning | Transmission |
|---|---|---:|
| `offline` | Inspect an existing file or replay retained evidence | forbidden |
| `passive` | Observe a live interface without requesting responses | forbidden |
| `active-read` | Send an allowlisted, non-mutating request under a target profile | future, separately authorized |
| `active-write` | Perform a state-changing operation | unsupported by the current Scout roadmap |

The manifest can describe an artifact produced elsewhere with an active mode.
That representation does not make an active adapter available in 0verse. Runtime
code must reject `offline` or `passive` evidence that claims transmitted frames.

## Prohibited activity

All outbound diagnostic services are prohibited in `offline` and `passive` mode,
including nominally read-only requests such as ReadDataByIdentifier, ReadDTCInformation,
ReadMemoryByAddress, and RequestUpload. TesterPresent and DiagnosticSessionControl
are also transmissions and may maintain or change ECU state, so they are not
passive operations.

The following service classes remain denied by default in every future active
profile unless a separately reviewed policy explicitly permits the exact target,
session, service, subfunction, limits, and recovery behavior:

- reset, clear-DTC, communication-control, and DTC-setting operations;
- SecurityAccess attempts, seed/key guessing, brute force, or lockout probing;
- data-identifier, memory, configuration, coding, or calibration writes;
- input/output and actuator control;
- routine control;
- download, upload, transfer-data, or transfer-exit workflows;
- session changes, keepalives, raw frame injection, malformed-request fuzzing,
  broadcast requests, and unbounded address scans.

An eventual `active-read` mode may admit a small identification or DTC-read
allowlist only after issue `#77` provides a centralized fail-closed governor.
No plugin or transport may bypass that governor. Loss of communication,
unexpected reset, changing response identity, exhausted retry budget, or an
unknown policy decision must stop transmission rather than retry optimistically.

## Evidence rules

`AcquisitionManifest` separates facts that must not be collapsed into one status:

| Dimension | Values | Purpose |
|---|---|---|
| availability | `present`, `missing` | whether the bundle contains the path |
| integrity | `recorded`, `verified`, `modified`, `unavailable` | whether observed size/hash match the declaration |
| content | `plaintext`, `encoded`, `encrypted`, `unknown` | whether firmware bytes are directly interpretable |
| coverage | `full`, `partial`, `virtual-read`, `calibration-only`, `not-applicable`, `unknown` | what the bytes actually cover |

Every present artifact has a declared size and lowercase SHA-256. Verification
records a second observed size and digest; `modified` evidence must identify a
real mismatch. Missing, modified, unverified, and encrypted firmware artifacts
remain visible but cannot enter the offline firmware-analysis projection.

Region-to-artifact references are reciprocal and bounded by the declared artifact
size. Addresses and roles may be declared, observed, inferred, or unknown. An
inference remains an inference; parsing a manifest cannot promote it to an
observation.

Private manifests may contain VINs, serials, operator names, locations, or network
identifiers only when the redaction record says sensitive values remain. Exported
reports should replace or remove direct identifiers by default and record each
transformation with a JSON Pointer. Raw hashes of low-entropy identifiers are not
assumed anonymous.

## Compatibility

The v1 discriminator is exactly `0verse.acquisition-manifest/v1`. Producers must
emit it; consumers must reject missing or unknown versions rather than guessing.

V1 is a closed core schema: every field is explicit, unknown fields are rejected,
and unknown enum values are rejected. Adding or removing a field, changing null
semantics, adding an enum value, relaxing a safety invariant, or changing the
meaning of an existing value requires a new manifest version and an explicit
migration. A v1 implementation may receive documentation corrections or a parser
fix that makes the Python model and published schema enforce the same existing
rule; it may not silently reinterpret valid v1 evidence.

Bundle paths are canonical relative POSIX paths, timestamps are RFC 3339 with an
explicit offset, addresses and sizes are non-negative JSON integers, and digests
are lowercase SHA-256. Object key order has no meaning. Array order is preserved
for reproducible round trips, while IDs and cross-references define identity.

The manifest does not contain its own digest because a self-hash is recursive.
The containing acquisition bundle, transaction log, or external receipt must hash
the serialized manifest when chain-of-custody binding is required.

## Consequences

- Core 0verse and offline analysis remain hardware-free and dependency-free.
- Live adapters can evolve independently but must emit the same evidence contract.
- A manifest can honestly represent incomplete or unsuccessful acquisition.
- No active ECU discovery or firmware read is implemented or authorized by R0.
- Bundle verification is an offline consumer of this contract. #78's optional
  SocketCAN adapter is library-only, receive-only, and classical-CAN-only; it
  remains non-operational until hardware-gated acceptance on an authorized Linux
  interface. Hardware-free evidence replay uses the same zero-transmission rule
  and cannot open an interface.
- Firmware inspection can derive candidate regions, but confidence and evidence
  remain in its report and projected manifest regions retain an `inferred` basis.

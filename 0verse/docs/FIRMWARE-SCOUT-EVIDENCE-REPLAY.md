# Firmware Scout evidence logging and replay

Issue `#76` provides the hardware-free producer and replay boundary. Its
implementation, [`zeroverse.scout_evidence`](../src/zeroverse/scout_evidence.py),
imports no CAN, ISO-TP, serial, or vendor adapter and exposes no send operation.
Issue `#78` adds its separate optional receive-only SocketCAN adapter.

## Passive workflow

```text
adapter or virtual ECU
        |
        | ScoutEvent observations only
        v
ScoutEvidenceSession
        |-- captures/passive-can.scoutcap
        |-- logs/transactions.jsonl
        |-- logs/session.json
        `-- acquisition.json (published last)
                         |
                         v
              load_acquisition_bundle
                         |
                         v
              replay_scout_bundle
                         |
                         v
           ScoutObservationConsumer
```

The consumer protocol is the seam for the discovery and identification logic in
issue `#75`. A live adapter can append an observation and pass the returned
`ScoutEvent` to a consumer. Offline replay delivers the same immutable event only
after the complete bundle, transaction log, raw capture, and session log agree.
Neither path grants transport authority.

## Session lifecycle

`ScoutEvidenceSession` requires a new output directory. It creates the capture
and transaction files with exclusive-create and append-only file descriptors.
Every event append is flushed before the method returns. Event sequence numbers,
capture indexes, and timestamps must be monotonic.

`seal(completed_at=...)` closes the append streams, writes a canonical session
log, computes SHA-256 and size for all three artifacts, constructs an
`AcquisitionManifest` v1 with `mode=passive` and `transmitted=false`, and publishes
`acquisition.json` last. It then marks the retained files read-only and reloads
the directory through the ordinary bundle validator. The manifest provenance
records the exact collector name and version, and the session log independently
binds that version to the format versions and event counts. File contents are
flushed on every supported platform; parent-directory metadata is also flushed
where the operating system exposes directory descriptors.

An aborted or failed session retains partial bytes for operator inspection but
does not publish a manifest. A sealed session cannot be reopened or appended by
the API. Read-only mode is an accidental-mutation barrier, not a cryptographic
claim; use an external signed receipt when custody must survive a malicious
filesystem owner.

## Structured event contract

Each line of `logs/transactions.jsonl` is canonical JSON conforming to
[`scout-event-v1.schema.json`](../schemas/scout-event-v1.schema.json). V1 is a
closed contract with the discriminator `0verse.scout-event/v1`.

| Kind | Meaning | Raw capture record |
|---|---|---:|
| `frame` | A decoded classical CAN or CAN FD observation | yes |
| `malformed-frame` | Retained bytes that violated decoding or length expectations | yes |
| `timeout` | A bounded receive interval ended without an observation | no |
| `reset` | A reset discontinuity was observed by the producer or fixture | no |
| `capture-error` | The receive path reported a non-frame error | no |

Normal frames retain the arbitration ID, 11/29-bit form, remote/error flags,
declared length, and up to 64 payload bytes. Malformed observations retain up to
4096 raw bytes, optional decoded CAN identity, the declared length when known,
and a required explanation. The transaction log records observations, not
requests; it contains no instruction that replay could transmit.

## Raw capture format

`captures/passive-can.scoutcap` is a byte-preserving companion to the structured
log. It starts with the literal header `0VERSE-SCOUT-CAPTURE\0v1\n`. Every normal
or malformed frame then has this big-endian record header followed by its raw
payload:

| Field | Width | Meaning |
|---|---:|---|
| record kind | 1 byte | `1` normal frame, `2` malformed frame |
| capture index | 8 bytes | contiguous raw-record index |
| event sequence | 8 bytes | corresponding transaction event |
| timestamp | 8 bytes | monotonic nanoseconds supplied by the producer |
| arbitration ID | 4 bytes | CAN ID, or `0xffffffff` when undecodable |
| flags | 1 byte | bit 7 ID present; bits 0/1/2 extended, remote, error |
| declared length | 2 bytes | producer-observed length, or `0xffff` when unknown |
| retained length | 2 bytes | following payload byte count |

The binary stream intentionally duplicates identity carried by the transaction
event. Replay regenerates the canonical capture from verified events and requires
byte-for-byte equality, so a log cannot be paired with a different raw capture.

## Replay validation

`replay_scout_bundle(path, consumer)` first runs the acquisition bundle validator,
then requires one referenced Scout capture, one evidence transaction log, one
evidence session log, verified artifact identities, and a non-transmitting CAN
transport. It rejects duplicate JSON keys, non-canonical lines, sequence or time
gaps, capture mismatches, tool/session drift, and configured resource-limit
violations. No event reaches the consumer until all these checks pass.

Default replay bounds are 500,000 events, 64 MiB of transaction data, 128 MiB of
capture data, and 64 KiB for the session log. Callers may pass an explicit
`ScoutReplayLimits` for a larger retained session; memory use scales with the
validated evidence size.

## Virtual ECU

`VirtualCanEcu.standard_fixture()` is an in-memory, deterministic bus trace. It
covers normal response-looking frames, a receive timeout, a malformed length,
an observed reset, and a post-reset frame. Its `transmitted_frames` value is
always zero and it has no request or send method. CI runs the complete virtual
capture, manifest, bundle-validation, and replay-consumer path without hardware.

This fixture is infrastructure validation, not a Delphi MT05.3 model and not
proof of compatibility with any physical ECU. Issue `#78` implements the
separately reviewed receive-only SocketCAN adapter, but hardware validation
remains gated on an authorized Linux interface. ISO-TP reassembly, UDS discovery,
and active identification requests remain outside this issue.

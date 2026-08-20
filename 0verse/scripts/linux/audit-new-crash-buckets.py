#!/usr/bin/env python3
"""Detect new or retitled syzkaller crash buckets across active workdirs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

FRAME_WITH_OFFSET = re.compile(r"^([A-Za-z_][A-Za-z0-9_.$]*)\+0x[0-9a-f]+/")
FRAME_WITH_SOURCE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.$]*)\s+[^ ]*/[^ ]+")
DIAGNOSTIC_KIND = re.compile(r"\b(KASAN|KMSAN|UBSAN|WARNING|INFO|Oops|BUG)\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="atomically snapshot NEW/RETITLED buckets before acknowledging them",
    )
    parser.add_argument("workdirs", nargs="+", type=Path)
    return parser.parse_args()


def snapshot(workdirs: list[Path]) -> dict[str, str]:
    buckets: dict[str, str] = {}
    for workdir in workdirs:
        for description in sorted((workdir / "crashes").glob("*/description")):
            bucket = str(description.parent)
            buckets[bucket] = " ".join(
                description.read_text(encoding="utf-8", errors="replace").split()
            )
    return buckets


def crash_fingerprint(bucket: Path, description: str) -> str:
    """Hash diagnostic kind plus the primary kernel call trace, not its title."""
    reports = sorted(bucket.glob("report*"))
    report = ""
    for candidate in reports:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        report = candidate.read_text(encoding="utf-8", errors="replace")
        if report:
            break

    kind_match = DIAGNOSTIC_KIND.search(report)
    kind = kind_match.group(1) if kind_match else description.split(":", 1)[0]
    frames: list[str] = []
    in_trace = False
    for raw_line in report.splitlines():
        line = raw_line.strip()
        if line == "Call Trace:":
            in_trace = True
            continue
        if not in_trace:
            continue
        if line in {"<TASK>", "<IRQ>", "<NMI>"}:
            continue
        if line in {"</TASK>", "</IRQ>", "</NMI>"}:
            if frames:
                break
            continue
        match = FRAME_WITH_OFFSET.match(line) or FRAME_WITH_SOURCE.match(line)
        if match:
            frames.append(match.group(1))
            if len(frames) == 24:
                break

    if frames:
        material = f"stack-v1\n{kind}\n" + "\n".join(frames)
        return f"stack-v1:{hashlib.sha256(material.encode()).hexdigest()}"

    fallback = re.sub(r"0x[0-9a-fA-F]+|\b\d+\b", "#", report[:4096])
    fallback = " ".join(fallback.split()) or description
    material = f"text-v1\n{kind}\n{fallback}"
    return f"text-v1:{hashlib.sha256(material.encode()).hexdigest()}"


def prior_snapshot_for_fingerprint(evidence_dir: Path, fingerprint: str) -> str | None:
    if not evidence_dir.exists():
        return None
    for prior in sorted(evidence_dir.iterdir()):
        if prior.is_symlink() or not prior.is_dir():
            continue
        event_path = prior / "EVENT.json"
        if not event_path.is_file() or event_path.is_symlink():
            continue
        event = json.loads(event_path.read_text(encoding="utf-8"))
        if not isinstance(event, dict):
            raise ValueError(f"malformed EVENT.json: {event_path}")
        if event.get("fingerprint") == fingerprint:
            return prior.name
        description = event.get("description")
        if isinstance(description, str):
            derived = crash_fingerprint(prior, description)
            if derived == fingerprint:
                return prior.name
    return None


def write_state(path: Path, state: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(state, output, indent=2, sort_keys=True)
            output.write("\n")
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def snapshot_event(
    evidence_dir: Path,
    event: str,
    bucket: Path,
    description: str,
) -> Path:
    revision = hashlib.sha256(description.encode()).hexdigest()[:12]
    destination = evidence_dir / f"{bucket.parent.parent.name}--{bucket.name}--{revision}"
    if destination.exists():
        verify_snapshot(destination)
        return destination

    evidence_dir.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=evidence_dir))
    try:
        for source in sorted(bucket.rglob("*")):
            relative = source.relative_to(bucket)
            target = temporary / relative
            if source.is_symlink():
                raise ValueError(f"refusing symlink in crash bucket: {source}")
            if source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif source.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            else:
                raise ValueError(f"refusing non-regular crash artifact: {source}")

        fingerprint = crash_fingerprint(bucket, description)
        duplicate_of = prior_snapshot_for_fingerprint(evidence_dir, fingerprint)
        event_record = {
            "captured_at": datetime.now(UTC).isoformat(),
            "description": description,
            "event": event,
            "fingerprint": fingerprint,
            "source_bucket": str(bucket),
        }
        if duplicate_of is not None:
            event_record["duplicate_of"] = duplicate_of
        (temporary / "EVENT.json").write_text(
            json.dumps(event_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        sums = []
        for artifact in sorted(temporary.rglob("*")):
            if artifact.is_file() and artifact.name != "SHA256SUMS":
                digest = file_digest(artifact)
                sums.append(f"{digest}  {artifact.relative_to(temporary)}")
        (temporary / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
        temporary.replace(destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return destination


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_snapshot(snapshot: Path) -> None:
    manifest = snapshot / "SHA256SUMS"
    if not manifest.is_file() or manifest.is_symlink():
        raise ValueError(f"missing safe SHA256SUMS: {snapshot}")

    expected: dict[Path, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        relative = Path(name)
        if (
            not separator
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or relative.is_absolute()
            or ".." in relative.parts
            or relative == Path("SHA256SUMS")
        ):
            raise ValueError(f"unsafe manifest entry in {manifest}: {line!r}")
        expected[relative] = digest

    actual: set[Path] = set()
    for artifact in sorted(snapshot.rglob("*")):
        if artifact.is_symlink():
            raise ValueError(f"refusing symlink in evidence snapshot: {artifact}")
        if artifact.is_file() and artifact != manifest:
            relative = artifact.relative_to(snapshot)
            actual.add(relative)
            if relative not in expected:
                continue
            if expected[relative] != file_digest(artifact):
                raise ValueError(f"evidence hash mismatch: {artifact}")
    if actual != set(expected):
        raise ValueError(f"evidence manifest/file set mismatch: {snapshot}")
    if Path("EVENT.json") not in actual:
        raise ValueError(f"snapshot lacks EVENT.json: {snapshot}")
    event_path = snapshot / "EVENT.json"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise ValueError(f"malformed EVENT.json: {event_path}")
    for field in ("captured_at", "description", "event", "source_bucket"):
        if not isinstance(event.get(field), str) or not event[field]:
            raise ValueError(f"malformed EVENT.json field {field}: {event_path}")
    fingerprint = event.get("fingerprint")
    if fingerprint is not None and (
        not isinstance(fingerprint, str)
        or not re.fullmatch(r"(?:stack|text)-v1:[0-9a-f]{64}", fingerprint)
    ):
        raise ValueError(f"malformed EVENT.json fingerprint: {event_path}")
    duplicate_of = event.get("duplicate_of")
    if duplicate_of is not None and (
        not isinstance(duplicate_of, str)
        or not duplicate_of
        or Path(duplicate_of).name != duplicate_of
    ):
        raise ValueError(f"malformed EVENT.json duplicate_of: {event_path}")


def verify_evidence_dir(evidence_dir: Path) -> None:
    if not evidence_dir.exists():
        return
    for snapshot in sorted(evidence_dir.iterdir()):
        if snapshot.is_symlink() or not snapshot.is_dir():
            raise ValueError(f"unexpected evidence-inbox entry: {snapshot}")
        verify_snapshot(snapshot)


def main() -> int:
    args = parse_args()
    if args.evidence_dir:
        verify_evidence_dir(args.evidence_dir)
    current = snapshot(args.workdirs)
    if not args.state.exists():
        write_state(args.state, current)
        print(f"BASELINE buckets={len(current)} state={args.state}")
        return 0

    previous = json.loads(args.state.read_text(encoding="utf-8"))
    events: list[tuple[str, str, str | None]] = []
    for bucket, description in current.items():
        if bucket not in previous:
            events.append(("NEW", bucket, description))
        elif previous[bucket] != description:
            events.append(("RETITLED", bucket, description))

    if args.evidence_dir:
        for event, bucket, description in events:
            destination = snapshot_event(
                args.evidence_dir,
                event,
                Path(bucket),
                description or "",
            )
            print(f"SNAPSHOT {destination}")

    write_state(args.state, current)
    if not events:
        print(f"OK buckets={len(current)}")
        return 0
    for event, bucket, description in events:
        print(f"{event} {bucket}: {description}")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        sys.exit(2)

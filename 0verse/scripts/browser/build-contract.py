#!/usr/bin/env python3
"""Create and verify canonical Chromium libFuzzer build contracts."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

CATALOG_SCHEMA = "0verse.chromium-libfuzzer-target-catalog/v1"
RECEIPT_SCHEMA = "0verse.chromium-libfuzzer-build-receipt/v1"
FUZZ_TARGET_MARKER = "//testing/libfuzzer:is_a_fuzz_target"
HEX = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
LABEL = re.compile(r"//[A-Za-z0-9_./+-]+:[A-Za-z0-9_.+-]+")


def canonical_bytes(value: object) -> bytes:
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return f"{text}\n".encode()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_regular_bytes(path: Path, *, limit: int = 64 * 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError(f"contract is not a bounded regular file: {path}")
        data = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError(f"contract exceeds its size limit: {path}")
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity or len(data) != after.st_size:
            raise ValueError(f"contract changed while it was read: {path}")
        return bytes(data)
    finally:
        os.close(descriptor)


def stable_executable(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o111 == 0:
            raise ValueError("catalog artifact is not a regular executable")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if before_identity != after_identity or size != after.st_size:
            raise ValueError("catalog artifact changed while it was hashed")
        return size, digest.hexdigest()
    finally:
        os.close(descriptor)


def load_canonical(path: Path, schema: str, expected_sha256: str = "") -> dict[str, Any]:
    data = stable_regular_bytes(path)
    if expected_sha256 and hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError(f"contract SHA-256 mismatch: {path}")
    raw = json.loads(data)
    if not isinstance(raw, dict) or raw.get("schema_version") != schema:
        raise ValueError(f"unsupported contract in {path}")
    if data != canonical_bytes(raw):
        raise ValueError(f"contract is not canonical JSON: {path}")
    return raw


def publish(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(canonical_bytes(value))
            output.flush()
            os.fsync(output.fileno())
        temporary_path = Path(temporary)
        temporary_path.chmod(0o640)
        temporary_path.replace(path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            Path(temporary).unlink()


def run(argv: list[str], *, cwd: Path) -> str:
    # Callers construct argv as an argument vector for fixed git/gn/clang
    # executables; shell interpretation is never enabled.
    result = subprocess.run(  # foxguard: ignore[py/no-command-injection]
        argv, cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise ValueError(f"command failed ({' '.join(argv)}): {result.stderr.strip()}")
    return result.stdout


def revision(source: Path) -> str:
    value = run(["git", "rev-parse", "HEAD"], cwd=source).strip().lower()
    if not REVISION.fullmatch(value):
        raise ValueError("Chromium checkout did not produce a full revision")
    if run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source).strip():
        raise ValueError("Chromium checkout has tracked modifications")
    return value


def read_gn_args(args_file: Path) -> tuple[str, str]:
    data = stable_regular_bytes(args_file, limit=1024 * 1024)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("GN args.gn is not UTF-8") from exc
    return text, hashlib.sha256(data).hexdigest()


def require_boolean_gn_arg(args_text: str, name: str, expected: bool = True) -> None:
    assignments = re.findall(
        rf"(?m)^\s*{re.escape(name)}\s*=\s*(true|false)\s*$",
        args_text,
    )
    wanted = "true" if expected else "false"
    if assignments != [wanted]:
        raise ValueError(f"GN arguments must set {name}={wanted} exactly once")



def require_integer_gn_arg(args_text: str, name: str, expected: int) -> None:
    assignments = re.findall(
        rf"(?m)^\s*{re.escape(name)}\s*=\s*(-?\d+)\s*$",
        args_text,
    )
    if assignments != [str(expected)]:
        raise ValueError(f"GN arguments must set {name}={expected} exactly once")

def require_sanitizer_gn_args(args_text: str, sanitizer: str) -> None:
    if sanitizer not in {"asan", "msan"}:
        raise ValueError("unsupported Chromium sanitizer")
    require_boolean_gn_arg(args_text, f"is_{sanitizer}")
    if sanitizer == "msan":
        require_boolean_gn_arg(args_text, "use_prebuilt_instrumented_libraries")
        require_integer_gn_arg(args_text, "msan_track_origins", 2)
    for other in {"asan", "msan", "ubsan"} - {sanitizer}:
        assignments = re.findall(
            rf"(?m)^\s*is_{other}\s*=\s*(true|false)\s*$",
            args_text,
        )
        if "true" in assignments or len(assignments) > 1:
            raise ValueError(f"GN arguments contradict sanitizer={sanitizer}")


def relative_output(value: str, out_relative: PurePosixPath) -> str:
    output = PurePosixPath(value)
    if not value.startswith("//"):
        if output.is_absolute() or not output.parts or ".." in output.parts:
            raise ValueError(f"unsafe GN output: {value}")
        return str(output)
    output = PurePosixPath(value[2:])
    try:
        relative = output.relative_to(out_relative)
    except ValueError as exc:
        raise ValueError(f"GN output is outside {out_relative}: {value}") from exc
    if not relative.parts or ".." in relative.parts:
        raise ValueError(f"unsafe GN output: {value}")
    return str(relative)


def create_catalog(source: Path, out: Path, output: Path) -> None:
    source = source.resolve(strict=True)
    out = out.resolve(strict=True)
    try:
        out_relative = PurePosixPath(out.relative_to(source).as_posix())
    except ValueError as exc:
        raise ValueError("GN output directory must be inside the Chromium checkout") from exc
    args_file = out / "args.gn"
    if not args_file.is_file():
        raise ValueError("GN args.gn is missing")
    args_text, args_digest = read_gn_args(args_file)
    require_boolean_gn_arg(args_text, "use_libfuzzer")
    refs_argv = [
        "gn",
        "refs",
        str(out_relative),
        FUZZ_TARGET_MARKER,
        "--all",
        "--default-toolchain",
        "--type=executable",
        "--testonly=true",
    ]
    labels = sorted({line.strip() for line in run(refs_argv, cwd=source).splitlines() if line.strip()})
    if not labels or any(not LABEL.fullmatch(label) for label in labels):
        raise ValueError("GN did not return canonical libFuzzer target labels")
    entries: list[dict[str, str]] = []
    artifacts: set[str] = set()
    for label in labels:
        values = run(["gn", "outputs", str(out_relative), label], cwd=source).splitlines()
        if len(values) != 1:
            raise ValueError(f"libFuzzer target must have exactly one executable output: {label}")
        artifact = relative_output(values[0], out_relative)
        if artifact in artifacts:
            raise ValueError(f"duplicate libFuzzer artifact output: {artifact}")
        artifacts.add(artifact)
        entries.append(
            {
                "artifact_relative_to_out": artifact,
                "classification": "fuzz-target-candidate",
                "gn_label": label,
            }
        )
    raw = {
        "schema_version": CATALOG_SCHEMA,
        "revision": revision(source),
        "engine_configuration": "use_libfuzzer=true",
        "discovery_marker": FUZZ_TARGET_MARKER,
        "discovery_scope": (
            "GN test-only executables with a reverse dependency path to is_a_fuzz_target"
        ),
        "gn_args_sha256": args_digest,
        "targets": entries,
    }
    publish(output, raw)


def entry(catalog: dict[str, Any], label: str) -> dict[str, str]:
    targets = catalog.get("targets")
    if not isinstance(targets, list):
        raise ValueError("target catalog has no target list")
    matches = [item for item in targets if isinstance(item, dict) and item.get("gn_label") == label]
    if len(matches) != 1:
        raise ValueError("target label does not identify exactly one catalog entry")
    item = matches[0]
    artifact = item.get("artifact_relative_to_out")
    if (
        not isinstance(artifact, str)
        or not artifact
        or PurePosixPath(artifact).is_absolute()
        or ".." in PurePosixPath(artifact).parts
    ):
        raise ValueError("catalog entry has an unsafe artifact path")
    if item.get("classification") != "fuzz-target-candidate":
        raise ValueError("catalog entry has an unsupported classification")
    return {
        "artifact_relative_to_out": artifact,
        "classification": "fuzz-target-candidate",
        "gn_label": label,
    }


def create_receipt(
    source: Path, out: Path, catalog_path: Path, label: str, sanitizer: str, output: Path
) -> None:
    catalog = load_canonical(catalog_path, CATALOG_SCHEMA)
    selected = entry(catalog, label)
    current_revision = revision(source)
    if catalog.get("revision") != current_revision:
        raise ValueError("target catalog revision does not match the checkout")
    args_file = out / "args.gn"
    args_text, args_digest = read_gn_args(args_file)
    if catalog.get("gn_args_sha256") != args_digest:
        raise ValueError("target catalog GN arguments do not match the build directory")
    require_sanitizer_gn_args(args_text, sanitizer)
    require_integer_gn_arg(args_text, "symbol_level", 2)
    artifact_path = out / selected["artifact_relative_to_out"]
    artifact = artifact_path.resolve(strict=True)
    try:
        artifact.relative_to(out.resolve(strict=True))
    except ValueError as exc:
        raise ValueError("catalog artifact resolves outside the build directory") from exc
    if artifact_path.is_symlink() or not artifact.is_file() or not os.access(artifact, os.X_OK):
        raise ValueError("catalog artifact is missing or not executable")
    artifact_size, artifact_sha256 = stable_executable(artifact)
    raw = {
        "schema_version": RECEIPT_SCHEMA,
        "revision": current_revision,
        "engine_configuration": "use_libfuzzer=true",
        "sanitizer": sanitizer,
        "gn_label": label,
        "artifact": str(artifact),
        "artifact_relative_to_out": selected["artifact_relative_to_out"],
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "catalog_sha256": sha256(catalog_path),
        "catalog_entry_sha256": hashlib.sha256(canonical_bytes(selected)).hexdigest(),
        "gn_args_sha256": args_digest,
        "compiler": run(["clang", "--version"], cwd=source).splitlines()[0],
        "built_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claim": (
            "exact worker-observed executable built under Chromium use_libfuzzer=true; "
            "interface family not inferred; no FuzzTest or LPM claim"
        ),
    }
    publish(output, raw)


def verify_binding(
    receipt_path: Path,
    receipt_digest: str,
    catalog_path: Path,
    catalog_digest: str,
    expected_revision: str,
    expected_label: str,
    expected_artifact: Path,
    expected_artifact_digest: str,
    expected_sanitizer: str,
) -> None:
    if not HEX.fullmatch(receipt_digest):
        raise ValueError("build receipt SHA-256 mismatch")
    if not HEX.fullmatch(catalog_digest):
        raise ValueError("target catalog SHA-256 mismatch")
    receipt = load_canonical(receipt_path, RECEIPT_SCHEMA, receipt_digest)
    catalog = load_canonical(catalog_path, CATALOG_SCHEMA, catalog_digest)
    selected = entry(catalog, expected_label)
    selected_digest = hashlib.sha256(canonical_bytes(selected)).hexdigest()
    artifact_size, artifact_digest = stable_executable(expected_artifact)
    bindings = (
        receipt.get("revision") == expected_revision == catalog.get("revision"),
        receipt.get("engine_configuration")
        == catalog.get("engine_configuration")
        == "use_libfuzzer=true",
        receipt.get("gn_label") == expected_label,
        receipt.get("artifact") == str(expected_artifact),
        receipt.get("artifact_relative_to_out") == selected["artifact_relative_to_out"],
        receipt.get("artifact_sha256") == expected_artifact_digest,
        receipt.get("artifact_size") == artifact_size,
        receipt.get("catalog_sha256") == catalog_digest,
        receipt.get("catalog_entry_sha256") == selected_digest,
        receipt.get("gn_args_sha256") == catalog.get("gn_args_sha256"),
        receipt.get("sanitizer") == expected_sanitizer,
    )
    if (
        expected_artifact.is_symlink()
        or not expected_artifact.is_file()
        or not os.access(expected_artifact, os.X_OK)
        or artifact_digest != expected_artifact_digest
        or not all(bindings)
    ):
        raise ValueError("build receipt is not bound to the exact catalog entry")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    catalog = commands.add_parser("catalog")
    for name in ("source", "out", "output"):
        catalog.add_argument(f"--{name}", type=Path, required=True)
    select = commands.add_parser("select")
    select.add_argument("--catalog", type=Path, required=True)
    select.add_argument("--label", required=True)
    receipt = commands.add_parser("receipt")
    for name in ("source", "out", "catalog", "output"):
        receipt.add_argument(f"--{name}", type=Path, required=True)
    receipt.add_argument("--label", required=True)
    receipt.add_argument("--sanitizer", choices=("asan", "msan"), required=True)
    verify = commands.add_parser("verify")
    for name in ("receipt", "catalog", "artifact"):
        verify.add_argument(f"--{name}", type=Path, required=True)
    for name in ("receipt-sha256", "catalog-sha256", "revision", "label", "artifact-sha256"):
        verify.add_argument(f"--{name}", required=True)
    verify.add_argument("--sanitizer", choices=("asan", "msan"), required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "catalog":
            create_catalog(args.source, args.out, args.output)
        elif args.command == "select":
            selected = entry(load_canonical(args.catalog, CATALOG_SCHEMA), args.label)
            print(selected["artifact_relative_to_out"])
        elif args.command == "receipt":
            create_receipt(
                args.source, args.out, args.catalog, args.label, args.sanitizer, args.output
            )
        else:
            verify_binding(
                args.receipt,
                args.receipt_sha256,
                args.catalog,
                args.catalog_sha256,
                args.revision,
                args.label,
                args.artifact,
                args.artifact_sha256,
                args.sanitizer,
            )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

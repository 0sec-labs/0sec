"""Fail-closed acquisition receipts for Microsoft public symbol PDBs.

The Microsoft symbol route is keyed by the PE's RSDS GUID and age, but the
returned public PDB can be a stripped transformation with a different internal
age.  This module records both identities and never treats that transformation
as an exact PE/PDB age match.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path, PureWindowsPath
from typing import IO, Protocol
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

from .pe_symbols import pdb_codeview_identity, pe_codeview_identity

PUBLIC_PDB_SCHEMA = "0verse.windows-public-pdb-download/v1"
PUBLIC_PDB_PRODUCER = "zeroverse.windows-public-pdb-download/v1"
PUBLIC_PDB_PROOF_LIMIT = (
    "Acquisition evidence only. The PDB was returned for the PE-derived Microsoft "
    "symbol key and has the same GUID, but a stripped PDB age mismatch is recorded "
    "rather than accepted as exact identity. Microsoft authenticity, transformation "
    "semantics, private types, vulnerability status, and redistribution rights are unproven."
)
_PDB_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\.pdb", re.I)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_BLOB_HOST = re.compile(r"[a-z0-9-]+\.blob\.core\.windows\.net", re.I)
_PE_SIZE_CAP = 512 * 1024 * 1024
_PDB_SIZE_CAP = 2 * 1024 * 1024 * 1024
_RECEIPT_SIZE_CAP = 1024 * 1024


class _Response(Protocol):
    status: int
    headers: Mapping[str, str]

    def geturl(self) -> str: ...
    def read(self, size: int = -1) -> bytes: ...
    def __enter__(self) -> _Response: ...
    def __exit__(self, *args: object) -> object: ...


class _Opener(Protocol):
    def __call__(self, request: urllib.request.Request, *, timeout: float) -> _Response: ...


@dataclass(frozen=True)
class PublicPdbReceipt:
    bundle_path: Path
    artifact_path: Path
    artifact_sha256: str
    artifact_size_bytes: int
    receipt_sha256: str
    requested_url: str
    pe_guid: str
    pe_age: int
    pdb_guid: str
    pdb_age: int
    exact_age_match: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": str(self.bundle_path),
            "artifact_path": str(self.artifact_path),
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "receipt_sha256": self.receipt_sha256,
            "requested_url": self.requested_url,
            "pe_guid": self.pe_guid,
            "pe_age": self.pe_age,
            "pdb_guid": self.pdb_guid,
            "pdb_age": self.pdb_age,
            "exact_age_match": self.exact_age_match,
        }


class _SymbolRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Permit only the SAS-bearing Azure blob redirect selected by msdl."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        _blob_url(newurl, "symbol redirect URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_pdb_url(binary: str | Path) -> str:
    """Return the canonical Microsoft symbol URL derived only from PE CodeView."""
    with tempfile.TemporaryDirectory(prefix="zeroverse-public-pdb-key-") as temporary:
        snapshot = Path(temporary) / "source.pe"
        _snapshot_regular(Path(binary), snapshot, "public PDB source PE", _PE_SIZE_CAP)
        identity = pe_codeview_identity(snapshot)
    return _url_from_identity(identity)


def _url_from_identity(identity: tuple[str, int, str] | None) -> str:
    if identity is None:
        raise ValueError("public PDB acquisition requires a PE RSDS CodeView record")
    guid, age, recorded_name = identity
    name = PureWindowsPath(recorded_name).name
    if _PDB_NAME.fullmatch(name) is None:
        raise ValueError("PE CodeView PDB basename is not safe for a symbol request")
    key = guid.replace("-", "").upper() + format(age, "X")
    escaped = quote(name, safe="._-")
    return f"https://msdl.microsoft.com/download/symbols/{escaped}/{key}/{escaped}"


def download_public_pdb(
    binary: str | Path,
    store_root: str | Path,
    *,
    max_bytes: int = _PDB_SIZE_CAP,
    timeout_seconds: float = 120.0,
    opener: _Opener | None = None,
) -> PublicPdbReceipt:
    """Acquire the PE-keyed public PDB and retain a non-secret route receipt."""
    source_binary = Path(binary)
    root = Path(store_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("public PDB store root must be a regular non-symlink directory")
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes <= 0
        or max_bytes > _PDB_SIZE_CAP
    ):
        raise ValueError("max_bytes must be positive and within the PDB size cap")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    temporary = Path(tempfile.mkdtemp(prefix=".windows-public-pdb-", dir=root))
    source_snapshot = temporary / "source.pe"
    artifact = temporary / "artifact"
    try:
        pe_digest, pe_size = _snapshot_regular(
            source_binary, source_snapshot, "public PDB source PE", _PE_SIZE_CAP
        )
        pe_identity = pe_codeview_identity(source_snapshot)
        requested_url = _url_from_identity(pe_identity)
        if pe_identity is None:  # narrowed by _url_from_identity; keeps mypy explicit
            raise AssertionError("unreachable PE identity state")
        request = urllib.request.Request(
            requested_url, headers={"User-Agent": "0verse-windows-public-pdb/1"}
        )
        if opener is None:
            response_context = urllib.request.build_opener(_SymbolRedirectHandler()).open(
                request, timeout=timeout_seconds
            )
        else:
            response_context = opener(request, timeout=timeout_seconds)
        digest = hashlib.sha256()
        size = 0
        with response_context as response:
            final_url = response.geturl()
            redacted_url, query_digest = _safe_final_url(final_url, requested_url)
            if int(response.status) != 200:
                raise ValueError(f"public PDB download returned HTTP {response.status}")
            with artifact.open("xb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("public PDB exceeds max_bytes")
                    digest.update(chunk)
                    output.write(chunk)
            content_length = str(response.headers.get("Content-Length", ""))
            if content_length and int(content_length) != size:
                raise ValueError("public PDB Content-Length mismatch")
            headers = {
                "etag": str(response.headers.get("ETag", "")),
                "last_modified": str(response.headers.get("Last-Modified", "")),
                "content_type": str(response.headers.get("Content-Type", "")),
                "content_length": content_length,
            }
            if any("\x00" in value for value in headers.values()):
                raise ValueError("public PDB response header contains a NUL byte")
        pdb_identity = pdb_codeview_identity(artifact)
        if pdb_identity is None:
            raise ValueError("downloaded public PDB is not inspectable with llvm-pdbutil")
        if not pdb_identity[2]:
            raise ValueError("Microsoft public PDB lane requires a stripped PDB")
        if pdb_identity[0] != pe_identity[0]:
            raise ValueError("public PDB GUID does not match PE CodeView GUID")
        artifact_digest = digest.hexdigest()
        receipt = {
            "schema_version": PUBLIC_PDB_SCHEMA,
            "producer": PUBLIC_PDB_PRODUCER,
            "pe": {
                "sha256": pe_digest,
                "size_bytes": pe_size,
                "codeview": {
                    "guid": pe_identity[0],
                    "age": pe_identity[1],
                    "pdb_name": PureWindowsPath(pe_identity[2]).name,
                },
            },
            "pdb": {
                "path": "artifact",
                "sha256": artifact_digest,
                "size_bytes": size,
                "identity": {
                    "guid": pdb_identity[0],
                    "age": pdb_identity[1],
                    "stripped": True,
                },
            },
            "source": {
                "requested_url": requested_url,
                "final_url_redacted": redacted_url,
                "final_query_sha256": query_digest,
                "retrieved_at_utc": datetime.now(UTC).isoformat(),
                "http_status": 200,
                **headers,
            },
            "exact_age_match": pdb_identity[1] == pe_identity[1],
            "verified_claims": [
                "pe-derived-symbol-key",
                "producer-observed-microsoft-symbol-route",
                "pdb-content-sha256",
                "pdb-guid-match",
                "pdb-stripped",
            ],
            "proof_limit": PUBLIC_PDB_PROOF_LIMIT,
        }
        with (temporary / "receipt.json").open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
        source_snapshot.unlink()
        destination = root / artifact_digest
        if destination.exists():
            raise ValueError(
                "public PDB content is already retained; verify the existing bundle "
                "instead of replacing its acquisition receipt"
            )
        temporary.rename(destination)
        receipt_path = destination / "receipt.json"
        return PublicPdbReceipt(
            destination.resolve(),
            (destination / "artifact").resolve(),
            artifact_digest,
            size,
            hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            requested_url,
            pe_identity[0],
            pe_identity[1],
            pdb_identity[0],
            pdb_identity[1],
            pdb_identity[1] == pe_identity[1],
        )
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_public_pdb_receipt(binary: str | Path, bundle_path: str | Path) -> PublicPdbReceipt:
    """Reparse both identities and verify a retained public-PDB route receipt."""
    source_binary = Path(binary)
    bundle = Path(bundle_path)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("public PDB bundle must be a regular non-symlink directory")
    if {path.name for path in bundle.iterdir()} != {"artifact", "receipt.json"}:
        raise ValueError("public PDB bundle must contain exactly artifact and receipt.json")
    artifact, receipt_path = bundle / "artifact", bundle / "receipt.json"
    with tempfile.TemporaryDirectory(prefix="zeroverse-public-pdb-verify-") as temporary:
        private = Path(temporary)
        pe_copy = private / "source.pe"
        pdb_copy = private / "artifact.pdb"
        receipt_copy = private / "receipt.json"
        pe_digest, pe_size = _snapshot_regular(
            source_binary, pe_copy, "public PDB source PE", _PE_SIZE_CAP
        )
        pdb_digest, pdb_size = _snapshot_regular(
            artifact, pdb_copy, "public PDB artifact", _PDB_SIZE_CAP
        )
        receipt_digest, _ = _snapshot_regular(
            receipt_path, receipt_copy, "public PDB receipt", _RECEIPT_SIZE_CAP
        )
        pe_identity = pe_codeview_identity(pe_copy)
        pdb_identity = pdb_codeview_identity(pdb_copy)
        receipt_bytes = receipt_copy.read_bytes()
    if pe_identity is None or pdb_identity is None:
        raise ValueError("public PDB receipt requires inspectable PE and PDB identities")
    raw = json.loads(receipt_bytes, object_pairs_hook=_unique)
    receipt = _object(raw, "receipt")
    _exact(
        receipt,
        {
            "schema_version",
            "producer",
            "pe",
            "pdb",
            "source",
            "exact_age_match",
            "verified_claims",
            "proof_limit",
        },
        "receipt",
    )
    if receipt["schema_version"] != PUBLIC_PDB_SCHEMA or receipt["producer"] != PUBLIC_PDB_PRODUCER:
        raise ValueError("public PDB receipt schema/producer mismatch")
    pe = _object(receipt["pe"], "pe")
    _exact(pe, {"sha256", "size_bytes", "codeview"}, "pe")
    codeview = _object(pe["codeview"], "pe.codeview")
    _exact(codeview, {"guid", "age", "pdb_name"}, "pe.codeview")
    expected_pe = {
        "sha256": pe_digest,
        "size_bytes": pe_size,
        "codeview": {
            "guid": pe_identity[0],
            "age": pe_identity[1],
            "pdb_name": PureWindowsPath(pe_identity[2]).name,
        },
    }
    if pe != expected_pe:
        raise ValueError("public PDB receipt PE binding mismatch")
    pdb = _object(receipt["pdb"], "pdb")
    _exact(pdb, {"path", "sha256", "size_bytes", "identity"}, "pdb")
    identity = _object(pdb["identity"], "pdb.identity")
    _exact(identity, {"guid", "age", "stripped"}, "pdb.identity")
    if pdb != {
        "path": "artifact",
        "sha256": pdb_digest,
        "size_bytes": pdb_size,
        "identity": {"guid": pdb_identity[0], "age": pdb_identity[1], "stripped": pdb_identity[2]},
    }:
        raise ValueError("public PDB receipt artifact binding mismatch")
    if not pdb_identity[2] or pdb_identity[0] != pe_identity[0]:
        raise ValueError("public PDB must be stripped and match the PE CodeView GUID")
    source = _object(receipt["source"], "source")
    _exact(
        source,
        {
            "requested_url",
            "final_url_redacted",
            "final_query_sha256",
            "retrieved_at_utc",
            "http_status",
            "etag",
            "last_modified",
            "content_type",
            "content_length",
        },
        "source",
    )
    expected_url = _url_from_identity(pe_identity)
    if source["requested_url"] != expected_url:
        raise ValueError("public PDB receipt symbol key mismatch")
    _redacted_final(str(source["final_url_redacted"]), expected_url)
    if _SHA256.fullmatch(str(source["final_query_sha256"])) is None:
        raise ValueError("public PDB final query digest is invalid")
    if source["http_status"] != 200:
        raise ValueError("public PDB receipt HTTP status mismatch")
    retrieved = datetime.fromisoformat(str(source["retrieved_at_utc"]))
    if retrieved.utcoffset() != UTC.utcoffset(retrieved):
        raise ValueError("public PDB retrieved_at_utc must be timezone-aware UTC")
    for field in ("etag", "last_modified", "content_type", "content_length"):
        field_value = source[field]
        if not isinstance(field_value, str) or "\x00" in field_value:
            raise ValueError(f"public PDB source.{field} is invalid")
    content_length = source["content_length"]
    if isinstance(content_length, str) and content_length and int(content_length) != pdb_size:
        raise ValueError("public PDB receipt Content-Length mismatch")
    if receipt["exact_age_match"] is not (pdb_identity[1] == pe_identity[1]):
        raise ValueError("public PDB exact_age_match is false or misleading")
    if receipt["verified_claims"] != [
        "pe-derived-symbol-key",
        "producer-observed-microsoft-symbol-route",
        "pdb-content-sha256",
        "pdb-guid-match",
        "pdb-stripped",
    ]:
        raise ValueError("public PDB verified_claims mismatch")
    if receipt["proof_limit"] != PUBLIC_PDB_PROOF_LIMIT:
        raise ValueError("public PDB proof_limit mismatch")
    if bundle.name != pdb_digest:
        raise ValueError("public PDB bundle directory must equal artifact SHA-256")
    return PublicPdbReceipt(
        bundle.resolve(),
        artifact.resolve(),
        pdb_digest,
        pdb_size,
        receipt_digest,
        expected_url,
        pe_identity[0],
        pe_identity[1],
        pdb_identity[0],
        pdb_identity[1],
        pdb_identity[1] == pe_identity[1],
    )


def _safe_final_url(final_url: str, requested_url: str) -> tuple[str, str]:
    if final_url == requested_url:
        return final_url, hashlib.sha256(b"").hexdigest()
    parsed = _blob_url(final_url, "public PDB final URL")
    redacted = urlunsplit(("https", parsed.netloc, parsed.path, "", ""))
    return redacted, hashlib.sha256(parsed.query.encode()).hexdigest()


def _redacted_final(value: str, requested_url: str) -> None:
    if value == requested_url:
        return
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment:
        raise ValueError("public PDB final URL was not redacted")
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or _BLOB_HOST.fullmatch(parsed.hostname or "") is None
        or not parsed.path.startswith("/")
    ):
        raise ValueError("public PDB redacted final URL is invalid")


def _blob_url(value: str, label: str) -> SplitResult:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or _BLOB_HOST.fullmatch(parsed.hostname or "") is None
        or not parsed.path.startswith("/")
        or not parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an Azure HTTPS blob URL with a query")
    return parsed


def _snapshot_regular(
    source: Path, destination: Path, label: str, size_cap: int
) -> tuple[str, int]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("public PDB stable no-follow snapshots are unavailable")
    try:
        descriptor = os.open(source, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ValueError(f"{label} must be a readable regular non-symlink file") from exc
    digest = hashlib.sha256()
    size = 0
    output = -1
    completed = False
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > size_cap:
            raise ValueError(f"{label} exceeds the supported size boundary")
        output = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
        )
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > size_cap:
                raise ValueError(f"{label} exceeds the supported size boundary")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(output, chunk[offset:])
                if written <= 0:
                    raise OSError(f"short write while retaining {label}")
                offset += written
        os.fsync(output)
        after = os.fstat(descriptor)
        named = os.lstat(source)
        before_id = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_id = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        named_id = (
            named.st_dev,
            named.st_ino,
            named.st_size,
            named.st_mtime_ns,
            named.st_ctime_ns,
        )
        if size != before.st_size or before_id != after_id or after_id != named_id:
            raise ValueError(f"{label} changed while it was retained")
        completed = True
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)
        if output >= 0:
            os.close(output)
        if not completed:
            destination.unlink(missing_ok=True)


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _exact(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} fields mismatch")

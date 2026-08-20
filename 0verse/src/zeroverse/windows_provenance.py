"""Content-addressed acquisition receipts for official Microsoft artifacts.

This module deliberately proves a narrow claim: exact bytes were retrieved over
HTTPS from an allow-listed Microsoft host and retained under their SHA-256.  It
does not claim that the bytes are correctly signed, belong to a specific KB, or
reproduce a Windows build; those claims require later signature, catalog, and
servicing receipts.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Protocol
from urllib.parse import urlsplit

DOWNLOAD_SCHEMA = "0verse.windows-official-download/v1"
DOWNLOAD_PRODUCER = "zeroverse.windows-official-download/v1"
DOWNLOAD_PROOF_LIMIT = (
    "Acquisition evidence only; signature, catalog membership, KB identity, "
    "servicing outcome, vulnerability status, and redistribution rights are unproven."
)

_ALLOWED_HOST_SUFFIXES = ("microsoft.com", "windowsupdate.com")
_KINDS = frozenset({"iso", "msu", "cab", "pdb", "pe", "catalog", "metadata"})
_SHA256 = re.compile(r"[0-9a-f]{64}")


class _Response(Protocol):
    status: int
    headers: Mapping[str, str]

    def geturl(self) -> str: ...

    def read(self, size: int = -1) -> bytes: ...

    def __enter__(self) -> _Response: ...

    def __exit__(self, *args: object) -> object: ...


class _Opener(Protocol):
    def __call__(
        self, request: urllib.request.Request, *, timeout: float
    ) -> _Response: ...


class _OfficialRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject a redirect before urllib sends a request outside the allow-list."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        _official_url(newurl, "redirect URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class DownloadReceipt:
    bundle_path: Path
    artifact_path: Path
    artifact_sha256: str
    artifact_size_bytes: int
    receipt_sha256: str
    source_url: str
    final_url: str
    kind: str

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_path": str(self.bundle_path),
            "artifact_path": str(self.artifact_path),
            "artifact_sha256": self.artifact_sha256,
            "artifact_size_bytes": self.artifact_size_bytes,
            "receipt_sha256": self.receipt_sha256,
            "source_url": self.source_url,
            "final_url": self.final_url,
            "kind": self.kind,
        }


def download_official_artifact(
    source_url: str,
    store_root: str | Path,
    *,
    kind: str,
    max_bytes: int = 16 * 1024 * 1024 * 1024,
    timeout_seconds: float = 120.0,
    opener: _Opener | None = None,
) -> DownloadReceipt:
    """Download one official artifact into a SHA-256-addressed immutable bundle."""
    _official_url(source_url, "source_url")
    if kind not in _KINDS:
        raise ValueError(f"unsupported Windows artifact kind: {kind}")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    root = Path(store_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("store_root must be a regular non-symlink directory")
    temporary = Path(tempfile.mkdtemp(prefix=".windows-download-", dir=root))
    artifact = temporary / "artifact"
    digest = hashlib.sha256()
    size = 0
    published: Path | None = None
    request = urllib.request.Request(
        source_url,
        headers={"User-Agent": "0verse-windows-provenance/1"},
    )
    try:
        if opener is None:
            response_context = urllib.request.build_opener(
                _OfficialRedirectHandler()
            ).open(request, timeout=timeout_seconds)
        else:
            response_context = opener(request, timeout=timeout_seconds)
        with response_context as response:
            final_url = response.geturl()
            _official_url(final_url, "final_url")
            status = int(response.status)
            if status != 200:
                raise ValueError(f"official artifact download returned HTTP {status}")
            with artifact.open("xb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("official artifact exceeds max_bytes")
                    digest.update(chunk)
                    output.write(chunk)
            headers = response.headers
            content_length = str(headers.get("Content-Length", ""))
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise ValueError("official artifact Content-Length is invalid") from exc
                if declared_size != size:
                    raise ValueError("official artifact Content-Length mismatch")
            header_values = {
                "etag": str(headers.get("ETag", "")),
                "last_modified": str(headers.get("Last-Modified", "")),
                "content_type": str(headers.get("Content-Type", "")),
                "content_length": content_length,
            }
            if any("\x00" in value for value in header_values.values()):
                raise ValueError("official artifact response header contains a NUL byte")
            metadata = {
                "requested_url": source_url,
                "final_url": final_url,
                "retrieved_at_utc": datetime.now(UTC).isoformat(),
                "http_status": status,
                **header_values,
            }
        artifact_digest = digest.hexdigest()
        receipt = {
            "schema_version": DOWNLOAD_SCHEMA,
            "producer": DOWNLOAD_PRODUCER,
            "source": metadata,
            "artifact": {
                "kind": kind,
                "path": "artifact",
                "sha256": artifact_digest,
                "size_bytes": size,
            },
            "verified_claims": [
                "producer-observed-official-https-source",
                "content-sha256",
            ],
            "proof_limit": DOWNLOAD_PROOF_LIMIT,
        }
        receipt_path = temporary / "receipt.json"
        with receipt_path.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2, sort_keys=True)
            output.write("\n")
        destination = root / artifact_digest
        if destination.exists():
            existing = _matching_existing(
                destination, artifact_digest, source_url, final_url, kind
            )
            shutil.rmtree(temporary)
            return existing
        try:
            temporary.rename(destination)
        except OSError:
            if not destination.exists():
                raise
            existing = _matching_existing(
                destination, artifact_digest, source_url, final_url, kind
            )
            shutil.rmtree(temporary)
            return existing
        published = destination
        return verify_official_download_receipt(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        if published is not None:
            shutil.rmtree(published, ignore_errors=True)
        raise


def verify_official_download_receipt(bundle_path: str | Path) -> DownloadReceipt:
    """Fail closed unless a retained download bundle exactly matches its receipt."""
    bundle = Path(bundle_path)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("download bundle must be a regular non-symlink directory")
    if {path.name for path in bundle.iterdir()} != {"artifact", "receipt.json"}:
        raise ValueError("download bundle must contain exactly artifact and receipt.json")
    receipt_path = bundle / "receipt.json"
    artifact_path = bundle / "artifact"
    for path, label in ((receipt_path, "receipt"), (artifact_path, "artifact")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"download {label} must be a regular non-symlink file")
    observed_digest, observed_size = _hash_file(artifact_path)
    return _verify_official_download_receipt_metadata(
        bundle, receipt_path, artifact_path, observed_digest, observed_size
    )


def verify_official_download_receipt_prehashed(
    bundle_path: str | Path, *, artifact_sha256: str, artifact_size_bytes: int
) -> DownloadReceipt:
    """Verify receipt semantics against bytes rehashed by the trusted CAS boundary."""
    bundle = Path(bundle_path)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("download bundle must be a regular non-symlink directory")
    if {path.name for path in bundle.iterdir()} != {"receipt.json"}:
        raise ValueError("prehashed download bundle must contain exactly receipt.json")
    receipt_path = bundle / "receipt.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise ValueError("download receipt must be a regular non-symlink file")
    if _SHA256.fullmatch(artifact_sha256) is None:
        raise ValueError("prehashed download artifact SHA-256 is invalid")
    if (
        isinstance(artifact_size_bytes, bool)
        or not isinstance(artifact_size_bytes, int)
        or artifact_size_bytes <= 0
    ):
        raise ValueError("prehashed download artifact size is invalid")
    return _verify_official_download_receipt_metadata(
        bundle,
        receipt_path,
        bundle / "artifact",
        artifact_sha256,
        artifact_size_bytes,
    )


def _verify_official_download_receipt_metadata(
    bundle: Path,
    receipt_path: Path,
    artifact_path: Path,
    observed_digest: str,
    observed_size: int,
) -> DownloadReceipt:
    raw = json.loads(receipt_path.read_bytes(), object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("download receipt must be a JSON object")
    _exact(
        raw,
        {
            "schema_version",
            "producer",
            "source",
            "artifact",
            "verified_claims",
            "proof_limit",
        },
        "receipt",
    )
    if raw["schema_version"] != DOWNLOAD_SCHEMA or raw["producer"] != DOWNLOAD_PRODUCER:
        raise ValueError("download receipt schema/producer mismatch")
    source = _mapping(raw["source"], "source")
    _exact(
        source,
        {
            "requested_url",
            "final_url",
            "retrieved_at_utc",
            "http_status",
            "etag",
            "last_modified",
            "content_type",
            "content_length",
        },
        "source",
    )
    requested_url = _official_url(source["requested_url"], "source.requested_url")
    final_url = _official_url(source["final_url"], "source.final_url")
    if source["http_status"] != 200:
        raise ValueError("download receipt HTTP status must be 200")
    _utc_timestamp(source["retrieved_at_utc"], "source.retrieved_at_utc")
    for field in ("etag", "last_modified", "content_type", "content_length"):
        value = source[field]
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError(f"source.{field} must be a string without NUL bytes")
    artifact = _mapping(raw["artifact"], "artifact")
    _exact(artifact, {"kind", "path", "sha256", "size_bytes"}, "artifact")
    kind = str(artifact["kind"])
    if kind not in _KINDS:
        raise ValueError(f"unsupported Windows artifact kind: {kind}")
    if artifact["path"] != "artifact":
        raise ValueError("download artifact path must be exactly artifact")
    expected_digest = _sha256(artifact["sha256"], "artifact.sha256")
    if expected_digest != observed_digest:
        raise ValueError("download artifact SHA-256 mismatch")
    declared_artifact_size = artifact["size_bytes"]
    if (
        not isinstance(declared_artifact_size, int)
        or isinstance(declared_artifact_size, bool)
        or declared_artifact_size <= 0
        or declared_artifact_size != observed_size
    ):
        raise ValueError("download artifact size mismatch")
    content_length = source["content_length"]
    if content_length:
        try:
            declared_content_length = int(str(content_length))
        except ValueError as exc:
            raise ValueError("download Content-Length is invalid") from exc
        if declared_content_length != observed_size:
            raise ValueError("download Content-Length mismatch")
    if bundle.name != observed_digest:
        raise ValueError("download bundle directory must equal artifact SHA-256")
    if raw["verified_claims"] != [
        "producer-observed-official-https-source",
        "content-sha256",
    ]:
        raise ValueError("download verified_claims mismatch")
    if raw["proof_limit"] != DOWNLOAD_PROOF_LIMIT:
        raise ValueError("download proof_limit mismatch")
    return DownloadReceipt(
        bundle.resolve(),
        artifact_path.resolve(),
        observed_digest,
        observed_size,
        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        requested_url,
        final_url,
        kind,
    )


def _matching_existing(
    destination: Path,
    artifact_digest: str,
    source_url: str,
    final_url: str,
    kind: str,
) -> DownloadReceipt:
    existing = verify_official_download_receipt(destination)
    if existing.artifact_sha256 != artifact_digest:
        raise ValueError("content-addressed destination does not match downloaded bytes")
    if (
        existing.source_url != source_url
        or existing.final_url != final_url
        or existing.kind != kind
    ):
        raise ValueError("content-addressed artifact already has different acquisition provenance")
    return existing


def _official_url(raw: object, label: str) -> str:
    if not isinstance(raw, str) or "\x00" in raw:
        raise ValueError(f"{label} must be an official HTTPS URL")
    parsed = urlsplit(raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or not host
        or not any(
            host == suffix or host.endswith(f".{suffix}")
            for suffix in _ALLOWED_HOST_SUFFIXES
        )
    ):
        raise ValueError(f"{label} must be an official HTTPS URL")
    return raw


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _mapping(raw: object, label: str) -> dict[str, object]:
    if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
        raise ValueError(f"{label} must be an object")
    return raw


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact(raw: Mapping[str, object], expected: set[str], label: str) -> None:
    missing = sorted(expected - raw.keys())
    unknown = sorted(raw.keys() - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ValueError(f"{label} fields invalid: {'; '.join(details)}")


def _sha256(raw: object, label: str) -> str:
    value = str(raw)
    if _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _utc_timestamp(raw: object, label: str) -> datetime:
    if not isinstance(raw, str):
        raise ValueError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{label} must be a UTC timestamp")
    return parsed

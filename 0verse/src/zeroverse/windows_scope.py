"""Fail-closed scope records for Windows and Hyper-V bounty replay."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

SCHEMA_VERSION = "0verse.windows-scope/v1"
SIGNED_SCOPE_SCHEMA_VERSION = "0verse.windows-scope/v2"
AUTHORIZATION_NAMESPACE = "0verse-windows-scope-authorization"
DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS = Path(
    "/etc/0verse/windows-authorization.allowed_signers"
)
PROGRAMS = frozenset({"windows-canary", "hyperv-insider", "hyperv-server"})
CANARY_SUCCESSOR_CHANNELS = frozenset(
    {"canary-legacy", "experimental-26h1", "experimental-future-platforms"}
)
_BUILD_NUMBER = re.compile(r"^(\d+)\.(\d+)")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}")


@dataclass(frozen=True)
class WindowsScope:
    campaign_id: str
    program: str
    scope_url: str
    target_feature: str
    reachability: str
    authorization: str
    worker: str
    latest_build_verified_at: str
    latest_build_number: str
    latest_build_source_url: str
    preflight_checked_at: str
    preflight_build_lab_ex: str
    preflight_product_name: str
    preflight_ring: str
    preflight_branch_name: str
    preflight_channel_family: str
    preflight_hyperv_available: bool
    authorized_by: str = ""
    issued_at: str = ""
    expires_at: str = ""
    nonce: str = ""
    signature_ssh: str = ""
    schema_version: str = SCHEMA_VERSION
    _signed_material: bytes = field(default=b"", repr=False, compare=False)
    _allowed_signers: Path | None = field(default=None, repr=False, compare=False)
    _require_trusted_policy: bool = field(default=True, repr=False, compare=False)
    _authorization_verified: bool = field(default=False, repr=False, compare=False)
    _source_bytes: bytes = field(default=b"", repr=False, compare=False)
    _source_sha256: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, object]) -> WindowsScope:
        schema = str(raw.get("schema_version", SCHEMA_VERSION))
        if schema == SIGNED_SCOPE_SCHEMA_VERSION:
            _validate_signed_scope_shape(raw)
        required = {
            "campaign_id",
            "program",
            "scope_url",
            "target_feature",
            "reachability",
            "authorization",
            "worker",
            "latest_build_verified_at",
            "preflight",
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ValueError(f"missing Windows scope fields: {', '.join(missing)}")
        preflight = raw["preflight"]
        if not isinstance(preflight, dict):
            raise ValueError("preflight must be the scope-preflight JSON object")
        if preflight.get("ok") is not True:
            raise ValueError("Windows scope preflight did not pass")
        program = str(raw["program"])
        if str(preflight.get("program", "")) != program:
            raise ValueError("manifest/preflight program mismatch")
        insider = preflight.get("insider")
        if not isinstance(insider, dict):
            raise ValueError("preflight.insider must be an object")
        hyperv_available = preflight.get("hyperv_available", False)
        if not isinstance(hyperv_available, bool):
            raise ValueError("preflight.hyperv_available must be a boolean")
        scope = cls(
            campaign_id=str(raw["campaign_id"]),
            program=program,
            scope_url=str(raw["scope_url"]),
            target_feature=str(raw["target_feature"]),
            reachability=str(raw["reachability"]),
            authorization=str(raw["authorization"]),
            worker=str(raw["worker"]),
            latest_build_verified_at=str(raw["latest_build_verified_at"]),
            latest_build_number=str(raw.get("latest_build_number", "")),
            latest_build_source_url=str(raw.get("latest_build_source_url", "")),
            preflight_checked_at=str(preflight.get("checked_at", "")),
            preflight_build_lab_ex=str(preflight.get("build_lab_ex", "")),
            preflight_product_name=str(preflight.get("product_name", "")),
            preflight_ring=str(insider.get("ring", "")),
            preflight_branch_name=str(insider.get("branch_name", "")),
            preflight_channel_family=str(insider.get("channel_family", "")),
            preflight_hyperv_available=hyperv_available,
            authorized_by=str(raw.get("authorized_by", "")),
            issued_at=str(raw.get("issued_at", "")),
            expires_at=str(raw.get("expires_at", "")),
            nonce=str(raw.get("nonce", "")),
            signature_ssh=str(raw.get("signature_ssh", "")),
            schema_version=schema,
        )
        scope.validate()
        return scope

    def validate(self) -> None:
        if self.schema_version not in {SCHEMA_VERSION, SIGNED_SCOPE_SCHEMA_VERSION}:
            raise ValueError(f"unsupported Windows scope schema: {self.schema_version}")
        for name in (
            "campaign_id",
            "target_feature",
            "reachability",
            "authorization",
            "worker",
            "preflight_build_lab_ex",
        ):
            if not getattr(self, name).strip():
                raise ValueError(f"Windows scope field is empty: {name}")
        if self.program not in PROGRAMS:
            raise ValueError(f"unsupported Windows bounty program: {self.program}")
        if self.program == "windows-canary":
            derived_channel = _canary_successor_channel(
                self.preflight_build_lab_ex,
                self.preflight_ring,
                self.preflight_branch_name,
            )
            if derived_channel not in CANARY_SUCCESSOR_CHANNELS:
                raise ValueError(
                    "preflight evidence does not identify a Canary-successor build"
                )
            if self.preflight_channel_family != derived_channel:
                raise ValueError("preflight Canary-successor channel classification mismatch")
            if not self.latest_build_number.strip():
                raise ValueError("latest_build_number is required for Windows bounty scope")
            observed_build = _normalized_build_number(self.preflight_build_lab_ex)
            if observed_build != self.latest_build_number:
                raise ValueError(
                    "preflight build is not the officially verified latest build: "
                    f"expected {self.latest_build_number!r}, observed {observed_build!r}"
                )
            source = urlparse(self.latest_build_source_url)
            if (
                source.scheme != "https"
                or source.hostname != "learn.microsoft.com"
                or source.path.rstrip("/") != "/en-us/windows-insider/flight-hub"
                or source.username is not None
                or source.password is not None
            ):
                raise ValueError(
                    "latest_build_source_url must be the official English Flight Hub"
                )
        if self.program == "hyperv-insider":
            if not (self.preflight_ring.strip() or self.preflight_branch_name.strip()):
                raise ValueError("preflight evidence has no Windows Insider identity")
            if not self.preflight_hyperv_available:
                raise ValueError("preflight evidence does not confirm Hyper-V")
        if self.program == "hyperv-server":
            if "server" not in self.preflight_product_name.lower():
                raise ValueError("preflight evidence does not identify Windows Server")
            if not self.preflight_hyperv_available:
                raise ValueError("preflight evidence does not confirm Hyper-V")
        if not self.scope_url.startswith("https://"):
            raise ValueError("scope_url must be an https URL")
        _require_fresh(self.preflight_checked_at, timedelta(hours=24), "scope preflight")
        _require_fresh(
            self.latest_build_verified_at, timedelta(hours=24), "latest-build verification"
        )
        if self.schema_version == SIGNED_SCOPE_SCHEMA_VERSION:
            _validate_authorization_window(
                self.authorized_by,
                self.issued_at,
                self.expires_at,
                self.nonce,
                "Windows scope authorization",
            )

    def require_signed_authorization(self) -> None:
        """Reverify the operator signature and freshness before disruptive use."""
        self.validate()
        if (
            self.schema_version != SIGNED_SCOPE_SCHEMA_VERSION
            or not self._authorization_verified
            or not self._signed_material
            or self._allowed_signers is None
        ):
            raise ValueError("disruptive Windows execution requires a verified signed scope v2")
        signed_raw = json.loads(self._signed_material, object_pairs_hook=_unique_object)
        if not isinstance(signed_raw, dict):
            raise ValueError("signed Windows scope material is malformed")
        signed_raw["signature_ssh"] = self.signature_ssh
        if self != WindowsScope.from_mapping(signed_raw):
            raise ValueError("live Windows scope fields differ from signed material")
        from .ssh_authorization import verify_ssh_signature

        verify_ssh_signature(
            self._signed_material,
            self.signature_ssh,
            identity=self.authorized_by,
            namespace=AUTHORIZATION_NAMESPACE,
            allowed_signers=self._allowed_signers,
            label="Windows scope authorization",
            require_trusted_policy=self._require_trusted_policy,
        )

    def require_source_binding(self, source_sha256: str) -> None:
        self.require_signed_authorization()
        if (
            not self._source_bytes
            or not self._source_sha256
            or hashlib.sha256(self._source_bytes).hexdigest() != self._source_sha256
            or source_sha256 != self._source_sha256
        ):
            raise ValueError("Windows scope SHA-256 differs from loaded source file")
        raw = json.loads(self._source_bytes, object_pairs_hook=_unique_object)
        if not isinstance(raw, dict) or self != WindowsScope.from_mapping(raw):
            raise ValueError("live Windows scope fields differ from loaded source file")


def load_scope(
    path: str | Path,
    *,
    allowed_signers: str | Path | None = None,
    require_authorized: bool = False,
) -> tuple[WindowsScope, str]:
    scope_path = Path(path)
    if scope_path.is_symlink() or not scope_path.is_file():
        raise ValueError("Windows scope manifest must be a regular non-symlink file")
    data = scope_path.read_bytes()
    raw = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(raw, dict):
        raise ValueError("Windows scope manifest must be a JSON object")
    digest = hashlib.sha256(data).hexdigest()
    scope = WindowsScope.from_mapping(raw)
    if scope.schema_version == SIGNED_SCOPE_SCHEMA_VERSION:
        from .ssh_authorization import canonical_signed_material, verify_ssh_signature

        configured = (
            Path(allowed_signers)
            if allowed_signers is not None
            else DEFAULT_AUTHORIZATION_ALLOWED_SIGNERS
        )
        require_trusted = allowed_signers is None
        material = canonical_signed_material(raw)
        verify_ssh_signature(
            material,
            scope.signature_ssh,
            identity=scope.authorized_by,
            namespace=AUTHORIZATION_NAMESPACE,
            allowed_signers=configured,
            label="Windows scope authorization",
            require_trusted_policy=require_trusted,
        )
        scope = replace(
            scope,
            _signed_material=material,
            _allowed_signers=configured.expanduser().resolve(),
            _require_trusted_policy=require_trusted,
            _authorization_verified=True,
            _source_bytes=data,
            _source_sha256=digest,
        )
    if require_authorized:
        scope.require_signed_authorization()
    return scope, digest


def verify_evidence_builds(scope: WindowsScope, builds: Sequence[str]) -> None:
    observed = {build for build in builds if build}
    if not observed:
        raise ValueError("Windows replay returned no BuildLabEx evidence")
    if observed != {scope.preflight_build_lab_ex}:
        raise ValueError(
            "Windows build changed after scope preflight: "
            f"expected {scope.preflight_build_lab_ex!r}, observed {sorted(observed)!r}"
        )


def _require_fresh(value: str, maximum_age: timedelta, label: str) -> None:
    try:
        checked = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} timestamp must be ISO-8601") from exc
    if checked.tzinfo is None:
        raise ValueError(f"{label} timestamp must include a timezone")
    age = datetime.now(UTC) - checked.astimezone(UTC)
    if age < timedelta(0) or age > maximum_age:
        raise ValueError(f"{label} must be no more than 24 hours old")


def _normalized_build_number(build_lab_ex: str) -> str:
    match = _BUILD_NUMBER.match(build_lab_ex)
    if match is None:
        raise ValueError("preflight BuildLabEx has no major.revision build number")
    return f"{match.group(1)}.{match.group(2)}"


def _canary_successor_channel(build_lab_ex: str, ring: str, branch: str) -> str:
    identity = f"{ring} {branch}".lower()
    build_major = int(_normalized_build_number(build_lab_ex).split(".", 1)[0])
    if "future platforms" in identity or (identity.strip() and build_major >= 29000):
        return "experimental-future-platforms"
    if "26h1" in identity or (identity.strip() and 28000 <= build_major < 29000):
        return "experimental-26h1"
    if "canary" in identity:
        return "canary-legacy"
    return "unknown"


def _validate_signed_scope_shape(raw: Mapping[str, object]) -> None:
    _exact(
        raw,
        {
            "schema_version",
            "campaign_id",
            "program",
            "scope_url",
            "target_feature",
            "reachability",
            "authorization",
            "worker",
            "latest_build_verified_at",
            "latest_build_number",
            "latest_build_source_url",
            "preflight",
            "authorized_by",
            "issued_at",
            "expires_at",
            "nonce",
            "signature_ssh",
        },
        "signed Windows scope",
    )
    for field_name in (
        "schema_version",
        "campaign_id",
        "program",
        "scope_url",
        "target_feature",
        "reachability",
        "authorization",
        "worker",
        "latest_build_verified_at",
        "latest_build_number",
        "latest_build_source_url",
        "authorized_by",
        "issued_at",
        "expires_at",
        "nonce",
        "signature_ssh",
    ):
        if not isinstance(raw[field_name], str):
            raise ValueError(f"signed Windows scope {field_name} must be a string")
    preflight = raw["preflight"]
    if not isinstance(preflight, dict):
        raise ValueError("preflight must be the scope-preflight JSON object")
    _exact(
        preflight,
        {
            "ok",
            "program",
            "checked_at",
            "build_lab_ex",
            "product_name",
            "hyperv_available",
            "insider",
        },
        "signed Windows scope preflight",
    )
    for field_name in ("program", "checked_at", "build_lab_ex", "product_name"):
        if not isinstance(preflight[field_name], str):
            raise ValueError(f"signed Windows scope preflight.{field_name} must be a string")
    for field_name in ("ok", "hyperv_available"):
        if not isinstance(preflight[field_name], bool):
            raise ValueError(f"signed Windows scope preflight.{field_name} must be a boolean")
    insider = preflight["insider"]
    if not isinstance(insider, dict):
        raise ValueError("preflight.insider must be an object")
    _exact(
        insider,
        {"ring", "content_type", "branch_name", "channel_family"},
        "signed Windows scope preflight.insider",
    )
    for field_name in ("ring", "content_type", "branch_name", "channel_family"):
        if not isinstance(insider[field_name], str):
            raise ValueError(
                f"signed Windows scope preflight.insider.{field_name} must be a string"
            )


def _validate_authorization_window(
    authorized_by: str, issued_at: str, expires_at: str, nonce: str, label: str
) -> None:
    if not authorized_by.strip() or any(char in authorized_by for char in "\x00\r\n"):
        raise ValueError(f"{label} authorized_by is empty or unsafe")
    if _NONCE.fullmatch(nonce) is None:
        raise ValueError(f"{label} nonce must be 32-128 URL-safe characters")
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} timestamps must be ISO-8601") from exc
    if issued.tzinfo is None or expires.tzinfo is None:
        raise ValueError(f"{label} timestamps must include a timezone")
    now = datetime.now(UTC)
    issued_utc = issued.astimezone(UTC)
    expires_utc = expires.astimezone(UTC)
    if issued_utc > now + timedelta(minutes=5) or now - issued_utc > timedelta(hours=24):
        raise ValueError(f"{label} issued_at is outside the 24-hour window")
    if expires_utc <= now or expires_utc <= issued_utc:
        raise ValueError(f"{label} has expired or has an invalid interval")
    if expires_utc - issued_utc > timedelta(hours=24):
        raise ValueError(f"{label} lifetime exceeds 24 hours")


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


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

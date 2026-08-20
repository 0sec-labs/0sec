"""Thin client for the AIxCC Competition API v1.4.0.

Usage
-----
    client = CompetitionApiClient(
        "https://competition.example.com",
        username="team1",
        password="secret",
    )
    client.ping()
    challenges = client.list_requests()
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, ClassVar, Protocol, runtime_checkable

__all__ = [
    "CompetitionApiClient",
    "CrsApiError",
    "Transport",
    "TransportResponse",
    "UrllibTransport",
]


class CrsApiError(Exception):
    """Raised on non-2xx responses or malformed JSON from the CRS.

    Attributes
    ----------
    status_code : int
        HTTP status code (0 when the transport itself failed).
    message : str
        Bounded error text (max 1 KiB, secrets never logged).
    """

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"CRS API error {status_code}: {message}")


class TransportResponse:
    """Raw HTTP response from a transport implementation."""

    __slots__ = ("body", "headers", "status_code")

    def __init__(
        self, status_code: int, headers: dict[str, str], body: bytes
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body


@runtime_checkable
class Transport(Protocol):
    """Injected HTTP transport.

    Implementations must not log or persist credentials and must return
    every response including non-2xx so the client can transform them
    into ``CrsApiError``.
    """

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> TransportResponse:
        """Perform a synchronous HTTP request.

        Parameters
        ----------
        method : str
            HTTP method (``GET``, ``POST``, …).
        path : str
            Absolute URL.
        headers : dict
            Request headers.
        body : bytes or None
            Request body.

        Returns
        -------
        TransportResponse
            The full HTTP response including non-2xx.
        """
        ...


class UrllibTransport:
    """Default transport backed by ``urllib.request``."""

    def __init__(self, timeout: float = 60) -> None:
        self._timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> TransportResponse:
        req = urllib.request.Request(path, data=body, headers=headers, method=method)
        try:
            # The client validates one operator-configured HTTPS base URL before
            # constructing paths; request input cannot choose a second origin.
            with urllib.request.urlopen(  # foxguard: ignore[py/no-ssrf]
                req, timeout=self._timeout
            ) as resp:
                return TransportResponse(resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as exc:
            return TransportResponse(exc.code, dict(exc.headers), exc.read())
        except urllib.error.URLError as exc:
            raise CrsApiError(0, str(exc.reason)) from exc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_ID_SAFE: str = ""

def _validate_id(value: str, *, name: str = "identifier") -> str:
    """Return URL-encoded *value* or raise on an empty/non-string identifier."""
    if not isinstance(value, str):
        raise ValueError(f"{name} must be non-empty")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must be non-empty")
    return urllib.parse.quote(normalized, safe=_ID_SAFE)


def _validated_base64(value: str, *, name: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid base64") from exc
    if len(decoded) > max_bytes:
        raise ValueError(f"{name} exceeds its {max_bytes}-byte limit")
    return value


def _validated_text(value: str, *, name: str, max_length: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{name} must be non-empty and at most {max_length} characters")
    return value


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class CompetitionApiClient:
    """HTTP client for the AIxCC CRS v1.4.0 competition API.

    Parameters
    ----------
    base_url:
        Base URL of the CRS (e.g. ``https://crs.example.com``).
    username:
        Basic-auth username.
    password:
        Basic-auth password. Never logged or persisted.
    transport:
        Pluggable HTTP transport. Defaults to ``UrllibTransport``.
    allow_insecure_http:
        Permit plain ``http://`` URLs. Required for local fixture clusters.
    """

    MAX_BODY_IN_ERROR: ClassVar[int] = 1024

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        transport: Transport | None = None,
        allow_insecure_http: bool = False,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url must be non-empty")
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.scheme == "http" and not allow_insecure_http:
            raise ValueError(
                "HTTP is not allowed by default; pass allow_insecure_http=True "
                "for local fixture clusters"
            )
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query or fragment")
        self._base_url = base_url.rstrip("/")
        raw = f"{username}:{password}".encode()
        self._auth = base64.b64encode(raw).decode()
        self._transport = transport if transport is not None else UrllibTransport()
    # ------------------------------------------------------------------
    # Internal request helpers
    # ------------------------------------------------------------------

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        url = self._base_url + path
        headers: dict[str, str] = {
            "Authorization": f"Basic {self._auth}",
            "Accept": "application/json",
        }
        body_bytes: bytes | None = None
        if body is not None:
            body_bytes = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"

        try:
            resp = self._transport.request(method, url, headers, body_bytes)
        except CrsApiError:
            raise
        except Exception as exc:
            raise CrsApiError(0, f"transport request failed ({type(exc).__name__})") from exc

        if not (200 <= resp.status_code < 300):
            msg = _truncate_error_body(resp.body, self.MAX_BODY_IN_ERROR)
            raise CrsApiError(resp.status_code, msg)

        if not resp.body:
            return None

        try:
            return json.loads(resp.body)
        except json.JSONDecodeError as exc:
            raise CrsApiError(resp.status_code, f"malformed JSON: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API - 8 operations matching the CRS v1.4.0 surface
    # ------------------------------------------------------------------

    def ping(self) -> Any:
        """``GET /v1/ping/`` — test credentials and connectivity."""
        return self._request("GET", "/v1/ping/")

    def list_requests(self) -> Any:
        """``GET /v1/request/list/`` — list taskable challenge names."""
        return self._request("GET", "/v1/request/list/")

    def request_task(self, challenge_name: str, duration_secs: int = 3600) -> Any:
        """``POST /v1/request/{challenge_name}`` — request a competition task."""
        if not isinstance(duration_secs, int) or duration_secs <= 0:
            raise ValueError("duration_secs must be a positive integer")
        challenge = _validate_id(challenge_name, name="challenge_name")
        return self._request(
            "POST",
            f"/v1/request/{challenge}",
            {"duration_secs": duration_secs},
        )

    def submit_pov(
        self,
        task_id: str,
        *,
        architecture: str = "x86_64",
        engine: str = "libfuzzer",
        fuzzer_name: str,
        sanitizer: str,
        testcase: str,
    ) -> Any:
        """``POST /v1/task/{task_id}/pov/`` — submit a base64 PoV."""
        task = _validate_id(task_id, name="task_id")
        return self._request(
            "POST",
            f"/v1/task/{task}/pov/",
            {
                "architecture": _validated_text(
                    architecture, name="architecture", max_length=4096
                ),
                "engine": _validated_text(engine, name="engine", max_length=4096),
                "fuzzer_name": _validated_text(
                    fuzzer_name, name="fuzzer_name", max_length=4096
                ),
                "sanitizer": _validated_text(
                    sanitizer, name="sanitizer", max_length=4096
                ),
                "testcase": _validated_base64(
                    testcase, name="testcase", max_bytes=2 * 1024 * 1024
                ),
            },
        )

    def submit_patch(self, task_id: str, *, patch: str) -> Any:
        """``POST /v1/task/{task_id}/patch/`` — submit a base64 unified diff."""
        task = _validate_id(task_id, name="task_id")
        return self._request(
            "POST",
            f"/v1/task/{task}/patch/",
            {"patch": _validated_base64(patch, name="patch", max_bytes=100 * 1024)},
        )

    def submit_sarif(self, task_id: str, *, sarif: dict[str, Any]) -> Any:
        """``POST /v1/task/{task_id}/submitted-sarif/`` — submit CRS SARIF."""
        if not isinstance(sarif, dict):
            raise ValueError("sarif must be an object")
        task = _validate_id(task_id, name="task_id")
        return self._request("POST", f"/v1/task/{task}/submitted-sarif/", {"sarif": sarif})

    def assess_broadcast_sarif(
        self,
        task_id: str,
        broadcast_sarif_id: str,
        *,
        assessment: str,
        description: str,
    ) -> Any:
        """``POST /v1/task/{task_id}/broadcast-sarif-assessment/{id}/``."""
        if assessment not in {"correct", "incorrect"}:
            raise ValueError("assessment must be 'correct' or 'incorrect'")
        if not description or len(description) > 131_072:
            raise ValueError("description must be non-empty and at most 131072 characters")
        task = _validate_id(task_id, name="task_id")
        broadcast = _validate_id(broadcast_sarif_id, name="broadcast_sarif_id")
        return self._request(
            "POST",
            f"/v1/task/{task}/broadcast-sarif-assessment/{broadcast}/",
            {"assessment": assessment, "description": description},
        )

    def submit_bundle(
        self,
        task_id: str,
        *,
        broadcast_sarif_id: str,
        patch_id: str,
        pov_id: str,
        submitted_sarif_id: str,
        description: str = "",
        freeform_id: str | None = None,
    ) -> Any:
        """``POST /v1/task/{task_id}/bundle/`` after its artifact IDs exist."""
        task = _validate_id(task_id, name="task_id")
        body: dict[str, Any] = {
            "broadcast_sarif_id": _validate_id(
                broadcast_sarif_id, name="broadcast_sarif_id"
            ),
            "patch_id": _validate_id(patch_id, name="patch_id"),
            "pov_id": _validate_id(pov_id, name="pov_id"),
            "submitted_sarif_id": _validate_id(
                submitted_sarif_id, name="submitted_sarif_id"
            ),
            "description": description,
        }
        if freeform_id is not None:
            body["freeform_id"] = _validate_id(freeform_id, name="freeform_id")
        return self._request("POST", f"/v1/task/{task}/bundle/", body)


# ---------------------------------------------------------------------------
# Module-scoped helpers (public for testing)
# ---------------------------------------------------------------------------


def _truncate_error_body(body: bytes, max_bytes: int) -> str:
    """Extract bounded, non-secret diagnostic text from a non-2xx response."""
    raw = body[:max_bytes].decode("utf-8", errors="replace")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    message = parsed.get("message") if isinstance(parsed, dict) else None
    if isinstance(message, str):
        return message[:max_bytes]
    return raw
"""Tests for ``zeroverse.crs_client``.

Proofs URL/payload/auth shape, HTTPS default rejection, explicit local HTTP
opt-in, path encoding, and error behaviour — all through a fake transport.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from zeroverse.crs_client import (
    CompetitionApiClient,
    CrsApiError,
    TransportResponse,
)

# ---------------------------------------------------------------------------
# Fake transport
# ---------------------------------------------------------------------------


class FakeTransport:
    """Records requests and returns pre-configured responses.

    Usage
    -----
        transport = FakeTransport()
        transport.add_response(200, b'{"status":"ok"}')
        client = CompetitionApiClient("https://ex.com", "u", "p",
                                      transport=transport)
        client.ping()
        assert len(transport.requests) == 1
    """

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str], bytes | None]] = []
        self._responses: list[TransportResponse] = []

    def add_response(
        self,
        status: int = 200,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._responses.append(
            TransportResponse(status, headers or {}, b"{}" if body is None else body)
        )

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
    ) -> TransportResponse:
        self.requests.append((method, path, headers, body))
        if self._responses:
            return self._responses.pop(0)
        return TransportResponse(200, {}, b'{"status":"ok"}')


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def make_client():
    """Factory: returns (CompetitionApiClient, FakeTransport)."""

    def _make(base_url: str = "https://crs.example.com", **kwargs: Any):
        transport = FakeTransport()
        client = CompetitionApiClient(
            base_url, "user", "pass", transport=transport, **kwargs
        )
        return client, transport

    return _make


@pytest.fixture
def client(make_client):
    """Default HTTPS client + transport pair."""
    return make_client()


# ===================================================================
# HTTPS enforcement
# ===================================================================


class TestHttpsEnforcement:
    def test_http_raises_without_flag(self) -> None:
        transport = FakeTransport()
        with pytest.raises(ValueError, match="HTTP is not allowed"):
            CompetitionApiClient(
                "http://localhost:8080", "u", "p", transport=transport
            )

    def test_http_allowed_with_flag(self, make_client) -> None:
        c, t = make_client(
            "http://localhost:8080", allow_insecure_http=True
        )
        t.add_response(200, b'{"status":"ok"}')
        c.ping()
        assert t.requests[0][1].startswith("http://localhost:8080")

    def test_https_default_not_stripped(self, make_client) -> None:
        c, t = make_client("https://crs.example.com")
        t.add_response(200, b"{}")
        c.ping()
        assert t.requests[0][1] == "https://crs.example.com/v1/ping/"

    def test_no_scheme_adds_https(self, make_client) -> None:
        c, t = make_client("crs.example.com")
        t.add_response(200, b"{}")
        c.ping()
        assert t.requests[0][1] == "https://crs.example.com/v1/ping/"

    @pytest.mark.parametrize(
        "base_url",
        ["https://", "https:///path", "https://crs.example.com/?query=1"],
    )
    def test_rejects_malformed_or_ambiguous_base_url(self, base_url: str) -> None:
        with pytest.raises(ValueError):
            CompetitionApiClient(base_url, "u", "p", transport=FakeTransport())


# ===================================================================
# Auth
# ===================================================================


class TestAuth:
    def test_basic_auth_header_sent(self, client) -> None:
        c, t = client
        t.add_response(200, b"{}")
        c.ping()
        _method, _path, headers, _body = t.requests[0]
        assert headers["Authorization"] == "Basic dXNlcjpwYXNz"

    def test_auth_sent_on_all_endpoints(self, make_client) -> None:
        c, t = make_client()
        t.add_response(200, b"{}")
        t.add_response(200, b"{}")
        c.ping()
        c.list_requests()
        for _method, _path, headers, _body in t.requests:
            assert "Authorization" in headers


# ===================================================================
# ping
# ===================================================================


class TestPing:
    def test_method_and_path(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"status":"ok"}')
        c.ping()
        method, url, _headers, _body = t.requests[0]
        assert method == "GET"
        assert url == "https://crs.example.com/v1/ping/"

    def test_returns_parsed_json(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"status":"ok"}')
        assert c.ping() == {"status": "ok"}

    def test_empty_body_returns_none(self, client) -> None:
        c, t = client
        t.add_response(200, b"")
        assert c.ping() is None


# ===================================================================
# list_requests
# ===================================================================


class TestListRequests:
    def test_method_and_path(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"challenges":["a","b"]}')
        c.list_requests()
        method, url, _headers, _body = t.requests[0]
        assert method == "GET"
        assert url == "https://crs.example.com/v1/request/list/"

    def test_returns_parsed_json(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"challenges":["a"]}')
        assert c.list_requests() == {"challenges": ["a"]}


# ===================================================================
# request_task
# ===================================================================


class TestRequestTask:
    def test_post_with_body(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"message":"created"}')
        c.request_task("chall", duration_secs=7200)
        method, url, headers, raw_body = t.requests[0]
        assert method == "POST"
        assert url == "https://crs.example.com/v1/request/chall"
        assert headers["Content-Type"] == "application/json"
        assert json.loads(raw_body) == {"duration_secs": 7200}

    def test_default_duration(self, client) -> None:
        c, t = client
        t.add_response(200, b"{}")
        c.request_task("chall")
        _m, _u, _h, raw_body = t.requests[0]
        assert json.loads(raw_body) == {"duration_secs": 3600}


# ===================================================================
# submit_pov
# ===================================================================


class TestSubmitPov:
    def test_post_with_correct_path_and_payload(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"pov_id":"abc","status":"accepted"}')
        c.submit_pov(
            "task-1",
            fuzzer_name="myfuzzer",
            sanitizer="address",
            testcase="dGVzdGNhc2U=",
        )
        method, url, headers, raw_body = t.requests[0]
        assert method == "POST"
        assert url == "https://crs.example.com/v1/task/task-1/pov/"
        assert headers["Content-Type"] == "application/json"
        payload = json.loads(raw_body)
        assert payload["architecture"] == "x86_64"
        assert payload["engine"] == "libfuzzer"
        assert payload["fuzzer_name"] == "myfuzzer"
        assert payload["sanitizer"] == "address"
        assert payload["testcase"] == "dGVzdGNhc2U="

    @pytest.mark.parametrize("testcase", ["not base64!", "", "%%%"])
    def test_rejects_invalid_pov_testcase(self, client, testcase: str) -> None:
        c, _t = client
        with pytest.raises(ValueError, match="testcase"):
            c.submit_pov(
                "task-1",
                fuzzer_name="fz",
                sanitizer="address",
                testcase=testcase,
            )

    def test_returns_parsed_response(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"pov_id":"abc","status":"accepted"}')
        result = c.submit_pov(
            "task-1",
            fuzzer_name="fz", sanitizer="s", testcase="dA==",
        )
        assert result == {"pov_id": "abc", "status": "accepted"}


# ===================================================================
# submit_patch
# ===================================================================


class TestSubmitPatch:
    def test_post_with_patch_payload(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"patch_id":"xyz","status":"accepted"}')
        c.submit_patch("task-1", patch="cGF0Y2g=")
        _m, url, _h, raw_body = t.requests[0]
        assert url == "https://crs.example.com/v1/task/task-1/patch/"
        assert json.loads(raw_body) == {"patch": "cGF0Y2g="}

    @pytest.mark.parametrize("patch", ["not base64!", ""])
    def test_rejects_invalid_patch(self, client, patch: str) -> None:
        c, _t = client
        with pytest.raises(ValueError, match="patch"):
            c.submit_patch("task-1", patch=patch)


# ===================================================================
# submit_sarif
# ===================================================================


class TestSubmitSarif:
    def test_post_with_sarif_object(self, client) -> None:
        c, t = client
        t.add_response(
            200, b'{"submitted_sarif_id":"sid","status":"accepted"}'
        )
        sarif_data = {"version": "2.1.0", "runs": []}
        c.submit_sarif("task-1", sarif=sarif_data)
        _m, url, _h, raw_body = t.requests[0]
        assert url == "https://crs.example.com/v1/task/task-1/submitted-sarif/"
        assert json.loads(raw_body) == {"sarif": sarif_data}

    def test_rejects_non_object_sarif(self, client) -> None:
        c, _t = client
        with pytest.raises(ValueError, match="sarif"):
            c.submit_sarif("task-1", sarif=["not", "an", "object"])  # type: ignore[arg-type]


# ===================================================================
# assess_broadcast_sarif
# ===================================================================


class TestAssessBroadcastSarif:
    def test_post_with_assessment(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"status":"accepted"}')
        c.assess_broadcast_sarif(
            "task-1",
            "broadcast-1",
            assessment="correct",
            description="matches the observed crash",
        )
        method, url, _h, raw_body = t.requests[0]
        assert method == "POST"
        assert url == (
            "https://crs.example.com/v1/task/task-1/"
            "broadcast-sarif-assessment/broadcast-1/"
        )
        assert json.loads(raw_body) == {
            "assessment": "correct",
            "description": "matches the observed crash",
        }


# ===================================================================
# submit_bundle
# ===================================================================


class TestSubmitBundle:
    def test_post_with_required_fields(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"bundle_id":"bid","status":"accepted"}')
        c.submit_bundle(
            "task-1",
            broadcast_sarif_id="b-sid",
            patch_id="p-id",
            pov_id="pv-id",
            submitted_sarif_id="s-id",
        )
        method, url, _h, raw_body = t.requests[0]
        assert method == "POST"
        assert url == "https://crs.example.com/v1/task/task-1/bundle/"
        payload = json.loads(raw_body)
        assert payload["broadcast_sarif_id"] == "b-sid"
        assert payload["patch_id"] == "p-id"
        assert payload["pov_id"] == "pv-id"
        assert payload["submitted_sarif_id"] == "s-id"
        assert "freeform_id" not in payload

    def test_includes_optional_freeform_id(self, client) -> None:
        c, t = client
        t.add_response(200, b'{"bundle_id":"b","status":"accepted"}')
        c.submit_bundle(
            "task-1",
            broadcast_sarif_id="b1",
            patch_id="p1",
            pov_id="pv1",
            submitted_sarif_id="s1",
            freeform_id="ff-id",
        )
        _m, _u, _h, raw_body = t.requests[0]
        assert json.loads(raw_body)["freeform_id"] == "ff-id"


# ===================================================================
# Path validation & encoding
# ===================================================================


class TestPathValidation:
    def test_empty_challenge_raises(self, client) -> None:
        c, _t = client
        with pytest.raises(ValueError, match="must be non-empty"):
            c.request_task("")

    def test_empty_task_id_raises(self, client) -> None:
        c, _t = client
        with pytest.raises(ValueError, match="must be non-empty"):
            c.submit_patch("", patch="abc")

    def test_special_chars_in_challenge_are_encoded(self, client) -> None:
        c, t = client
        t.add_response(200, b"{}")
        c.request_task("chall/1?foo")
        _m, url, _h, _b = t.requests[0]
        assert url == "https://crs.example.com/v1/request/chall%2F1%3Ffoo"

    def test_special_chars_in_task_id_are_encoded(self, client) -> None:
        c, t = client
        t.add_response(200, b"{}")
        c.submit_patch("task/1", patch="YQ==")
        _m, url, _h, _b = t.requests[0]
        assert url == "https://crs.example.com/v1/task/task%2F1/patch/"

    def test_whitespace_is_trimmed_from_task_id(self, client) -> None:
        c, t = client
        t.add_response(200, b"{}")
        c.submit_patch(" task/1 ", patch="YQ==")
        _m, url, _h, _b = t.requests[0]
        assert url == "https://crs.example.com/v1/task/task%2F1/patch/"


# ===================================================================
# Error handling
# ===================================================================


class TestErrorHandling:
    def test_non_2xx_raises_crs_api_error(self, client) -> None:
        c, t = client
        t.add_response(400, b'{"message":"bad request"}')
        with pytest.raises(CrsApiError) as exc:
            c.ping()
        assert exc.value.status_code == 400
        assert "bad request" in exc.value.message

    def test_non_2xx_extracts_message_field(self, client) -> None:
        c, t = client
        t.add_response(500, b'{"message":"internal error"}')
        with pytest.raises(CrsApiError) as exc:
            c.ping()
        assert "internal error" in exc.value.message

    def test_non_2xx_truncates_large_body(self, client) -> None:
        c, t = client
        big = "x" * (CompetitionApiClient.MAX_BODY_IN_ERROR + 1000)
        t.add_response(500, big.encode())
        with pytest.raises(CrsApiError) as exc:
            c.ping()
        assert len(exc.value.message) <= CompetitionApiClient.MAX_BODY_IN_ERROR

    def test_non_2xx_with_non_json_body(self, client) -> None:
        c, t = client
        t.add_response(502, b"upstream error")
        with pytest.raises(CrsApiError) as exc:
            c.ping()
        assert exc.value.status_code == 502
        assert "upstream error" in exc.value.message

    def test_malformed_json_response_raises(self, client) -> None:
        c, t = client
        t.add_response(200, b"not json")
        with pytest.raises(CrsApiError, match="malformed JSON"):
            c.ping()

    def test_network_error_raises_crs_api_error(self, client) -> None:
        """Transport-level failures are wrapped."""
        c, _t = client

        class BrokenTransport:
            def request(self, method, path, headers, body):
                raise CrsApiError(0, "connection refused")

        c._transport = BrokenTransport()  # type: ignore[assignment]
        with pytest.raises(CrsApiError, match="connection refused"):
            c.ping()


# ===================================================================
# Transport protocol adherence
# ===================================================================


class TestTransportProtocol:
    def test_custom_transport_is_used(self) -> None:
        """A bare object with the right method signature works."""
        calls: list[str] = []

        class CustomTransport:
            def request(self, method, path, headers, body):
                calls.append((method, path))
                return TransportResponse(200, {}, b'{"ok":true}')

        client = CompetitionApiClient(
            "https://ex.com", "u", "p", transport=CustomTransport()
        )
        client.ping()
        assert len(calls) == 1
        assert calls[0][0] == "GET"
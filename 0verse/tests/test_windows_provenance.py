from __future__ import annotations

import hashlib
import json
from http.client import HTTPMessage
from pathlib import Path
from urllib.request import Request

import pytest

from zeroverse.cli import main
from zeroverse.windows_provenance import (
    _OfficialRedirectHandler,
    download_official_artifact,
    verify_official_download_receipt,
)


class FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        final_url: str = "https://download.microsoft.com/example/update.msu",
        status: int = 200,
    ) -> None:
        self.body = body
        self.offset = 0
        self.final_url = final_url
        self.status = status
        self.headers = {
            "ETag": '"fixture"',
            "Last-Modified": "Mon, 13 Jul 2026 00:00:00 GMT",
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(body)),
        }

    def geturl(self) -> str:
        return self.final_url

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request: Request | None = None
        self.timeout = 0.0

    def __call__(self, request: Request, *, timeout: float) -> FakeResponse:
        self.request = request
        self.timeout = timeout
        return self.response


def test_download_is_content_addressed_and_reverifiable(tmp_path: Path) -> None:
    body = b"signed-package-fixture"
    opener = FakeOpener(FakeResponse(body))
    result = download_official_artifact(
        "https://catalog.update.microsoft.com/package.msu",
        tmp_path,
        kind="msu",
        opener=opener,
    )
    digest = hashlib.sha256(body).hexdigest()
    assert result.bundle_path == (tmp_path / digest).resolve()
    assert result.artifact_path.read_bytes() == body
    assert result.artifact_sha256 == digest
    assert result.artifact_size_bytes == len(body)
    assert result.kind == "msu"
    assert opener.request is not None
    assert opener.request.headers["User-agent"] == "0verse-windows-provenance/1"
    assert verify_official_download_receipt(result.bundle_path) == result

    raw = json.loads((result.bundle_path / "receipt.json").read_text(encoding="utf-8"))
    assert raw["verified_claims"] == [
        "producer-observed-official-https-source",
        "content-sha256",
    ]
    assert "signature" in raw["proof_limit"]
    assert "vulnerability status" in raw["proof_limit"]


@pytest.mark.parametrize(
    "url",
    [
        "http://download.microsoft.com/file.msu",
        "https://microsoft.com.attacker.example/file.msu",
        "https://user@microsoft.com/file.msu",
        "https://download.microsoft.com/file.msu#fragment",
        "https://download.microsoft.com/file.msu?token=secret",
    ],
)
def test_download_rejects_nonofficial_source_before_network(tmp_path: Path, url: str) -> None:
    opener = FakeOpener(FakeResponse(b"unused"))
    with pytest.raises(ValueError, match="official HTTPS URL"):
        download_official_artifact(url, tmp_path, kind="msu", opener=opener)
    assert opener.request is None


def test_download_rejects_redirect_outside_official_hosts(tmp_path: Path) -> None:
    opener = FakeOpener(
        FakeResponse(b"payload", final_url="https://mirror.attacker.example/update.msu")
    )
    with pytest.raises(ValueError, match="final_url must be an official HTTPS URL"):
        download_official_artifact(
            "https://download.microsoft.com/update.msu",
            tmp_path,
            kind="msu",
            opener=opener,
        )
    assert not list(tmp_path.iterdir())


def test_redirect_handler_rejects_before_following() -> None:
    handler = _OfficialRedirectHandler()
    with pytest.raises(ValueError, match="redirect URL must be an official HTTPS URL"):
        handler.redirect_request(
            Request("https://download.microsoft.com/update.msu"),
            None,  # type: ignore[arg-type]
            302,
            "Found",
            HTTPMessage(),
            "https://attacker.example/capture",
        )


def test_download_size_limit_cleans_temporary_bytes(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exceeds max_bytes"):
        download_official_artifact(
            "https://download.microsoft.com/update.msu",
            tmp_path,
            kind="msu",
            max_bytes=3,
            opener=FakeOpener(FakeResponse(b"too-large")),
        )
    assert not list(tmp_path.iterdir())


def test_download_rejects_truncated_transfer(tmp_path: Path) -> None:
    response = FakeResponse(b"short")
    response.headers["Content-Length"] = "999"
    with pytest.raises(ValueError, match="Content-Length mismatch"):
        download_official_artifact(
            "https://download.microsoft.com/update.msu",
            tmp_path,
            kind="msu",
            opener=FakeOpener(response),
        )
    assert not list(tmp_path.iterdir())


def test_verifier_rejects_tampering_and_unknown_claims(tmp_path: Path) -> None:
    result = download_official_artifact(
        "https://download.microsoft.com/update.msu",
        tmp_path,
        kind="msu",
        opener=FakeOpener(FakeResponse(b"payload")),
    )
    result.artifact_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_official_download_receipt(result.bundle_path)

    result.artifact_path.write_bytes(b"payload")
    receipt_path = result.bundle_path / "receipt.json"
    raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    raw["verified_claims"].append("authenticode-valid")
    receipt_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="verified_claims mismatch"):
        verify_official_download_receipt(result.bundle_path)


def test_cas_rejects_same_bytes_with_different_provenance(tmp_path: Path) -> None:
    first_url = "https://download.microsoft.com/update.msu"
    final_url = "https://download.microsoft.com/final/update.msu"
    body = b"same-payload"
    download_official_artifact(
        first_url,
        tmp_path,
        kind="msu",
        opener=FakeOpener(FakeResponse(body, final_url=final_url)),
    )
    with pytest.raises(ValueError, match="different acquisition provenance"):
        download_official_artifact(
            "https://www.microsoft.com/other.msu",
            tmp_path,
            kind="msu",
            opener=FakeOpener(FakeResponse(body, final_url=final_url)),
        )
    with pytest.raises(ValueError, match="different acquisition provenance"):
        download_official_artifact(
            first_url,
            tmp_path,
            kind="cab",
            opener=FakeOpener(FakeResponse(body, final_url=final_url)),
        )
    assert len(list(tmp_path.iterdir())) == 1


def test_verifier_rejects_extra_files_and_duplicate_keys(tmp_path: Path) -> None:
    result = download_official_artifact(
        "https://download.microsoft.com/update.msu",
        tmp_path,
        kind="msu",
        opener=FakeOpener(FakeResponse(b"payload")),
    )
    extra = result.bundle_path / "untracked"
    extra.write_text("extra", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain exactly"):
        verify_official_download_receipt(result.bundle_path)
    extra.unlink()

    receipt = result.bundle_path / "receipt.json"
    text = receipt.read_text(encoding="utf-8")
    receipt.write_text(
        text.replace('"producer":', '"producer": "duplicate", "producer":', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key: producer"):
        verify_official_download_receipt(result.bundle_path)


def test_verify_cli_emits_bound_receipt(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    result = download_official_artifact(
        "https://download.microsoft.com/update.msu",
        tmp_path,
        kind="msu",
        opener=FakeOpener(FakeResponse(b"payload")),
    )
    assert main(["windows-official-verify", str(result.bundle_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["artifact_sha256"] == result.artifact_sha256
    assert output["receipt_sha256"] == result.receipt_sha256

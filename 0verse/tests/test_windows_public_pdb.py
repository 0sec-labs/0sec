from __future__ import annotations

import hashlib
import json
from http.client import HTTPMessage
from pathlib import Path
from urllib.request import Request

import pytest

from zeroverse.cli import main
from zeroverse.windows_public_pdb import (
    _SymbolRedirectHandler,
    download_public_pdb,
    public_pdb_url,
    verify_public_pdb_receipt,
)

GUID = "93330237-B14D-5026-D9F6-AE42B34F869F"


class FakeResponse:
    def __init__(self, body: bytes, final_url: str) -> None:
        self.body = body
        self.offset = 0
        self.final_url = final_url
        self.status = 200
        self.headers = {
            "Content-Length": str(len(body)),
            "Content-Type": "application/octet-stream",
            "ETag": '"fixture"',
            "Last-Modified": "Mon, 01 Apr 2024 23:02:34 GMT",
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

    def __call__(self, request: Request, *, timeout: float) -> FakeResponse:
        assert timeout > 0
        self.request = request
        return self.response


def _identities(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pdb_guid: str = GUID,
    stripped: bool = True,
) -> None:
    monkeypatch.setattr(
        "zeroverse.windows_public_pdb.pe_codeview_identity",
        lambda _path: (GUID, 1, r"C:\symbols\vmswitch.pdb"),
    )
    monkeypatch.setattr(
        "zeroverse.windows_public_pdb.pdb_codeview_identity",
        lambda _path: (pdb_guid, 4, stripped),
    )


def test_url_is_derived_from_pe_guid_age_and_basename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "vmswitch.sys"
    binary.write_bytes(b"MZ")
    _identities(monkeypatch)
    assert public_pdb_url(binary) == (
        "https://msdl.microsoft.com/download/symbols/vmswitch.pdb/"
        "93330237B14D5026D9F6AE42B34F869F1/vmswitch.pdb"
    )


def test_download_records_public_age_mismatch_without_sas_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "vmswitch.sys"
    binary.write_bytes(b"MZ-GA-vmswitch")
    store = tmp_path / "store"
    store.mkdir()
    _identities(monkeypatch)
    sas = "sv=2019-07-07&sig=secret-value&se=2026-07-17"
    final = f"https://vsblobprodshard9.blob.core.windows.net/container/object.blob?{sas}"
    opener = FakeOpener(FakeResponse(b"public-stripped-pdb", final))
    result = download_public_pdb(binary, store, opener=opener)
    assert result.pe_age == 1
    assert result.pdb_age == 4
    assert result.exact_age_match is False
    assert verify_public_pdb_receipt(binary, result.bundle_path) == result
    raw_bytes = (result.bundle_path / "receipt.json").read_bytes()
    assert b"secret-value" not in raw_bytes
    raw = json.loads(raw_bytes)
    assert raw["source"]["final_url_redacted"].endswith("/container/object.blob")
    assert raw["source"]["final_query_sha256"] == hashlib.sha256(sas.encode()).hexdigest()
    assert raw["exact_age_match"] is False
    assert "rather than accepted as exact identity" in raw["proof_limit"]
    assert opener.request is not None
    assert opener.request.full_url == public_pdb_url(binary)

    assert main(["windows-public-pdb-verify", str(binary), str(result.bundle_path)]) == 0


@pytest.mark.parametrize(
    ("pdb_guid", "stripped", "message"),
    [
        ("11111111-2222-3333-4444-555555555555", True, "GUID does not match"),
        (GUID, False, "requires a stripped PDB"),
    ],
)
def test_download_rejects_unbound_or_private_pdb(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pdb_guid: str,
    stripped: bool,
    message: str,
) -> None:
    binary = tmp_path / "vmswitch.sys"
    binary.write_bytes(b"MZ")
    store = tmp_path / "store"
    store.mkdir()
    _identities(monkeypatch, pdb_guid=pdb_guid, stripped=stripped)
    with pytest.raises(ValueError, match=message):
        download_public_pdb(
            binary,
            store,
            opener=FakeOpener(FakeResponse(b"pdb", public_pdb_url(binary))),
        )
    assert not list(store.iterdir())


def test_redirect_handler_rejects_non_azure_destination() -> None:
    handler = _SymbolRedirectHandler()
    with pytest.raises(ValueError, match="Azure HTTPS blob URL"):
        handler.redirect_request(
            Request("https://msdl.microsoft.com/download/symbols/x.pdb/key/x.pdb"),
            None,  # type: ignore[arg-type]
            302,
            "Found",
            HTTPMessage(),
            "https://attacker.example/capture?sig=secret",
        )


def test_verifier_rejects_receipt_claim_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "vmswitch.sys"
    binary.write_bytes(b"MZ")
    store = tmp_path / "store"
    store.mkdir()
    _identities(monkeypatch)
    result = download_public_pdb(
        binary,
        store,
        opener=FakeOpener(FakeResponse(b"pdb", public_pdb_url(binary))),
    )
    receipt = result.bundle_path / "receipt.json"
    raw = json.loads(receipt.read_text(encoding="utf-8"))
    raw["exact_age_match"] = True
    receipt.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="exact_age_match"):
        verify_public_pdb_receipt(binary, result.bundle_path)


def test_repeat_download_does_not_return_stale_route_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "vmswitch.sys"
    binary.write_bytes(b"MZ")
    store = tmp_path / "store"
    store.mkdir()
    _identities(monkeypatch)

    def response(query: str) -> FakeOpener:
        return FakeOpener(
            FakeResponse(
                b"pdb",
                f"https://vsblobprodshard9.blob.core.windows.net/c/o?sig={query}",
            )
        )

    download_public_pdb(binary, store, opener=response("first"))
    with pytest.raises(ValueError, match="already retained"):
        download_public_pdb(binary, store, opener=response("second"))

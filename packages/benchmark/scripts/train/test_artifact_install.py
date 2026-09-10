import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import artifact_install


def authorized(content: bytes):
    return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({
        "authorized": True, "versionId": "accepted",
        "fileDigest": "sha256:" + hashlib.sha256(content).hexdigest(),
    }))


def install(candidate: Path, destination: Path):
    return artifact_install.install_authorized_artifact(
        candidate.parent / "store", "accepted", candidate, "runtime/model.json", "router", destination
    )


def test_installs_exact_exported_bytes_without_text_conversion(tmp_path, monkeypatch):
    content = b'{"exported":true}\r\n\x00'
    candidate = tmp_path / "export.json"
    destination = tmp_path / "installed.json"
    candidate.write_bytes(content)
    destination.write_bytes(b"old model")
    monkeypatch.setattr(artifact_install.subprocess, "run", lambda *args, **kwargs: authorized(content))
    install(candidate, destination)
    assert destination.read_bytes() == content


def test_rejects_bytes_replaced_after_authorization_without_touching_installed_model(tmp_path, monkeypatch):
    original = b'{"exported":"evaluated"}'
    candidate = tmp_path / "export.json"
    destination = tmp_path / "installed.json"
    candidate.write_bytes(original)
    destination.write_bytes(b"accepted parent")

    def authorize_then_replace(*args, **kwargs):
        candidate.write_bytes(b'{"exported":"not evaluated"}')
        return authorized(original)

    monkeypatch.setattr(artifact_install.subprocess, "run", authorize_then_replace)
    with pytest.raises(SystemExit):
        install(candidate, destination)
    assert destination.read_bytes() == b"accepted parent"


def test_failed_atomic_install_preserves_parent_and_leaves_no_partial_file(tmp_path, monkeypatch):
    content = b"evaluated export"
    candidate = tmp_path / "export.json"
    destination = tmp_path / "installed.json"
    candidate.write_bytes(content)
    destination.write_bytes(b"accepted parent")
    before = set(tmp_path.iterdir())
    monkeypatch.setattr(artifact_install.subprocess, "run", lambda *args, **kwargs: authorized(content))

    def denied(*args):
        raise OSError("installation denied")

    monkeypatch.setattr(artifact_install.os, "replace", denied)
    with pytest.raises(SystemExit):
        install(candidate, destination)
    assert destination.read_bytes() == b"accepted parent"
    assert set(tmp_path.iterdir()) == before


def test_unstructured_digest_text_cannot_authorize_installation(tmp_path, monkeypatch):
    candidate = tmp_path / "export.json"
    destination = tmp_path / "installed.json"
    candidate.write_bytes(b"unapproved bytes")
    text = "OK artifact=injected digest=sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
    monkeypatch.setattr(artifact_install.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=text, stderr=""))
    with pytest.raises(SystemExit):
        install(candidate, destination)
    assert not destination.exists()

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from zeroverse.windows_token_attestation import (
    SCHEMA_VERSION,
    load_windows_token_contract_fixture,
    retain_windows_token_contract_fixture,
)

FIXTURE = Path(__file__).parent / "fixtures" / "windows-token-capture-v1" / "contract.json"


def load_fixture(path: Path = FIXTURE):
    return load_windows_token_contract_fixture(path)


def write_variant(
    tmp_path: Path, update: Callable[[dict[str, Any]], None]
) -> Path:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    update(raw)
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_contract_fixture_is_per_run_canonical_and_non_claimable(tmp_path: Path) -> None:
    verified = load_fixture()
    assert verified.contract.schema_version == SCHEMA_VERSION
    assert verified.contract.case == "control"
    assert verified.contract.fixture is True
    assert verified.contract.claim_eligible is False
    assert verified.sha256 == hashlib.sha256(verified.canonical_bytes).hexdigest()

    destination, digest = retain_windows_token_contract_fixture(
        verified, tmp_path / "token-contract.json"
    )
    assert digest == verified.sha256
    assert destination.read_bytes() == verified.canonical_bytes
    with pytest.raises(FileExistsError):
        retain_windows_token_contract_fixture(verified, destination)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        (lambda raw: raw.update(fixture=False), "only non-claim"),
        (lambda raw: raw.update(claim_eligible=True), "only non-claim"),
        (lambda raw: raw["finish_token"].update(elevated=True), "remain unprivileged"),
        (
            lambda raw: raw["start_token"].update(
                enabled_privileges=["SeImpersonatePrivilege"]
            ),
            "remain unprivileged",
        ),
        (
            lambda raw: raw["finish_token"].update(
                enabled_privileges=["SeCreateTokenPrivilege"]
            ),
            "remain unprivileged",
        ),
        (
            lambda raw: raw["finish_token"].update(
                token_id=raw["start_token"]["token_id"]
            ),
            "identities must be distinct",
        ),
        (lambda raw: raw.update(weaponization=True), "forbid"),
        (lambda raw: raw.update(run_nonce=raw["capture_nonce"]), "nonces must be distinct"),
        (lambda raw: raw.update(case="unknown"), "target or control"),
        (lambda raw: raw.update(trial=0), "positive integer"),
    ],
)
def test_rejects_live_unsafe_or_ambiguous_contracts(
    tmp_path: Path,
    update: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        load_fixture(write_variant(tmp_path, update))


def test_rejects_duplicate_unknown_keys_and_symlinks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_fixture(duplicate)

    unknown = write_variant(tmp_path, lambda raw: raw.update(impact="system"))
    with pytest.raises(ValueError, match="exactly"):
        load_fixture(unknown)

    link = tmp_path / "link.json"
    link.symlink_to(FIXTURE)
    with pytest.raises(OSError, match="symlinks are forbidden"):
        load_fixture(link)

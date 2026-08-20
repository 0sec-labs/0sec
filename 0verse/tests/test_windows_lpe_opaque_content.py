from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeroverse.windows_lpe_opaque_content import load_windows_lpe_opaque_content


def _write(path: Path, files: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-lpe-opaque-content/v1",
                "files": files,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def test_consumes_exact_canonical_prehashed_files(tmp_path: Path) -> None:
    path = tmp_path / "opaque.json"
    _write(
        path,
        [
            {"path": "a/artifact", "sha256": "1" * 64, "size_bytes": 8},
            {"path": "b/transcript", "sha256": "2" * 64, "size_bytes": 0},
        ],
    )
    content = load_windows_lpe_opaque_content(path)
    content.require("a/artifact", "1" * 64, 8)
    ref = content.consume("b/transcript")
    assert ref.size_bytes == 0
    content.require_all_consumed()


@pytest.mark.parametrize(
    ("files", "message"),
    [
        (
            [{"path": "../escape", "sha256": "1" * 64, "size_bytes": 1}],
            "portable and relative",
        ),
        (
            [
                {"path": "b", "sha256": "1" * 64, "size_bytes": 1},
                {"path": "a", "sha256": "2" * 64, "size_bytes": 1},
            ],
            "path-sorted",
        ),
        (
            [{"path": "a", "sha256": "x" * 64, "size_bytes": 1}],
            "SHA-256",
        ),
    ],
)
def test_rejects_unsafe_or_noncanonical_entries(
    tmp_path: Path, files: list[dict[str, object]], message: str
) -> None:
    path = tmp_path / "opaque.json"
    _write(path, files)
    with pytest.raises(ValueError, match=message):
        load_windows_lpe_opaque_content(path)


def test_rejects_mismatch_unused_duplicate_keys_and_noncanonical_json(
    tmp_path: Path,
) -> None:
    path = tmp_path / "opaque.json"
    files = [{"path": "a", "sha256": "1" * 64, "size_bytes": 1}]
    _write(path, files)
    content = load_windows_lpe_opaque_content(path)
    with pytest.raises(ValueError, match="mismatch"):
        content.require("a", "2" * 64, 1)
    with pytest.raises(ValueError, match="unused"):
        content.require_all_consumed()

    path.write_text(
        '{"schema_version":"0verse.windows-lpe-opaque-content/v1",'
        '"schema_version":"0verse.windows-lpe-opaque-content/v1","files":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_windows_lpe_opaque_content(path)

    path.write_text(
        json.dumps(
            {
                "schema_version": "0verse.windows-lpe-opaque-content/v1",
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not canonical"):
        load_windows_lpe_opaque_content(path)

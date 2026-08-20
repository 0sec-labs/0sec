"""Structured seed-corpus hook (opt-in ZEROVERSE_SEED_DIR) for parser targets.

Token-derived seeds can build a magic header but not a whole valid container, so
a coverage-guided fuzzer never reaches a format-specific parser sink from them. A
handful of real files (valid JPEG/EXIF/RTF/…) give it a foothold deep in the
parser. This proves the file-seed hook reads real inputs and is prepended to the
token seeds, and stays inert when unset.
"""

from zeroverse.fuzz.aflpp import (
    env_seed_files,
    initial_seeds,
    seeds_from_files,
    seeds_from_tokens,
)


def test_seeds_from_files_reads_dir_and_file(tmp_path):
    (tmp_path / "a.jpg").write_bytes(b"\xff\xd8\xff\xe1AAAA")
    (tmp_path / "b.rtf").write_bytes(b"{\\rtf1 BBBB}")
    seeds = seeds_from_files(str(tmp_path))
    assert b"\xff\xd8\xff\xe1AAAA" in seeds
    assert b"{\\rtf1 BBBB}" in seeds
    # a single file path also works
    assert seeds_from_files(str(tmp_path / "a.jpg")) == [b"\xff\xd8\xff\xe1AAAA"]


def test_seeds_from_files_bounds(tmp_path):
    (tmp_path / "big").write_bytes(b"Z" * 100)
    assert seeds_from_files(str(tmp_path), max_bytes=10) == [b"Z" * 10]
    for i in range(5):
        (tmp_path / f"f{i}").write_bytes(b"x")
    assert len(seeds_from_files(str(tmp_path), max_files=3)) == 3


def test_env_seed_files_opt_in(tmp_path, monkeypatch):
    (tmp_path / "s.jpg").write_bytes(b"\xff\xd8seed")
    monkeypatch.delenv("ZEROVERSE_SEED_DIR", raising=False)
    assert env_seed_files() == []                       # unset -> inert
    monkeypatch.setenv("ZEROVERSE_SEED_DIR", str(tmp_path))
    assert b"\xff\xd8seed" in env_seed_files()


def test_initial_seeds_prepends_file_seeds(tmp_path, monkeypatch):
    (tmp_path / "s.jpg").write_bytes(b"\xff\xd8REAL")
    monkeypatch.setenv("ZEROVERSE_SEED_DIR", str(tmp_path))
    seeds = initial_seeds(["MAGIC"])
    assert seeds[0] == b"\xff\xd8REAL"                  # structured file seed first
    assert any(s in seeds for s in seeds_from_tokens(["MAGIC"]))  # then token seeds


def test_initial_seeds_default_unchanged(monkeypatch):
    monkeypatch.delenv("ZEROVERSE_SEED_DIR", raising=False)
    assert initial_seeds(["MAGIC"]) == seeds_from_tokens(["MAGIC"])
    assert initial_seeds([]) == [b"\x00"]               # never empty

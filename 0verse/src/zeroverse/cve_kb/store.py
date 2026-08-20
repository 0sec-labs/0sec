"""Local, dependency-free store for normalized :class:`CveRecord`s.

Backed by a single newline-delimited JSON file (``records.jsonl``) plus in-memory
indices built on load. A JSONL file (not sqlite) keeps the store diff-friendly,
trivially inspectable, and importable without a DB dependency — the corpus is
tens of thousands of records at most for the surfaces we care about, which loads
in well under a second. Swap for sqlite behind this same interface if the NVD
full mirror (~250k CVEs) is ever ingested wholesale.

Indices:
  * by id / alias  — O(1) exact CVE/GHSA lookup
  * by file token  — driver ``.sys``/binary filename -> records (the closed-source
                     attribution path, where no CPE exists)
  * by vendor:product token, by CPE product — for the CPE version-range path
  * by CWE         — coarse bucketing

Upsert is idempotent on ``id``: re-ingesting the same CVE from a fresher feed
replaces the record. Two sources describing the same CVE (NVD + OSV) are merged
by :func:`merge_records` so neither loses fields the other has.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import CveRecord

DEFAULT_STORE_ENV = "ZEROVERSE_CVE_KB_DIR"


def default_store_dir() -> Path:
    """Where the KB lives. Overridable via ``ZEROVERSE_CVE_KB_DIR`` (bench runs
    point this at a shared mirror); otherwise a package-local ``kb_store/``."""
    env = os.environ.get(DEFAULT_STORE_ENV)
    if env:
        return Path(env)
    return Path(__file__).resolve().parent / "kb_store"


def merge_records(a: CveRecord, b: CveRecord) -> CveRecord:
    """Merge two records for the same id (field-wise union; ``a`` wins on scalars
    it already has). Used when NVD and OSV both describe one CVE."""

    def _pick(x: str, y: str) -> str:
        return x if x else y

    def _union(xs: tuple[Any, ...], ys: tuple[Any, ...]) -> tuple[Any, ...]:
        out: list[Any] = list(xs)
        for y in ys:
            if y not in out:
                out.append(y)
        return tuple(out)

    merged_sources = "+".join(dict.fromkeys([*a.source.split("+"), *b.source.split("+")]))
    return CveRecord(
        id=a.id,
        source=merged_sources,
        description=_pick(a.description, b.description),
        vendor=_pick(a.vendor, b.vendor),
        product=_pick(a.product, b.product),
        cwes=_union(a.cwes, b.cwes),
        aliases=_union(a.aliases, b.aliases),
        cpe_matches=_union(a.cpe_matches, b.cpe_matches),
        affected=_union(a.affected, b.affected),
        files=_union(a.files, b.files),
        functions=_union(a.functions, b.functions),
        references=_union(a.references, b.references),
        published=_pick(a.published, b.published),
    )


class CveStore:
    """In-memory index over a JSONL record file."""

    def __init__(self, records: Iterable[CveRecord] | None = None) -> None:
        self._by_id: dict[str, CveRecord] = {}
        self._by_alias: dict[str, str] = {}          # alias id -> primary id
        self._by_file: dict[str, set[str]] = defaultdict(set)
        self._by_cpe_product: dict[str, set[str]] = defaultdict(set)  # "vendor:product"
        self._by_cwe: dict[str, set[str]] = defaultdict(set)
        if records:
            for r in records:
                self.upsert(r)

    # --- mutation ---------------------------------------------------------
    def upsert(self, rec: CveRecord) -> None:
        existing = self._by_id.get(rec.id)
        if existing is not None:
            rec = merge_records(existing, rec)
            self._unindex(existing)
        self._by_id[rec.id] = rec
        self._index(rec)

    def _index(self, rec: CveRecord) -> None:
        for a in rec.aliases:
            self._by_alias[a.upper()] = rec.id
        for f in rec.files:
            self._by_file[f.lower()].add(rec.id)
        for cwe in rec.cwes:
            self._by_cwe[cwe.upper()].add(rec.id)
        for key in _cpe_product_keys(rec):
            self._by_cpe_product[key].add(rec.id)
        for aff in rec.affected:
            self._by_cpe_product[f"{aff.ecosystem.lower()}:{aff.package.lower()}"].add(rec.id)

    def _unindex(self, rec: CveRecord) -> None:
        for a in rec.aliases:
            self._by_alias.pop(a.upper(), None)
        for f in rec.files:
            self._by_file.get(f.lower(), set()).discard(rec.id)
        for cwe in rec.cwes:
            self._by_cwe.get(cwe.upper(), set()).discard(rec.id)
        for key in _cpe_product_keys(rec):
            self._by_cpe_product.get(key, set()).discard(rec.id)

    # --- lookup -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._by_id)

    def all(self) -> list[CveRecord]:
        return list(self._by_id.values())

    def get(self, cve_or_alias_id: str) -> CveRecord | None:
        key = cve_or_alias_id.upper()
        if key in self._by_id:
            return self._by_id[key]
        # ids may be stored with original casing for GHSA; try raw then alias.
        if cve_or_alias_id in self._by_id:
            return self._by_id[cve_or_alias_id]
        primary = self._by_alias.get(key)
        return self._by_id.get(primary) if primary else None

    def by_file(self, filename: str) -> list[CveRecord]:
        ids = self._by_file.get(filename.lower(), set())
        return [self._by_id[i] for i in ids]

    def by_cwe(self, cwe: str) -> list[CveRecord]:
        return [self._by_id[i] for i in self._by_cwe.get(cwe.upper(), set())]

    def by_cpe_product(self, vendor: str, product: str) -> list[CveRecord]:
        ids = self._by_cpe_product.get(f"{vendor.lower()}:{product.lower()}", set())
        return [self._by_id[i] for i in ids]

    def cpe_product_keys(self) -> list[str]:
        return list(self._by_cpe_product)

    # --- persistence ------------------------------------------------------
    def save(self, path: str | os.PathLike[str] | None = None) -> Path:
        p = Path(path) if path is not None else (default_store_dir() / "records.jsonl")
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for rec in self._by_id.values():
                fh.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")
        tmp.replace(p)
        return p

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> CveStore:
        p = Path(path) if path is not None else (default_store_dir() / "records.jsonl")
        store = cls()
        if not p.exists():
            return store
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                store.upsert(CveRecord.from_dict(json.loads(line)))
        return store


def _cpe_product_keys(rec: CveRecord) -> set[str]:
    """"vendor:product" keys derived from a record's CPE match criteria (and the
    record's own vendor/product prose as a fallback)."""
    keys: set[str] = set()
    for m in rec.cpe_matches:
        parsed = _cpe_vendor_product(m.criteria)
        if parsed:
            keys.add(f"{parsed[0]}:{parsed[1]}")
    if rec.vendor and rec.product:
        keys.add(f"{rec.vendor.lower()}:{rec.product.lower()}")
    return keys


def _cpe_vendor_product(criteria: str) -> tuple[str, str] | None:
    # cpe:2.3:part:vendor:product:version:...
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3].lower(), parts[4].lower()
    return None

"""Ingest free structured feeds into the local :class:`CveStore`.

Dependency-free: fetch is stdlib ``urllib``. Every fetcher degrades gracefully —
a network failure returns an empty list with a logged note rather than raising,
so ``build_store`` always yields a usable (possibly bundled-only) store. Heavy
full-mirror ingestion (NVD's ~250k CVEs, the whole OSV corpus) should run on
bench and write ``records.jsonl`` to a shared ``ZEROVERSE_CVE_KB_DIR``; the Mac
loads that file. The bundled ``data/sample_*.json`` payloads make ingest + the
whole gate reproducible **offline** (tests never hit the network).

Feeds:
  * NVD JSON 2.0        — CVE + CPE version ranges + CWE (``nvd.normalize_*``)
  * OSV.dev / GHSA      — open-source package-level ranges (``osv.normalize_*``)
  * loldrivers BY NAME  — the driver blocklist, keyed by filename (NOT by hash),
                          normalized to KNOWN-driver CveRecords so a fresh hash
                          of known-vulnerable code still resolves.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import nvd, osv
from .models import CveRecord
from .store import CveStore

DATA_DIR = Path(__file__).resolve().parent / "data"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY_API = "https://api.osv.dev/v1/query"
LOLDRIVERS_API = "https://www.loldrivers.io/api/drivers.json"

_USER_AGENT = "0verse-cve-kb/1.0 (+defensive-security)"


# --- low-level HTTP (stdlib, optional) --------------------------------------

def _get_json(url: str, *, timeout: float = 20.0) -> Any:
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url: str, body: dict[str, Any], *, timeout: float = 20.0) -> Any:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": _USER_AGENT, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --- live fetchers (each degrades to [] on failure) -------------------------

def fetch_nvd_cve(cve_id: str, *, timeout: float = 20.0) -> list[CveRecord]:
    try:
        payload = _get_json(f"{NVD_API}?cveId={urllib.parse.quote(cve_id)}", timeout=timeout)
        return nvd.normalize_response(payload)
    except (urllib.error.URLError, OSError, ValueError):
        return []


def fetch_nvd_keyword(
    keyword: str, *, results: int = 200, timeout: float = 30.0
) -> list[CveRecord]:
    """Keyword search (NVD's ``keywordSearch``) — the driver/vendor sweep path."""
    try:
        q = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": results})
        payload = _get_json(f"{NVD_API}?{q}", timeout=timeout)
        return nvd.normalize_response(payload)
    except (urllib.error.URLError, OSError, ValueError):
        return []


def fetch_osv_package(
    name: str, ecosystem: str, version: str = "", *, timeout: float = 20.0
) -> list[CveRecord]:
    body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    try:
        payload = _post_json(OSV_QUERY_API, body, timeout=timeout)
        return osv.normalize_query_response(payload)
    except (urllib.error.URLError, OSError, ValueError):
        return []


def fetch_loldrivers(*, timeout: float = 40.0) -> list[CveRecord]:
    try:
        payload = _get_json(LOLDRIVERS_API, timeout=timeout)
        return normalize_loldrivers(payload)
    except (urllib.error.URLError, OSError, ValueError):
        return []


def fetch_nvd_all(
    *,
    api_key: str | None = None,
    page_size: int = 2000,
    max_pages: int | None = None,
    store: CveStore | None = None,
    log: Callable[[str], None] | None = None,
    timeout: float = 60.0,
) -> CveStore:
    """Paginate the ENTIRE NVD 2.0 corpus via ``startIndex`` into ``store``.

    The full-mirror path when no local NVD tree is available. Honors the NVD
    rate limits (with an API key: ~0.6s between calls; without: ~6s / 5-per-30s).
    ``max_pages`` caps the pull for smoke runs. Resilient: a failed page is
    retried a few times, then the pull stops cleanly with whatever it has.
    """
    import time

    store = store if store is not None else CveStore()
    delay = 0.6 if api_key else 6.0
    headers_extra = {"apiKey": api_key} if api_key else {}
    start = 0
    page = 0
    total = None
    while True:
        if max_pages is not None and page >= max_pages:
            break
        q = urllib.parse.urlencode({"resultsPerPage": page_size, "startIndex": start})
        url = f"{NVD_API}?{q}"
        payload = None
        for attempt in range(4):
            try:
                payload = _get_json_headers(url, headers_extra, timeout=timeout)
                break
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(delay * (attempt + 2))
        if payload is None:
            if log:
                log(f"nvd page@{start}: giving up after retries; stopping")
            break
        recs = nvd.normalize_response(payload)
        for r in recs:
            store.upsert(r)
        total = payload.get("totalResults", total)
        got = len(payload.get("vulnerabilities", []))
        if log:
            log(f"nvd page@{start}: +{len(recs)} (store={len(store)}, total={total})")
        page += 1
        start += page_size
        if got < page_size or (total is not None and start >= total):
            break
        time.sleep(delay)
    return store


def load_nvd_dir(path: str | Path, *, store: CveStore | None = None,
                 log: Callable[[str], None] | None = None) -> CveStore:
    """Ingest a directory tree of NVD 2.0 JSON files (e.g. the fkie-cad mirror,
    or a dump of API responses). Accepts ``.json`` and ``.json.gz``."""
    store = store if store is not None else CveStore()
    root = Path(path)
    files = sorted([*root.rglob("*.json"), *root.rglob("*.json.gz")])
    n = 0
    for i, p in enumerate(files):
        for rec in nvd.normalize_any(_read_json_maybe_gz(p)):
            store.upsert(rec)
            n += 1
        if log and (i + 1) % 5000 == 0:
            log(f"nvd dir: {i + 1}/{len(files)} files, {len(store)} records")
    if log:
        log(f"nvd dir: {len(files)} files -> {n} records parsed, store={len(store)}")
    return store


def load_osv_dir(path: str | Path, *, store: CveStore | None = None,
                 log: Callable[[str], None] | None = None) -> CveStore:
    """Ingest a directory tree of OSV JSON files (one vuln object per file)."""
    store = store if store is not None else CveStore()
    root = Path(path)
    files = sorted([*root.rglob("*.json"), *root.rglob("*.json.gz")])
    for i, p in enumerate(files):
        for rec in osv.normalize_query_response(_read_json_maybe_gz(p)):
            store.upsert(rec)
        if log and (i + 1) % 20000 == 0:
            log(f"osv dir: {i + 1}/{len(files)} files, {len(store)} records")
    if log:
        log(f"osv dir: {len(files)} files, store={len(store)}")
    return store


def load_osv_zip(path: str | Path, *, store: CveStore | None = None,
                 log: Callable[[str], None] | None = None) -> CveStore:
    """Ingest an OSV ecosystem ``all.zip`` (each member is one vuln JSON)."""
    import zipfile

    store = store if store is not None else CveStore()
    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if n.endswith(".json")]
        for i, name in enumerate(names):
            try:
                payload = json.loads(zf.read(name).decode("utf-8"))
            except (ValueError, OSError):
                continue
            for rec in osv.normalize_query_response(payload):
                store.upsert(rec)
            if log and (i + 1) % 20000 == 0:
                log(f"osv zip {Path(path).name}: {i + 1}/{len(names)}, store={len(store)}")
    if log:
        log(f"osv zip {Path(path).name}: {len(names)} members, store={len(store)}")
    return store


def _get_json_headers(url: str, extra: dict[str, str], *, timeout: float = 60.0) -> Any:
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json", **extra}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _read_json_maybe_gz(p: Path) -> Any:
    if p.suffix == ".gz":
        import gzip

        with gzip.open(p, "rt", encoding="utf-8") as fh:
            return json.load(fh)
    return json.loads(p.read_text(encoding="utf-8"))


# --- loldrivers BY NAME normalization ---------------------------------------

def normalize_loldrivers(payload: Any) -> list[CveRecord]:
    """Normalize the loldrivers catalog into KNOWN-driver records keyed BY NAME.

    The catalog lists each vulnerable/malicious driver with ``Tags`` (filenames),
    ``KnownVulnerableSamples`` (hashes we ignore — hash is the evasion axis),
    ``Commands``, ``MitreID`` and any ``CVE`` references. We key on the filename
    so a driver that changed only its hash still resolves as KNOWN.
    """
    entries = payload if isinstance(payload, list) else payload.get("drivers", [])
    out: list[CveRecord] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        names = _loldrivers_filenames(e)
        if not names:
            continue
        cves = tuple(sorted({c.upper() for c in _loldrivers_cves(e)}))
        desc = str(
            e.get("Description") or e.get("Category") or "loldrivers vulnerable/malicious driver"
        )
        cat = str(e.get("Category", ""))
        primary = cves[0] if cves else f"LOLDRV-{names[0]}"
        aliases = tuple(n for n in names) + tuple(c for c in cves if c != primary)
        out.append(
            CveRecord(
                id=primary,
                source="loldrivers",
                description=f"loldrivers ({cat}): {desc}",
                files=tuple(names),
                aliases=aliases,
                references=("https://www.loldrivers.io/",),
            )
        )
    return out


def _loldrivers_filenames(e: dict[str, Any]) -> tuple[str, ...]:
    names: set[str] = set()
    for tag in e.get("Tags", []) or []:
        t = str(tag).strip().lower()
        if t.endswith((".sys", ".dll", ".exe")):
            names.add(t)
    for sample in e.get("KnownVulnerableSamples", []) or []:
        fn = str((sample or {}).get("Filename", "")).strip().lower()
        if fn.endswith((".sys", ".dll", ".exe")):
            names.add(fn)
    return tuple(sorted(names))


def _loldrivers_cves(e: dict[str, Any]) -> list[str]:
    import re

    blob = json.dumps(e)
    return re.findall(r"CVE-\d{4}-\d{4,7}", blob, flags=re.IGNORECASE)


# --- driver novelty-tally (our own curated per-driver -> CVE table) ----------

def normalize_driver_tally(payload: Any) -> list[CveRecord]:
    """Normalize the windows-driver corpus ``novelty-tally.json`` produced by the
    driver novelty gate into KNOWN-driver records keyed BY NAME + CVE.

    Shape: ``drivers.<filename>.{verdict, cve_ids, advisory_ids, sources, label}``.
    A driver with cve_ids keys on its first CVE (filename as a file token so it
    resolves by name); an advisory-only driver keys ``LOLDRV-<name>``. Drivers the
    gate marked NO-PUBLIC-RECORD are deliberately NOT added — absence is the point,
    and adding them would fabricate a known record.
    """
    drivers = payload.get("drivers", {}) if isinstance(payload, dict) else {}
    out: list[CveRecord] = []
    for name, entry in drivers.items():
        if not isinstance(entry, dict):
            continue
        name = str(name).strip().lower()
        verdict = str(entry.get("verdict", "")).upper()
        cve_ids = tuple(sorted({str(c).upper() for c in entry.get("cve_ids", []) if c}))
        advisory_ids = tuple(sorted({str(a).upper() for a in entry.get("advisory_ids", []) if a}))
        sources = tuple(str(s) for s in entry.get("sources", []) if s)
        # Only KNOWN-* verdicts become records. A NO-PUBLIC-RECORD driver is
        # deliberately absent — synthesizing a record would fabricate a known
        # match. A KNOWN-ADVISORY with no parsed id is still a real public
        # vulnerable-driver record (keyed by name), so it is kept.
        if not verdict.startswith("KNOWN"):
            continue
        primary = cve_ids[0] if cve_ids else f"LOLDRV-{name}"
        aliases = tuple(dict.fromkeys((name, *cve_ids[1:], *advisory_ids)))
        label = str(entry.get("label", "")) or verdict
        out.append(
            CveRecord(
                id=primary,
                source="driver-tally",
                description=f"0verse driver novelty gate: {label} ({name})",
                files=(name,),
                aliases=aliases,
                references=sources or ("https://www.loldrivers.io/",),
            )
        )
    return out


# --- bundled offline payloads -----------------------------------------------

def load_bundled(store: CveStore | None = None) -> CveStore:
    """Ingest the bundled real ``data/sample_*.json`` payloads (offline)."""
    if store is None:
        store = CveStore()
    for p in sorted(DATA_DIR.glob("sample_nvd_*.json")):
        for rec in nvd.normalize_response(json.loads(p.read_text())):
            store.upsert(rec)
    for p in sorted(DATA_DIR.glob("sample_osv_*.json")):
        for rec in osv.normalize_query_response(json.loads(p.read_text())):
            store.upsert(rec)
    for p in sorted(DATA_DIR.glob("sample_loldrivers_*.json")):
        for rec in normalize_loldrivers(json.loads(p.read_text())):
            store.upsert(rec)
    for p in sorted(DATA_DIR.glob("sample_driver_tally*.json")):
        for rec in normalize_driver_tally(json.loads(p.read_text())):
            store.upsert(rec)
    return store


def build_store(
    *,
    include_bundled: bool = True,
    include_seed: bool = True,
    nvd_cves: list[str] | None = None,
    nvd_keywords: list[str] | None = None,
    osv_packages: list[tuple[str, str]] | None = None,
    include_loldrivers: bool = False,
    log: Callable[[str], None] | None = None,
) -> CveStore:
    """Assemble a store from bundled data + seed table + any requested live feeds.

    Live feeds are opt-in (pass ids/keywords/packages, or ``include_loldrivers``).
    A live failure is logged and skipped, never fatal.
    """
    from .seed import seed_records  # local import: seed depends on models only

    def _log(msg: str) -> None:
        if log:
            log(msg)

    store = CveStore()
    if include_bundled:
        load_bundled(store)
        _log(f"bundled: store now {len(store)} records")
    if include_seed:
        for rec in seed_records():
            store.upsert(rec)
        _log(f"seed: store now {len(store)} records")
    for cid in nvd_cves or []:
        recs = fetch_nvd_cve(cid)
        for r in recs:
            store.upsert(r)
        _log(f"nvd {cid}: +{len(recs)}")
    for kw in nvd_keywords or []:
        recs = fetch_nvd_keyword(kw)
        for r in recs:
            store.upsert(r)
        _log(f"nvd kw '{kw}': +{len(recs)}")
    for name, eco in osv_packages or []:
        recs = fetch_osv_package(name, eco)
        for r in recs:
            store.upsert(r)
        _log(f"osv {eco}/{name}: +{len(recs)}")
    if include_loldrivers:
        recs = fetch_loldrivers()
        for r in recs:
            store.upsert(r)
        _log(f"loldrivers: +{len(recs)}")
    return store

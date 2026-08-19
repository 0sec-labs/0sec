#!/usr/bin/env python3
"""Cross-reference syzbot fix commits with CVE databases for ground-truth labels.

Strategy (three data sources, local-first):
  1. nluedtke/linux_kernel_cves kernel_cves.json (~3.1k CVEs, archived 2024)
     Maps CVE → {fixes: <full_hash>, cvss2, cvss3}.
  2. NVD bulk download of ALL Linux kernel CVEs (~15k, paginated at 2000/page).
     Each CVE has references like https://git.kernel.org/stable/c/<hash>.
     We extract commit hashes from those URLs and build a reverse index.
  3. Per-commit NVD keyword search (slow fallback, 1 req / 6s).

Phase 1+2 run automatically and cover ~15k CVEs.  Phase 3 is opt-in.

Outputs enriched JSONL with added fields:
    has_cve       bool   – True if at least one CVE references this fix commit
    cve_id        str    – first matched CVE (or null)
    cve_ids       list   – all matched CVEs
    cvss_score    float  – highest CVSS v3 score across matched CVEs (or null)

Usage:
    python crossref_syzbot_cve.py --input /tmp/syzbot-exploitability.jsonl
    python crossref_syzbot_cve.py --input /tmp/syzbot-exploitability.jsonl --output /tmp/syzbot-cve-labeled.jsonl
    python crossref_syzbot_cve.py --input /tmp/syzbot-exploitability.jsonl --nvd-fallback --nvd-limit 20
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# ── Constants ───────────────────────────────────────────────────────────────

KERNEL_CVES_URL = (
    "https://raw.githubusercontent.com/nluedtke/linux_kernel_cves"
    "/master/data/kernel_cves.json"
)
KERNEL_CVES_CACHE = Path("/tmp/kernel_cves.json")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BULK_CACHE = Path("/tmp/nvd_linux_kernel_cves.json")
NVD_RATE_LIMIT = 6.0  # seconds between requests (no API key)
NVD_PAGE_SIZE = 2000

# Regex to extract commit hashes from kernel.org git URLs
RE_KERNEL_COMMIT = re.compile(
    r"https?://git\.kernel\.org/(?:stable|pub/scm/linux/kernel/git/[^/]+/[^/]+\.git)"
    r"/(?:commit/?\?id=|c/)([0-9a-f]{7,40})"
)

UA = "pwnkit-cve-crossref/0.1"
CACHE_TTL_HOURS = 168  # 1 week


# ── Helpers ─────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _fetch_json(url: str, timeout: int = 60) -> Any:
    return json.loads(_fetch(url, timeout))


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _cache_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age_h = (time.time() - path.stat().st_mtime) / 3600
    return age_h < CACHE_TTL_HOURS


# ── Source 1: nluedtke/linux_kernel_cves ────────────────────────────────────

def download_kernel_cves(force: bool = False) -> dict:
    """Download or load cached kernel_cves.json (~6 MB)."""
    if not force and _cache_fresh(KERNEL_CVES_CACHE):
        age_h = (time.time() - KERNEL_CVES_CACHE.stat().st_mtime) / 3600
        log(f"Using cached {KERNEL_CVES_CACHE} (age {age_h:.0f}h)")
        with open(KERNEL_CVES_CACHE) as f:
            return json.load(f)

    log("Downloading kernel_cves.json from GitHub ...")
    data = _fetch(KERNEL_CVES_URL, timeout=120)
    KERNEL_CVES_CACHE.write_bytes(data)
    log(f"Saved {len(data):,} bytes to {KERNEL_CVES_CACHE}")
    return json.loads(data)


def _extract_cvss_from_nluedtke(entry: dict) -> float | None:
    """Extract best CVSS score from a kernel_cves.json entry."""
    for key in ("cvss3", "cvss2"):
        obj = entry.get(key)
        if obj and isinstance(obj, dict):
            score = obj.get("score")
            if score is not None:
                try:
                    return float(score)
                except (ValueError, TypeError):
                    pass
    return None


def build_index_from_nluedtke(kernel_cves: dict) -> dict[str, list[tuple[str, float | None]]]:
    """Build prefix → [(cve_id, score)] index from nluedtke data."""
    index: dict[str, list[tuple[str, float | None]]] = defaultdict(list)
    n = 0
    for cve_id, entry in kernel_cves.items():
        fixes_hash = (entry.get("fixes") or "").strip()
        if len(fixes_hash) < 8:
            continue
        score = _extract_cvss_from_nluedtke(entry)
        _index_hash(index, fixes_hash, cve_id, score)
        n += 1
    log(f"  nluedtke: indexed {n:,} CVEs with fix commits")
    return index


# ── Source 2: NVD bulk download ─────────────────────────────────────────────

def _extract_cvss_from_nvd(cve_obj: dict) -> float | None:
    """Extract highest CVSS score from an NVD CVE object."""
    metrics = cve_obj.get("metrics", {})
    best = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            s = m.get("cvssData", {}).get("baseScore")
            if s is not None and (best is None or s > best):
                best = s
    return best


def _extract_commits_from_nvd(cve_obj: dict) -> list[str]:
    """Extract kernel git commit hashes from NVD CVE references."""
    commits = []
    for ref in cve_obj.get("references", []):
        url = ref.get("url", "")
        m = RE_KERNEL_COMMIT.search(url)
        if m:
            commits.append(m.group(1))
    return commits


def download_nvd_bulk(force: bool = False) -> list[dict]:
    """Download all Linux kernel CVEs from NVD, paginated. Returns raw CVE list."""
    if not force and _cache_fresh(NVD_BULK_CACHE):
        age_h = (time.time() - NVD_BULK_CACHE.stat().st_mtime) / 3600
        log(f"Using cached NVD bulk data {NVD_BULK_CACHE} (age {age_h:.0f}h)")
        with open(NVD_BULK_CACHE) as f:
            return json.load(f)

    log("Downloading ALL Linux kernel CVEs from NVD (paginated) ...")
    all_vulns = []
    start_index = 0
    total = None

    while True:
        url = (
            f"{NVD_API}"
            f"?virtualMatchString=cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
            f"&resultsPerPage={NVD_PAGE_SIZE}"
            f"&startIndex={start_index}"
        )
        retries = 3
        data = None
        for attempt in range(retries):
            try:
                data = _fetch_json(url, timeout=120)
                break
            except Exception as e:
                log(f"  Page {start_index}: attempt {attempt+1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(NVD_RATE_LIMIT * 2)

        if data is None:
            log(f"  FATAL: Could not fetch page at startIndex={start_index}")
            break

        if total is None:
            total = data.get("totalResults", 0)
            log(f"  NVD reports {total:,} total Linux kernel CVEs")

        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        log(f"  Fetched {len(all_vulns):,} / {total:,}")

        if len(all_vulns) >= total or not vulns:
            break
        start_index += NVD_PAGE_SIZE
        time.sleep(NVD_RATE_LIMIT)

    # Cache the raw data
    log(f"  Caching {len(all_vulns):,} CVE records to {NVD_BULK_CACHE}")
    # Extract just what we need to keep cache manageable
    slim = []
    for v in all_vulns:
        cve = v.get("cve", {})
        slim.append({
            "id": cve.get("id"),
            "references": cve.get("references", []),
            "metrics": cve.get("metrics", {}),
        })
    with open(NVD_BULK_CACHE, "w") as f:
        json.dump(slim, f)
    log(f"  Saved {NVD_BULK_CACHE.stat().st_size / 1e6:.1f} MB cache")

    return slim


def build_index_from_nvd(nvd_cves: list[dict]) -> dict[str, list[tuple[str, float | None]]]:
    """Build prefix → [(cve_id, score)] index from NVD bulk data."""
    index: dict[str, list[tuple[str, float | None]]] = defaultdict(list)
    n_with_commits = 0

    for cve in nvd_cves:
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        score = _extract_cvss_from_nvd(cve)
        commits = _extract_commits_from_nvd(cve)
        if commits:
            n_with_commits += 1
        for h in commits:
            _index_hash(index, h, cve_id, score)

    log(f"  NVD bulk: {n_with_commits:,} CVEs with kernel.org commit refs")
    return index


# ── Shared indexing ─────────────────────────────────────────────────────────

def _index_hash(
    index: dict[str, list[tuple[str, float | None]]],
    full_hash: str,
    cve_id: str,
    score: float | None,
) -> None:
    """Add a commit hash to the reverse index at multiple prefix lengths."""
    full_hash = full_hash.strip().lower()
    record = (cve_id, score)
    for plen in (8, 10, 12, 16, 20, 40):
        if len(full_hash) >= plen:
            prefix = full_hash[:plen]
            if record not in index[prefix]:
                index[prefix].append(record)
    if len(full_hash) not in (8, 10, 12, 16, 20, 40):
        if record not in index[full_hash]:
            index[full_hash].append(record)


def merge_indices(*indices: dict) -> dict[str, list[tuple[str, float | None]]]:
    """Merge multiple prefix indices, deduplicating by CVE ID per prefix."""
    merged: dict[str, list[tuple[str, float | None]]] = defaultdict(list)
    for idx in indices:
        for prefix, records in idx.items():
            existing_cves = {r[0] for r in merged[prefix]}
            for r in records:
                if r[0] not in existing_cves:
                    merged[prefix].append(r)
                    existing_cves.add(r[0])
    return dict(merged)


def lookup_commit(
    index: dict[str, list[tuple[str, float | None]]],
    short_hash: str,
) -> list[tuple[str, float | None]]:
    """Look up a short commit hash in the reverse index."""
    short_hash = short_hash.strip().lower()
    for plen in (len(short_hash), 12, 10, 8):
        prefix = short_hash[:plen]
        if prefix in index:
            return index[prefix]
    return []


# ── Source 3 (optional): per-commit NVD keyword search ──────────────────────

def nvd_search_commit(commit_hash: str) -> list[dict]:
    """Search NVD for a specific commit hash. Returns [{cve_id, cvss_score}]."""
    url = f"{NVD_API}?keywordSearch={commit_hash}&keywordExactMatch"
    try:
        data = _fetch_json(url, timeout=30)
    except urllib.error.HTTPError as e:
        log(f"  NVD HTTP {e.code} for {commit_hash}")
        return []
    except Exception as e:
        log(f"  NVD error for {commit_hash}: {e}")
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        score = _extract_cvss_from_nvd(cve)
        results.append({"cve_id": cve_id, "cvss_score": score})
    return results


# ── Main pipeline ───────────────────────────────────────────────────────────

def enrich_records(
    input_path: str,
    output_path: str | None,
    nvd_fallback: bool = False,
    nvd_limit: int = 0,
    skip_nvd_bulk: bool = False,
    force_refresh: bool = False,
) -> None:
    # Load syzbot data
    records = []
    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    log(f"Loaded {len(records):,} syzbot records")

    with_fix = [r for r in records if r.get("fix_commit")]
    log(f"  {len(with_fix):,} have fix_commit")

    # ── Build combined index ────────────────────────────────────────────
    log("\nBuilding commit → CVE index ...")

    # Source 1: nluedtke
    kernel_cves = download_kernel_cves(force=force_refresh)
    log(f"kernel_cves.json: {len(kernel_cves):,} CVE entries")
    idx1 = build_index_from_nluedtke(kernel_cves)

    # Source 2: NVD bulk
    if not skip_nvd_bulk:
        nvd_cves = download_nvd_bulk(force=force_refresh)
        idx2 = build_index_from_nvd(nvd_cves)
        index = merge_indices(idx1, idx2)
        # Count unique CVEs across both
        all_cves = set()
        for records_list in index.values():
            for cve_id, _ in records_list:
                all_cves.add(cve_id)
        log(f"Combined index: {len(all_cves):,} unique CVEs, "
            f"{len(index):,} prefix entries")
    else:
        log("Skipping NVD bulk download (--skip-nvd-bulk)")
        index = dict(idx1)

    # ── Match ───────────────────────────────────────────────────────────
    matched = 0
    unmatched_with_fix = []
    for rec in records:
        commit = rec.get("fix_commit")
        if not commit:
            rec["has_cve"] = False
            rec["cve_id"] = None
            rec["cve_ids"] = []
            rec["cvss_score"] = None
            continue

        hits = lookup_commit(index, commit)
        if hits:
            matched += 1
            seen = set()
            unique = []
            for cve_id, score in hits:
                if cve_id not in seen:
                    seen.add(cve_id)
                    unique.append((cve_id, score))

            rec["has_cve"] = True
            rec["cve_id"] = unique[0][0]
            rec["cve_ids"] = [c for c, _ in unique]
            scores = [s for _, s in unique if s is not None]
            rec["cvss_score"] = max(scores) if scores else None
        else:
            rec["has_cve"] = False
            rec["cve_id"] = None
            rec["cve_ids"] = []
            rec["cvss_score"] = None
            unmatched_with_fix.append(rec)

    log(f"\nPhase 1+2 results:")
    log(f"  Matched:   {matched:,} / {len(with_fix):,} fix commits have CVE")
    log(f"  Unmatched: {len(unmatched_with_fix):,}")

    # ── Phase 3: per-commit NVD keyword search (optional) ───────────────
    if nvd_fallback and unmatched_with_fix:
        limit = (
            min(nvd_limit, len(unmatched_with_fix))
            if nvd_limit > 0
            else len(unmatched_with_fix)
        )
        log(f"\nPhase 3: NVD keyword search for {limit} unmatched commits "
            f"(~{limit * NVD_RATE_LIMIT / 60:.0f} min) ...")
        nvd_found = 0
        for i, rec in enumerate(unmatched_with_fix[:limit]):
            commit = rec["fix_commit"]
            log(f"  [{i+1}/{limit}] {commit}")
            results = nvd_search_commit(commit)
            if results:
                nvd_found += 1
                rec["has_cve"] = True
                rec["cve_id"] = results[0]["cve_id"]
                rec["cve_ids"] = [r["cve_id"] for r in results]
                scores = [r["cvss_score"] for r in results
                          if r["cvss_score"] is not None]
                rec["cvss_score"] = max(scores) if scores else None
                log(f"    -> {rec['cve_id']} (CVSS {rec['cvss_score']})")
            if i < limit - 1:
                time.sleep(NVD_RATE_LIMIT)
        log(f"  NVD keyword search found {nvd_found} more CVEs "
            f"from {limit} queries")

    # ── Summary ─────────────────────────────────────────────────────────
    cve_count = sum(1 for r in records if r.get("has_cve"))
    score_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "no_score": 0}
    for r in records:
        s = r.get("cvss_score")
        if s is None:
            continue
        if s >= 9.0:
            score_counts["critical"] += 1
        elif s >= 7.0:
            score_counts["high"] += 1
        elif s >= 4.0:
            score_counts["medium"] += 1
        elif s > 0:
            score_counts["low"] += 1
        else:
            score_counts["no_score"] += 1

    log(f"\n{'='*60}")
    log(f"FINAL SUMMARY")
    log(f"  Total records:     {len(records):,}")
    log(f"  With fix_commit:   {len(with_fix):,}")
    log(f"  With CVE:          {cve_count:,} "
        f"({100*cve_count/max(len(with_fix),1):.1f}% of fixes)")
    log(f"  CVSS distribution: {score_counts}")

    # Cross-tab: syzbot heuristic vs CVE ground truth
    cross = Counter()
    for r in records:
        label = r.get("exploitability", "unknown")
        has = "cve" if r.get("has_cve") else "no_cve"
        cross[(label, has)] += 1

    log(f"\nSyzbot-label x CVE cross-tabulation:")
    log(f"  {'label':<25} {'has_cve':>10} {'no_cve':>10} {'cve_rate':>10}")
    for label in sorted(set(la for la, _ in cross)):
        c = cross.get((label, "cve"), 0)
        n = cross.get((label, "no_cve"), 0)
        rate = c / (c + n) * 100 if (c + n) > 0 else 0
        log(f"  {label:<25} {c:>10,} {n:>10,} {rate:>9.1f}%")
    log(f"{'='*60}")

    # Write output
    out = output_path or input_path.replace(".jsonl", "-cve-labeled.jsonl")
    if out == input_path:
        out = input_path + ".cve-labeled.jsonl"

    with open(out, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    log(f"\nWrote {len(records):,} records to {out}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-reference syzbot fix commits with CVE databases"
    )
    parser.add_argument("--input", required=True,
                        help="Input syzbot JSONL file")
    parser.add_argument("--output", default=None,
                        help="Output JSONL (default: <input>-cve-labeled.jsonl)")
    parser.add_argument("--nvd-fallback", action="store_true",
                        help="Per-commit NVD keyword search for unmatched (slow)")
    parser.add_argument("--nvd-limit", type=int, default=0,
                        help="Max per-commit NVD queries (0=unlimited)")
    parser.add_argument("--skip-nvd-bulk", action="store_true",
                        help="Skip NVD bulk download, use only nluedtke data")
    parser.add_argument("--refresh-cache", action="store_true",
                        help="Force re-download all cached data")
    args = parser.parse_args()

    enrich_records(
        input_path=args.input,
        output_path=args.output,
        nvd_fallback=args.nvd_fallback,
        nvd_limit=args.nvd_limit,
        skip_nvd_bulk=args.skip_nvd_bulk,
        force_refresh=args.refresh_cache,
    )


if __name__ == "__main__":
    main()

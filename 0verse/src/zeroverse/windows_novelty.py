"""Novelty gate: public-record (CVE/advisory) search over a driver's identity.

A driver's absence from a hash-based blocklist (loldrivers-by-hash) is a
blocklist-EVASION signal, NOT a novelty signal. A fresh hash of known-CVE'd
code evades a hash catalog while being entirely non-novel — segwindrvx64.sys
(sha 0d30c6c4…) is exactly this: absent from loldrivers by that hash yet it is
CVE-2024-33228 (Insyde SEG driver, arbitrary kernel R/W via crafted IOCTL). The
whole reason it was mislabeled "novel" is that the triage pipeline only checked
hash-absence.

This gate searches public records by driver NAME + vendor + filename + device
family and classifies the result. It NEVER emits "novel": the strongest honest
verdict is NO-PUBLIC-RECORD-FOUND, and the assessment carries the explicit
caveat that absence of a public record is not proof of novelty (the search can
be incomplete, region-limited, or the bug may be catalogued under a different
name). A caller may only speak of a *candidate* for novelty on that verdict,
never a novelty claim.

The classification (``classify_hits``) is a pure, unit-tested function over
recorded search hits — the trustworthy pipeline artifact. The live search is a
pluggable ``NoveltySearcher`` (mirroring windows_provenance's pluggable opener)
so production wires it to WebSearch/NVD while tests and reproducible tallies
feed recorded hits through ``StaticSearcher``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

NOVELTY_SCHEMA = "0verse.windows-driver-novelty/v1"

# Verdicts. Note the deliberate absence of any "NOVEL" verdict.
KNOWN_CVE = "KNOWN-CVE"
KNOWN_ADVISORY = "KNOWN-ADVISORY"
NO_PUBLIC_RECORD = "NO-PUBLIC-RECORD-FOUND"

NO_PUBLIC_RECORD_CAVEAT = (
    "No public CVE/advisory record was found for this driver identity. Absence "
    "of a public record is NOT proof of novelty: the search may be incomplete or "
    "region-limited, and the same bug may be catalogued under a different driver "
    "name, vendor, or hash. Treat only as a novelty CANDIDATE pending manual "
    "confirmation — never as a novelty claim."
)

_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_ID = re.compile(r"\bGHSA(?:-[0-9a-z]{4}){3}\b", re.IGNORECASE)

# Public-record signals that mark a hit as a KNOWN-vulnerability reference even
# when no CVE id is parsed from it (loldrivers-by-name, BYOVD writeups, vendor
# bulletins, advisory databases).
_KNOWN_SIGNAL_SUBSTRINGS = (
    "loldrivers",
    "byovd",
    "bring your own vulnerable driver",
    "vulnerable driver",
    "vulnerable-driver",
    "security advisory",
    "security bulletin",
    "nvd.nist.gov/vuln/detail",
    "github.com/advisories",
    "cvedetails.com",
    "exploit-db",
    "vulnerability",
)


@dataclass(frozen=True)
class DriverIdentity:
    """The public-name identity of a driver, used to build search queries.

    filename is the on-disk driver name (e.g. ``segwindrvx64.sys``); vendor is
    the signing company (e.g. ``Insyde Software``); device_family is the
    driver's device/symlink base (e.g. ``RwDrv`` from \\Device\\RwDrv) which is
    often the searchable handle when the filename is generic; extra_terms are
    any additional discriminators (PDB product name, IOCTL family).
    """

    filename: str
    vendor: str = ""
    device_family: str = ""
    extra_terms: tuple[str, ...] = ()

    @property
    def stem(self) -> str:
        """The filename without its .sys extension, lowercased (the strongest
        attribution token — a hit must mention this or the device family to be
        attributed to THIS driver, so a generic 'vulnerable drivers' roundup
        cannot falsely mark an unrelated driver KNOWN)."""
        name = self.filename.strip()
        if name.lower().endswith(".sys"):
            name = name[:-4]
        return name.lower()

    def attribution_tokens(self) -> tuple[str, ...]:
        tokens = [self.stem]
        if self.device_family:
            tokens.append(self.device_family.lower())
        return tuple(t for t in tokens if t)

    def search_queries(self) -> list[str]:
        base = self.filename.strip()
        queries = [
            f"{base} CVE",
            f"{base} vulnerable driver IOCTL",
        ]
        if self.vendor:
            queries.append(f"{self.vendor} {base} advisory")
        if self.device_family and self.device_family.lower() != self.stem:
            queries.append(f"{self.device_family} driver CVE vulnerability")
        for term in self.extra_terms:
            queries.append(f"{base} {term}")
        # de-dup preserving order
        seen: set[str] = set()
        out: list[str] = []
        for q in queries:
            k = q.lower()
            if k not in seen:
                seen.add(k)
                out.append(q)
        return out

    def to_dict(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "vendor": self.vendor,
            "device_family": self.device_family,
            "extra_terms": list(self.extra_terms),
        }


@dataclass(frozen=True)
class SearchHit:
    query: str
    title: str
    url: str
    snippet: str = ""

    def haystack(self) -> str:
        return f"{self.title}\n{self.url}\n{self.snippet}".lower()

    def to_dict(self) -> dict[str, object]:
        return {"query": self.query, "title": self.title, "url": self.url, "snippet": self.snippet}


class NoveltySearcher(Protocol):
    def __call__(self, query: str) -> Sequence[SearchHit]: ...


@dataclass(frozen=True)
class StaticSearcher:
    """A searcher backed by pre-recorded hits (tests + reproducible tallies).

    Hits are matched to a query by exact query string; a hit recorded with an
    empty query matches every query (used when the caller pooled all results).
    """

    hits: tuple[SearchHit, ...]

    def __call__(self, query: str) -> Sequence[SearchHit]:
        return tuple(h for h in self.hits if h.query in ("", query))


@dataclass(frozen=True)
class NoveltyAssessment:
    identity: DriverIdentity
    queries: tuple[str, ...]
    hits: tuple[SearchHit, ...]
    verdict: str
    cve_ids: tuple[str, ...]
    advisory_ids: tuple[str, ...]
    known_signal_urls: tuple[str, ...]
    caveat: str
    assessed_at_utc: str
    schema: str = NOVELTY_SCHEMA

    @property
    def is_known(self) -> bool:
        return self.verdict in (KNOWN_CVE, KNOWN_ADVISORY)

    def label(self) -> str:
        """A short, honest label for a verdict record."""
        if self.verdict == KNOWN_CVE:
            return f"KNOWN-CVE({', '.join(self.cve_ids)})"
        if self.verdict == KNOWN_ADVISORY:
            return "KNOWN-ADVISORY(public vulnerable-driver record, no CVE id parsed)"
        return NO_PUBLIC_RECORD

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "identity": self.identity.to_dict(),
            "queries": list(self.queries),
            "verdict": self.verdict,
            "label": self.label(),
            "cve_ids": list(self.cve_ids),
            "advisory_ids": list(self.advisory_ids),
            "known_signal_urls": list(self.known_signal_urls),
            "caveat": self.caveat if self.verdict == NO_PUBLIC_RECORD else "",
            "assessed_at_utc": self.assessed_at_utc,
            "hits": [h.to_dict() for h in self.hits],
        }


def _relevant(identity: DriverIdentity, hit: SearchHit) -> bool:
    """A hit is attributed to THIS driver only if it names the filename stem or
    the device family. This keeps attribution honest in both directions: a
    generic BYOVD roundup that never names the driver cannot mark it KNOWN, and
    a CVE page that does name it cannot be missed."""
    hay = hit.haystack()
    return any(tok in hay for tok in identity.attribution_tokens())


def classify_hits(
    identity: DriverIdentity, hits: Sequence[SearchHit]
) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Pure classifier. Returns (verdict, cve_ids, advisory_ids, known_urls).

    Only hits that attribute to this driver (``_relevant``) contribute. CVE ids
    win; failing that, any public vulnerable-driver signal yields KNOWN-ADVISORY;
    otherwise NO-PUBLIC-RECORD-FOUND.
    """
    cve_ids: set[str] = set()
    advisory_ids: set[str] = set()
    known_urls: set[str] = set()
    for hit in hits:
        if not _relevant(identity, hit):
            continue
        text = f"{hit.title}\n{hit.url}\n{hit.snippet}"
        for m in _CVE_ID.findall(text):
            cve_ids.add(m.upper())
        for m in _GHSA_ID.findall(text):
            advisory_ids.add(m.upper())
        hay = hit.haystack()
        if any(sig in hay for sig in _KNOWN_SIGNAL_SUBSTRINGS):
            known_urls.add(hit.url)
    if cve_ids:
        verdict = KNOWN_CVE
    elif advisory_ids or known_urls:
        verdict = KNOWN_ADVISORY
    else:
        verdict = NO_PUBLIC_RECORD
    return (
        verdict,
        tuple(sorted(cve_ids)),
        tuple(sorted(advisory_ids)),
        tuple(sorted(known_urls)),
    )


def assess_novelty(
    identity: DriverIdentity,
    searcher: NoveltySearcher,
    *,
    now: datetime | None = None,
) -> NoveltyAssessment:
    """Run every derived query through ``searcher`` and classify the pooled hits."""
    queries = tuple(identity.search_queries())
    pooled: list[SearchHit] = []
    seen: set[tuple[str, str]] = set()
    for query in queries:
        for hit in searcher(query):
            key = (hit.url, hit.title)
            if key in seen:
                continue
            seen.add(key)
            pooled.append(hit)
    verdict, cve_ids, advisory_ids, known_urls = classify_hits(identity, pooled)
    stamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    return NoveltyAssessment(
        identity=identity,
        queries=queries,
        hits=tuple(pooled),
        verdict=verdict,
        cve_ids=cve_ids,
        advisory_ids=advisory_ids,
        known_signal_urls=known_urls,
        caveat=NO_PUBLIC_RECORD_CAVEAT,
        assessed_at_utc=stamp,
    )

"""Data model for the shared CVE knowledge base.

Two families of records:

* :class:`CveRecord` — a normalized public advisory (NVD CVE, OSV/GHSA, a
  loldrivers-by-name entry, or a hand-seeded driver fact). Every ingest source
  normalizes onto this one shape so downstream matching is source-agnostic.
* :class:`FindingFingerprint` — the *cross-profile* descriptor of one of OUR
  findings (a stripped-driver primitive, an ELF sink bug, an npm-package bug),
  reduced to the fields a novelty/dedup lookup keys on. Every 0verse profile
  builds one of these; none of them share the binary-native ``analyze.Finding``.

The design deliberately keeps closed-source drivers first-class: a driver CVE
(CVE-2024-33228 is the canonical case) frequently carries **no CPE** — the only
machine-usable attribution is the ``.sys`` filename and vendor inside the free
text ``description``. So a :class:`CveRecord` stores ``files``/``functions``
extracted from prose alongside the structured ``cpe_matches``/``affected``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "0verse.cve-kb/v1"

# --- verdicts (shared with windows_novelty's vocabulary, deliberately) -------
KNOWN_CVE = "KNOWN-CVE"
KNOWN_ADVISORY = "KNOWN-ADVISORY"
NO_PUBLIC_RECORD = "NO-PUBLIC-RECORD-FOUND"

NO_PUBLIC_RECORD_CAVEAT = (
    "No public CVE/advisory record was found in the knowledge base for this "
    "finding. Absence of a record is NOT proof of novelty: the local KB may be "
    "stale or incomplete, the finding's structured attribution (product/vendor/"
    "file/CWE) may be too thin to match, and the same bug may be catalogued "
    "under a different name, vendor, or hash. Treat only as a novelty CANDIDATE "
    "pending manual confirmation and the web/CVE-search fallback — never as a "
    "novelty claim."
)

_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_ID = re.compile(r"\bGHSA(?:-[0-9a-z]{4}){3}\b", re.IGNORECASE)
# .sys / .dll / .exe / .so filenames mentioned in prose (driver + binary attribution).
_FILE_TOKEN = re.compile(r"\b([A-Za-z0-9_.\-]+\.(?:sys|dll|exe|so|ko|dylib))\b", re.IGNORECASE)


def parse_cve_ids(text: str) -> tuple[str, ...]:
    return tuple(sorted({m.upper() for m in _CVE_ID.findall(text or "")}))


def parse_ghsa_ids(text: str) -> tuple[str, ...]:
    return tuple(sorted({m.upper() for m in _GHSA_ID.findall(text or "")}))


def parse_file_tokens(text: str) -> tuple[str, ...]:
    return tuple(sorted({m.lower() for m in _FILE_TOKEN.findall(text or "")}))


@dataclass(frozen=True)
class CpeMatch:
    """One CPE 2.3 applicability statement + its (optional) version range.

    ``criteria`` is the raw ``cpe:2.3:...`` string. The four ``version_*`` bounds
    mirror NVD's ``versionStartIncluding`` / ``versionStartExcluding`` /
    ``versionEndIncluding`` / ``versionEndExcluding``. A ``None`` bound means
    unbounded on that side; if the CPE pins an exact version in field 5
    (``criteria`` component ``version``) and no range is given, that exact
    version is the only affected one.
    """

    criteria: str
    version_start_incl: str | None = None
    version_start_excl: str | None = None
    version_end_incl: str | None = None
    version_end_excl: str | None = None
    vulnerable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "criteria": self.criteria,
            "version_start_incl": self.version_start_incl,
            "version_start_excl": self.version_start_excl,
            "version_end_incl": self.version_end_incl,
            "version_end_excl": self.version_end_excl,
            "vulnerable": self.vulnerable,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CpeMatch:
        return cls(
            criteria=str(d["criteria"]),
            version_start_incl=d.get("version_start_incl"),
            version_start_excl=d.get("version_start_excl"),
            version_end_incl=d.get("version_end_incl"),
            version_end_excl=d.get("version_end_excl"),
            vulnerable=bool(d.get("vulnerable", True)),
        )


@dataclass(frozen=True)
class AffectedRange:
    """An OSV/GHSA affected-package range: ecosystem name + [introduced, fixed)."""

    ecosystem: str
    package: str
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    versions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "package": self.package,
            "introduced": self.introduced,
            "fixed": self.fixed,
            "last_affected": self.last_affected,
            "versions": list(self.versions),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AffectedRange:
        return cls(
            ecosystem=str(d.get("ecosystem", "")),
            package=str(d.get("package", "")),
            introduced=d.get("introduced"),
            fixed=d.get("fixed"),
            last_affected=d.get("last_affected"),
            versions=tuple(d.get("versions", ())),
        )


@dataclass(frozen=True)
class CveRecord:
    """A normalized public advisory. ``id`` is the primary key (a CVE id when one
    exists, else the source id, e.g. a GHSA or ``LOLDRV-<name>``)."""

    id: str
    source: str  # nvd | osv | ghsa | loldrivers | seed
    description: str = ""
    vendor: str = ""
    product: str = ""
    cwes: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()  # other ids for the same advisory (CVE<->GHSA)
    cpe_matches: tuple[CpeMatch, ...] = ()
    affected: tuple[AffectedRange, ...] = ()
    files: tuple[str, ...] = ()  # e.g. ("segwindrvx64.sys",)
    functions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    published: str = ""

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids = set(parse_cve_ids(self.id)) | {a.upper() for a in self.aliases if _CVE_ID.match(a)}
        return tuple(sorted(ids))

    def haystack(self) -> str:
        """Lowercased searchable blob for coarse text attribution."""
        parts = [self.id, self.description, self.vendor, self.product]
        parts.extend(self.files)
        parts.extend(self.functions)
        parts.extend(m.criteria for m in self.cpe_matches)
        parts.extend(a.package for a in self.affected)
        return "\n".join(parts).lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "description": self.description,
            "vendor": self.vendor,
            "product": self.product,
            "cwes": list(self.cwes),
            "aliases": list(self.aliases),
            "cpe_matches": [m.to_dict() for m in self.cpe_matches],
            "affected": [a.to_dict() for a in self.affected],
            "files": list(self.files),
            "functions": list(self.functions),
            "references": list(self.references),
            "published": self.published,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CveRecord:
        return cls(
            id=str(d["id"]),
            source=str(d.get("source", "")),
            description=str(d.get("description", "")),
            vendor=str(d.get("vendor", "")),
            product=str(d.get("product", "")),
            cwes=tuple(d.get("cwes", ())),
            aliases=tuple(d.get("aliases", ())),
            cpe_matches=tuple(CpeMatch.from_dict(m) for m in d.get("cpe_matches", ())),
            affected=tuple(AffectedRange.from_dict(a) for a in d.get("affected", ())),
            files=tuple(d.get("files", ())),
            functions=tuple(d.get("functions", ())),
            references=tuple(d.get("references", ())),
            published=str(d.get("published", "")),
        )


@dataclass(frozen=True)
class FindingFingerprint:
    """Cross-profile descriptor of one of OUR findings, reduced to lookup keys.

    Every profile (linux-kernel, windows-driver, binary, web) constructs one.
    All fields optional so a thin closed-source finding (just a ``.sys`` name +
    a bug class) is representable next to a rich source-level one (file +
    function + CWE + package version).
    """

    product: str = ""
    vendor: str = ""
    version: str = ""
    ecosystem: str = ""  # windows-driver | npm | Maven | elf | firmware | ...
    file: str = ""       # segwindrvx64.sys, or src/foo.c
    function: str = ""   # sink function
    cwe: str = ""        # CWE-94
    bug_class: str = ""  # arb-physical-rw, oob-write, ssrf, ...
    description: str = ""
    device_family: str = ""       # driver device/symlink base (\Device\RwDrv -> RwDrv)
    extra_terms: tuple[str, ...] = ()
    finding_id: str = ""  # our internal id, for dedup provenance

    def attribution_tokens(self) -> tuple[str, ...]:
        """Strong tokens that must appear in a record for it to attribute here.

        A generic 'vulnerable drivers' roundup that never names our file/family
        cannot mark the finding KNOWN off these tokens alone.
        """
        toks: list[str] = []
        stem = self.file_stem
        if stem:
            toks.append(stem)
        if self.device_family:
            toks.append(self.device_family.lower())
        if self.product:
            toks.append(self.product.lower())
        return tuple(dict.fromkeys(t for t in toks if t))

    @property
    def file_stem(self) -> str:
        name = self.file.strip().lower()
        for ext in (".sys", ".dll", ".exe", ".so", ".ko", ".dylib"):
            if name.endswith(ext):
                return name[: -len(ext)]
        return name

    def fingerprint_text(self) -> str:
        """Compact technical blob for embedding-based dedup (Mode B)."""
        parts = [
            self.bug_class,
            self.cwe,
            self.function,
            self.file,
            self.product,
            self.vendor,
            self.device_family,
            self.description,
        ]
        parts.extend(self.extra_terms)
        return " ".join(p for p in parts if p).strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "vendor": self.vendor,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "file": self.file,
            "function": self.function,
            "cwe": self.cwe,
            "bug_class": self.bug_class,
            "description": self.description,
            "device_family": self.device_family,
            "extra_terms": list(self.extra_terms),
            "finding_id": self.finding_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FindingFingerprint:
        return cls(
            product=str(d.get("product", "")),
            vendor=str(d.get("vendor", "")),
            version=str(d.get("version", "")),
            ecosystem=str(d.get("ecosystem", "")),
            file=str(d.get("file", "")),
            function=str(d.get("function", "")),
            cwe=str(d.get("cwe", "")),
            bug_class=str(d.get("bug_class", "")),
            description=str(d.get("description", "")),
            device_family=str(d.get("device_family", "")),
            extra_terms=tuple(d.get("extra_terms", ())),
            finding_id=str(d.get("finding_id", "")),
        )


@dataclass(frozen=True)
class CveCandidate:
    """One KB record matched to a finding, with a score and human-readable why."""

    cve_id: str                      # primary/canonical CVE id (may be "")
    record_id: str
    source: str
    score: float
    reasons: tuple[str, ...]
    cve_ids: tuple[str, ...] = ()     # ALL CVE ids on the matched record (multi-CVE drivers)

    def all_cve_ids(self) -> tuple[str, ...]:
        ids = list(self.cve_ids)
        if self.cve_id and self.cve_id not in ids:
            ids.insert(0, self.cve_id)
        return tuple(ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cve_ids": list(self.all_cve_ids()),
            "record_id": self.record_id,
            "source": self.source,
            "score": round(self.score, 4),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class NoveltyResult:
    """Result of the shared gate: is this finding a known CVE, or no-record?

    Never carries a "NOVEL" verdict. ``NO-PUBLIC-RECORD-FOUND`` + caveat is the
    strongest honest statement. ``candidates`` is recall-oriented — anything
    plausibly-known for a human/verifier to review, never auto-dropped.
    """

    verdict: str
    confidence: str  # low | medium | high
    candidates: tuple[CveCandidate, ...] = ()
    method: str = ""  # structured | embedding | web | structured+embedding | ...
    caveat: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    schema: str = SCHEMA

    @property
    def is_known(self) -> bool:
        return self.verdict in (KNOWN_CVE, KNOWN_ADVISORY)

    @property
    def cve_ids(self) -> tuple[str, ...]:
        ids: list[str] = []
        for c in self.candidates:
            for cid in c.all_cve_ids():
                if cid and cid not in ids:
                    ids.append(cid)
        return tuple(ids)

    def label(self) -> str:
        if self.verdict == KNOWN_CVE:
            return f"KNOWN-CVE({', '.join(self.cve_ids)})"
        if self.verdict == KNOWN_ADVISORY:
            top = self.candidates[0].record_id if self.candidates else "public record"
            return f"KNOWN-ADVISORY({top})"
        return NO_PUBLIC_RECORD

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "verdict": self.verdict,
            "label": self.label(),
            "confidence": self.confidence,
            "method": self.method,
            "cve_ids": list(self.cve_ids),
            "candidates": [c.to_dict() for c in self.candidates],
            "caveat": self.caveat if self.verdict == NO_PUBLIC_RECORD else "",
            "evidence": self.evidence,
        }

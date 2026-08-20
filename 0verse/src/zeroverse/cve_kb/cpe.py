"""CPE 2.3 parsing + version-range containment — the deterministic Mode C path.

``cves_for(product, version)`` is a version-range lookup, NOT an embedding query:
given a concrete target {vendor?, product, version} it returns every KB record
whose CPE (or OSV affected-range) *covers* that version. This is the blackbox-
test-seeding path — "what known bugs apply to this exact build, so we can try
them first."

Version comparison is the load-bearing subtlety. There is no single correct
order across every ecosystem (npm semver vs Windows ``100.00.07.02`` vs Java
``2.14.1``). We use a permissive dotted-numeric-with-suffix comparator that is
correct for the overwhelmingly common numeric-dotted case and degrades to a
stable string compare otherwise. When a range bound cannot be compared to the
queried version with confidence, containment is reported as *uncertain* and the
record is still surfaced (recall-first) with that caveat, never silently dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import AffectedRange, CpeMatch, CveRecord
from .store import CveStore

_TOKEN = re.compile(r"(\d+|[a-zA-Z]+)")

# Pre-release/suffix ordering: a bare release (no suffix) outranks any pre-release
# suffix of the same numeric core (2.0 > 2.0-rc1 > 2.0-beta1 > 2.0-alpha1).
_SUFFIX_RANK = {"alpha": -4, "a": -4, "beta": -3, "b": -3, "rc": -2, "pre": -2, "": 0}


@dataclass(frozen=True)
class VersionKey:
    numeric: tuple[int, ...]
    suffix_rank: int
    raw: str


def parse_version(v: str) -> VersionKey:
    """Parse a version into (numeric-tuple, suffix-rank). Robust to leading 'v',
    embedded suffixes ('2.0-beta9'), and zero-padded driver quads."""
    raw = (v or "").strip()
    s = raw.lower().lstrip("v")
    # split the core numeric run from any trailing/embedded suffix
    m = re.match(r"^([0-9][0-9.]*)(.*)$", s)
    if not m:
        return VersionKey((), 0, raw)
    core, rest = m.group(1), m.group(2)
    nums = tuple(int(n) for n in core.split(".") if n != "")
    suffix_rank = 0
    suf = _TOKEN.search(rest)
    if suf and suf.group(1).isalpha():
        suffix_rank = _SUFFIX_RANK.get(suf.group(1), -1)
    return VersionKey(nums, suffix_rank, raw)


def _cmp_numeric(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    for i in range(n):
        ai = a[i] if i < len(a) else 0  # pad shorter with zeros: 2.0 == 2.0.0
        bi = b[i] if i < len(b) else 0
        if ai != bi:
            return -1 if ai < bi else 1
    return 0


def compare_versions(x: str, y: str) -> int:
    """-1 / 0 / 1 for x<y / x==y / x>y. Falls back to string compare only when
    neither side parses to any numeric core (avoids garbage-ordering weird tags)."""
    kx, ky = parse_version(x), parse_version(y)
    if not kx.numeric and not ky.numeric:
        return (kx.raw > ky.raw) - (kx.raw < ky.raw)
    c = _cmp_numeric(kx.numeric, ky.numeric)
    if c != 0:
        return c
    if kx.suffix_rank != ky.suffix_rank:
        return -1 if kx.suffix_rank < ky.suffix_rank else 1
    return 0


def cpe_covers(match: CpeMatch, version: str) -> bool | None:
    """Does this CPE match cover ``version``? True/False, or None if undecidable.

    Order of decision: explicit range bounds first; else an exact pinned version
    in the CPE criteria (field 5) if it is concrete; else wildcard '*'/'-' which
    covers everything (True). None only when a bound exists but can't be compared.
    """
    has_range = any(
        b is not None
        for b in (
            match.version_start_incl,
            match.version_start_excl,
            match.version_end_incl,
            match.version_end_excl,
        )
    )
    if has_range:
        try:
            lo_i, lo_e = match.version_start_incl, match.version_start_excl
            hi_i, hi_e = match.version_end_incl, match.version_end_excl
            if lo_i is not None and compare_versions(version, lo_i) < 0:
                return False
            if lo_e is not None and compare_versions(version, lo_e) <= 0:
                return False
            if hi_i is not None and compare_versions(version, hi_i) > 0:
                return False
            return not (hi_e is not None and compare_versions(version, hi_e) >= 0)
        except Exception:
            return None
    # no range: check the pinned version field of the CPE criteria
    parts = match.criteria.split(":")
    pinned = parts[5] if len(parts) > 5 else "*"
    if pinned in ("*", "-", ""):
        return True  # applies to all versions of the product
    return compare_versions(version, pinned) == 0


def affected_covers(rng: AffectedRange, version: str) -> bool | None:
    """OSV [introduced, fixed) / last_affected containment."""
    if version in rng.versions:
        return True
    try:
        lo = rng.introduced
        if lo and lo != "0" and compare_versions(version, lo) < 0:
            return False
        if rng.fixed and compare_versions(version, rng.fixed) >= 0:
            return False
        if rng.last_affected and compare_versions(version, rng.last_affected) > 0:
            return False
        # An enumerated-versions-only range with no bounds can't confirm coverage
        # for a version that wasn't in the list.
        if not rng.introduced and not rng.fixed and not rng.last_affected:
            return None
        return True
    except Exception:
        return None


@dataclass(frozen=True)
class CoverageHit:
    cve_id: str
    record_id: str
    source: str
    certain: bool
    via: str  # cpe:<criteria> | osv:<ecosystem>:<package>
    reason: str


def product_matches(query: str, candidate: str) -> bool:
    """Precise product match for Mode C. Tightened from bare substring after the
    full mirror exposed two over-inclusions:

    * a CPE product ``log4j`` matched the Maven coordinate
      ``org.apache.logging.log4j:log4j-core`` (unrelated CVEs), and
    * two DISTINCT coordinates sharing an artifact name
      (``com.guicedee.services:log4j-core`` vs ``org.apache...:log4j-core``)
      matched on last component.

    Rule: two full coordinates (containing ``:`` or ``/``) must match EXACTLY;
    a bare token (a CPE product like ``log4j``/``dbutil``, or an unscoped npm
    name like ``lodash``) matches the other side only when it equals the other's
    last coordinate component. Exact equality always matches."""
    query = (query or "").strip().lower()
    candidate = (candidate or "").strip().lower()
    if not query or query == candidate:
        return True
    q_coord = ":" in query or "/" in query
    c_coord = ":" in candidate or "/" in candidate
    if q_coord and c_coord:
        return False  # distinct coordinates, exact-only (already handled above)
    q_last = re.split(r"[:/]", query)[-1]
    c_last = re.split(r"[:/]", candidate)[-1]
    if not q_coord:  # query is a bare token
        return query == c_last
    return candidate == q_last  # candidate is a bare token


def cves_for(
    store: CveStore,
    product: str,
    version: str,
    *,
    vendor: str = "",
) -> list[CoverageHit]:
    """Mode C: deterministic version-range lookup. Returns coverage hits sorted
    certain-first. ``vendor`` narrows the candidate set when known; otherwise all
    records whose CPE/affected product matches ``product`` are considered."""
    product = product.strip().lower()
    candidates: dict[str, CveRecord] = {}

    # Narrow via the product index (CPE vendor:product + OSV ecosystem:package).
    for key in store.cpe_product_keys():
        try:
            k_vendor, k_product = key.split(":", 1)
        except ValueError:
            continue
        if product and not product_matches(product, k_product):
            continue
        if vendor and vendor.lower() not in k_vendor and k_vendor not in vendor.lower():
            continue
        for rec in store.by_cpe_product(k_vendor, k_product):
            candidates[rec.id] = rec

    hits: list[CoverageHit] = []
    for rec in candidates.values():
        for m in rec.cpe_matches:
            if not m.vulnerable:
                continue
            vp = _cpe_vp(m.criteria)
            if vp is None:
                continue
            _, prod = vp
            if product and not product_matches(product, prod):
                continue
            cov = cpe_covers(m, version)
            if cov is False:
                continue
            hits.append(
                CoverageHit(
                    cve_id=(rec.cve_ids[0] if rec.cve_ids else rec.id),
                    record_id=rec.id,
                    source=rec.source,
                    certain=cov is True,
                    via=f"cpe:{m.criteria}",
                    reason=_range_reason(m) if cov is True else "version pin/range undecidable",
                )
            )
        for aff in rec.affected:
            if product and not product_matches(product, aff.package):
                continue
            cov = affected_covers(aff, version)
            if cov is False:
                continue
            hits.append(
                CoverageHit(
                    cve_id=(rec.cve_ids[0] if rec.cve_ids else rec.id),
                    record_id=rec.id,
                    source=rec.source,
                    certain=cov is True,
                    via=f"osv:{aff.ecosystem}:{aff.package}",
                    reason=f"[{aff.introduced or '0'}, {aff.fixed or '∞'})"
                    if cov is True
                    else "range undecidable",
                )
            )

    # de-dup by (cve_id, via), certain-first
    seen: set[tuple[str, str]] = set()
    uniq: list[CoverageHit] = []
    for h in sorted(hits, key=lambda h: (not h.certain, h.cve_id)):
        dkey = (h.cve_id, h.via)
        if dkey in seen:
            continue
        seen.add(dkey)
        uniq.append(h)
    return uniq


def _cpe_vp(criteria: str) -> tuple[str, str] | None:
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        return parts[3].lower(), parts[4].lower()
    return None


def _range_reason(m: CpeMatch) -> str:
    lo = m.version_start_incl or (f">{m.version_start_excl}" if m.version_start_excl else "0")
    hi = m.version_end_excl or (f"<={m.version_end_incl}" if m.version_end_incl else "∞")
    return f"[{lo}, {hi})"

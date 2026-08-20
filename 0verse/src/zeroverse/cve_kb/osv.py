"""OSV.dev / GitHub Security Advisory JSON -> :class:`CveRecord`.

OSV is the open-source package-level feed (it also mirrors GHSA). The shape,
learned from a real ``api.osv.dev/v1/query`` response for log4j-core:

* ``id`` is the advisory id (often ``GHSA-...``); ``aliases`` carries the CVE
  id(s). We key the record on the CVE id when one is present in ``aliases`` so
  the CVE-first index resolves, and keep the GHSA id as an alias — that way a
  finding attributed either way still hits.
* ``affected[].package.{name,ecosystem,purl}`` + ``affected[].ranges[].events[]``
  ({introduced}, {fixed}) become :class:`AffectedRange` (the Mode C path for
  package ecosystems). ``affected[].versions[]`` (the enumerated list) is kept
  for exact-membership coverage.
* ``details``/``summary`` become the description; CWE ids, when present, live in
  ``database_specific.cwe_ids`` (GHSA) — we harvest them if there.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import AffectedRange, CveRecord, parse_file_tokens


def _prefer_cve_id(osv_id: str, aliases: list[str]) -> tuple[str, tuple[str, ...]]:
    """Key on a CVE id if the advisory has one; keep every other id as an alias."""
    all_ids = [osv_id, *aliases]
    cve = next((a for a in all_ids if a.upper().startswith("CVE-")), None)
    if cve:
        primary = cve.upper()
        others = tuple(dict.fromkeys(a for a in all_ids if a and a != cve))
        return primary, others
    return osv_id, tuple(dict.fromkeys(a for a in aliases if a))


def _affected(vuln: dict[str, Any]) -> tuple[AffectedRange, ...]:
    out: list[AffectedRange] = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {}) or {}
        ecosystem = str(pkg.get("ecosystem", ""))
        name = str(pkg.get("name", ""))
        versions = tuple(str(v) for v in aff.get("versions", []))
        ranges = aff.get("ranges", [])
        if not ranges:
            if name:
                out.append(AffectedRange(ecosystem=ecosystem, package=name, versions=versions))
            continue
        for rng in ranges:
            introduced = fixed = last_affected = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = str(ev["introduced"])
                elif "fixed" in ev:
                    fixed = str(ev["fixed"])
                elif "last_affected" in ev:
                    last_affected = str(ev["last_affected"])
            out.append(
                AffectedRange(
                    ecosystem=ecosystem,
                    package=name,
                    introduced=introduced,
                    fixed=fixed,
                    last_affected=last_affected,
                    versions=versions,
                )
            )
    return tuple(out)


def _cwes(vuln: dict[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    ds = vuln.get("database_specific", {}) or {}
    for c in ds.get("cwe_ids", []) or []:
        c = str(c).strip()
        if c and c not in out:
            out.append(c)
    for aff in vuln.get("affected", []):
        ads = aff.get("database_specific", {}) or {}
        for c in ads.get("cwes", []) or []:
            cid = str((c or {}).get("cweId", c)).strip() if isinstance(c, dict) else str(c).strip()
            if cid and cid not in out:
                out.append(cid)
    return tuple(out)


def _references(vuln: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(r.get("url", "")) for r in vuln.get("references", []) if r.get("url"))


def normalize_vuln(vuln: dict[str, Any]) -> CveRecord:
    """Normalize one OSV vulnerability object."""
    osv_id = str(vuln.get("id", ""))
    aliases = [str(a) for a in vuln.get("aliases", [])]
    primary, other_ids = _prefer_cve_id(osv_id, aliases)
    desc = str(vuln.get("details") or vuln.get("summary") or "")
    affected = _affected(vuln)
    # product = first affected package name (best available "product" for OSV)
    product = affected[0].package if affected else ""
    return CveRecord(
        id=primary,
        source="osv",
        description=desc,
        product=product,
        cwes=_cwes(vuln),
        aliases=other_ids,
        affected=affected,
        files=parse_file_tokens(desc),
        references=_references(vuln),
        published=str(vuln.get("published", "")),
    )


def normalize_query_response(payload: dict[str, Any]) -> list[CveRecord]:
    """Normalize an ``api.osv.dev/v1/query`` response (``vulns[]``) — or a single
    vuln object, or a list of them."""
    if isinstance(payload, dict) and "vulns" in payload:
        vulns = payload.get("vulns", [])
    elif isinstance(payload, list):
        vulns = payload
    else:
        vulns = [payload]
    return [normalize_vuln(v) for v in vulns if isinstance(v, dict) and v.get("id")]


def iter_records(payloads: Iterable[dict[str, Any]]) -> Iterable[CveRecord]:
    for p in payloads:
        yield from normalize_query_response(p)

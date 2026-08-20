"""NVD JSON 2.0 -> :class:`CveRecord` normalization.

Parses the shape returned by ``services.nvd.nist.gov/rest/json/cves/2.0`` (also
the NVD data-feed archives). The load-bearing details, learned from the real
CVE-2024-33228 (segwindrvx64) and CVE-2021-21551 (dbutil) records:

* Driver CVEs frequently carry **no CPE at all** — the only machine-usable
  attribution is the ``.sys`` filename + vendor inside the description prose.
  So we always mine ``files`` out of the description, not just from CPE.
* CWE lives under ``weaknesses[].description[].value`` (e.g. ``CWE-94``); NVD
  also emits sentinel values like ``NVD-CWE-Other`` which we keep verbatim.
* Vendor/product are recovered from the first vulnerable CPE when present, else
  left blank (the description carries them for closed-source drivers).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import CpeMatch, CveRecord, parse_file_tokens


def _first_english(descriptions: list[dict[str, Any]]) -> str:
    for d in descriptions:
        if d.get("lang") == "en":
            return str(d.get("value", ""))
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _cwes(cve: dict[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = str(d.get("value", "")).strip()
            if val and val not in out:
                out.append(val)
    return tuple(out)


def _cpe_matches(cve: dict[str, Any]) -> tuple[CpeMatch, ...]:
    out: list[CpeMatch] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                out.append(
                    CpeMatch(
                        criteria=str(m.get("criteria", "")),
                        version_start_incl=m.get("versionStartIncluding"),
                        version_start_excl=m.get("versionStartExcluding"),
                        version_end_incl=m.get("versionEndIncluding"),
                        version_end_excl=m.get("versionEndExcluding"),
                        vulnerable=bool(m.get("vulnerable", True)),
                    )
                )
    return tuple(out)


def _vendor_product(matches: tuple[CpeMatch, ...]) -> tuple[str, str]:
    for m in matches:
        if not m.vulnerable:
            continue
        parts = m.criteria.split(":")
        # cpe:2.3:a:vendor:product:...  — prefer application ('a') parts
        if len(parts) >= 5 and parts[2] == "a":
            return _deslug(parts[3]), _deslug(parts[4])
    for m in matches:
        parts = m.criteria.split(":")
        if len(parts) >= 5:
            return _deslug(parts[3]), _deslug(parts[4])
    return "", ""


def _deslug(s: str) -> str:
    return s.replace("_", " ").strip()


def normalize_cve(cve: dict[str, Any]) -> CveRecord:
    """Normalize one NVD ``cve`` object (the element under ``vulnerabilities[]``)."""
    cid = str(cve.get("id", "")).upper()
    desc = _first_english(cve.get("descriptions", []))
    cpe = _cpe_matches(cve)
    vendor, product = _vendor_product(cpe)
    refs = tuple(str(r.get("url", "")) for r in cve.get("references", []) if r.get("url"))
    files = parse_file_tokens(desc)
    return CveRecord(
        id=cid,
        source="nvd",
        description=desc,
        vendor=vendor,
        product=product,
        cwes=_cwes(cve),
        cpe_matches=cpe,
        files=files,
        references=refs,
        published=str(cve.get("published", "")),
    )


def normalize_response(payload: dict[str, Any]) -> list[CveRecord]:
    """Normalize a full ``/rest/json/cves/2.0`` response (``vulnerabilities[]``)."""
    out: list[CveRecord] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve")
        if isinstance(cve, dict):
            out.append(normalize_cve(cve))
    return out


def normalize_any(payload: Any) -> list[CveRecord]:
    """Normalize whatever NVD 2.0 shape a mirror file holds:

    * a full API response ``{"vulnerabilities": [{"cve": {...}}, ...]}``;
    * a single wrapped item ``{"cve": {...}}`` (fkie-cad per-CVE files);
    * a bare cve object ``{"id": "CVE-...", "descriptions": [...], ...}``;
    * a list of any of the above.
    """
    if isinstance(payload, list):
        out: list[CveRecord] = []
        for item in payload:
            out.extend(normalize_any(item))
        return out
    if not isinstance(payload, dict):
        return []
    if "vulnerabilities" in payload:
        return normalize_response(payload)
    if isinstance(payload.get("cve"), dict):
        return [normalize_cve(payload["cve"])]
    if isinstance(payload.get("id"), str) and payload["id"].upper().startswith("CVE-"):
        return [normalize_cve(payload)]
    return []


def iter_records(payloads: Iterable[dict[str, Any]]) -> Iterable[CveRecord]:
    for p in payloads:
        yield from normalize_response(p)

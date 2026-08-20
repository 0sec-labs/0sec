"""Hand-curated seed records: known facts with thin or absent public structure.

These are records we assert from our own confirmed triage + published advisories,
for cases the free structured feeds don't index cleanly (a vendor advisory with
no CVE, a driver family whose CPE NVD never assigned). Each is honestly sourced.

IMPORTANT: segwindrvx64.sys is deliberately NOT seeded here — it resolves from
the REAL bundled NVD record (``data/sample_nvd_cve-2024-33228.json``), whose
description names the file. The segwindrvx64 -> CVE-2024-33228 proof therefore
rides on live public data, not a hand-written answer key.
"""

from __future__ import annotations

from .models import CveRecord


def seed_records() -> list[CveRecord]:
    return [
        # Insyde iscflashx64 — same physical-R/W family as segwindrvx64; the
        # public trail is a vendor/family advisory rather than a per-file CVE.
        CveRecord(
            id="LOLDRV-iscflashx64.sys",
            source="seed",
            description=(
                "iscflashx64.sys — Insyde Software winflashcommon/SEG flash driver "
                "family (2015-gen). Class-1 arbitrary physical read/write via "
                "MmMapIoSpace + METHOD_OUT_DIRECT IOCTL, the same primitive family "
                "as segwindrvx64.sys (CVE-2024-33228). Catalogued as a known "
                "BYOVD/vulnerable-driver family; no distinct per-file CVE assigned."
            ),
            vendor="Insyde Software",
            product="Insyde SEG/winflashcommon flash driver",
            files=("iscflashx64.sys",),
            cwes=("CWE-782",),
            references=(
                "https://www.loldrivers.io/",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-33228",
            ),
        ),
    ]

"""Stable, ranking-neutral identities for Windows IOCTL static sites."""

from __future__ import annotations

import hashlib
import json

_SITE_DOMAIN = b"0verse-windows-ioctl-real-site-v1\0"
_SITE_UNIVERSE_DOMAIN = b"0verse-windows-ioctl-real-site-universe-v1\0"


def ioctl_site_id(driver_sha256: str, analysis_sha256: str, record: dict[str, object]) -> str:
    """Bind one normalized site record to the exact driver and analysis export."""
    material = json.dumps(
        {
            "driver_sha256": driver_sha256,
            "analysis_sha256": analysis_sha256,
            **record,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(_SITE_DOMAIN + material).hexdigest()


def site_universe_sha256(sites: list[dict[str, object]]) -> str:
    """Commit to the complete, identity-sorted set of normalized site records."""
    material = json.dumps(
        sorted(sites, key=lambda row: str(row["site_id"])),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(_SITE_UNIVERSE_DOMAIN + material).hexdigest()

"""Exact validators for Windows AppContainer identities."""

from __future__ import annotations


def valid_package_app_container_sid(value: str) -> bool:
    """Return whether *value* is a package AppContainer SID, not a group SID.

    Package AppContainer SIDs have the authority/prefix ``S-1-15-2`` followed
    by the eight uint32 RIDs produced from the package-family-name hash.
    """
    parts = value.split("-")
    return (
        len(parts) == 12
        and parts[:4] == ["S", "1", "15", "2"]
        and all(
            part.isascii()
            and part.isdecimal()
            and 1 <= len(part) <= 10
            and (len(part) == 1 or not part.startswith("0"))
            and int(part) <= 2**32 - 1
            for part in parts[4:]
        )
    )

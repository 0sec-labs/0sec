"""Static installer unpacker — cracks installer-gated driver packages WITHOUT execution.

The board-access driver vein (Moxa NPort/UPort, ICP DAS, Advantech DAQ/CAN — the
vendors whose drivers carry the dbutil-shape physical-mem / port-I/O primitives)
ships behind InstallShield / Inno / NSIS / MSI installers that a plain archive tool
can't parse. This module is the STATIC key: it sniffs the installer kind and routes
to the right off-the-shelf STATIC extractor — ``unshield`` (InstallShield .cab),
``innoextract`` (Inno Setup), ``cabextract`` (Microsoft CAB), ``7zz`` (NSIS, MSI,
ZIP, ISO, 7z, RAR) — then harvests every ``.sys`` it produced, recursing one level
into extracted CAB/MSI payloads and falling back to the no-execute PE carver
(:mod:`zeroverse.pe_driver_carve`) for drivers embedded as resources in extracted
binaries (or never unpacked at all).

HARD RULE: nothing here ever EXECUTES the installer or any extracted file. The only
processes spawned are the four unpacker CLIs above, each a pure static extractor
(they parse and decompress; they do not run the target). That keeps the campaign's
static-only invariant intact end to end.

Output is a harvest record per driver (source tool, container kind, member path,
sha256, x86/x64) for hash-pinning into the CAS before triage.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .pe_driver_carve import carve_drivers

# Per-tool wall-clock bound and a total output-size cap — a hostile/corrupt package
# must not hang the campaign or fill the disk (a "zip bomb" surfaces as a truncated
# harvest with a note, not a runaway).
TOOL_TIMEOUT_S = 300
MAX_EXTRACT_BYTES = 2 << 30  # 2 GiB
# One level of payload recursion: installers routinely nest a .cab/.msi holding the
# actual driver files (InstallShield data1.cab, MSI Binary/streams).
_MAX_PAYLOAD_DEPTH = 2


@dataclass
class UnpackedDriver:
    """One recovered driver candidate, with provenance for CAS hash-pinning."""

    sha256: str
    path: str
    source: str          # "7zz" | "innoextract" | "unshield" | "cabextract" | "carve" | "loose"
    container_kind: str  # sniffed installer kind (see sniff_kind)
    member: str          # path of the file within the extraction tree (or carve offset)
    machine: int | None = None  # COFF machine when parsed (0x8664 x64, 0x14c x86)

    def as_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "path": self.path,
            "source": self.source,
            "container_kind": self.container_kind,
            "member": self.member,
            "machine": f"0x{self.machine:x}" if self.machine else None,
        }


@dataclass
class UnpackResult:
    package: str
    kind: str
    drivers: list[UnpackedDriver] = field(default_factory=list)
    extracted_files: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "kind": self.kind,
            "drivers": [d.as_dict() for d in self.drivers],
            "extracted_files": self.extracted_files,
            "truncated": self.truncated,
            "notes": self.notes,
        }


# --- installer-kind sniffing -------------------------------------------------

_KIND_HINTS = (
    # (byte needle, kind) — searched in the first/last chunks of a PE installer.
    (b"Nullsoft Install", "nsis"),
    (b"NullsoftInst", "nsis"),
    (b"Inno Setup", "inno"),
    (b"JR.Inno.Setup", "inno"),
    (b"InstallShield", "installshield"),
    (b"_ISDel", "installshield"),
    (b"InstallShield", "installshield"),
    (b"Wise Installation", "wise"),
)


def _is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    return data[e_lfanew : e_lfanew + 4] == b"PE\0\0"


def sniff_kind(path: str | Path) -> str:
    """Best-effort installer format from magic bytes + format-hint strings.

    Returns one of: ``zip`` ``cab`` ``7z`` ``rar`` ``iso`` ``msi`` ``installshield``
    ``inno`` ``nsis`` ``wise`` ``pe`` (a PE with no known-installer hint) or
    ``unknown``. String hints are searched in the first and last 2 MiB — NSIS/Inno
    sign near the end (overlay), InstallShield near the version resources."""
    path = Path(path)
    with path.open("rb") as fh:
        head = fh.read(4 << 20)
        try:
            fh.seek(max(0, path.stat().st_size - (4 << 20)))
            tail = fh.read(4 << 20)
        except OSError:
            tail = b""
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if head[:4] == b"MSCF":
        return "cab"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:4] == b"Rar!":
        return "rar"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "msi"  # OLE2 compound — MSI packages are CFB
    if len(head) > 0x9300 and head[0x8001:0x8006] == b"CD001":
        return "iso"
    if head[:4] == b"ISc(":
        return "installshield-cab"
    if _is_pe(head):
        blob = head + tail
        for needle, kind in _KIND_HINTS:
            if needle in blob:
                return kind
        return "pe"
    return "unknown"


# --- tool runners ------------------------------------------------------------


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def available_tools() -> dict[str, bool]:
    return {t: bool(_which(t)) for t in ("7zz", "innoextract", "unshield", "cabextract")}


def _run(tool: str, args: list[str], timeout: int = TOOL_TIMEOUT_S) -> tuple[bool, str]:
    """Run one STATIC extractor. The tool parses/decompresses; the target package is
    data to it — nothing in the package is executed by any of these tools."""
    exe = _which(tool)
    if not exe:
        return False, f"{tool} not installed"
    try:
        proc = subprocess.run(
            [exe, *args], capture_output=True, timeout=timeout, check=False,
        )
        out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
        return proc.returncode == 0, out[-4000:]
    except subprocess.TimeoutExpired:
        return False, f"{tool} timed out after {timeout}s"
    except OSError as exc:
        return False, f"{tool} failed to launch: {exc}"


def _tree_size(root: Path) -> tuple[int, int]:
    total, count = 0, 0
    for p in root.rglob("*"):
        if p.is_file():
            count += 1
            with suppress(OSError):
                total += p.stat().st_size
    return total, count


def _extract(kind: str, pkg: Path, outdir: Path, notes: list[str]) -> str:
    """Route to the static extractor for ``kind``. Returns the source tag used."""
    if kind == "inno":
        # --collisions=rename: multi-arch packages ship same-named members per arch
        # (measured on Moxa drvmgr 4.2: nptdrv2.sys x64 twice + ARM64, same member
        # name — the default overwrite keeps only the LAST arch). Renamed members
        # land as ``name.sys$N`` and the harvest regex picks them up too.
        ok, log = _run("innoextract", ["--extract", "--collisions=rename",
                                       "--output-dir", str(outdir), str(pkg)])
        if ok:
            return "innoextract"
        notes.append(f"innoextract failed ({log.strip()[:200]}); falling back to 7zz")
    if kind in ("installshield", "installshield-cab"):
        ok, log = _run("unshield", ["-d", str(outdir), "x", str(pkg)])
        if ok:
            return "unshield"
        notes.append(f"unshield failed ({log.strip()[:200]}); falling back to 7zz")
    if kind == "cab":
        ok, _ = _run("cabextract", ["-d", str(outdir), str(pkg)])
        if ok:
            return "cabextract"
        notes.append("cabextract failed; falling back to 7zz")
    # 7zz is the generalist: NSIS, MSI (as CFB), ZIP, ISO, 7z, RAR, and a
    # second-chance for Inno/InstallShield PEs whose dedicated tool failed.
    ok, log = _run("7zz", ["x", f"-o{outdir}", "-y", str(pkg)])
    if ok:
        return "7zz"
    notes.append(f"7zz could not parse ({log.strip()[:200]})")
    return ""


# --- harvesting --------------------------------------------------------------

_SYS_RE = re.compile(r"\.sys(?:\$\d+)?$", re.IGNORECASE)  # also innoextract $N renames
_PAYLOAD_RE = re.compile(r"\.(cab|msi)$", re.IGNORECASE)


def _pe_machine(path: Path) -> int | None:
    try:
        with path.open("rb") as fh:
            head = fh.read(0x400)
        if head[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if head[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return None
        return int(struct.unpack_from("<H", head, e_lfanew + 4)[0])
    except (OSError, struct.error):
        return None


def _harvest(
    root: Path,
    out: list[UnpackedDriver],
    seen: set[str],
    source: str,
    kind: str,
    result: UnpackResult,
    depth: int = 0,
) -> None:
    """Collect every .sys under ``root``; recurse one level into CAB/MSI payloads;
    carve embedded drivers out of any other extracted binary."""
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        member = str(p.relative_to(root))
        if _SYS_RE.search(p.name):
            digest = _sha256(p)
            if digest in seen:
                continue
            seen.add(digest)
            out.append(UnpackedDriver(
                sha256=digest, path=str(p), source=source, container_kind=kind,
                member=member, machine=_pe_machine(p),
            ))
            continue
        if _PAYLOAD_RE.search(p.name) and depth < _MAX_PAYLOAD_DEPTH:
            sub = p.parent / (p.stem + ".unpacked")
            sub.mkdir(exist_ok=True)
            sub_kind = sniff_kind(p)
            sub_source = _extract(sub_kind, p, sub, result.notes)
            if sub_source:
                _harvest(sub, out, seen, sub_source, f"{kind}/{sub_kind}", result, depth + 1)
            continue
        # a non-driver binary: a driver may be embedded as a resource (the
        # no-execute carver scans for native-subsystem PE images).
        try:
            carved = carve_drivers(p)
        except Exception:
            carved = []
        for c in carved:
            if c.sha256 in seen:
                continue
            seen.add(c.sha256)
            carve_path = p.parent / f"{p.stem}.carved-{c.offset:x}.sys"
            carve_path.write_bytes(c.data)
            out.append(UnpackedDriver(
                sha256=c.sha256, path=str(carve_path), source="carve",
                container_kind=kind, member=f"{member}@0x{c.offset:x}", machine=c.machine,
            ))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def unpack_drivers(
    package: str | Path, outdir: str | Path | None = None
) -> UnpackResult:
    """Statically unpack ``package`` and harvest every driver it contains.

    ``outdir`` defaults to a temp dir alongside the package. The package and its
    extracted files are NEVER executed — only the static extractor CLIs run."""
    package = Path(package)
    kind = sniff_kind(package)
    result = UnpackResult(package=str(package), kind=kind)
    if outdir is None:
        outdir = Path(tempfile.mkdtemp(prefix=f"unpack-{package.stem[:32]}-"))
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    if kind == "pe":
        result.notes.append("plain PE with no installer hint — carving embedded drivers only")
    elif kind == "unknown":
        result.notes.append("unrecognised container — carving embedded drivers only")
    else:
        source = _extract(kind, package, out, result.notes)
        if source:
            total, count = _tree_size(out)
            result.extracted_files = count
            if total > MAX_EXTRACT_BYTES:
                result.truncated = True
                result.notes.append(
                    f"extraction exceeds {MAX_EXTRACT_BYTES >> 30} GiB cap — harvest truncated")
            result.notes.append(f"extracted with {source}")
            _harvest(out, result.drivers, set(), source, kind, result)

    # Carve the package itself last: catches drivers embedded in the installer stub
    # even when the archive layer yielded nothing (or wasn't attempted).
    try:
        carved = carve_drivers(package)
    except Exception:
        carved = []
    seen = {d.sha256 for d in result.drivers}
    for c in carved:
        if c.sha256 in seen:
            continue
        seen.add(c.sha256)
        carve_path = out / f"{package.stem}.carved-{c.offset:x}.sys"
        carve_path.write_bytes(c.data)
        result.drivers.append(UnpackedDriver(
            sha256=c.sha256, path=str(carve_path), source="carve",
            container_kind=kind, member=f"{package.name}@0x{c.offset:x}", machine=c.machine,
        ))
    if carved:
        result.notes.append(f"carved {len(carved)} embedded driver image(s) from the package")
    if not result.drivers and not result.notes:
        result.notes.append("no drivers recovered")
    return result


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m zeroverse.installer_unpack <package> [outdir]`` — one JSON
    harvest record per unpack. Static only; packages are never executed."""
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("packages", nargs="+")
    ap.add_argument("--outdir", default=None)
    ns = ap.parse_args(argv)
    for pkg in ns.packages:
        res = unpack_drivers(pkg, ns.outdir)
        print(json.dumps(res.as_dict()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Windows kernel-driver LPE triage — defensive candidate-surfacing (static-only).

Two crutch-free, import-anchored stages over a stripped ``.sys`` (no PDB required):

1. **no-ACL reachability pre-filter** (:func:`prefilter`): a driver that installs a
   user-reachable device symlink (``IoCreateSymbolicLink`` /
   ``IoCreateUnprotectedSymbolicLink``) WITHOUT the secure creation variant
   (``IoCreateDeviceSecure`` / ``WdmlibIoCreateDeviceSecure``) and without an embedded
   SDDL string exposes its ``IRP_MJ_DEVICE_CONTROL`` surface to any unprivileged
   caller — the ``dbutil_2_3`` world-accessible pattern (``\\DosDevices\\DBUtil_2_3``,
   no ACL). Imports and the ``\\Device\\`` / ``\\DosDevices\\`` names survive stripping,
   so this gate needs no symbol table and no analysis pass (cheap: it runs BEFORE
   ``aaa``).

2. **crutch-free LOCATE** (:func:`zeroverse.backends.rizin._windows_driver_priority`):
   for a world-accessible survivor, anchor on the ``MajorFunction[14]`` dispatch handler
   and rank the copy-sinks reachable from it by direct-call graph.

This module NEVER loads or runs the driver — static analysis only. Its output is a
RANKED TRIAGE RECORD for human review, not a confirmed bug: confirming a new (non-CVE)
bug needs execution against the Phase B kernel oracle (Driver Verifier Special Pool +
KDNET), which is out of scope here.

The gate is deliberately import-anchored, which bounds what it can see. Honest limits:
a device ACL applied by the INF at install time (not in the binary), or set at runtime
via ``ZwSetSecurityObject`` / ``ObSetSecurityObjectByPointer`` rather than the secure
creation import, is invisible to a static import scan — such a driver would be flagged
``world_accessible`` here yet be ACL-protected in practice. The pre-filter is a
high-recall cheap gate for review, not a proof of reachability.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backends.rizin import (
    _augmented_driver_adjacency,
    _func_ops,
    _is_windows_kernel_driver,
    _loadj,
    _windows_driver_priority,
)

# Imports that expose a device to unprivileged user mode. A symbolic link publishes the
# device under ``\DosDevices\`` (== ``\??\``) so a plain ``CreateFile("\\\\.\\Name")``
# from any integrity level reaches the IRP_MJ_DEVICE_CONTROL dispatch.
_USER_REACHABLE_IMPORTS = (
    "IoCreateSymbolicLink",
    "IoCreateUnprotectedSymbolicLink",
)
# The secure creation variants take an SDDL and stamp an ACL on the device object, so
# their presence is evidence the author gated access.
_SECURE_CREATE_IMPORTS = (
    "IoCreateDeviceSecure",
    "WdmlibIoCreateDeviceSecure",
)
# Kernel primitives that, when reachable from an unprivileged IOCTL dispatch, ARE the
# LPE: they map or move physical/arbitrary kernel memory under caller-influenced
# arguments. A world-accessible driver reaching one of these is the iqvw64e /
# CVE-2015-2291 class (arbitrary physical read/write via MmMapIoSpace) — a sink class
# distinct from an inlined copy, so the triage surfaces it too.
_KERNEL_PRIMITIVE_SINKS = (
    "MmMapIoSpace",
    "MmMapIoSpaceEx",
    "MmMapLockedPages",
    "MmMapLockedPagesSpecifyCache",
    "ZwMapViewOfSection",
    "MmCopyMemory",
    "MmGetPhysicalAddress",
    "HalTranslateBusAddress",
)

# The HAL hardware-access family: port-I/O and MMIO register reads/writes. These are
# the x86 board-driver's primitives — ISA/PCI DAQ and serial boards don't inline
# ``in``/``out`` (they call ``WRITE_PORT_UCHAR`` etc.), and MMIO boards go through
# ``READ/WRITE_REGISTER_*``. Reachable from a world-accessible IOCTL with a
# caller-influenced port/register + value, they are the dbutil/giveio shape (the
# reviewer confirms the port/value taint from the IRP — the shape is static evidence).
# Writes rank ahead of reads (the stronger primitive).
_HAL_PORT_SINKS = tuple(
    f"{rw}_{kind}_{width}"
    for rw, kinds in (("WRITE", ("PORT", "REGISTER")), ("READ", ("PORT", "REGISTER")))
    for kind in kinds
    for width in ("UCHAR", "USHORT", "ULONG",
                  "BUFFER_UCHAR", "BUFFER_USHORT", "BUFFER_ULONG")
)

# A raw device name embedded in the image (``\Device\Foo`` / ``\DosDevices\Foo`` /
# ``\??\Foo``). ``izzj`` returns these with the backslashes unescaped.
_DEVICE_NAME_RE = re.compile(r"\\(?:Device|DosDevices|\?\?)\\[^\s\"']*")
# An SDDL security descriptor literal — a DACL/owner prefix followed by at least one ACE.
# e.g. ``D:P(A;;GA;;;SY)(A;;GA;;;BA)``. Its presence means an ACL is applied in-binary.
_SDDL_RE = re.compile(r"[OGDS]:[A-Z]*\((?:A|D|OA|OD|AU|AL|OU);")
# An SDDL *allow* ACE — ``(A;flags;rights;;;SID)`` — granting one of the low-privilege
# trustees: BU (Users), WD (Everyone), AU (Authenticated Users), IU (Interactive), AN
# (Anonymous), or the equivalent well-known numeric SIDs. An SDDL is only a real lock-out
# when NONE of its allow-ACEs name such a trustee — a descriptor that grants BU/WD (e.g.
# Rzpnk's ``(A;;GA;;;BU)``) is still world-accessible. "SDDL present" alone is NOT a lock.
_SDDL_ALLOW_LOWPRIV = re.compile(
    r"\(A;[^;()]*;[^;()]*;[^;()]*;[^;()]*;"
    r"(?:BU|WD|AU|IU|AN|S-1-1-0|S-1-5-11|S-1-5-7|S-1-5-32-545)\)"
)


@dataclass
class SinkCandidate:
    """A copy-sink reachable from the dispatch handler — a candidate memory-unsafe site
    for human review. ``length_operands`` records the copy instruction(s) whose count
    register is the attacker-controlled-length surface to check (taint from the IRP
    ``SystemBuffer`` is left for review — the shape is static evidence, not a proof)."""

    addr: int
    tier: int  # 1 == reachable copy-sink (the memory-safety candidates)
    distance: int  # direct-call hops from the nearest dispatch handler (lower == closer)
    shape: str  # "rep_movs" | "indexed_copy" | "kernel_primitive:<name>"
    length_operands: list[str] = field(default_factory=list)
    severity: int = 0  # tie-break within the primitive class (lower == higher value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "addr": f"0x{self.addr:x}",
            "tier": self.tier,
            "distance": self.distance,
            "shape": self.shape,
            "length_operands": self.length_operands,
        }


@dataclass
class TriageRecord:
    """Per-driver triage output: the pre-filter verdict plus, for a world-accessible
    driver, the ranked reachable copy-sinks. A candidate list for review, not a bug."""

    sha256: str
    path: str
    is_driver: bool
    world_accessible: bool
    device_names: list[str] = field(default_factory=list)
    security_imports: list[str] = field(default_factory=list)
    sddl_present: bool = False
    prefilter_reason: str = ""
    dispatch_handlers: list[int] = field(default_factory=list)
    sinks: list[SinkCandidate] = field(default_factory=list)
    located: bool = False  # whether the LOCATE stage ran (gated on world_accessible)
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "path": self.path,
            "is_driver": self.is_driver,
            "world_accessible": self.world_accessible,
            "device_names": self.device_names,
            "security_imports": self.security_imports,
            "sddl_present": self.sddl_present,
            "prefilter_reason": self.prefilter_reason,
            "dispatch_handlers": [f"0x{h:x}" for h in self.dispatch_handlers],
            "sinks": [s.as_dict() for s in self.sinks],
            "located": self.located,
            "note": self.note,
        }


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _import_names(r2: Any) -> set[str]:
    return {str(i.get("name", "")) for i in (_loadj(r2, "iij") or [])}


def _device_names(r2: Any) -> list[str]:
    names: set[str] = set()
    for s in _loadj(r2, "izzj") or []:
        text = s.get("string")
        if not isinstance(text, str):
            continue
        # ``izzj`` doubles the literal backslashes; collapse runs so the reported name is
        # the real object path (``\Device\Foo``), not ``\Device\\Foo``.
        names.update(re.sub(r"\\{2,}", r"\\", n) for n in _DEVICE_NAME_RE.findall(text))
    return sorted(names)


def _sddl_verdict(r2: Any) -> tuple[bool, bool]:
    """Returns ``(sddl_present, locks_out_users)``. An in-binary SDDL locks out
    unprivileged callers only when it has NO allow-ACE granting a low-privilege trustee
    (BU/WD/AU/IU/...). A descriptor that grants Users/Everyone leaves the device
    world-accessible despite being ACL'd."""
    present = False
    grants_lowpriv = False
    for s in _loadj(r2, "izzj") or []:
        text = s.get("string")
        if not isinstance(text, str) or not _SDDL_RE.search(text):
            continue
        present = True
        if _SDDL_ALLOW_LOWPRIV.search(text):
            grants_lowpriv = True
    return present, (present and not grants_lowpriv)


@dataclass
class PrefilterVerdict:
    world_accessible: bool
    device_names: list[str]
    security_imports: list[str]
    sddl_present: bool
    reason: str


def prefilter(r2: Any) -> PrefilterVerdict:
    """no-ACL reachability gate — cheap, symbol-free, runs before any analysis pass.

    ``world_accessible`` is True when the driver publishes a user-openable device symlink
    but shows no evidence of gating it (no secure-create import, no in-binary SDDL)."""
    imports = _import_names(r2)
    user_reachable = sorted(imports & set(_USER_REACHABLE_IMPORTS))
    secure = sorted(imports & set(_SECURE_CREATE_IMPORTS))
    sddl_present, sddl_locks = _sddl_verdict(r2)
    names = _device_names(r2)

    if not user_reachable:
        reason = "no user-reachable symlink import (IoCreateSymbolicLink absent)"
        world = False
    elif secure:
        reason = f"secure device creation present: {', '.join(secure)}"
        world = False
    elif sddl_locks:
        reason = "in-binary SDDL grants only privileged trustees (SY/BA) — locked"
        world = False
    else:
        detail = "SDDL grants an unprivileged trustee" if sddl_present else "no in-binary SDDL"
        reason = (
            f"user-reachable symlink ({', '.join(user_reachable)}) with no secure-create "
            f"import and {detail}"
        )
        world = True
    return PrefilterVerdict(
        world_accessible=world,
        device_names=names,
        security_imports=user_reachable + secure,
        sddl_present=sddl_present,
        reason=reason,
    )


# Sort class for a sink shape: a reachable kernel map/RW primitive is a cleaner LPE than
# a generic inlined copy, so it ranks ahead at equal call-distance.
def _shape_class(shape: str) -> int:
    if shape.startswith(("kernel_primitive:", "port_io:", "msr:")):
        return 0  # a direct hardware/memory primitive — the strongest LPE shape
    if shape == "rep_movs":
        return 1
    return 2  # indexed_copy


def _instr_primitive(
    r2: Any, addr: int, cache: dict[int, list[dict[str, Any]]]
) -> tuple[str | None, str]:
    """The worst privileged port-I/O / MSR instruction in function ``addr`` (or None).
    ``out``/``wrmsr`` (writes) outrank ``in``/``rdmsr`` (reads)."""
    best: str | None = None
    evidence = ""
    for op in _func_ops(r2, addr, cache):
        d = str(op.get("disasm", ""))
        m = _INSTR_PRIM_RE.match(d)
        if not m:
            continue
        mnem = m.group(1)
        if best is None or _INSTR_PRIMITIVES.index(mnem) < _INSTR_PRIMITIVES.index(best):
            best, evidence = mnem, d
    return best, evidence


def _rank_sinks(r2: Any, prio: dict[int, int],
                tier_stats: dict[str, int] | None = None) -> tuple[list[int], list[SinkCandidate]]:
    """Turn the LOCATE tier map into ranked triage sinks.

    Returns ``(dispatch_handlers, sinks)``. Sinks are two classes, both reachable from a
    dispatch handler: the tier-1 inlined copy-sinks, plus any reachable caller of a
    kernel map/RW primitive (:data:`_KERNEL_PRIMITIVE_SINKS`). Ordered by call-distance
    from the nearest handler, then by sink class, so the closest highest-value candidate
    is on top. Each carries the instruction(s) whose count/argument is the
    attacker-controlled surface a reviewer confirms against the IRP input buffer.
    Distances are measured over the ICFG-augmented graph; ``tier_stats`` (optional)
    collects the per-tier indirect-edge counts for the record's provenance note."""
    handlers = sorted(a for a, t in prio.items() if t == 0)
    reachable = set(prio)
    cache: dict[int, list[dict[str, Any]]] = {}
    funcs = _loadj(r2, "aflj") or []
    stats = tier_stats if tier_stats is not None else {}
    adj, _ = _augmented_driver_adjacency(r2, set(handlers), funcs, cache, stats)
    dist = _bfs_distance(adj, set(handlers))

    candidates: dict[int, SinkCandidate] = {}
    # class 1: inlined copy-sinks (tier 1 from LOCATE).
    for a in (a for a, t in prio.items() if t == 1):
        shape, ops = _copy_evidence(r2, a, cache)
        candidates[a] = SinkCandidate(
            addr=a, tier=1, distance=dist.get(a, 1 << 30), shape=shape, length_operands=ops
        )
    # class 2a: reachable functions issuing a privileged port-I/O / MSR instruction
    # (the overclock/EC/sensor driver primitive — arbitrary hardware/register access).
    for addr in reachable:
        instr, ev = _instr_primitive(r2, addr, cache)
        if instr:
            candidates[addr] = SinkCandidate(
                addr=addr, tier=prio.get(addr, 2), distance=dist.get(addr, 1 << 30),
                shape=f"port_io:{instr}" if instr in ("in", "out") else f"msr:{instr}",
                length_operands=[ev], severity=_INSTR_PRIMITIVES.index(instr),
            )
    # class 2: reachable callers of a kernel map/RW primitive (the MmMapIoSpace class)
    # or of a HAL port/register access (the x86 board-driver dbutil/giveio class).
    for addr, name, call_disasm, pdist in _kernel_primitive_sinks(r2, reachable, dist):
        # a primitive caller outranks the same function's incidental copy shape.
        candidates[addr] = SinkCandidate(
            addr=addr,
            tier=prio.get(addr, 2),
            distance=pdist,
            shape=f"kernel_primitive:{name}",
            length_operands=[call_disasm],
            severity=(_KERNEL_PRIMITIVE_SINKS + _HAL_PORT_SINKS).index(name),
        )

    ranked = sorted(
        candidates.values(),
        key=lambda c: (c.distance, _shape_class(c.shape), c.severity, c.addr),
    )
    return handlers, ranked


def _kernel_primitive_sinks(
    r2: Any, reachable: set[int], dist: dict[int, int]
) -> list[tuple[int, str, str, int]]:
    """Reachable functions that call a kernel map/RW primitive.

    Returns ``(caller_addr, primitive_name, call_disasm, distance)``. A caller counts as
    reachable if it is in the dispatch-reachable set directly, OR is one cross-reference
    hop from a reachable function — this recovers the primitive leaf when r2 splits its
    caller across a non-contiguous function boundary (measured on iqvw64e: the
    MmMapIoSpace leaf is called from a reachable IOCTL sub-handler but the linear
    disasm drops that edge)."""
    out: list[tuple[int, str, str, int]] = []
    for imp in _loadj(r2, "iij") or []:
        name = str(imp.get("name", ""))
        if name not in _KERNEL_PRIMITIVE_SINKS and name not in _HAL_PORT_SINKS:
            continue
        addr = imp.get("plt") or imp.get("vaddr")
        if not isinstance(addr, int):
            continue
        for xref in _loadj(r2, f"axtj @ 0x{addr:x}") or []:
            caller = xref.get("fcn_addr")
            if not isinstance(caller, int):
                continue
            cdist = _reach_distance(r2, caller, reachable, dist)
            if cdist is not None:
                out.append((caller, name, str(xref.get("opcode", f"call {name}")), cdist))
    return out


def _reach_distance(
    r2: Any, func: int, reachable: set[int], dist: dict[int, int]
) -> int | None:
    """Call-distance of ``func`` from the dispatch handler, or None if unreachable.
    Falls back to one cross-reference hop when the direct-call graph misses ``func``."""
    if func in dist:
        return dist[func]
    best: int | None = None
    for xref in _loadj(r2, f"axtj @ 0x{func:x}") or []:
        c = xref.get("fcn_addr")
        if isinstance(c, int) and c in dist:
            best = min(best if best is not None else 1 << 30, dist[c] + 1)
    if best is None and func in reachable:
        return 1 << 20  # reachable but distance unknown — rank it last, still surfaced
    return best


def _bfs_distance(adj: dict[int, set[int]], roots: set[int]) -> dict[int, int]:
    dist = dict.fromkeys(roots, 0)
    frontier = list(roots)
    while frontier:
        nxt: list[int] = []
        for a in frontier:
            for y in adj.get(a, ()):
                if y not in dist:
                    dist[y] = dist[a] + 1
                    nxt.append(y)
        frontier = nxt
    return dist


# Privileged CPU instructions that ARE an LPE primitive when reachable from an
# unprivileged IOCTL: arbitrary port I/O (``in``/``out``) and MSR access
# (``rdmsr``/``wrmsr``) let a caller touch hardware / model-specific registers directly.
# This is the overclock / EC / sensor / flash driver class — a huge fraction of the OEM
# vein whose primitive is NOT a memory copy or an Mm* map (measured on Foxconn FXDrv64).
# Ordered worst-first: a write primitive (out/wrmsr) outranks a read (in/rdmsr).
_INSTR_PRIMITIVES = ("wrmsr", "out", "rdmsr", "in")
_INSTR_PRIM_RE = re.compile(r"^(wrmsr|rdmsr|out|in)\b")

_REP_MOVS_RE = re.compile(r"\brep\b.*\bmovs")


def _copy_evidence(
    r2: Any, addr: int, cache: dict[int, list[dict[str, Any]]]
) -> tuple[str, list[str]]:
    """Classify the sink's copy shape and pull the copy instruction disasm — the site
    whose count register (rcx for ``rep movs``) is the attacker-controlled-length surface
    a reviewer confirms against the IRP input buffer."""
    rep: list[str] = []
    idx: list[str] = []
    for op in _func_ops(r2, addr, cache):
        d = str(op.get("disasm", ""))
        if _REP_MOVS_RE.search(d):
            rep.append(d)
        elif "mov" in d and "[" in d and "[rsp" not in d and "[rbp" not in d and "[ebp" not in d:
            # a memory access through a non-stack pointer — the actual copy site, not a
            # prologue register spill to the stack frame (which is noise for triage).
            # The filter names rsp/rbp AND ebp: x86 frame reads ([ebp+8] arg loads)
            # are the same prologue noise on the 32-bit board-driver slice.
            idx.append(d)
    if rep:
        return "rep_movs", rep[:4]
    # indexed copy: keep a couple of representative pointer ops as the shape witness.
    return "indexed_copy", idx[:4]


def triage_driver(path: str | Path, *, run_locate: bool = True) -> TriageRecord:
    """Full triage of one driver binary: pre-filter, then (if world-accessible) LOCATE.

    Opens the binary once. The pre-filter runs on the un-analysed handle so a
    NOT-world-accessible driver is gated out before the expensive ``aaa`` pass; only a
    survivor pays for analysis + LOCATE. Static only — the binary is never executed."""
    import r2pipe

    path = str(path)
    sha = sha256_file(path)
    rec = TriageRecord(sha256=sha, path=path, is_driver=False, world_accessible=False)

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        rec.is_driver = _is_windows_kernel_driver(r2)
        if not rec.is_driver:
            rec.prefilter_reason = "not a Windows kernel driver (PE subsystem/imports)"
            return rec

        verdict = prefilter(r2)
        rec.world_accessible = verdict.world_accessible
        rec.device_names = verdict.device_names
        rec.security_imports = verdict.security_imports
        rec.sddl_present = verdict.sddl_present
        rec.prefilter_reason = verdict.reason

        if not (verdict.world_accessible and run_locate):
            return rec  # gate: no expensive analysis for a non-reachable driver

        r2.cmd("e bin.relocs.apply=true")
        r2.cmd("e scr.color=0")
        r2.cmd("aaa")
        prio = _windows_driver_priority(r2)
        if not prio:
            rec.note = "world-accessible but no IRP_MJ_DEVICE_CONTROL dispatch anchor found"
            return rec
        tier_stats: dict[str, int] = {}
        handlers, sinks = _rank_sinks(r2, prio, tier_stats)
        rec.dispatch_handlers = handlers
        rec.sinks = sinks
        rec.located = True
        rec.note = f"{len(handlers)} dispatch handler(s), {len(sinks)} reachable copy-sink(s)"
        if tier_stats:
            tiers = ", ".join(f"{k}:{v}" for k, v in sorted(tier_stats.items()))
            rec.note += f" [icfg edges: {tiers}]"
        return rec
    finally:
        r2.quit()


def batch_triage(
    paths: list[str | Path], *, run_locate: bool = True
) -> list[TriageRecord]:
    """Triage a corpus. Records are returned world-accessible-first, then by sink count —
    the review queue with the highest-signal candidates on top."""
    records = [triage_driver(p, run_locate=run_locate) for p in paths]
    records.sort(key=lambda r: (not r.world_accessible, -len(r.sinks)))
    return records


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m zeroverse.windows_driver_triage <driver.sys|dir> ...``

    Triages each driver (or every ``*.sys`` under a directory) and prints one JSON
    triage record per line — the review queue, world-accessible + most-sinks first.
    Static only; drivers are never loaded or run."""
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+", help="driver .sys files or directories to scan")
    ap.add_argument("--no-locate", action="store_true",
                    help="run the no-ACL pre-filter only (skip the LOCATE stage)")
    ns = ap.parse_args(argv)

    targets: list[str | Path] = []
    for p in ns.paths:
        path = Path(p)
        if path.is_dir():
            # a real .sys corpus, or the CAS layout (<sha256>/artifact, extensionless).
            found = sorted(path.rglob("*.sys")) + sorted(path.rglob("artifact"))
            targets.extend(found)
        else:
            targets.append(path)

    records = batch_triage(targets, run_locate=not ns.no_locate)
    for rec in records:
        print(json.dumps(rec.as_dict()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

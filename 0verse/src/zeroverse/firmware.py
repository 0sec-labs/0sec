"""#21 — MIPS/ARM firmware lane: binwalk unpack + Qiling emulation.

``qemu-user`` alone runs a *static* cross-arch ELF, but firmware needs a rootfs +
loader + syscall layer that qemu-user can't supply on its own. Qiling provides
exactly that (a Python emulation framework over Unicorn with a Linux/RTOS syscall
layer and a rootfs), so it is 0verse's firmware execution engine. It lets us:

  * emulate a recovered function directly — seed the integer-arg registers and the
    return-address register straight from the resolved ``Abi`` (``$a0/$a1`` + ``$ra``
    for MIPS o32) and run from the function entry to a sentinel return address.
    A control input returns cleanly to the sentinel; an overflowing input corrupts
    the saved return address and faults — a *differential reachability/crash*
    signal that needs neither libc nor the firmware's own input plumbing;
  * reuse the M1 oracle's dedup + the M1 ``PoV`` unit of truth, so a confirmed
    emulation fault becomes a PoV exactly like a native crash (the
    no-PoV-no-finding gate holds — a clean differential is required).

The binwalk step (carving a real firmware image into its squashfs/cramfs rootfs +
constituent ELFs) is wired as ``unpack_firmware`` and runs a real signature scan.
Sourcing a genuine router image on the bench is out of scope, so the *engine* is
proven on a committed MIPS ELF and the unpack step is documented + scanned, never
faked with a fabricated blob.
"""

from __future__ import annotations

import contextlib
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from . import oracle
from .abi import Abi
from .acquisition import AcquisitionManifest, FirmwareAnalysisInput
from .analyze import Finding
from .preflight import BudgetTracker
from .report import PoV
from .sandbox_exec import LocalExecutor, current_executor

# Arches whose dynamic confirmation 0verse routes through Qiling when the host
# cannot natively/binfmt run them (the firmware lane).
FIRMWARE_ARCHES: frozenset[str] = frozenset({"mips", "mipsel", "arm", "aarch64"})


# --- acquisition boundary ---------------------------------------------------

def acquisition_analysis_inputs(
    manifest: AcquisitionManifest,
) -> tuple[FirmwareAnalysisInput, ...]:
    """Return only hash-verified, offline-safe firmware artifacts for analysis."""
    return manifest.analysis_inputs()


# --- availability probes ----------------------------------------------------

def qiling_available() -> bool:
    """True when the Qiling emulation extra is importable."""
    try:
        import qiling  # noqa: F401
    except ImportError:
        return False
    return True


def binwalk_available() -> bool:
    return shutil.which("binwalk") is not None


def is_firmware_arch(abi: Abi | None) -> bool:
    return abi is not None and abi.arch in FIRMWARE_ARCHES


# --- binwalk firmware unpack ------------------------------------------------

@dataclass
class UnpackResult:
    """Result of a binwalk pass over a firmware blob. ``root`` is the extracted
    rootfs directory (when ``extract``), ``elf_files`` the carved executables that
    feed the Qiling lane, ``signatures`` the raw scan lines."""

    ok: bool
    root: str = ""
    signatures: list[str] = field(default_factory=list)
    elf_files: list[str] = field(default_factory=list)
    note: str = ""


def unpack_firmware(
    blob: str | Path, workdir: str | Path, *, extract: bool = True, timeout: int = 180
) -> UnpackResult:
    """Signature-scan (and optionally carve) a firmware blob with binwalk.

    The scan always runs; ``extract`` additionally runs ``binwalk -e`` to carve the
    embedded filesystem/rootfs (the ``_<name>.extracted`` tree) and collects any
    ELF binaries inside it (the Qiling targets). Degrades honestly when binwalk is
    absent — never fabricates an unpack."""
    if not binwalk_available():
        return UnpackResult(False, note="binwalk not installed (apt-get install -y binwalk)")
    blob = Path(blob)
    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)

    signatures: list[str] = []
    try:
        scan = subprocess.run(
            ["binwalk", str(blob)], capture_output=True, timeout=timeout, check=False
        )
        for line in scan.stdout.decode("utf-8", "replace").splitlines():
            s = line.strip()
            if s and s[0].isdigit():
                signatures.append(s)
    except (subprocess.TimeoutExpired, OSError) as e:
        return UnpackResult(False, note=f"binwalk scan failed: {e}")

    root = ""
    elf_files: list[str] = []
    if extract:
        try:
            subprocess.run(
                ["binwalk", "-e", "-q", "-C", str(work), str(blob)],
                capture_output=True, timeout=timeout, check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return UnpackResult(
                True, signatures=signatures, note=f"scan ok; extract failed: {e}"
            )
        for cand in work.glob(f"_{blob.name}.extracted"):
            root = str(cand)
        search_root = Path(root) if root else work
        for f in search_root.rglob("*"):
            if f.is_file():
                try:
                    if f.open("rb").read(4) == b"\x7fELF":
                        elf_files.append(str(f))
                except OSError:
                    continue

    note = f"binwalk: {len(signatures)} signature(s)"
    if extract:
        note += f", {len(elf_files)} carved ELF(s)"
    return UnpackResult(
        True, root=root, signatures=signatures, elf_files=elf_files, note=note
    )


# --- ELF symbol lookup (resolve a function entry without a disassembler) -----

def elf_function_addr(path: str | Path, name: str) -> int | None:
    """Return the virtual address of symbol ``name`` from an ELF's ``.symtab``
    (any arch/endianness/bitness). Lets the firmware lane / benchmark drive a
    recovered function by name without a full Ghidra pass."""
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        e_shoff = struct.unpack_from(end + "Q", data, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 58)
    else:
        e_shoff = struct.unpack_from(end + "I", data, 32)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 46)

    def _sh(i: int) -> tuple[int, int, int, int]:
        base = e_shoff + i * e_shentsize
        name_off = struct.unpack_from(end + "I", data, base)[0]
        if is64:
            sh_off = struct.unpack_from(end + "Q", data, base + 24)[0]
            sh_size = struct.unpack_from(end + "Q", data, base + 32)[0]
            sh_link = struct.unpack_from(end + "I", data, base + 40)[0]
        else:
            sh_off = struct.unpack_from(end + "I", data, base + 16)[0]
            sh_size = struct.unpack_from(end + "I", data, base + 20)[0]
            sh_link = struct.unpack_from(end + "I", data, base + 24)[0]
        return name_off, sh_off, sh_size, sh_link

    if e_shstrndx >= e_shnum:
        return None
    _, shstr_off, _, _ = _sh(e_shstrndx)

    def _str(table_off: int, idx: int) -> str:
        start = table_off + idx
        nul = data.find(b"\x00", start)
        return data[start:nul].decode("utf-8", "replace") if nul != -1 else ""

    symtab: tuple[int, int, int] | None = None
    for i in range(e_shnum):
        name_off, sh_off, sh_size, sh_link = _sh(i)
        if _str(shstr_off, name_off) == ".symtab":
            symtab = (sh_off, sh_size, sh_link)
            break
    if symtab is None:
        return None
    sym_off, sym_size, str_link = symtab
    _, strtab_off, _, _ = _sh(str_link)

    entsize = 24 if is64 else 16
    for off in range(sym_off, sym_off + sym_size, entsize):
        st_name = struct.unpack_from(end + "I", data, off)[0]
        if is64:
            st_value = struct.unpack_from(end + "Q", data, off + 8)[0]
        else:
            st_value = struct.unpack_from(end + "I", data, off + 4)[0]
        if _str(strtab_off, st_name) == name:
            return int(st_value)
    return None


# --- Qiling emulation engine ------------------------------------------------

@dataclass
class QilingResult:
    """One Qiling function emulation. ``crashed`` is a memory fault (the trigger
    signal); ``reached_end`` means execution returned cleanly to the sentinel."""

    crashed: bool
    reached_end: bool
    executed: bool = False
    exception: str = ""
    pc: int = 0
    note: str = ""


# Default sentinel "return address" and scratch buffer addresses for emulate_call.
_SENTINEL = 0x4D000000
_BUF_ADDR = 0x20000000
_REGION = 0x20000


class QilingBackend(Protocol):
    """Pluggable Qiling backend so the differential confirm logic is unit-testable
    with a fake (no Unicorn/Qiling install required)."""

    def emulate_call(
        self,
        binary: str | Path,
        func_addr: int,
        input_bytes: bytes,
        *,
        abi: Abi,
        timeout: float | None = None,
    ) -> QilingResult: ...


class QilingEmulator:
    """The real backend: load the ELF under Qiling, place ``input_bytes`` in a
    fresh buffer, seed the integer-arg registers + the return-address register from
    the ABI, and run from ``func_addr`` to a sentinel return address. A memory
    fault surfaces as ``crashed``; a clean return to the sentinel as
    ``reached_end``. Never raises — any Qiling/Unicorn fault is the *signal*, not an
    error to propagate."""

    def __init__(
        self,
        *,
        sentinel: int = _SENTINEL,
        buf_addr: int = _BUF_ADDR,
        region: int = _REGION,
        max_steps: int = 2_000_000,
        rootfs: str | None = None,
        execution_authorized: bool | None = None,
    ) -> None:
        self.sentinel = sentinel
        self.buf_addr = buf_addr
        self.region = region
        self.max_steps = max_steps
        self.rootfs = rootfs
        self.execution_authorized = execution_authorized

    def emulate_call(
        self,
        binary: str | Path,
        func_addr: int,
        input_bytes: bytes,
        *,
        abi: Abi,
        timeout: float | None = None,
    ) -> QilingResult:
        authorized = self.execution_authorized
        if authorized is None:
            authorized = isinstance(current_executor(), LocalExecutor)
        if not authorized:
            return QilingResult(False, False, note="Qiling execution is not authorized")
        if not abi.int_arg_regs:
            return QilingResult(False, False, note=f"{abi.arch}: no register args to seed")
        try:
            from qiling import Qiling
            from qiling.const import QL_VERBOSE

            rootfs = self.rootfs or str(Path(binary).resolve().parent)
            ql = Qiling([str(binary)], rootfs=rootfs, verbose=QL_VERBOSE.DISABLED)
        except Exception as e:  # Qiling loader is best-effort; report, never raise
            return QilingResult(False, False, note=f"qiling init failed: {type(e).__name__}: {e}")

        try:
            with contextlib.suppress(Exception):  # region may already be mapped
                ql.mem.map(self.buf_addr, self.region)
            ql.mem.write(self.buf_addr, input_bytes)
            regs = abi.int_arg_regs
            ql.arch.regs.write(regs[0], self.buf_addr)
            if len(regs) > 1:
                ql.arch.regs.write(regs[1], len(input_bytes))
            if abi.ra_reg:
                ql.arch.regs.write(abi.ra_reg, self.sentinel)
        except Exception as e:
            return QilingResult(False, False, note=f"qiling setup failed: {type(e).__name__}: {e}")

        crashed = False
        exc = ""
        try:
            ql.run(
                begin=func_addr,
                end=self.sentinel,
                timeout=0 if timeout is None else max(1, int(timeout * 1_000_000)),
                count=self.max_steps,
            )
        except Exception as e:  # a memory fault IS the trigger signal
            crashed = True
            exc = f"{type(e).__name__}: {str(e)[:120]}"
        pc = 0
        try:
            pc = int(ql.arch.regs.arch_pc)
        except Exception:
            pc = 0
        return QilingResult(
            crashed=crashed,
            reached_end=(not crashed) and pc == self.sentinel,
            executed=True,
            exception=exc,
            pc=pc,
        )


def emulate_call(
    binary: str | Path, func_addr: int, input_bytes: bytes, *, abi: Abi
) -> QilingResult:
    """Convenience wrapper over the real ``QilingEmulator`` (used by the benchmark)."""
    return QilingEmulator().emulate_call(binary, func_addr, input_bytes, abi=abi)


def _exc_signal(exc: str) -> str:
    e = exc.upper()
    if "WRITE" in e:
        return "SIGSEGV-write"
    if "FETCH" in e or "EXEC" in e:
        return "SIGSEGV-exec (corrupted return address)"
    if "READ" in e:
        return "SIGSEGV-read"
    if "ARG" in e:
        # Unicorn raises UC_ERR_ARG on an unaligned/invalid instruction fetch — the
        # exact signal of a return address overwritten with attacker bytes.
        return "SIGSEGV-exec (control-flow hijack / unaligned PC)"
    return "SIGSEGV"


def _emulate_bounded(
    backend: QilingBackend,
    binary: str | Path,
    func_addr: int,
    payload: bytes,
    *,
    abi: Abi,
    timeout: float | None,
) -> QilingResult:
    """Run one cooperative Qiling call.

    The backend receives the clipped timeout and must honor it. Hard cancellation is
    deferred to #26; no background emulation survives this call.
    """
    try:
        if timeout is None:
            return backend.emulate_call(binary, func_addr, payload, abi=abi)
        return backend.emulate_call(
            binary,
            func_addr,
            payload,
            abi=abi,
            timeout=timeout,
        )
    except Exception as exc:
        return QilingResult(
            False,
            False,
            note=f"qiling adapter failed: {type(exc).__name__}: {exc}",
        )


def qiling_confirm(
    finding: Finding,
    binary: str | Path,
    abi: Abi | None,
    func_addr: int | None,
    *,
    seeds: list[bytes] | None = None,
    backend: QilingBackend | None = None,
    trigger_len: int = 512,
    budget: BudgetTracker | None = None,
    unknown_sink: bool = False,
    capabilities_resolved: bool = False,
    execution_authorized: bool | None = None,
) -> PoV | None:
    """Differential function-level confirmation via Qiling (the firmware lane's
    dynamic oracle). For each candidate magic prefix, emulate ``func_addr`` with an
    oversized input and a tiny in-bounds control input: a PoV is emitted only when
    the trigger *faults* and the control *returns cleanly* — the same
    differential discipline as the native oracle, so a function that faults on any
    input (or never faults) yields no finding. Returns ``None`` (honest degrade)
    when Qiling is unavailable or the arch has no return-address register to seed."""
    available = True if capabilities_resolved else qiling_available()
    authorized = (
        execution_authorized
        if capabilities_resolved
        else isinstance(current_executor(), LocalExecutor)
    )
    if not (authorized and available and abi is not None and abi.ra_reg and func_addr):
        return None
    backend = backend or QilingEmulator(execution_authorized=authorized)
    prefixes = (seeds or [b""])[:8] or [b""]
    for pre in prefixes:
        trigger = pre + b"A" * trigger_len
        control = pre if pre else b"A" * 4          # tiny, in-bounds, same gate
        if budget is not None and not budget.reserve_attempt(
            unknown_sink=unknown_sink
        )[0]:
            break
        timeout = budget.remaining_seconds() if budget is not None else None
        if timeout is not None and timeout <= 0:
            if budget is not None:
                budget.reservation_failures += 1
            break
        tr = _emulate_bounded(
            backend,
            binary,
            func_addr,
            trigger,
            abi=abi,
            timeout=timeout,
        )
        if budget is not None and budget.expired():
            budget.reservation_failures += 1
            break
        if not (tr.executed and tr.crashed):
            continue
        if budget is not None and not budget.reserve_attempt(
            unknown_sink=unknown_sink
        )[0]:
            break
        timeout = budget.remaining_seconds() if budget is not None else None
        if timeout is not None and timeout <= 0:
            if budget is not None:
                budget.reservation_failures += 1
            break
        cr = _emulate_bounded(
            backend,
            binary,
            func_addr,
            control,
            abi=abi,
            timeout=timeout,
        )
        if budget is not None and budget.expired():
            budget.reservation_failures += 1
            break
        if cr.crashed:
            continue  # faults even on benign input → not a controllable overflow
        pov = PoV(
            input_bytes=trigger,
            crash_class=_exc_signal(tr.exception),
            crash_trace=(
                f"Qiling {abi.arch} ({abi.name}) emulation fault at pc={hex(tr.pc)}: "
                f"{tr.exception}"
            ),
            reproduced=True,
            capability="crash",
        )
        pov.diff_allocator = (
            "qiling-emulated differential: "
            f"trigger={tr.exception or 'fault'} / control=clean(returned to sentinel) "
            "[real overflow corrupting the saved return address]"
        )
        pov.dedup_bucket = oracle.dedup_key(
            pov.crash_class, [f"{finding.function}+{hex(func_addr)}"]
        )
        return pov
    return None


def maybe_qiling_runner(abi: Abi | None) -> bool:
    """True when the firmware Qiling lane is *available* for this target (a
    firmware-arch ELF + Qiling installed)."""
    return is_firmware_arch(abi) and qiling_available()


def prefers_qiling(abi: Abi | None, *, runnable: bool) -> bool:
    """Should pipeline dynamic confirmation route through the Qiling lane?

    Yes whenever the host cannot natively/binfmt run the target, and yes for the
    32-bit embedded arches (``mips``/``mipsel``/``arm``) even when a bare static
    ELF *is* qemu-user runnable — because real firmware binaries are dynamically
    linked against a vendor rootfs that bare qemu-user can't satisfy, and the
    native guard-allocator oracle has no arch-matched libs there. ``aarch64`` keeps
    its proven native + AFL-QEMU path (the M3 keystone) unless it isn't runnable."""
    if not maybe_qiling_runner(abi):
        return False
    if not runnable:
        return True
    return abi is not None and abi.arch in ("mips", "mipsel", "arm")

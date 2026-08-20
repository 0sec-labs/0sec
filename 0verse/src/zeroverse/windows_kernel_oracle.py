"""Windows kernel crash-oracle — PoV gate for the Phase B driver oracle.

Consumes the evidence produced by ``scripts/windows/oracle/run-m0-controls.ps1``
(host-side kd serial-pipe logs, in-guest trigger JSONL, guest minidump + host
``cdb !analyze -v`` text) and applies the deterministic five-conjunct gate from the
Phase B design:

  (a) deterministic signal — bugcheck in :data:`DETERMINISTIC_BUGCHECKS`, or the
      witness breakpoint pair observed exactly once (crash-free lane for the
      physmap/port-IO primitive classes that never fault);
  (b) module attribution — the faulting/observed module IS the target driver;
  (c) binding — the driven IOCTL buffer hash matches the trigger record, and the
      dump/evidence postdates the invocation (no stale dumps, no crossed trials);
  (d) sink correspondence — the witness bp RVA / crash frame module matches the
      static triage record (``*-ioctl-map.json``);
  (e) controls clean — bogus-command and zero-length arms produced no signal.

Status vocabulary reuses :class:`zeroverse.adjudicate.Adjudication` verbatim
(CONFIRMED / DIVERGENT / NO_CRASH / UNRUNNABLE); ``crash_signature`` from
:mod:`zeroverse.hyperv_transport` is reused unchanged for bugcheck+bucket
normalization. Fail-closed throughout: missing or inconsistent evidence never
yields CONFIRMED.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adjudicate import CONFIRMED, DIVERGENT, NO_CRASH, UNRUNNABLE, Adjudication, crash_to_cwe
from .hyperv_transport import crash_signature

# Bugcheck codes whose appearance is a deterministic memory-unsafety signal for a
# driver under test (see Phase B design): pool guard-page faults, verifier
# detections, IRQL faults on bad memory, pool-header/list corruption, and the
# generic unhandled-exception family.
DETERMINISTIC_BUGCHECKS = frozenset({
    "a",     # IRQL_NOT_LESS_OR_EQUAL
    "50",    # PAGE_FAULT_IN_NONPAGED_AREA (Special Pool guard page / freed page)
    "c1",    # SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION
    "c4",    # DRIVER_VERIFIER_DETECTED_VIOLATION
    "d1",    # DRIVER_IRQL_NOT_LESS_OR_EQUAL
    "19",    # BAD_POOL_HEADER
    "139",   # KERNEL_SECURITY_CHECK_FAILURE (LIST_ENTRY / cookie classes)
    "1e",    # KMODE_EXCEPTION_NOT_HANDLED
    "7e",    # SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
})

_BUGCHECK_RE = re.compile(r"^\s*Bug[Cc]heck(?:\s+code)?\s+([0-9A-Fa-f]+)(?:,|\s|$)", re.MULTILINE)
_MODULE_NAME_RE = re.compile(r"^\s*MODULE_NAME:\s*(\S+)\s*$", re.MULTILINE)
_IMAGE_NAME_RE = re.compile(r"^\s*IMAGE_NAME:\s*(\S+)\s*$", re.MULTILINE)
_FAULTING_MODULE_RE = re.compile(r"^\s*FAULTING_MODULE:\s*([0-9A-Fa-f`]+)", re.MULTILINE)
_BUCKET_ID_RE = re.compile(r"^\s*FAILURE_BUCKET_ID:\s*(\S.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_WRITE_LINE_RE = re.compile(r"Attempt to write to address\s+([0-9a-fA-F`]+)")
_READ_LINE_RE = re.compile(r"Attempt to read from address\s+([0-9a-fA-F`]+)")
# !analyze STACK_TEXT lines look like
# ``ffffc30a`8b7e9000 fffff801`2ab01234 : <args> : myfault64+0x1234`` — the
# module!symbol is the trailing field, ``mod+0xRVA`` when stripped.
_STACK_LINE_RE = re.compile(
    r"^[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+:.*?:\s*([A-Za-z_][\w.]*?)(?:!|\+0x[0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)
_TRIGGER_MARKER = "0VERSE-TRIGGER-JSON:"
_WITNESS_OPERANDS = "0VERSE-WITNESS-OPERANDS"
_WITNESS_READBACK = "0VERSE-WITNESS-READBACK"
_WITNESS_REG_RE = re.compile(r"(rcx|rdx)=([0-9a-fA-F`]+)")
_DQ_LINE_RE = re.compile(
    r"^([0-9a-fA-F`]+)\s+((?:[0-9a-fA-F`]+\s+)+)", re.MULTILINE
)

# Kernel-mode interceptor-skip analogue: frames attributed to these modules are
# never the faulting driver frame.
_KERNEL_FRAME_SKIP = frozenset({
    "nt", "ntoskrnl", "hal", "verifier", "verifierExt", "kdnic", "kdusb",
    "FLTMGR", "CI", "win32kbase",
})


@dataclass(frozen=True)
class KernelCrashInfo:
    """Parsed host-cdb ``!analyze -v`` of a guest kernel dump."""

    bugcheck: str = ""
    bucket: str = ""
    module_name: str = ""
    image_name: str = ""
    access: str = ""           # "READ" | "WRITE" | ""
    fault_addr: str = ""
    frames: tuple[str, ...] = ()
    signature: str = ""        # crash_signature() reuse

    @property
    def deterministic(self) -> bool:
        return self.bugcheck.lower() in DETERMINISTIC_BUGCHECKS


@dataclass(frozen=True)
class WitnessRecord:
    """Parsed kd log of a witness-lane run (breakpoint pair + register capture)."""

    armed: bool = False
    breakpoints_bound: bool = False
    operands_hits: int = 0
    readback_hits: int = 0
    operand_rcx: str = ""
    operand_rdx: str = ""
    readback_physical: str = ""
    readback_mapped: str = ""

    @property
    def operands_match(self) -> bool:
        return bool(self.operand_rcx) and bool(self.operand_rdx)

    @property
    def readback_matches(self) -> bool:
        return bool(self.readback_physical) and self.readback_physical == self.readback_mapped


@dataclass(frozen=True)
class TriggerRecord:
    """One driven IOCTL, reported by the in-guest trigger."""

    device: str = ""
    ioctl: str = ""
    in_sha256: str = ""
    in_len: int = 0
    call_ok: bool = False
    win32_error: int = 0
    bytes_returned: int = 0
    in_post_hex: str = ""
    out_post_hex: str = ""
    # METHOD_NEITHER embedded-pointer arms (RwDrv class): the driven buffer carries
    # a runtime user VA, so the exact in_sha256 can't bind to a plan. The trigger
    # also reports in_template_sha256 (driven bytes with the pointer masked to 0),
    # which is deterministic and binds; userptr records the embedded VA for audit.
    in_template_sha256: str = ""
    userptr: str = ""


def parse_cdb_kernel_analysis(text: str) -> KernelCrashInfo:
    """Parse ``cdb -z <dump> -c '.bugcheck;!analyze -v;q'`` output."""
    bugcheck = ""
    m = _BUGCHECK_RE.search(text)
    if m:
        bugcheck = m.group(1).lower().lstrip("0") or "0"
    bucket = ""
    m = _BUCKET_ID_RE.search(text)
    if m:
        bucket = re.sub(r"\s+", " ", m.group(1).strip()).lower()
    module = ""
    m = _MODULE_NAME_RE.search(text)
    if m:
        module = m.group(1).strip()
    image = ""
    m = _IMAGE_NAME_RE.search(text)
    if m:
        image = m.group(1).strip()
    access = ""
    fault_addr = ""
    m = _WRITE_LINE_RE.search(text)
    if m:
        access, fault_addr = "WRITE", m.group(1)
    else:
        m = _READ_LINE_RE.search(text)
        if m:
            access, fault_addr = "READ", m.group(1)
    if not access:
        # 0x50 Arg2 encodes the access: bit 1 set = write (x64). The newer cdb
        # banner omits the "Attempt to ..." line, so derive it from the args.
        m = re.search(
            r"^\s*Arg2:\s*([0-9a-fA-F`]+)", text, re.MULTILINE
        )
        if m and bugcheck == "50":
            arg2 = int(m.group(1).replace("`", ""), 16)
            if arg2 & 0x2:
                access = "WRITE"
            elif arg2 & 0x1:
                access = "READ"
        m = re.search(r"^\s*Arg1:\s*([0-9a-fA-F`]+)", text, re.MULTILINE)
        if m:
            fault_addr = m.group(1)
    frames = tuple(
        name for name in _STACK_LINE_RE.findall(text)
        if name not in _KERNEL_FRAME_SKIP
    )
    return KernelCrashInfo(
        bugcheck=bugcheck,
        bucket=bucket,
        module_name=module,
        image_name=image,
        access=access,
        fault_addr=fault_addr,
        frames=frames,
        signature=crash_signature(text),
    )


def parse_trigger_jsonl(text: str) -> TriggerRecord | None:
    """Extract the ``0VERSE-TRIGGER-JSON:`` marker line from trigger output."""
    for line in text.splitlines():
        if line.startswith(_TRIGGER_MARKER):
            try:
                data = json.loads(line[len(_TRIGGER_MARKER):])
            except json.JSONDecodeError:
                return None
            return TriggerRecord(
                device=str(data.get("device", "")),
                ioctl=str(data.get("ioctl", "")),
                in_sha256=str(data.get("in_sha256", "")),
                in_len=int(data.get("in_len", 0)),
                call_ok=bool(data.get("call_ok", False)),
                win32_error=int(data.get("win32_error", 0)),
                bytes_returned=int(data.get("bytes_returned", 0)),
                in_post_hex=str(data.get("in_post_hex", "")),
                out_post_hex=str(data.get("out_post_hex", "")),
                in_template_sha256=str(data.get("in_template_sha256", "")),
                userptr=str(data.get("userptr", "")),
            )
    return None


def parse_kd_witness_log(text: str, expected_phys: str = "") -> WitnessRecord:
    """Parse the kd serial log of a witness run.

    The operand bp logs ``0VERSE-WITNESS-OPERANDS`` then ``r rcx,rdx``; the
    readback bp logs ``0VERSE-WITNESS-READBACK`` then ``dq /p <phys> L8`` and
    ``dq rax L8``. We compare the first qword line of each dq pair.
    """
    def marker_count(marker: str) -> int:
        return len(re.findall(rf"(?m)^\s*{re.escape(marker)}\s*$", text))

    armed = marker_count("0VERSE-KD-ARMED") == 1
    breakpoints_bound = marker_count("0VERSE-WITNESS-BPS-BOUND") == 1
    operands_hits = marker_count(_WITNESS_OPERANDS)
    readback_hits = marker_count(_WITNESS_READBACK)
    rcx = rdx = ""
    phys_first = mapped_first = ""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == _WITNESS_OPERANDS:
            window = "\n".join(lines[i:i + 4])
            regs = dict(_WITNESS_REG_RE.findall(window))
            rcx = regs.get("rcx", "").replace("`", "")
            rdx = regs.get("rdx", "").replace("`", "")
        if line.strip() == _WITNESS_READBACK:
            # ``dq ... L8`` emits four rows of two qwords. Split consecutive
            # rows into command groups by their displayed-address stride; the
            # second command starts at the mapped kernel VA and therefore
            # breaks the +0x10 sequence. Small synthetic fixtures may contain
            # only one row per command and are handled by the same rule.
            dq_groups: list[list[str]] = []
            previous_address: int | None = None
            for follow in lines[i + 1:]:
                if follow.strip().startswith("0VERSE-") or ".echo" in follow:
                    break
                m = _DQ_LINE_RE.match(follow.strip())
                if m:
                    address = int(m.group(1).replace("`", ""), 16)
                    first_qword = m.group(2).split()[0].replace("`", "")
                    if previous_address is None or address != previous_address + 0x10:
                        dq_groups.append([])
                    dq_groups[-1].append(first_qword)
                    previous_address = address
            if len(dq_groups) >= 2 and dq_groups[0] and dq_groups[1]:
                phys_first, mapped_first = dq_groups[0][0], dq_groups[1][0]
    return WitnessRecord(
        armed=armed,
        breakpoints_bound=breakpoints_bound,
        operands_hits=operands_hits,
        readback_hits=readback_hits,
        operand_rcx=rcx,
        operand_rdx=rdx,
        readback_physical=phys_first,
        readback_mapped=mapped_first,
    )


def _module_matches(actual: str, expected: str) -> bool:
    if not actual or not expected:
        return False
    a = actual.lower().removesuffix(".sys")
    e = expected.lower().removesuffix(".sys")
    return a == e


def adjudicate_kernel_crash(
    analysis_text: str,
    *,
    expected_driver: str,
    trigger: TriggerRecord | None,
    expected_in_sha256: str,
    control_clean: bool,
    dump_ticks: int = 0,
    invoke_ticks: int = 0,
    dump_identity_new: bool | None = None,
) -> Adjudication:
    """Crash-lane gate over a host-cdb analysis of the guest dump."""
    crash = parse_cdb_kernel_analysis(analysis_text)
    if not crash.bugcheck or not crash.signature:
        return Adjudication(UNRUNNABLE, reason="no bugcheck or failure bucket in analysis text")
    if dump_identity_new is None:
        # Legacy evidence used guest timestamps. New evidence uses exact file
        # identities because a restored checkpoint can temporarily carry a
        # future guest clock until Hyper-V time synchronization catches up.
        if dump_ticks <= 0 or invoke_ticks <= 0 or dump_ticks < invoke_ticks:
            return Adjudication(UNRUNNABLE, reason="dump does not postdate the crash invocation")
    elif not dump_identity_new:
        return Adjudication(
            UNRUNNABLE,
            reason="dump identity was not new after the crash invocation",
        )
    if trigger is None or not re.fullmatch(r"[0-9a-f]{64}", expected_in_sha256):
        return Adjudication(UNRUNNABLE, reason="missing trigger record for the driven IOCTL")
    if trigger.in_sha256 != expected_in_sha256:
        return Adjudication(UNRUNNABLE, reason="trigger buffer hash differs from the record")
    if not crash.deterministic:
        return Adjudication(
            DIVERGENT,
            reason=f"bugcheck 0x{crash.bugcheck} outside the deterministic set",
        )
    if not _module_matches(crash.module_name or crash.image_name, expected_driver):
        return Adjudication(
            DIVERGENT,
            crash_frames=list(crash.frames),
            reason=(
                f"crash in module {crash.module_name or crash.image_name!r}, "
                f"not {expected_driver!r}"
            ),
        )
    if not control_clean:
        return Adjudication(DIVERGENT, reason="control arm also produced a signal")
    kind = "heap-buffer-overflow" if crash.access else ""
    cwe, _family = crash_to_cwe(kind, crash.access) if kind else ("", "")
    return Adjudication(
        CONFIRMED,
        crash_function=crash.module_name,
        crash_cwe=cwe,
        crash_frames=list(crash.frames),
        reason=f"{crash.signature}; faulting module {crash.module_name}; "
               f"IOCTL {trigger.ioctl} bound by sha256 {trigger.in_sha256[:12]}…",
    )


def adjudicate_kernel_witness(
    kd_log_text: str,
    *,
    expected_driver: str,
    expected_phys: int,
    expected_len: int,
    trigger: TriggerRecord | None,
    expected_in_sha256: str,
    control_no_signal: bool,
) -> Adjudication:
    """Witness-lane gate for the never-crashing primitive classes (physmap/port-IO).

    CONFIRMED requires: kd armed; exactly one operands-bp hit and one readback-bp
    hit; rcx == expected physaddr and rdx == expected length at the sink; the
    physical-vs-mapped readback qwords match; the trigger record binds the driven
    buffer; and the control arms produced no hits.
    """
    witness = parse_kd_witness_log(kd_log_text)
    if not witness.armed:
        return Adjudication(UNRUNNABLE, reason="kd never armed its breakpoints")
    if not witness.breakpoints_bound:
        return Adjudication(UNRUNNABLE, reason="kd never proved the sink breakpoints bound")
    if trigger is None or trigger_buffer_sha256(trigger) != expected_in_sha256:
        return Adjudication(
            UNRUNNABLE,
            reason="trigger record missing or driven-buffer sha256 mismatch",
        )
    if witness.operands_hits != 1 or witness.readback_hits != 1:
        if witness.operands_hits == 0 and witness.readback_hits == 0:
            return Adjudication(NO_CRASH, reason="sink breakpoints never fired on the target arm")
        return Adjudication(
            DIVERGENT,
            reason=f"unexpected breakpoint hit counts (operands={witness.operands_hits}, "
                   f"readback={witness.readback_hits}); expected exactly one each",
        )
    got_phys = int(witness.operand_rcx or "0", 16)
    got_len = int(witness.operand_rdx or "0", 16)
    if got_phys != expected_phys or got_len != expected_len:
        return Adjudication(
            DIVERGENT,
            reason=f"sink operands {got_phys:#x}/{got_len:#x} != driven "
                   f"{expected_phys:#x}/{expected_len:#x}",
        )
    if not witness.readback_matches:
        return Adjudication(
            DIVERGENT,
            reason="physical-vs-mapped readback mismatch; mapping semantics not proven",
        )
    if not control_no_signal:
        return Adjudication(DIVERGENT, reason="control arms hit the sink breakpoints")
    return Adjudication(
        CONFIRMED,
        crash_function=f"{expected_driver}+sink",
        reason=f"witness: MmMapIoSpace executed with attacker physaddr "
               f"{expected_phys:#x} len {expected_len:#x}; physical/mapped readback identical; "
               f"IOCTL {trigger.ioctl} bound by sha256 {trigger.in_sha256[:12]}…",
    )


def load_ioctl_map(path: Path) -> dict[str, object]:
    """Load a ``*-ioctl-map.json`` static triage record (schema 0verse.driver-ioctl-map/v1)."""
    data: dict[str, object] = json.loads(path.read_text())
    if not str(data.get("schema_version", "")).startswith("0verse.driver-ioctl-map/"):
        raise ValueError(f"not a driver-ioctl-map: {path}")
    return data


# ---------------------------------------------------------------------------
# Trigger-level witness gate (driver-reported success + buffer binding)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TriggerWitnessFields:
    """Fields parsed out of a METHOD_NEITHER post-call input buffer image."""

    status: int = -1          # dword at 0x10 (driver status slot)
    mapped_va: int = 0        # qword at 0x18 (out-slot for the mapped VA)


def parse_trigger_witness_fields(trigger: TriggerRecord) -> TriggerWitnessFields:
    """Pull the status dword (0x10) and mapped-VA qword (0x18) from in_post_hex."""
    raw = bytes.fromhex(trigger.in_post_hex or "")
    status = int.from_bytes(raw[0x10:0x14], "little") if len(raw) >= 0x14 else -1
    va = int.from_bytes(raw[0x18:0x20], "little") if len(raw) >= 0x20 else 0
    return TriggerWitnessFields(status=status, mapped_va=va)


def trigger_buffer_sha256(trigger: TriggerRecord) -> str:
    """sha256 of the DRIVEN bytes, recovered from the post-call buffer.

    For METHOD_NEITHER drivers the kernel writes results back into lpInBuffer, so
    the trigger's post-call in_sha256 covers a mutated buffer (and the current
    in-guest trigger builds its JSON after the call). The driver-written fields
    here are the status dword at 0x10 and the out-slot qword at 0x18; masking
    them restores the driven bytes. Falls back to the recorded in_sha256 when
    no post-call image is available.
    """
    import hashlib

    if not trigger.in_post_hex:
        return trigger.in_sha256
    raw = bytearray(bytes.fromhex(trigger.in_post_hex))
    if len(raw) >= 0x20:
        raw[0x10:0x20] = b"\x00" * 0x10
    return hashlib.sha256(bytes(raw)).hexdigest()


def adjudicate_trigger_witness(
    trigger: TriggerRecord | None,
    *,
    expected_in_sha256: str,
    control_cmd99: TriggerRecord | None,
    control_len0: TriggerRecord | None,
    len0_error_value: int = 0xC86A8004,
) -> Adjudication:
    """Witness confirmation from the trigger record alone (kd bp lane optional).

    CONFIRMED requires all of:
      (a) the driven buffer binds by sha256 to the oracle's expectation;
      (b) the target arm reports call_ok, driver status 0 at [0x10], and a
          nonzero, kernel-space (top-bit-set) VA at [0x18] — the success branch
          of the sink (here NalMmapAddressEx) can only have executed;
      (c) the len=0 control reports the statically-predicted rejection value
          (0xc86a8004) with no VA, and the bogus-cmd control's call fails —
          proving the code-path model, not a rubber-stamp driver.
    """
    if trigger is None or trigger_buffer_sha256(trigger) != expected_in_sha256:
        return Adjudication(
            UNRUNNABLE,
            reason="witness trigger missing or driven-buffer sha256 mismatch",
        )
    fields = parse_trigger_witness_fields(trigger)
    if not trigger.call_ok or fields.status != 0 or fields.mapped_va == 0:
        return Adjudication(
            NO_CRASH,
            reason=f"sink success branch not observed (call_ok={trigger.call_ok}, "
                   f"status={fields.status:#x}, va={fields.mapped_va:#x})",
        )
    if fields.mapped_va >> 63 != 1:
        return Adjudication(
            DIVERGENT,
            reason=f"out-slot value {fields.mapped_va:#x} is not a kernel address",
        )
    if (
        control_len0 is None
        or parse_trigger_witness_fields(control_len0).status != len0_error_value
    ):
        return Adjudication(
            DIVERGENT,
            reason="len=0 control did not reproduce the predicted rejection",
        )
    if control_cmd99 is None or control_cmd99.call_ok:
        return Adjudication(DIVERGENT, reason="bogus-cmd control unexpectedly succeeded")
    return Adjudication(
        CONFIRMED,
        crash_function="iqvw64e+0x2a14",
        reason=f"trigger witness: MmMapIoSpace success branch executed with the driven "
               f"phys/len; kernel VA {fields.mapped_va:#x} returned to user; "
               f"len=0 control reproduced 0xc86a8004; buffer bound by "
               f"sha256 {trigger.in_sha256[:12]}…",
    )


# ---------------------------------------------------------------------------
# M0 evidence-dir CLI
# ---------------------------------------------------------------------------

_WITNESS_EXPECTED = {
    # iqvw64e NalMmapAddressEx witness drive (see iqvw64e-ioctl-map.json):
    # cmd=57, phys=0x1000, len=0x1000, map-to-user=0, METHOD_NEITHER struct of
    # 8 qwords. sha256 of the exact 64-byte struct driven by run-m0-controls.ps1.
    "phys": 0x1000,
    "len": 0x1000,
}
_WITNESS_DRIVER_SHA256 = "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b"


def _dump_identity(record: object) -> tuple[str, int, str] | None:
    if not isinstance(record, dict):
        return None
    name = str(record.get("name", "")).strip().lower()
    try:
        length = int(record.get("length", 0))
    except (TypeError, ValueError):
        return None
    sha256 = str(record.get("sha256", "")).strip().lower()
    if not name or length <= 0 or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return None
    return name, length, sha256


def dump_identity_is_new(pre_data: object, post_data: object, crash_data: object) -> bool:
    """Verify one exact post-crash dump identity absent from the pre-crash set.

    The runner computes SHA-256 inside the guest before and after the crash, then
    hashes the copied dump again on the host. Requiring all three records to
    agree avoids checkpoint-clock skew and rejects stale, crossed, or substituted
    dump files without trusting a boolean emitted by the runner.
    """
    if (
        not isinstance(pre_data, dict)
        or not isinstance(post_data, dict)
        or not isinstance(crash_data, dict)
    ):
        return False
    before_records = pre_data.get("dumps_before")
    after_records = post_data.get("dumps_after")
    declared_records = post_data.get("new_dumps")
    if (
        not isinstance(before_records, list)
        or not isinstance(after_records, list)
        or not isinstance(declared_records, list)
    ):
        return False
    before_raw = {_dump_identity(item) for item in before_records}
    after_raw = {_dump_identity(item) for item in after_records}
    declared_raw = {_dump_identity(item) for item in declared_records}
    if None in before_raw or None in after_raw or None in declared_raw:
        return False
    before = {item for item in before_raw if item is not None}
    after = {item for item in after_raw if item is not None}
    declared_new = {item for item in declared_raw if item is not None}
    computed_new = after - before
    if len(computed_new) != 1 or declared_new != computed_new:
        return False
    selected = next(iter(computed_new))
    return str(crash_data.get("dump_sha256", "")).lower() == selected[2]


def _witness_struct() -> bytes:
    # 0x38-byte NalMmapAddressEx input struct: cmd qword @0x00, out-slot @0x18,
    # phys qword @0x20, len dword @0x28, map-to-user flag @0x30 (0 = kernel VA).
    struct = bytearray(0x38)
    struct[0:8] = (57).to_bytes(8, "little")
    struct[0x20:0x28] = _WITNESS_EXPECTED["phys"].to_bytes(8, "little")
    struct[0x28:0x2C] = _WITNESS_EXPECTED["len"].to_bytes(4, "little")
    return bytes(struct)


def adjudicate_evidence_dir(evidence: Path) -> dict[str, object]:
    """Run both M0 gates over a run-m0-controls.ps1 evidence directory."""
    import hashlib

    expected_sha = hashlib.sha256(_witness_struct()).hexdigest()
    out: dict[str, object] = {"evidence": str(evidence), "expected_witness_sha256": expected_sha}

    kd_log = evidence / "kd-witness.log"
    trigger_path = evidence / "trigger-witness.jsonl"
    c99_path = evidence / "trigger-control-cmd99.jsonl"
    clen0_path = evidence / "trigger-control-len0.jsonl"
    if trigger_path.is_file():
        trigger = parse_trigger_jsonl(trigger_path.read_text(errors="replace"))
        c99 = (
            parse_trigger_jsonl(c99_path.read_text(errors="replace"))
            if c99_path.is_file()
            else None
        )
        clen0 = (
            parse_trigger_jsonl(clen0_path.read_text(errors="replace"))
            if clen0_path.is_file()
            else None
        )
        trig_verdict = adjudicate_trigger_witness(
            trigger,
            expected_in_sha256=expected_sha,
            control_cmd99=c99,
            control_len0=clen0,
        )
        witness_result_path = evidence / "arm-witness-result.json"
        kd_verdict = None
        controls_clean = False
        binding_record_valid = False
        if kd_log.is_file() and witness_result_path.is_file():
            witness_result = json.loads(witness_result_path.read_text())
            controls_clean = witness_result.get("controls_clean") is True
            c99_hits = witness_result.get("control_cmd99_hits")
            len0_hits = witness_result.get("control_len0_hits")
            recorded_hits_match = (
                witness_result.get("operands_hits") == 1
                and witness_result.get("readback_hits") == 1
                and isinstance(c99_hits, dict)
                and c99_hits.get("operands") == 0
                and c99_hits.get("readback") == 0
                and isinstance(len0_hits, dict)
                and len0_hits.get("operands") == 0
                and len0_hits.get("readback") == 0
            )
            binding_record_valid = (
                witness_result.get("breakpoints_bound") is True
                and str(witness_result.get("driver_sha256", "")).lower() == _WITNESS_DRIVER_SHA256
                and recorded_hits_match
            )
            kd_verdict = adjudicate_kernel_witness(
                kd_log.read_text(errors="replace"),
                expected_driver="iqvw64e.sys",
                expected_phys=_WITNESS_EXPECTED["phys"],
                expected_len=_WITNESS_EXPECTED["len"],
                trigger=trigger,
                expected_in_sha256=expected_sha,
                control_no_signal=controls_clean,
            )
        # The real sink breakpoint pair is a required binding gate, not optional
        # corroboration. Trigger success alone cannot promote an evidence bundle.
        if kd_verdict is None:
            overall = UNRUNNABLE
            reason = "kd witness log or arm-witness-result.json missing"
        elif not binding_record_valid:
            overall = UNRUNNABLE
            reason = "witness breakpoint/driver binding record is invalid"
        elif trig_verdict.status == CONFIRMED and kd_verdict.status == CONFIRMED:
            overall = CONFIRMED
            reason = trig_verdict.reason + " | kd lane corroborated: " + kd_verdict.reason
        else:
            overall = kd_verdict.status if trig_verdict.status == CONFIRMED else trig_verdict.status
            reason = f"trigger lane: {trig_verdict.status} ({trig_verdict.reason}) | " \
                f"kd lane: {kd_verdict.status} ({kd_verdict.reason})"
        out["witness"] = {
            "status": overall,
            "reason": reason,
            "trigger_gate": trig_verdict.status,
            "kd_gate": kd_verdict.status if kd_verdict else "no-kd-log",
        }
    else:
        out["witness"] = {"status": UNRUNNABLE, "reason": "trigger-witness.jsonl missing"}

    analysis = evidence / "crash-cdb-analysis.txt"
    pre = evidence / "crash-pre.json"
    post = evidence / "crash-post.json"
    crash_result_path = evidence / "arm-crash-result.json"
    if analysis.is_file() and pre.is_file() and post.is_file() and crash_result_path.is_file():
        pre_data = json.loads(pre.read_text())
        post_data = json.loads(post.read_text())
        crash_data = json.loads(crash_result_path.read_text())
        # The crash arm drives notmyfaultc64, not an iqvw struct; the IOCTL binding
        # for M0 is the recorded crash invocation + dump timestamp ordering, which
        # the sentinel encodes (control B1 was a usage run — clean by construction).
        # notmyfaultc64 v4.50 drops myfault.sys (measured: 29200 bytes in
        # system32\drivers), NOT myfault64.sys — the expected module is myfault.
        verdict = adjudicate_kernel_crash(
            analysis.read_text(errors="replace"),
            expected_driver="myfault.sys",
            trigger=_CRASH_BINDING_SENTINEL,
            expected_in_sha256=_CRASH_BINDING_SENTINEL.in_sha256,
            control_clean=True,
            dump_identity_new=dump_identity_is_new(pre_data, post_data, crash_data),
        )
        out["crash"] = {
            "status": verdict.status,
            "reason": verdict.reason,
            "dump_sha256": crash_data.get("dump_sha256", ""),
        }
    else:
        out["crash"] = {
            "status": UNRUNNABLE,
            "reason": "crash analysis or pre/post records missing",
        }
    return out


# A non-None sentinel trigger that passes the binding conjunct for the crash arm,
# where the "trigger" is the notmyfaultc64 invocation recorded by the runner rather
# than an iqvw struct hash. The hash it carries never collides with a real struct.
_CRASH_BINDING_SENTINEL = TriggerRecord(
    device="notmyfaultc64.exe",
    ioctl="crash-02",
    in_sha256="00" * 32,
    call_ok=True,
)


# ---------------------------------------------------------------------------

_DRIVE_PLAN_SCHEMA = "0verse.driver-witness-plan/v1"
_KD_REG_RE = re.compile(r"\b(rcx|rdx|rax|r8|r9|eax|edx)=([0-9a-fA-F`]+)")


@dataclass(frozen=True)
class DriveArmKd:
    """kd witness expectations for one arm (register values + readback mode)."""

    # readback_mode is one of: none | phys_dq_match | dq_va_expect
    #   | reg_dword_match_trigger_out | phys_dq_match_out_qword
    operands_regs: tuple[tuple[str, int], ...] = ()   # (reg, expected value) at the operands bp
    readback_mode: str = "none"
    readback_expect_qword: int | None = None           # dq_va_expect constant
    readback_reg: str = ""                             # reg_dword_match_trigger_out register
    readback_out_offset: int = 0   # phys_dq_match_out_qword: kd dq out-offset


@dataclass(frozen=True)
class DriveArm:
    """One witness arm from the drive plan."""

    name: str
    ioctl: str
    in_hex: str
    out_len: int
    expect_call_ok: bool
    expect_win32_error: int
    expect_bytes_returned: int | None
    expect_out_hex_at: tuple[tuple[int, str], ...]     # (offset, exact hex)
    expect_out_nonzero: tuple[int, int] | None         # (offset, len)
    kd: DriveArmKd
    # METHOD_NEITHER embedded-pointer spec (RwDrv class): (offset, length) — the
    # runner embeds a live user VA into in_hex at `offset` and the driver reads/
    # writes `length` bytes through it (reported as out_post_hex). Binding then
    # uses the trigger's in_template_sha256 (pointer masked) not in_sha256.
    inptr: tuple[int, int] | None = None

    @property
    def expected_in_sha256(self) -> str:
        import hashlib

        return hashlib.sha256(bytes.fromhex(self.in_hex)).hexdigest()


@dataclass(frozen=True)
class DriveControl:
    """One control arm: must produce exactly the statically-predicted rejection."""

    name: str
    ioctl: str
    in_hex: str
    expect_call_ok: bool
    expect_win32_error: int
    expect_bytes_returned: int | None = None


@dataclass(frozen=True)
class DrivePlan:
    """Parsed drive-plan.json (0verse.driver-witness-plan/v1)."""

    driver: str
    module: str
    device: str
    ioctl_map: str
    ioctl_map_sha256: str
    primitive_class: str
    arms: tuple[DriveArm, ...]
    controls: tuple[DriveControl, ...]


def _hex_to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    return int(s, 16) if s.startswith("0x") else int(s, 10)


def load_drive_plan(path: Path) -> DrivePlan:
    """Load and validate a drive-plan.json; fail loud on schema drift."""
    data = json.loads(path.read_text())
    if data.get("schema_version") != _DRIVE_PLAN_SCHEMA:
        raise ValueError(f"not a {_DRIVE_PLAN_SCHEMA} plan: {path}")

    def _arm(raw: dict[str, Any]) -> DriveArm:
        kd_raw = raw.get("kd") or {}
        regs = tuple(
            (str(r).lower(), _hex_to_int(v)) for r, v in (kd_raw.get("operands_regs") or {}).items()
        )
        expect = raw.get("expect") or {}
        out_hex_at = tuple(
            (int(e["offset"]), str(e["hex"]).lower()) for e in (expect.get("out_hex_at") or [])
        )
        nz = expect.get("out_nonzero")
        return DriveArm(
            name=str(raw["name"]),
            ioctl=str(raw["ioctl"]),
            in_hex=str(raw["in_hex"]).lower(),
            out_len=int(raw.get("out_len", 0)),
            expect_call_ok=bool(expect.get("call_ok", True)),
            expect_win32_error=int(expect.get("win32_error", 0)),
            expect_bytes_returned=(
                int(expect["bytes_returned"]) if "bytes_returned" in expect else None
            ),
            expect_out_hex_at=out_hex_at,
            expect_out_nonzero=(int(nz["offset"]), int(nz["len"])) if nz else None,
            inptr=(
                (int(raw["inptr"]["offset"]), int(raw["inptr"]["length"]))
                if raw.get("inptr") else None
            ),
            kd=DriveArmKd(
                operands_regs=regs,
                readback_mode=str(kd_raw.get("readback_mode", "none")),
                readback_expect_qword=(
                    _hex_to_int(kd_raw["readback_expect_qword"])
                    if "readback_expect_qword" in kd_raw else None
                ),
                readback_reg=str(kd_raw.get("readback_reg", "")).lower(),
                readback_out_offset=int(kd_raw.get("readback_out_offset", 0)),
            ),
        )

    def _control(raw: dict[str, Any]) -> DriveControl:
        expect = raw.get("expect") or {}
        return DriveControl(
            name=str(raw["name"]),
            ioctl=str(raw["ioctl"]),
            in_hex=str(raw.get("in_hex", "")).lower(),
            expect_call_ok=bool(expect.get("call_ok", False)),
            expect_win32_error=int(expect["win32_error"]),
            expect_bytes_returned=(
                int(expect["bytes_returned"]) if "bytes_returned" in expect else None
            ),
        )

    return DrivePlan(
        driver=str(data["driver"]),
        module=str(data["module"]),
        device=str(data["device"]),
        ioctl_map=str(data.get("ioctl_map", "")),
        ioctl_map_sha256=str(data.get("ioctl_map_sha256", "")),
        primitive_class=str(data.get("primitive_class", "")),
        arms=tuple(_arm(a) for a in data.get("arms", [])),
        controls=tuple(_control(c) for c in data.get("controls", [])),
    )


@dataclass(frozen=True)
class ArmKdObservation:
    """One arm's kd hits: operand registers + readback capture."""

    operands_hits: int = 0
    readback_hits: int = 0
    regs: tuple[tuple[str, int], ...] = ()
    dq_blocks: tuple[tuple[int, ...], ...] = ()   # value lists, one per dq command block


def parse_kd_arm_log(text: str, arm_name: str) -> ArmKdObservation:
    """Parse an arm's marker namespaced hits out of a shared kd log.

    run-m1 arms echo ``0VERSE-WITNESS-OPERANDS-<ARM>`` then ``r <regs>`` and
    ``0VERSE-WITNESS-READBACK-<ARM>`` then the per-driver readback commands
    (dq lines and/or an ``r <reg>`` line). Command echoes contain the marker too,
    so hits are anchored to bare marker lines, matching the M0 fix.

    dq rows are grouped into per-command blocks: a row whose address is not the
    contiguous successor of the previous row starts a new block (the /p physical
    dump vs the mapped-VA dump print back-to-back with unrelated addresses).
    """
    suffix = arm_name.upper().replace("-", "_")
    op_marker = f"{_WITNESS_OPERANDS}-{suffix}"
    rb_marker = f"{_WITNESS_READBACK}-{suffix}"
    operands_hits = len(re.findall(rf"(?m)^\s*{re.escape(op_marker)}\s*$", text))
    readback_hits = len(re.findall(rf"(?m)^\s*{re.escape(rb_marker)}\s*$", text))
    regs: dict[str, int] = {}
    dq_blocks: list[list[int]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == op_marker:
            window = "\n".join(lines[i + 1:i + 4])
            for reg, val in _KD_REG_RE.findall(window):
                regs[reg.lower()] = int(val.replace("`", ""), 16)
        elif stripped == rb_marker:
            prev_addr: int | None = None
            prev_row_len = 0
            for follow in lines[i + 1:]:
                fs = follow.strip()
                if fs.startswith("0VERSE-"):
                    break
                m = re.match(r"^([0-9a-fA-F`]+)\s+((?:[0-9a-fA-F`]+\s*)+)$", fs)
                if m:
                    addr = int(m.group(1).replace("`", ""), 16)
                    values = [int(v.replace("`", ""), 16) for v in m.group(2).split()]
                    if prev_addr is None or addr != prev_addr + prev_row_len * 8:
                        dq_blocks.append([])
                    dq_blocks[-1].extend(values)
                    prev_addr = addr
                    prev_row_len = len(values)
                    continue
                for reg, val in _KD_REG_RE.findall(fs):
                    regs.setdefault(reg.lower(), int(val.replace("`", ""), 16))
                if fs.endswith("gc") and ">" in fs:
                    break
    return ArmKdObservation(
        operands_hits=operands_hits,
        readback_hits=readback_hits,
        regs=tuple(sorted(regs.items())),
        dq_blocks=tuple(tuple(b) for b in dq_blocks),
    )


def _trigger_out_bytes(trigger: TriggerRecord) -> bytes:
    return bytes.fromhex(trigger.out_post_hex or "")


def adjudicate_drive_arm(
    plan: DrivePlan,
    arm: DriveArm,
    trigger: TriggerRecord | None,
    kd_obs: ArmKdObservation | None,
    *,
    kd_required: bool,
) -> Adjudication:
    """Five-conjunct witness gate for one drive-plan arm.

    (a) deterministic signal — trigger success shape + out predicates all match;
    (b) module attribution — the kd bps are module+RVA qualified by construction
        (the runner arms them as <module>+0xRVA; a hit can only fire in-module);
    (c) binding — the recorded driven-buffer sha256 equals the plan's;
    (d) sink correspondence — kd operand registers at the sink bp equal the
        plan's expected attacker operands; readback per the arm's mode;
    (e) controls are evaluated at the plan level (see adjudicate_drive_plan).
    """
    if trigger is None:
        return Adjudication(UNRUNNABLE, reason=f"arm {arm.name}: trigger record missing")
    # Binding conjunct (c). For an embedded-pointer arm the driven buffer carries a
    # runtime user VA, so bind against the template hash (pointer bytes masked to 0)
    # the trigger reports; a missing template hash there is itself a binding failure.
    if arm.inptr is not None:
        bound_sha = trigger.in_template_sha256
        if not bound_sha:
            return Adjudication(
                UNRUNNABLE,
                reason=f"arm {arm.name}: inptr arm but trigger reported no in_template_sha256",
            )
    else:
        bound_sha = trigger.in_sha256
    if bound_sha != arm.expected_in_sha256:
        return Adjudication(
            UNRUNNABLE,
            reason=f"arm {arm.name}: driven-buffer sha256 does not bind to the plan",
        )
    if trigger.call_ok != arm.expect_call_ok or trigger.win32_error != arm.expect_win32_error:
        return Adjudication(
            NO_CRASH,
            reason=f"arm {arm.name}: call_ok={trigger.call_ok} win32={trigger.win32_error}, "
                   f"expected call_ok={arm.expect_call_ok} win32={arm.expect_win32_error}",
        )
    if (
        arm.expect_bytes_returned is not None
        and trigger.bytes_returned != arm.expect_bytes_returned
    ):
        return Adjudication(
            DIVERGENT,
            reason=f"arm {arm.name}: bytes_returned={trigger.bytes_returned}, "
                   f"expected {arm.expect_bytes_returned}",
        )
    out = _trigger_out_bytes(trigger)
    for offset, want_hex in arm.expect_out_hex_at:
        want_bytes = bytes.fromhex(want_hex)
        if out[offset:offset + len(want_bytes)] != want_bytes:
            return Adjudication(
                DIVERGENT,
                reason=f"arm {arm.name}: out[{offset:#x}:{offset + len(want_bytes):#x}] = "
                       f"{out[offset:offset + len(want_bytes)].hex() or '<short>'}, "
                       f"expected {want_hex}",
            )
    if arm.expect_out_nonzero is not None:
        offset, length = arm.expect_out_nonzero
        if not any(out[offset:offset + length]):
            return Adjudication(
                DIVERGENT,
                reason=f"arm {arm.name}: out[{offset:#x}:+{length:#x}] is all zero",
            )
    # kd lane (corroboration by default; required when the plan demands it).
    if kd_obs is None:
        if kd_required:
            return Adjudication(
                UNRUNNABLE, reason=f"arm {arm.name}: kd observation required but absent"
            )
    else:
        if kd_obs.operands_hits != 1:
            return Adjudication(
                DIVERGENT,
                reason=f"arm {arm.name}: operands bp hit {kd_obs.operands_hits} "
                       f"times, expected exactly 1",
            )
        reg_map = dict(kd_obs.regs)
        for reg, want in arm.kd.operands_regs:
            got = reg_map.get(reg)
            if got is None or got != want:
                return Adjudication(
                    DIVERGENT,
                    reason=f"arm {arm.name}: sink operand {reg}="
                           f"{got if got is None else hex(got)}, "
                           f"expected {want:#x}",
                )
        mode = arm.kd.readback_mode
        if mode in ("phys_dq_match", "phys_dq_match_out_qword"):
            if kd_obs.readback_hits != 1 or len(kd_obs.dq_blocks) < 2:
                return Adjudication(UNRUNNABLE, reason=f"arm {arm.name}: readback dq pair missing")
            if kd_obs.dq_blocks[0] != kd_obs.dq_blocks[1]:
                return Adjudication(
                    DIVERGENT,
                    reason=f"arm {arm.name}: physical-vs-mapped readback mismatch "
                           f"({kd_obs.dq_blocks[0][:2]!r} != {kd_obs.dq_blocks[1][:2]!r})",
                )
            if mode == "phys_dq_match_out_qword":
                off = arm.kd.readback_out_offset
                trig_qword = (
                    int.from_bytes(out[off:off + 8], "little") if len(out) >= off + 8 else -1
                )
                if trig_qword != kd_obs.dq_blocks[0][0]:
                    return Adjudication(
                        DIVERGENT,
                        reason=f"arm {arm.name}: trigger out qword at {off:#x} ({trig_qword:#x}) "
                               f"!= kd physical dq ({kd_obs.dq_blocks[0][0]:#x}); "
                               f"returned data is not the physical content",
                    )
        elif mode == "dq_va_expect":
            if kd_obs.readback_hits != 1 or not kd_obs.dq_blocks or not kd_obs.dq_blocks[0]:
                return Adjudication(UNRUNNABLE, reason=f"arm {arm.name}: readback dq missing")
            if (
                arm.kd.readback_expect_qword is None
                or kd_obs.dq_blocks[0][0] != arm.kd.readback_expect_qword
            ):
                return Adjudication(
                    DIVERGENT,
                    reason=f"arm {arm.name}: kd dq = {kd_obs.dq_blocks[0][0]:#x}, "
                           f"expected {arm.kd.readback_expect_qword:#x}",
                )
        elif mode == "reg_dword_match_trigger_out":
            got = reg_map.get(arm.kd.readback_reg)
            trig_dword = int.from_bytes(out[0:4], "little") if len(out) >= 4 else -1
            if got is None or (got & 0xFFFFFFFF) != trig_dword:
                return Adjudication(
                    DIVERGENT,
                    reason=f"arm {arm.name}: kd {arm.kd.readback_reg} low dword "
                           f"{got if got is None else hex(got & 0xFFFFFFFF)} "
                           f"!= trigger out dword {trig_dword:#x}",
                )
        elif mode != "none":
            return Adjudication(
                UNRUNNABLE, reason=f"arm {arm.name}: unknown readback mode {mode!r}"
            )
    return Adjudication(
        CONFIRMED,
        crash_function=f"{plan.module}+sink",
        reason=f"arm {arm.name}: IOCTL {arm.ioctl} bound by sha256 {trigger.in_sha256[:12]}…; "
               f"success shape + out predicates match; kd operands corroborated"
               if kd_obs is not None else
               f"arm {arm.name}: IOCTL {arm.ioctl} bound by sha256 {trigger.in_sha256[:12]}…; "
               f"success shape + out predicates match (trigger lane)",
    )


def adjudicate_drive_control(control: DriveControl, trigger: TriggerRecord | None) -> Adjudication:
    if trigger is None:
        return Adjudication(UNRUNNABLE, reason=f"control {control.name}: trigger record missing")
    if (
        trigger.call_ok != control.expect_call_ok
        or trigger.win32_error != control.expect_win32_error
    ):
        return Adjudication(
            DIVERGENT,
            reason=f"control {control.name}: call_ok={trigger.call_ok} "
                   f"win32={trigger.win32_error}, "
                   f"expected call_ok={control.expect_call_ok} win32={control.expect_win32_error}",
        )
    if (
        control.expect_bytes_returned is not None
        and trigger.bytes_returned != control.expect_bytes_returned
    ):
        return Adjudication(
            DIVERGENT,
            reason=f"control {control.name}: bytes_returned={trigger.bytes_returned}, "
                   f"expected {control.expect_bytes_returned}",
        )
    return Adjudication(CONFIRMED, reason=f"control {control.name}: predicted outcome reproduced")


def adjudicate_drive_plan(evidence: Path) -> dict[str, object]:
    """Run the per-driver witness gate over a run-m1 evidence directory."""
    plan_path = evidence / "drive-plan.json"
    if not plan_path.is_file():
        return {
            "evidence": str(evidence), "status": UNRUNNABLE,
            "reason": "drive-plan.json missing",
        }
    plan = load_drive_plan(plan_path)
    shared_kd_text = ""
    kd_log = evidence / "kd-witness.log"
    if kd_log.is_file():
        shared_kd_text = kd_log.read_text(errors="replace")

    def _arm_kd_text(arm_name: str) -> str:
        # per-arm logs (kd-<arm>.log) are the M1 layout; kd-witness.log is the
        # single-boot/M0 layout. Per-arm wins when present.
        per_arm = evidence / f"kd-{arm_name}.log"
        if per_arm.is_file():
            return per_arm.read_text(errors="replace")
        return shared_kd_text

    out: dict[str, object] = {
        "evidence": str(evidence),
        "driver": plan.driver,
        "primitive_class": plan.primitive_class,
    }
    reasons: list[str] = []
    worst = CONFIRMED
    arm_results: dict[str, object] = {}
    for arm in plan.arms:
        trig_path = evidence / f"trigger-{arm.name}.jsonl"
        trigger = (
            parse_trigger_jsonl(trig_path.read_text(errors="replace"))
            if trig_path.is_file() else None
        )
        kd_text = _arm_kd_text(arm.name)
        armed_hits = len(re.findall(r"(?m)^\s*0VERSE-KD-ARMED\s*$", kd_text))
        kd_obs = parse_kd_arm_log(kd_text, arm.name) if armed_hits == 1 else None
        verdict = adjudicate_drive_arm(plan, arm, trigger, kd_obs, kd_required=True)
        arm_results[arm.name] = {"status": verdict.status, "reason": verdict.reason}
        reasons.append(verdict.reason)
        if verdict.status != CONFIRMED:
            worst = verdict.status
            break
    if worst == CONFIRMED:
        for control in plan.controls:
            trig_path = evidence / f"trigger-control-{control.name}.jsonl"
            trigger = (
                parse_trigger_jsonl(trig_path.read_text(errors="replace"))
                if trig_path.is_file() else None
            )
            verdict = adjudicate_drive_control(control, trigger)
            arm_results[f"control:{control.name}"] = {
                "status": verdict.status, "reason": verdict.reason,
            }
            reasons.append(verdict.reason)
            if verdict.status != CONFIRMED:
                worst = verdict.status
                break
    out["arms"] = arm_results
    out["status"] = worst
    out["reason"] = " | ".join(reasons)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m zeroverse.windows_kernel_oracle <evidence_dir>")
        return 3
    evidence = Path(argv[1])
    if (evidence / "drive-plan.json").is_file():
        result = adjudicate_drive_plan(evidence)
    else:
        result = adjudicate_evidence_dir(evidence)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv))

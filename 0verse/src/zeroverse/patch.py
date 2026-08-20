"""Stage 9 — the patch loop (M7 #45/#46): the AIxCC "second half".

0verse's spine stops at a confirmed PoV (``pov.reproduced == True``). This stage
adds the scored half AIxCC measured — *propose a fix that closes the PoV without
breaking functionality* — and keeps PoV-is-truth's sibling discipline: a patch is
``verified`` ONLY when the confirmed PoV no longer reproduces against the patched
artifact AND no regression is observed (``oracle.verify_patch``, the deterministic
LLM-free adjudicator). It is gated on ``ZEROVERSE_PATCH=1`` and iterates ONLY over
findings that already carry a reproducing PoV.

Three layers, ordered by maturity (docs/… patching-design §4):

  * **B0 — located fix RECOMMENDATION** (always-on, zero-dep, deterministic): the
    sink symbol + ``sink_addr`` + function + decompiled-C snippet + a
    bug-class→fix-template. A *recommendation*, never a verified patch.
  * **Mode A — source patch** (opt-in ``PatchContext``): RCA from data 0verse
    already has → an LLM unified diff (the provider-neutral ``LLM`` protocol +
    ``MockLLM``) → rebuild → ``verify_patch`` → reflect. It is an independent
    implementation of public methodology, capped at three iterations.
  * **B1 — binary micro-patch** (flag-gated, x86-64 ELF): a self-contained
    immediate-clamp guard works today; the SCRIBE recompile-trampoline and
    e9patch/Patcherex2 guard-insertion engines are scaffolded with backend
    detection and **degrade honestly to B0** when their tooling is absent. Always
    verified by re-running the PoV against the patched binary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import oracle
from .agent import LLM
from .analyze import Finding
from .preflight import BudgetTracker
from .report import Patch, PoV
from .sandbox_exec import Executor, LocalExecutor

# Sinks whose source-level fix template is known (mirrors dynamic/bugclasses).
_COPY_SINKS = ("strcpy", "strcat", "stpcpy", "sprintf", "gets", "memcpy")
_CMDI_SINKS = ("system", "popen", "execl", "execlp", "execve", "execv", "execvp")


# --- B0: bug-class → located fix template ----------------------------------

# A located, deterministic remediation per bug class. ``{}`` slots are filled from
# the finding's symbols. No LLM — produced for every confirmed PoV.
_FIX_TEMPLATES: dict[str, str] = {
    "overflow": (
        "the copy length is attacker-controlled and unbounded. Bound the copy to "
        "the destination size: replace `{sink}(dst, src)` with "
        "`strncpy(dst, src, sizeof dst - 1); dst[sizeof dst - 1] = 0;` (or clamp the "
        "source length before the copy)."
    ),
    "memory-safety": (
        "the copy length is attacker-controlled and unbounded. Bound the copy to "
        "the destination size (`strncpy`/`snprintf` with `sizeof dst`) or validate "
        "the input length before reaching `{sink}`."
    ),
    "intoverflow": (
        "an arithmetic result feeds an allocation/copy size unchecked. Check for "
        "overflow before the allocation: `if (a && n / a != b) fail();` (or use a "
        "checked-arithmetic builtin) before sizing the buffer."
    ),
    "fmtstring": (
        "attacker-controlled data is used as a format string. Pass it as an "
        "argument under a constant format: `printf(\"%s\", user)` instead of "
        "`printf(user)`."
    ),
    "uaf": (
        "the object is used after it is freed. Null the pointer immediately after "
        "`free()` and gate every later use on non-null, or extend the object's "
        "lifetime so the dangling access cannot occur."
    ),
    "cmdi": (
        "untrusted input reaches a shell. Avoid the shell entirely: build a fixed "
        "argument vector and call `execv`/`posix_spawn` (no `{sink}`), or strictly "
        "allow-list the argument."
    ),
}
_DEFAULT_TEMPLATE = (
    "validate / bound the attacker-controlled value on the taint path before it "
    "reaches `{sink}`."
)

# CWE / bug-class string → template key.
_CLASS_ALIASES: dict[str, str] = {
    "buffer overflow": "overflow", "cwe-120": "overflow", "cwe-121": "overflow",
    "cwe-122": "overflow", "stack-buffer-overflow": "overflow",
    "heap-buffer-overflow": "overflow", "oob-write": "overflow",
    "memory-safety": "memory-safety",
    "cwe-190": "intoverflow", "integer overflow": "intoverflow",
    "cwe-134": "fmtstring", "format string": "fmtstring",
    "cwe-416": "uaf", "use-after-free": "uaf", "double-free": "uaf",
    "cwe-78": "cmdi", "command injection": "cmdi", "os command injection": "cmdi",
}


def _template_key(bug_class: str, sink: str) -> str:
    bc = (bug_class or "").lower()
    for needle, key in _CLASS_ALIASES.items():
        if needle in bc:
            return key
    if sink in _CMDI_SINKS:
        return "cmdi"
    if sink in ("gets", "strcpy", "strcat", "stpcpy", "sprintf", "memcpy"):
        return "overflow"
    return "memory-safety"


def fix_template(bug_class: str, sink: str) -> str:
    key = _template_key(bug_class, sink)
    return _FIX_TEMPLATES.get(key, _DEFAULT_TEMPLATE).format(sink=sink or "the sink")


def _locator(finding: Finding) -> str:
    addr = hex(finding.sink_addr) if finding.sink_addr else "0x0"
    src = f", source `{finding.source}`" if finding.source else ""
    return f"{finding.function} @ {addr} (sink `{finding.sink}`{src})"


def _snippet(decompiled: dict[str, str] | None, function: str) -> str:
    body = (decompiled or {}).get(function, "")
    if not body:
        return ""
    # Keep the few lines around the sink call short — context, not a dump.
    return body.strip()[:600]


def recommend(
    finding: Finding,
    pov: PoV,
    *,
    bug_class: str = "",
    decompiled: dict[str, str] | None = None,
) -> Patch:
    """B0 — the always-on located fix recommendation. Deterministic, zero-dep,
    produced for every confirmed PoV. Never ``verified`` (it is advice, not a
    re-run-proven fix)."""
    bc = bug_class
    locator = _locator(finding)
    snippet = _snippet(decompiled, finding.function)
    rec = f"{locator}: {fix_template(bc, finding.sink)}"
    if snippet:
        rec += f"\n--- decompiled {finding.function} ---\n{snippet}"
    return Patch(
        mode="recommendation",
        verified=False,
        recommendation=rec,
        locator=locator,
        method="B0 located-fix template",
    )


# --- Mode A: source-available LLM patch + verify loop ----------------------

@dataclass
class PatchContext:
    """Opt-in source context (the 0cloud / AIxCC source-CP setting). 0verse is
    binary-first, so source mode is never assumed — only attempted when supplied."""

    source_root: str                  # repo / source dir (copied to a scratch build)
    build_cmd: list[str]              # rebuilds the target, e.g. ["make"]
    test_cmd: list[str] | None = None # regression oracle (Atlantis test.sh analog)
    target_rel: str = ""              # built artifact rel path (the scanned binary)
    source_rel: str = ""              # source file to patch (else located by sink)
    control_inputs: list[bytes] = field(default_factory=list)
    timeout: float = 120.0


_PATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "diff": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["diff"],
    "additionalProperties": False,
}

_PATCH_SYSTEM = (
    "You are an automated program-repair agent. You are given a CONFIRMED "
    "vulnerability (a reproducing PoV already exists) plus the vulnerable source "
    "file. Produce a MINIMAL unified diff that fixes the ROOT CAUSE on the tainted "
    "data flow — bound the copy / validate the length / sanitize the input / swap "
    "the sink for a safe API. Do NOT 'fix' it by adding compiler hardening flags, a "
    "broad catch, or a signal handler (that is mitigation, not a fix, and will be "
    "rejected). Preserve all benign behavior. Return ONLY a unified diff with "
    "`a/<path>` and `b/<path>` headers; no prose."
)


def _locate_source(root: Path, sink: str, hint: str) -> Path | None:
    if hint:
        p = root / hint
        return p if p.is_file() else None
    best: Path | None = None
    for c in sorted(root.rglob("*.c")):
        try:
            txt = c.read_text(errors="replace")
        except OSError:
            continue
        if re.search(rf"\b{re.escape(sink)}\s*\(", txt):
            return c
        if best is None:
            best = c
    return best


# How many prior failed attempts are replayed into the patch prompt. Bounded: the
# loop's own ``max_iters`` defaults to 3, but a caller may raise it and the prompt
# already carries the full source file, so this cannot be allowed to grow freely.
_MAX_REFLECTIONS = 4


def _reflection_text(reflections: list[str]) -> str:
    """Render the ACCUMULATED failure history, oldest of the retained window first.
    Feeding back only the latest failure let attempt 3 re-propose the approach that
    already failed at attempt 1, because nothing in its context said it had."""
    recent = [r for r in reflections if r][-_MAX_REFLECTIONS:]
    if not recent:
        return ""
    n = len(reflections)
    head = (
        f"\nPREVIOUS ATTEMPTS FAILED ({n} so far) — fix accordingly, and do NOT "
        "re-propose an approach already listed here as failed:\n"
    )
    first = n - len(recent) + 1
    body = "\n".join(f"  attempt {first + k}: {r}" for k, r in enumerate(recent))
    return f"{head}{body}\n"


def _patch_prompt(
    finding: Finding, pov: PoV, verdict_expl: str, rel: str, source: str,
    reflections: list[str], bug_class: str
) -> str:
    casr = f"CASR: {pov.casr_severity} {pov.casr_desc}\n" if pov.casr_severity else ""
    frames = ("Crash frames: " + " <- ".join(pov.frames) + "\n") if pov.frames else ""
    crashing = ""
    if pov.input_bytes:
        crashing = f"Crashing input: {len(pov.input_bytes)} bytes of {pov.input_bytes[:8]!r}...\n"
    reflect = _reflection_text(reflections)
    return (
        f"BUG: {bug_class or 'memory-safety'} — {finding.source} -> {finding.sink} "
        f"in {finding.function} @ {hex(finding.sink_addr)}\n"
        f"RCA: {verdict_expl}\n"
        f"{casr}{frames}{crashing}"
        f"SINK: {finding.sink}\n"
        f"SOURCE FILE: {rel}\n"
        f"--- BEGIN SOURCE ---\n{source}\n--- END SOURCE ---\n"
        f"{reflect}"
        "Return a minimal unified diff (a/<path> b/<path>) that fixes the root cause."
    )


def _copytree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _apply_diff(
    root: Path,
    diff: str,
    *,
    budget: BudgetTracker | None = None,
) -> tuple[bool, str]:
    """Apply a unified diff into ``root``. Tries ``git apply`` (works without a
    repo) then ``patch -p1``. Returns ``(ok, log)``."""
    if not diff.strip():
        return (False, "empty diff")
    pf = root / ".0verse-patch.diff"
    body = diff if diff.endswith("\n") else diff + "\n"
    try:
        pf.write_text(body)
    except OSError as e:
        return (False, f"could not stage diff: {e}")
    last_error = "apply tool unavailable"
    for cmd in (
        ["git", "apply", "-p1", "--whitespace=nowarn", str(pf)],
        ["patch", "-p1", "-i", str(pf)],
    ):
        timeout = 60.0
        if budget is not None:
            reserved, reason = budget.reserve_attempt()
            if not reserved:
                return False, f"apply budget skipped: {reason}"
            timeout = budget.remaining_seconds()
            if timeout <= 0:
                budget.reservation_failures += 1
                return False, "apply deadline exhausted"
        try:
            p = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                cmd, cwd=root, capture_output=True, timeout=timeout
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue
        if p.returncode == 0:
            return (True, f"applied via {cmd[0]}")
        last_error = p.stderr.decode("utf-8", "replace")[:200]
    return (False, f"apply failed: {last_error}")


def _build(
    root: Path,
    build_cmd: list[str],
    timeout: float,
    *,
    budget: BudgetTracker | None = None,
    native_compiler_path: str | None = None,
) -> tuple[bool, str]:
    if budget is not None:
        reserved, reason = budget.reserve_attempt()
        if not reserved:
            return False, f"build budget skipped: {reason}"
        remaining = budget.remaining_seconds()
        if remaining <= 0:
            budget.reservation_failures += 1
            return False, "build deadline exhausted"
        timeout = min(timeout, remaining)
    command = list(build_cmd)
    env = {**os.environ}
    if native_compiler_path:
        env["CC"] = native_compiler_path
        if command and Path(command[0]).name in {"cc", "gcc", "clang"}:
            command[0] = native_compiler_path
    try:
        p = subprocess.run(  # foxguard: ignore[py/no-command-injection]
            command,
            cwd=root,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return (False, "build timed out")
    except OSError as e:
        return (False, f"build failed to launch: {e}")
    if p.returncode == 0:
        return (True, "build ok")
    return (False, f"build error: {p.stderr.decode('utf-8', 'replace')[-400:]}")


def generate_source_patch(
    finding: Finding,
    pov: PoV,
    ctx: PatchContext,
    llm: LLM,
    *,
    bug_class: str = "",
    verdict_expl: str = "",
    max_iters: int = 3,
    output_dir: Path | None = None,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    executor_provider: str = "",
    native_compiler_path: str | None = None,
) -> Patch:
    """Mode A — independent RCA→generate→build→verify→reflect loop.

    It is capped at ``max_iters`` and returns a verified ``Patch`` only when the
    rebuilt binary closes the PoV and passes the regression oracle. Otherwise it
    returns the best unverified candidate, clearly labelled (never promoted).
    """
    candidate = Patch(
        mode="source-diff",
        verified=False,
        locator=_locator(finding),
        method="source APR",
        rejected_reason="no candidate produced",
    )
    if budget is not None and (
        not isinstance(executor, LocalExecutor) or not executor_provider
    ):
        candidate.rejected_reason = "planned local patch executor/provider unavailable"
        return candidate
    if budget is not None and native_compiler_path is None:
        candidate.rejected_reason = "planned native compiler unavailable for source patch build"
        return candidate
    root = Path(ctx.source_root)
    src_file = _locate_source(root, finding.sink, ctx.source_rel)
    if src_file is None:
        return Patch(mode="source-diff", verified=False, locator=_locator(finding),
                     rejected_reason="could not locate the vulnerable source file",
                     method="source APR")
    rel = str(src_file.relative_to(root))
    source_text = src_file.read_text(errors="replace")
    controls = ctx.control_inputs or [b"A"]

    # Baseline: build the UNPATCHED source once as the regression reference binary.
    orig_target: str | None = None
    base = Path(tempfile.mkdtemp(prefix="0verse-patch-orig-"))
    try:
        _copytree(root, base)
        ok, baseline_log = _build(
            base,
            ctx.build_cmd,
            ctx.timeout,
            budget=budget,
            native_compiler_path=native_compiler_path,
        )
        if not ok and budget is not None and not budget.can_reserve():
            candidate.rejected_reason = baseline_log
            return candidate
        if ok and ctx.target_rel and (base / ctx.target_rel).is_file():
            orig_target = str(base / ctx.target_rel)
    except OSError:
        pass

    # ACCUMULATED, not overwritten: every failed attempt is appended so a later
    # attempt can see the whole dead-end history instead of only the last one.
    reflections: list[str] = []
    best = candidate
    try:
        for attempt in range(1, max_iters + 1):
            if budget is not None:
                reserved, reason = budget.reserve_attempt()
                if not reserved:
                    best.rejected_reason = f"patch generation budget skipped: {reason}"
                    break
                if budget.remaining_seconds() <= 0:
                    budget.reservation_failures += 1
                    best.rejected_reason = "patch generation deadline exhausted"
                    break
            try:
                raw = llm.complete_json(
                    _PATCH_SYSTEM,
                    _patch_prompt(finding, pov, verdict_expl, rel, source_text,
                                  reflections, bug_class),
                    _PATCH_SCHEMA,
                )
                diff = str(raw.get("diff", ""))
            except Exception as exc:  # any backend failure → reflect, keep going
                reflections.append(f"LLM error: {type(exc).__name__}")
                continue
            best.attempts = attempt
            if not diff.strip():
                reflections.append(
                    "no diff produced; emit a unified diff that bounds the copy"
                )
                continue
            work = Path(tempfile.mkdtemp(prefix="0verse-patch-"))
            try:
                _copytree(root, work)
                applied, alog = _apply_diff(work, diff, budget=budget)
                if not applied:
                    reflections.append(
                        f"diff did not apply ({alog}); regenerate against the shown source"
                    )
                    if budget is not None and not budget.can_reserve():
                        best.rejected_reason = alog
                        break
                    continue
                built, blog = _build(
                    work,
                    ctx.build_cmd,
                    ctx.timeout,
                    budget=budget,
                    native_compiler_path=native_compiler_path,
                )
                if not built:
                    reflections.append(f"patched build failed — {blog}")
                    best.diff, best.rejected_reason = diff, blog
                    if budget is not None and not budget.can_reserve():
                        break
                    continue
                target = work / ctx.target_rel if ctx.target_rel else None
                if target is None or not target.is_file():
                    reflections.append(
                        "build produced no target binary; check target_rel"
                    )
                    continue
                verdict = oracle.verify_patch(
                    pov, str(target),
                    original_target=orig_target,
                    control_inputs=controls,
                    test_cmd=_resolve_test_cmd(ctx, work),
                    test_cwd=str(work) if ctx.test_cmd else None,
                    diff=diff,
                    sink=finding.sink,
                    sink_function=finding.function,
                    budget=budget,
                    executor=executor,
                    executor_provider=executor_provider,
                    native_compiler_path=native_compiler_path,
                )
                patch = Patch(
                    mode="source-diff", verified=verdict.verified, diff=diff,
                    locator=_locator(finding), method="source APR",
                    pov_recheck=verdict.gate1_note, regression=verdict.gate2_note,
                    attempts=attempt,
                )
                if verdict.verified:
                    # Persist the verified patched artifact outside the scratch dir.
                    patch.patched_artifact = _persist(target, output_dir=output_dir)
                    if patch.patched_artifact:
                        return patch
                    patch.verified = False
                    patch.rejected_reason = (
                        "patch verified but planned artifact persistence failed"
                    )
                if not patch.rejected_reason:
                    patch.rejected_reason = "; ".join(verdict.notes) or (
                        "GATE1 fail" if not verdict.gate1_closes_pov else "GATE2 fail"
                    )
                best = patch
                reflections.append(
                    f"{patch.rejected_reason}. GATE1: {verdict.gate1_note}. "
                    f"GATE2: {verdict.gate2_note}."
                )
                if budget is not None and not budget.can_reserve():
                    break
            finally:
                shutil.rmtree(work, ignore_errors=True)
        return best
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _resolve_test_cmd(ctx: PatchContext, work: Path) -> list[str] | None:
    return list(ctx.test_cmd) if ctx.test_cmd else None


def _persist(target: Path, *, output_dir: Path | None = None) -> str:
    root = output_dir or Path(os.environ.get("ZEROVERSE_OUT", "0verse-out"))
    cache = root / "patches"
    try:
        cache.mkdir(parents=True, exist_ok=True)
        dst = cache / f"{target.name}.patched"
        shutil.copy2(target, dst)
        return str(dst)
    except OSError:
        return ""


# --- B1: binary micro-patch (flag-gated, x86-64 ELF) -----------------------

def binpatch_available() -> bool:
    return os.environ.get("ZEROVERSE_BINPATCH", "") not in ("", "0")


def _detect_backends() -> dict[str, bool]:
    """Which binary-rewriting engines are installed (scaffold). The immediate-clamp
    engine needs none of these; SCRIBE-recompile / e9patch / Patcherex2 do, and we
    degrade to B0 when they are absent."""
    import importlib.util

    try:
        have_p2 = importlib.util.find_spec("patcherex2") is not None
    except (ImportError, ValueError):
        have_p2 = False
    return {
        "e9patch": shutil.which("e9tool") is not None,
        "patcherex2": have_p2,
        "immediate-clamp": True,  # always available (pure binutils byte-patch)
    }


@dataclass
class _Insn:
    va: int
    raw: bytes
    mnem: str
    ops: str


def _patch_operation_timeout(
    budget: BudgetTracker | None,
    timeout: float,
) -> float | None:
    if budget is None:
        return timeout
    reserved, _ = budget.reserve_attempt()
    if not reserved:
        return None
    remaining = budget.remaining_seconds()
    if remaining <= 0:
        budget.reservation_failures += 1
        return None
    return min(timeout, remaining)


def _disasm_function(
    binary: str,
    function: str,
    *,
    budget: BudgetTracker | None = None,
) -> list[_Insn]:
    """Disassemble one function via ``objdump`` (raw bytes + mnemonics). Empty when
    objdump is missing or the symbol is not found."""
    if shutil.which("objdump") is None:
        return []
    timeout = _patch_operation_timeout(budget, 60.0)
    if timeout is None:
        return []
    try:
        out = subprocess.run(
            ["objdump", "-d", "--show-raw-insn", binary],
            capture_output=True,
            timeout=timeout,
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return []
    insns: list[_Insn] = []
    in_fn = False
    header = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
    line_re = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)\s*(\S+)\s*(.*)$")
    for line in out.splitlines():
        h = header.match(line)
        if h:
            in_fn = h.group(1) == function
            continue
        if not in_fn:
            continue
        m = line_re.match(line)
        if not m:
            continue
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        insns.append(_Insn(int(m.group(1), 16), raw, m.group(3), m.group(4).strip()))
    return insns


def _section_for_va(
    binary: str,
    va: int,
    *,
    budget: BudgetTracker | None = None,
) -> tuple[int, int] | None:
    """Map a virtual address to a file offset via ``readelf -SW``. Returns
    ``(file_offset_of_va, section_size_remaining)`` or None."""
    if shutil.which("readelf") is None:
        return None
    timeout = _patch_operation_timeout(budget, 30.0)
    if timeout is None:
        return None
    try:
        out = subprocess.run(
            ["readelf", "-SW", binary],
            capture_output=True,
            timeout=timeout,
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    row = re.compile(
        r"^\s*\[\s*\d+\]\s+\S+\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)"
    )
    for line in out.splitlines():
        m = row.match(line)
        if not m:
            continue
        addr, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
        if addr and addr <= va < addr + size:
            return (off + (va - addr), addr + size - va)
    return None


# `mov $imm32, %e{reg}` opcodes (B8+rd): edi=BF esi=BE edx=BA ecx=B9. The size
# arg of read/recv/fread on SysV x86-64 is the 3rd int arg → %rdx/%edx (BA).
_MOV_IMM32 = {0xBF: "edi", 0xBE: "esi", 0xBA: "edx", 0xB9: "ecx", 0xB8: "eax"}
_SIZE_SOURCES = ("read", "recv", "recvfrom", "fread", "fgets", "pread")


def immediate_clamp(
    binary: str,
    function: str,
    source: str,
    dest_bound: int,
    *,
    budget: BudgetTracker | None = None,
) -> str | None:
    """Working B1 engine — an instruction-level guard via an in-place immediate
    clamp. When the overflow is driven by a tainted *length immediate* (the size
    arg of ``read``/``recv`` that later overruns a fixed buffer), clamp that
    immediate down to the destination bound. Same-length byte edit (the imm32 in
    place), no trampoline. Writes a patched copy and returns its path, or None when
    no clampable immediate is found (→ caller degrades to B0)."""
    insns = _disasm_function(binary, function, budget=budget)
    if not insns:
        return None
    # Find the call to the tainted source, then the size-register mov just before it.
    call_idx = -1
    for i, ins in enumerate(insns):
        if ins.mnem == "call" and any(s in ins.ops for s in (source, *_SIZE_SOURCES)):
            call_idx = i
            break
    window = insns[max(0, call_idx - 10):call_idx] if call_idx >= 0 else insns
    target: _Insn | None = None
    for ins in reversed(window):
        if len(ins.raw) == 5 and ins.raw[0] in _MOV_IMM32:
            imm = int.from_bytes(ins.raw[1:5], "little")
            if imm > dest_bound:
                target = ins
                break
    if target is None:
        return None
    loc = _section_for_va(binary, target.va, budget=budget)
    if loc is None or loc[1] < 5:
        return None
    file_off = loc[0]
    data = bytearray(Path(binary).read_bytes())
    # sanity: the bytes at file_off must match the instruction we located
    if bytes(data[file_off:file_off + 5]) != target.raw:
        return None
    clamp = max(1, dest_bound - 1)
    data[file_off + 1:file_off + 5] = clamp.to_bytes(4, "little")
    out = Path(tempfile.mkdtemp(prefix="0verse-binpatch-")) / (Path(binary).name + ".patched")
    out.write_bytes(bytes(data))
    out.chmod(0o755)
    return str(out)


def binary_micropatch(
    finding: Finding,
    pov: PoV,
    binary: str,
    *,
    dest_bound: int,
    bug_class: str = "",
    decompiled: dict[str, str] | None = None,
    control_inputs: list[bytes] | None = None,
    output_dir: Path | None = None,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    executor_provider: str = "",
    native_compiler_path: str | None = None,
) -> Patch:
    """B1 entry — try the working immediate-clamp engine; verify by re-running the
    PoV against the patched binary; **degrade honestly to the B0 recommendation**
    when no engine produces a verified patch. Always verified-by-re-run, never
    over-claimed."""
    backends = _detect_backends()
    base = recommend(finding, pov, bug_class=bug_class, decompiled=decompiled)
    if budget is not None and (
        not isinstance(executor, LocalExecutor) or not executor_provider
    ):
        base.rejected_reason = "planned local patch executor/provider unavailable"
        return base
    base.method = (
        "B1 binary micro-patch — backends: "
        + ", ".join(k for k, v in backends.items() if v)
        + " (SCRIBE-recompile + e9patch/Patcherex2 scaffolded; immediate-clamp live)"
    )
    patched = immediate_clamp(
        binary,
        finding.function,
        finding.source,
        dest_bound,
        budget=budget,
    )
    if patched is None:
        if budget is not None and not budget.can_reserve():
            base.rejected_reason = (
                f"binary patch budget skipped: {budget.exhaustion_reason()}"
            )
        else:
            base.rejected_reason = (
                "no clampable immediate found; degraded to B0 recommendation"
            )
        return base
    verdict = oracle.verify_patch(
        pov, patched,
        original_target=binary,
        control_inputs=control_inputs or [b"A"],
        binary_touches_taintpath=True,
        sink=finding.sink,
        sink_function=finding.function,
        budget=budget,
        executor=executor,
        executor_provider=executor_provider,
        native_compiler_path=native_compiler_path,
    )
    if verdict.verified:
        persisted = _persist(Path(patched), output_dir=output_dir)
        if not persisted:
            base.rejected_reason = (
                "binary patch verified but planned artifact persistence failed; "
                "degraded to B0 recommendation"
            )
            return base
        return Patch(
            mode="binary-micropatch", verified=True, patched_artifact=persisted,
            locator=_locator(finding), recommendation=base.recommendation,
            regression=verdict.gate2_note, pov_recheck=verdict.gate1_note,
            method="B1 immediate-clamp (in-place .text guard)",
        )
    base.rejected_reason = (
        "binary patch did not verify (" + "; ".join(verdict.notes or ["gate fail"])
        + "); degraded to B0 recommendation"
    )
    return base


# --- orchestration: stage 9 driver -----------------------------------------

def patch_enabled() -> bool:
    return os.environ.get("ZEROVERSE_PATCH", "") not in ("", "0")


def _ctx_from_env() -> PatchContext | None:
    root = os.environ.get("ZEROVERSE_PATCH_SOURCE_ROOT", "").strip()
    build = os.environ.get("ZEROVERSE_PATCH_BUILD", "").strip()
    if not root or not build:
        return None
    test = os.environ.get("ZEROVERSE_PATCH_TEST", "").strip()
    return PatchContext(
        source_root=root,
        build_cmd=build.split(),
        test_cmd=test.split() if test else None,
        target_rel=os.environ.get("ZEROVERSE_PATCH_TARGET", "").strip(),
        source_rel=os.environ.get("ZEROVERSE_PATCH_SOURCE_REL", "").strip(),
    )


def patch_finding(
    finding: Finding,
    pov: PoV,
    *,
    binary: str,
    bug_class: str = "",
    decompiled: dict[str, str] | None = None,
    ctx: PatchContext | None = None,
    llm: LLM | None = None,
    verdict_expl: str = "",
    dest_bound: int = 0,
    output_dir: Path | None = None,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    executor_provider: str = "",
    native_compiler_path: str | None = None,
) -> Patch:
    """Patch one confirmed finding. Always returns at least a B0 recommendation;
    upgrades to a verified source-diff (Mode A) when ``ctx`` is supplied, or a
    verified binary micro-patch (B1) when ``ZEROVERSE_BINPATCH=1`` and no source."""
    if ctx is not None and llm is not None:
        patch = generate_source_patch(
            finding,
            pov,
            ctx,
            llm,
            bug_class=bug_class,
            verdict_expl=verdict_expl,
            output_dir=output_dir,
            budget=budget,
            executor=executor,
            executor_provider=executor_provider,
            native_compiler_path=native_compiler_path,
        )
        if patch.verified:
            return patch
        # Source mode failed to verify — keep the located recommendation as the
        # shipped artifact, but record the source attempt's reason.
        rec = recommend(finding, pov, bug_class=bug_class, decompiled=decompiled)
        rec.rejected_reason = f"source patch unverified: {patch.rejected_reason}"
        rec.diff = patch.diff
        return rec
    if binpatch_available():
        return binary_micropatch(
            finding,
            pov,
            binary,
            dest_bound=dest_bound or 16,
            bug_class=bug_class,
            decompiled=decompiled,
            output_dir=output_dir,
            budget=budget,
            executor=executor,
            executor_provider=executor_provider,
            native_compiler_path=native_compiler_path,
        )
    return recommend(finding, pov, bug_class=bug_class, decompiled=decompiled)


def run_patch_stage(
    result: Any,
    path: str,
    decompiled: dict[str, str] | None = None,
    *,
    llm: LLM | None = None,
    output_dir: Path | None = None,
    budget: BudgetTracker | None = None,
    executor: Executor | None = None,
    executor_provider: str = "",
    native_compiler_path: str | None = None,
) -> int:
    """Stage 9 driver — gated on ``ZEROVERSE_PATCH=1``. Iterates ONLY over findings
    with a reproducing PoV, dedups per ``pov.dedup_bucket`` (Theori), and attaches a
    ``Patch`` to each ``pov``. Returns the number of patches attached. Best-effort:
    a per-finding failure never crashes the run."""
    if not patch_enabled():
        return 0
    if budget is not None and (
        not isinstance(executor, LocalExecutor) or not executor_provider
    ):
        return 0
    ctx = _ctx_from_env()
    seen_buckets: set[str] = set()
    attached = 0
    for tf in result.findings:
        pov = getattr(tf, "pov", None)
        if not (pov and pov.reproduced) or pov.patch is not None:
            continue
        bucket = pov.dedup_bucket or ""
        if bucket and bucket in seen_buckets:
            continue
        f = tf.finding
        if (
            budget is not None
            and (ctx is not None or binpatch_available())
            and not budget.can_reserve()
        ):
            break
        try:
            pov.patch = patch_finding(
                f,
                pov,
                binary=path,
                bug_class=getattr(tf.verdict, "bug_class", ""),
                decompiled=decompiled,
                ctx=ctx,
                llm=llm,
                verdict_expl=getattr(tf.verdict, "explanation", ""),
                output_dir=output_dir,
                budget=budget,
                executor=executor,
                executor_provider=executor_provider,
                native_compiler_path=native_compiler_path,
            )
            attached += 1
            if bucket:
                seen_buckets.add(bucket)
        except Exception:
            continue
    if attached and "patch" not in result.stages_run:
        result.stages_run.append("patch")
    return attached

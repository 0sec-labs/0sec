"""Mechanical gate-constant extraction — recover the magic/field equality that routes
input to a LOCATEd function, straight from the binary's disassembly.

WHY. Reaching a sink often turns on a single dominating comparison: the wavpack
dispatcher calls the v3 legacy decoder ``open_file3`` only when the first byte is
``'R'`` (a RIFF wrapper), encoded as ``cmp $0x52,%r14d`` immediately before the call.
The LLM envelope-recovery in :mod:`zeroverse.trace_synth` tries to guess such gates from
decompiled C and often misses them; this module reads them off the instruction stream
instead — the constant that gates the call IS a byte the input must satisfy.

WHAT. Given a target function, find every direct ``call <target>`` site and, walking
back a short window, the constant compares (``cmp $imm, …`` and the SanitizerCoverage
``__sanitizer_cov_trace_const_cmpN`` hooks whose constant operand is in a register)
that dominate the call. Return the immediates with an ASCII gloss (``0x52`` -> ``'R'``)
— the mechanically-recovered routing gate. These feed a synth template as HARD
constraints (a seed known to satisfy the gate), complementing the coverage-based seed
selection in :mod:`zeroverse.sink_basin`.

HONEST LIMITS. This recovers the CONSTANT and its width, not yet the input BYTE OFFSET
it lands at — mapping the compared register back to a file offset needs value taint
(future work); for a first-byte magic the offset is obvious, for a deep field it names
the constant to search for. Direct calls only (indirect/vtable dispatch is invisible —
the info-loss wall). Best-effort: an empty result on any disassembly failure.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

# A named function header in objdump output: ``0000000000138d70 <WavpackOpenFileInputEx64>:``
_FN_HDR = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
# A direct call: ``call   1655d0 <open_file3>`` (callee may carry a +0xNN offset).
_CALL = re.compile(r"\bcall[a-z]*\s+[0-9a-f]+ <([^>+]+)(?:\+0x[0-9a-f]+)?>")
# A constant compare: ``cmp    $0x52,%r14d`` / ``cmpb   $0x3,0x10(%rbx)`` / ``cmpl`` ...
_CMP = re.compile(r"\bcmp([bwlq]?)\s+\$0x([0-9a-f]+),\s*(%?\S+)")


@dataclass
class GateConst:
    """One constant that gates a call to the target function."""

    value: int
    width: int              # compare width in bytes (1/2/4/8), best-effort
    ascii: str              # printable gloss ('R' for 0x52), else ''
    operand: str            # the compared operand text (register/memory)
    caller: str             # function containing the gating compare
    distance: int           # instructions between the compare and the call (closer = tighter)

    def gloss(self) -> str:
        a = f" '{self.ascii}'" if self.ascii else ""
        return (
            f"{hex(self.value)}{a} (w{self.width}) via {self.operand} "
            f"in {self.caller} @-{self.distance}"
        )


_WIDTH = {"b": 1, "w": 2, "l": 4, "q": 8, "": 4}


def _ascii(value: int, width: int) -> str:
    """Printable ASCII gloss for a single-byte magic constant. Width-independent: a byte
    magic is often compared in a dword register (``cmp $0x52,%r14d``), so we gloss any
    value that fits in a printable byte, not only ``cmpb``."""
    if 0x20 <= value <= 0x7E:
        return chr(value)
    return ""


def dominating_gate_consts(
    binary: str | Path,
    target_func: str,
    *,
    window: int = 48,
    max_value: int = 0xFFFF,
) -> list[GateConst]:
    """Constant compares that dominate a direct ``call target_func``, nearest first.

    For each call site, scan back up to ``window`` instructions within the same function
    and collect ``cmp $imm, …`` immediates (below ``max_value`` — filtering out address
    constants and large sizes, keeping magic/field values). The result is de-duplicated
    on (value, operand, caller) and ordered by proximity to the call, so the tightest
    gate (wavpack's ``cmp $0x52`` one instruction before ``call open_file3``) is first."""
    try:
        out = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", str(binary)],
            capture_output=True,
            text=True,
            timeout=300,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []

    # Group instruction lines by enclosing function, keeping order.
    funcs: dict[str, list[str]] = {}
    cur: str | None = None
    for line in out.splitlines():
        h = _FN_HDR.match(line)
        if h:
            cur = h.group(1)
            funcs[cur] = []
            continue
        if cur is not None and ":\t" in line:
            funcs[cur].append(line)

    gates: list[GateConst] = []
    seen: set[tuple[int, str, str]] = set()
    for fname, insns in funcs.items():
        for i, line in enumerate(insns):
            c = _CALL.search(line)
            if not c or c.group(1) != target_func:
                continue
            # Walk back over the window collecting constant compares.
            for j in range(i - 1, max(-1, i - 1 - window), -1):
                m = _CMP.search(insns[j])
                if not m:
                    continue
                try:
                    val = int(m.group(2), 16)
                except ValueError:
                    continue
                if val > max_value:
                    continue  # address / large size, not a magic/field gate
                width = _WIDTH.get(m.group(1), 4)
                operand = m.group(3)
                key = (val, operand, fname)
                if key in seen:
                    continue
                seen.add(key)
                gates.append(
                    GateConst(
                        value=val,
                        width=width,
                        ascii=_ascii(val, width),
                        operand=operand,
                        caller=fname,
                        distance=i - j,
                    )
                )
    gates.sort(key=lambda g: g.distance)
    return gates

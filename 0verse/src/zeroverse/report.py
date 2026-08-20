"""Finding + PoV data model.

Core principle: a finding without a reproducing proof-of-vulnerability is a
*hypothesis*, not a finding. ``Finding.is_confirmed`` is true only when a PoV is
attached. The reporter refuses to emit unconfirmed findings unless explicitly
asked for the hypothesis list.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Patch:
    """A proposed fix for a confirmed PoV (stage 9 / M7 #45-#46).

    Structurally hung off the ``PoV`` so a patch is inseparable from the proof it
    closes. ``verified`` is the strict sibling of ``PoV.reproduced``: it is true
    ONLY when a deterministic re-run shows the confirmed PoV NO LONGER reproduces
    against the patched artifact AND no regression is observed (oracle.verify_patch).
    A patch is never labelled "correct" — only "closes-the-PoV-and-passes-tests"
    (AIxCC finalists ship 16-21% semantically-incorrect patches; build+PoV+tests is
    evidence, not proof)."""

    mode: str = "recommendation"   # recommendation | source-diff | binary-micropatch
    verified: bool = False         # PoV no longer reproduces AND no regression
    diff: str = ""                 # unified diff (source) or decompiled-C diff
    patched_artifact: str = ""     # path to the rebuilt/patched binary, or ""
    recommendation: str = ""       # located fix text (file:line / func+offset + check)
    locator: str = ""              # "func @ 0x.. (sink <name>)" — always set
    regression: str = ""           # "tests N/N pass" | "control-inputs identical" | note
    pov_recheck: str = ""          # "PoV no longer reproduces (exit 0, no signal)"
    method: str = ""               # which agent/strategy produced it
    rejected_reason: str = ""      # why an unverified candidate was dropped
    attempts: int = 0              # how many generate→verify iterations were spent


@dataclass
class PoV:
    """A reproducing proof-of-vulnerability — the unit of truth."""

    input_bytes: bytes | None = None       # crashing stdin / file contents
    argv: list[str] = field(default_factory=list)
    file_input: bool = False               # deliver input_bytes as a FILE (argv[1])
    env: dict[str, str] = field(default_factory=dict)
    crash_class: str = "unknown"           # e.g. SIGSEGV-write, controllable-PC
    crash_trace: str = ""
    reproduced: bool = False               # did we re-run and observe the crash?
    # --- oracle evidence (filled by oracle.py / the dynamic stage) ---
    casr_severity: str = ""                # EXPLOITABLE | PROBABLY_EXPLOITABLE | ...
    casr_desc: str = ""                    # e.g. "ReturnAv: ... stack corruption"
    capability: str = ""                   # ladder rung: oob-write / oob-read / crash
    frames: list[str] = field(default_factory=list)   # normalized backtrace
    dedup_bucket: str = ""                 # ClusterFuzz-style crash-state key
    diff_allocator: str = ""               # differential-allocator verdict summary
    suspected_known: list[str] = field(default_factory=list)  # public advisory ids
    execution_provenance: dict[str, str] = field(default_factory=dict)
    pov_script: str = ""                   # path to the standalone pwntools replay
    patch: Patch | None = None             # stage 9 fix (M7 #45/#46), or None


@dataclass
class Finding:
    title: str
    binary: str
    function: str = ""
    bug_class: str = ""                    # memory-safety / intoverflow / ...
    severity: str = "unknown"
    description: str = ""
    sink: str = ""
    source: str = ""
    pov: PoV | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def is_confirmed(self) -> bool:
        return self.pov is not None and self.pov.reproduced

    @property
    def is_patched(self) -> bool:
        """Strict sibling of ``is_confirmed``: a *verified* fix is attached (the
        confirmed PoV no longer reproduces and no regression was observed)."""
        return (
            self.pov is not None
            and self.pov.patch is not None
            and self.pov.patch.verified
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.pov and self.pov.input_bytes is not None:
            d["pov"]["input_bytes"] = self.pov.input_bytes.hex()
        return d


def to_json(findings: list[Finding], *, confirmed_only: bool = True) -> str:
    rows = [f for f in findings if (f.is_confirmed or not confirmed_only)]
    return json.dumps([f.to_dict() for f in rows], indent=2)

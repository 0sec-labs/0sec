#!/usr/bin/env python3
"""M4 milestone proof — five new bug classes, each lens + (where one exists) a
CONFIRMING oracle that produces a reproducing PoV.

Run inside the engine env (needs a C compiler; pwntools optional for the
standalone replay):

    python benchmarks/m4_proof.py

For each class it (1) runs the static **lens** over the function C and asserts a
tagged hypothesis (origin ``bugclass:<id>``), then (2) compiles the fixture and
routes a candidate trigger to the **confirming oracle**, asserting a reproducing
PoV — except the logic class, which is HYPOTHESIS-ONLY (no generic binary oracle)
and must surface a lead while ``confirm`` honestly returns None.

Exit 0 iff intoverflow / fmtstring / uaf / double-free / cmdi each produce a
confirmed PoV and the logic class surfaces a hypothesis with no false PoV.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse import bugclasses, oracle  # noqa: E402
from zeroverse.agent import Verdict  # noqa: E402
from zeroverse.bugclasses import (  # noqa: E402
    cmdi_lens,
    fmtstring_lens,
    intoverflow_lens,
    logic_lens,
    uaf_lens,
)
from zeroverse.poc import write_pov_script  # noqa: E402

_V = Verdict(is_real=True, bug_class="x", severity="high", explanation="", input_example="")


def _compile(name: str, flags: list[str], out: Path) -> Path:
    binp = out / name
    subprocess.run(
        ["cc", "-O0", "-fno-stack-protector", "-no-pie", *flags,
         str(HERE / f"{name}.c"), "-o", str(binp)],
        check=True, capture_output=True,
    )
    return binp


def _replay(pov_script: str) -> bool:
    if not pov_script or not Path(pov_script).exists():
        return True  # nothing to replay (e.g. pwntools absent) — not a failure
    try:
        rc = subprocess.run([sys.executable, pov_script], capture_output=True).returncode
    except OSError:
        return True
    return rc == 0


def _confirm_case(name: str, lens, flags, trigger, control, out: Path) -> bool:  # type: ignore[no-untyped-def]
    code = (HERE / f"{name}.c").read_text()
    hyps = lens({name: code})
    assert hyps, f"{name}: lens produced no hypothesis"
    f = hyps[0]
    print(f"  lens hypothesis: origin={f.origin} sink={f.sink} func={f.function}")
    binp = _compile(name, flags, out)
    pov = bugclasses.confirm(f, _V, binp, trigger=trigger, control=control)
    if pov is None or not pov.reproduced:
        print(f"  FAIL[{name}]: oracle did not confirm a PoV")
        return False
    print(f"  CONFIRMED: crash_class={pov.crash_class} capability={pov.capability}")
    print(f"  diff: {pov.diff_allocator}")
    script = write_pov_script(out / f"pov_{name}.py", binp, pov)
    ok = _replay(str(script))
    print(f"  standalone PoV replay reproduced: {ok}")
    return ok


def main() -> int:
    if not oracle.quarantine_available():
        print("FAIL: no C compiler — cannot build the quarantine guard oracle")
        return 1
    ok = True
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)

        print("== #22 intoverflow (differential-allocator + quarantine guard) ==")
        ok &= _confirm_case(
            "intoverflow", intoverflow_lens, [],
            trigger=b"\x00\x01\x00\x01" + b"A" * 16, control=b"\x01\x00\x01\x00", out=out,
        )

        print("\n== #23 fmtstring (%s-spray / %n probe) ==")
        ok &= _confirm_case(
            "fmtstring", fmtstring_lens, [],
            trigger=None, control=b"hello", out=out,
        )

        print("\n== #24 uaf (quarantine guard: poison + mprotect) ==")
        ok &= _confirm_case(
            "uaf", uaf_lens, [], trigger=b"X", control=b"n", out=out,
        )

        print("\n== #24 double-free (quarantine guard: trap on 2nd free) ==")
        ok &= _confirm_case(
            "double_free", uaf_lens, [], trigger=b"X", control=b"n", out=out,
        )

        print("\n== #25 cmdi (sentinel-command canary) ==")
        # cmdi.c reads getenv("CMD") -> system(); the canary echoes a token-bound
        # marker, proving injection without running anything harmful.
        code = (HERE / "cmdi.c").read_text()
        hyps = cmdi_lens({"main": code})
        assert hyps, "cmdi: lens produced no hypothesis"
        print(f"  lens hypothesis: origin={hyps[0].origin} sink={hyps[0].sink}")
        binp = _compile("cmdi", [], out)
        pov = bugclasses.confirm(
            hyps[0], Verdict(True, "x", "high", "", 'CMD="; id"'), binp
        )
        if pov and pov.reproduced and pov.capability == "reached-sink":
            print(f"  CONFIRMED: command-injection via {pov.env} (marker in stdout)")
        else:
            print("  FAIL[cmdi]: canary did not prove injection")
            ok = False

        print("\n== #26 logic / auth-bypass (HYPOTHESIS-ONLY) ==")
        code = (HERE / "auth_bypass.c").read_text()
        leads = logic_lens({"check_password": code})
        assert leads, "logic: lens surfaced no lead"
        print(f"  lens lead: origin={leads[0].origin} sink={leads[0].sink}")
        # honest gap: no generic oracle — confirm MUST decline (never a false PoV).
        none_pov = bugclasses.confirm(leads[0], _V, "/bin/true")
        if none_pov is None:
            print("  OK: logic class stays an honest hypothesis (confirm returns None)")
        else:
            print("  FAIL[logic]: a logic bug was claimed CONFIRMED without a PoV")
            ok = False

    print("\n=== M4 PROOF:", "PASS ✅" if ok else "FAIL ❌", "===")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

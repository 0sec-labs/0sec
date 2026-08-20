#!/usr/bin/env python3
"""Magma at-scale eval runner — the credibility instrument on REAL library bugs.

Extracts each built Magma target's driver binary from its Docker image, runs the
**full 0verse pipeline** (`zeroverse.api.scan`) over it with the **real LLM**
(Codex `gpt-5.5` by default), and scores the findings against Magma's KNOWN bug
locations with the typed, unit-tested scorer in `zeroverse.magma`: bug-sites
**reached** (slice/lens), bug-sites **confirmed** (reproducing PoV at the bug
function), **unmatched confirmations** (ASSUME-FP), precision, wall-time + token
cost per target. No cherry-picking — misses and FPs are emitted verbatim.

Pre-req: build the targets first (fatal canaries, -O0), e.g. on `bench`:

    cd magma && docker build -t magma/aflplusplus/libpng:isan \
        --build-arg fuzzer_name=aflplusplus --build-arg target_name=libpng \
        --build-arg USER_ID=1000 --build-arg GROUP_ID=1000 \
        --build-arg canaries=1 --build-arg isan=1 \
        -f docker/Dockerfile .

Note the context is the magma repo ROOT (`.`), not a `magma/` subdirectory.
The Dockerfile COPYs `${magma_root}/magma`, `${magma_root}/fuzzers/<f>` and
`${magma_root}/targets/<t>` with `magma_root=./`, so building from one level
up fails immediately with
`lstat magma/docker: no such file or directory`.

`libtiff` needs one extra step before that build works. libtiff's own
`autogen.sh` unconditionally refetches `config.guess`/`config.sub` from
`git.savannah.gnu.org` and hard-exits when the fetch fails, and it DOES fail from
inside the ubuntu:18.04 magma build container (the URL 301s to
`cgit.git.savannah.gnu.org`, whose DNS round-robin includes IPs that black-hole
:443, against autogen.sh's `--timeout=5`). Run
`/root/magma-libtiff-offline-autogen.sh` on `bench` first: it vendors the
byte-identical upstream `config.guess`/`config.sub` into
`magma/targets/libtiff/src/` and patches `magma/targets/libtiff/fetch.sh` to use
them instead of the network. Those are autotools host-triplet detection scripts
read by `./configure`; they are never compiled into libtiff, so the library under
test and its instrumentation are unchanged. Without libtiff the scored
denominator drops from **53 bug-sites to 39**.

Host pre-req: `kernel.core_pattern` must NOT be a userspace pipe. A crash
reporter (apport, systemd-coredump) swallows the crashes afl-fuzz has to observe,
and the fuzz lane sets `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, so AFL's own hard
abort would become a silent stall. `SubprocessAfl.fuzz` refuses the instrumented
lane on such a host (#312); persist the fix so a reboot cannot reintroduce it:

    printf 'kernel.core_pattern=core\n' > /etc/sysctl.d/60-afl.conf
    sysctl --system

Then:

    python benchmarks/magma/run.py --targets libpng lua --llm codex \
        --out benchmarks/magma/results-magma.json

`--last-mile` enables runtime-proven, GDB-assisted mutation of sink-reaching AFL
queue inputs. It requires `ZEROVERSE_EXECUTOR=local`; a containerized run must
also opt into ptrace (for example `--cap-add=SYS_PTRACE --security-opt
seccomp=unconfined`). On Apple Silicon, where Rosetta cannot expose x86
registers through ptrace, set `ZEROVERSE_GDB_QEMU=/usr/bin/qemu-x86_64` to use
QEMU's remote-GDB stub instead. The result JSON records whether the lane was
enabled.

`--llm mock` runs the deterministic CI-regression floor (NOT a capability number).
The HEADLINE Magma number is always the real-LLM lane.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from zeroverse.llm.usage import merge_accounting  # noqa: E402
from zeroverse.magma import (  # noqa: E402
    MAGMA_SCHEMA_VERSION,
    MagmaTargetScore,
    aggregate_magma,
    bugs_for_target,
    estimated_cost_usd,
    format_magma_report,
    load_catalogue,
    score_target,
)

DEFAULT_CATALOGUE = ROOT / "benchmarks" / "groundtruth" / "CATALOGUE-magma.json"
IMAGE_FMT = "magma/aflplusplus/{target}:{tag}"


# --- docker extraction ------------------------------------------------------

def extract_binaries(target: str, tag: str, dest: Path) -> list[Path]:
    """Copy `/magma_out/afl` out of the target's Docker image; return the ELF
    driver binaries found there."""
    image = IMAGE_FMT.format(target=target, tag=tag)
    dest.mkdir(parents=True, exist_ok=True)
    cid = subprocess.run(
        ["docker", "create", image], capture_output=True, text=True, check=True
    ).stdout.strip()
    try:
        subprocess.run(["docker", "cp", f"{cid}:/magma_out/afl/.", str(dest)],
                       capture_output=True, text=True, check=True)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, text=True)
    out: list[Path] = []
    for p in sorted(dest.iterdir()):
        if not p.is_file() or not os.access(p, os.X_OK):
            continue
        head = p.read_bytes()[:4]
        if head[:4] == b"\x7fELF":
            out.append(p)
    return out


# --- runtime-lib provisioning ----------------------------------------------
#
# A magma/OSS-Fuzz isan driver is built inside its image against the image's LLVM
# runtime (libc++/libc++abi/libunwind). A non-LLVM host lacks those, so the
# EXTRACTED ELF cannot dynamically link on the host — every exec dies with
# ``error while loading shared libraries: libc++.so.1: cannot open shared object
# file`` (exit 127). The fuzzer and the sanitizer/casr oracle then never actually
# run the target, so no crash is ever found (the fuzz stage reports "no confirmed
# crash" even though the in-container source lane crashes the same binary in
# seconds). Copy each SONAME the driver needs but the host cannot resolve out of
# the image and put them on LD_LIBRARY_PATH so host execs can load the driver.

def _missing_sonames(binary: Path, libdir: Path | None = None) -> set[str]:
    """SONAMEs ``ldd`` reports as ``=> not found`` for ``binary`` (the libs the
    host cannot resolve). ``libdir`` is prepended to ``LD_LIBRARY_PATH`` for the
    probe so already-staged libs resolve and ldd walks into THEIR dependencies."""
    env = dict(os.environ)
    if libdir is not None:
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = (
            f"{libdir}{os.pathsep}{prev}" if prev else str(libdir))
    try:
        p = subprocess.run(["ldd", str(binary)], capture_output=True, text=True,
                           timeout=30, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return set()
    missing: set[str] = set()
    for line in p.stdout.splitlines():
        if "=> not found" in line:
            missing.add(line.split("=>", 1)[0].strip())
    return missing


_IMAGE_LIBDIRS = ("/usr/lib/x86_64-linux-gnu", "/usr/lib", "/usr/local/lib",
                  "/lib/x86_64-linux-gnu")

# `ldd` only walks INTO a dependency it could resolve, so one pass reports the
# binary's own unresolvable SONAMEs and stops there. Staging those makes the NEXT
# pass see one level deeper: magma `lua` needs `libreadline.so.7`, which itself
# needs `libtinfo.so.5`, which a single pass never reports (#315). Loop until the
# missing set stops shrinking. The cap is a runaway guard only — a real ELF
# dependency graph is a DAG a handful of levels deep — and the "no NEW soname
# this pass" exit below is what actually terminates the loop, including when a
# soname is simply absent from the image and can never be staged.
_MAX_LIB_PASSES = 12


def provide_runtime_libs(target: str, tag: str, binaries: list[Path],
                         dest: Path) -> Path | None:
    """Copy the runtime libs the extracted drivers need but the host lacks out of
    the target image (following symlinks with ``docker cp -L`` so the real ELF
    lands under its SONAME), TRANSITIVELY — a staged lib's own dependencies are
    staged too. Returns the lib dir for LD_LIBRARY_PATH, or ``None`` when the host
    already resolves everything."""
    missing: set[str] = set()
    for b in binaries:
        missing |= _missing_sonames(b)
    if not missing:
        return None
    dest.mkdir(parents=True, exist_ok=True)
    image = IMAGE_FMT.format(target=target, tag=tag)
    cid = subprocess.run(
        ["docker", "create", image], capture_output=True, text=True, check=True
    ).stdout.strip()
    attempted: set[str] = set()
    try:
        for _ in range(_MAX_LIB_PASSES):
            fresh = missing - attempted
            if not fresh:
                break
            attempted |= fresh
            for so in sorted(fresh):
                for d in _IMAGE_LIBDIRS:
                    r = subprocess.run(
                        ["docker", "cp", "-L", f"{cid}:{d}/{so}", str(dest / so)],
                        capture_output=True, text=True,
                    )
                    if r.returncode == 0:
                        break
            # Re-probe with the staged libs visible: what was hidden behind an
            # unresolvable dependency shows up now.
            missing = set()
            for b in binaries:
                missing |= _missing_sonames(b, libdir=dest)
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, text=True)
    if missing:
        # Everything reachable has been staged and the target STILL cannot link.
        # Say so; the caller refuses to score a target that cannot execute.
        print(f"!! {target}: unresolved after {len(attempted)} staged lib(s): "
              f"{', '.join(sorted(missing))}", file=sys.stderr)
    return dest if any(dest.iterdir()) else None


def unrunnable_binaries(binaries: list[Path], libdir: Path | None) -> list[str]:
    """The extracted binaries that still cannot resolve their shared libraries.

    Such a binary exits 127 at the loader without executing a single instruction,
    so afl-fuzz reports ``Fork server handshake failed`` and the oracle sees no
    crash — a structural zero that is shaped exactly like a measured one (#262,
    #297, #304, #315). The caller must refuse to publish a score for it."""
    return [b.name for b in binaries if _missing_sonames(b, libdir=libdir)]


# --- the per-binary scan (run in a child for timeout + isolation) -----------

# Margin between the pipeline's soft wall clock and the parent's hard timeout
# kill, so the run can wind down and emit partial state instead of being killed.
WALL_CLOCK_KILL_MARGIN_S = 30


def _run_wall_clock_seconds() -> float:
    """Run-level wall clock for the child scan.

    `RunBudget` defaults to 300s and bounds the WHOLE scan. Ghidra alone spends
    119-610s on these drivers, so the default starves the fuzz stage: budget
    checks short-circuit and the fuzz complement returns a note rather than
    running, producing a well-formed zero (#304).

    Derive it from the parent's `--timeout` (exported below) so the soft budget
    always sits just under the hard kill and the two cannot disagree."""
    raw = os.environ.get("ZEROVERSE_RUN_WALL_CLOCK", "")
    try:
        wall = float(raw) if raw else 0.0
    except ValueError:
        wall = 0.0
    if wall > 0:
        return wall
    # Standalone `--scan-one` invocation with no parent: fall back to something
    # that at least covers decompilation plus the requested fuzz window.
    try:
        fuzz_s = float(os.environ.get("ZEROVERSE_FUZZ_DURATION", "0") or 0)
    except ValueError:
        fuzz_s = 0.0
    return 1200.0 + max(0.0, fuzz_s)


def _scan_one(binary: str, llm_name: str, backend: str) -> dict[str, Any]:
    """Run the full pipeline once; return findings + token usage + stages. This is
    the child entry (`--scan-one`) so the parent can bound it with a hard timeout."""
    os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/ghidra")
    from zeroverse import api
    from zeroverse.pipeline import run as pipeline_run
    from zeroverse.preflight import RunBudget

    llm = None
    if llm_name not in ("mock", "", None):
        from zeroverse.llm.providers import build_llm
        llm = build_llm(provider=None if llm_name == "auto" else llm_name)

    prev = os.environ.get("ZEROVERSE_BACKEND")
    if backend:
        os.environ["ZEROVERSE_BACKEND"] = backend

    # The run-level wall clock bounds the WHOLE scan, and RunBudget defaults to
    # 300s. Ghidra alone routinely spends 200-600s on these drivers, so the
    # default leaves little or nothing for the fuzz stage: every budget check
    # short-circuits and the fuzz complement returns a note instead of running.
    # The result is a well-formed zero — the run exits 0, `dynamic` reports as
    # run, and no AFL artifacts exist (#304). Size the wall clock to cover
    # decompilation plus the requested fuzz window so --fuzz-seconds is
    # actually satisfiable.
    budget = RunBudget(wall_clock_seconds=_run_wall_clock_seconds())

    t0 = time.monotonic()
    try:
        rr = pipeline_run(binary, llm=llm, budget=budget)
    finally:
        if backend and prev is not None:
            os.environ["ZEROVERSE_BACKEND"] = prev
    result = api._result_from_run(binary, rr, backend=backend or "auto")
    acct = _llm_accounting(llm, llm_name)
    return {
        "findings": [f.to_dict() for f in result.findings],
        "stages": list(result.stages_run),
        "ghidra_ok": "decompile" in result.stages_run,
        "wall_s": round(time.monotonic() - t0, 1),
        "input_tokens": int(acct["input_tokens"]),
        "output_tokens": int(acct["output_tokens"]),
        "llm_accounting": acct,
        "note": result.note,
    }


# Accounting status for a lane that was never meant to call a model at all.
_MOCK_ACCT = "mock"


def _llm_accounting(llm: Any, llm_name: str) -> dict[str, Any]:
    """The child's LLM call/token ledger, carried back over the ``--scan-one``
    subprocess boundary as plain JSON.

    This used to be ``dict(getattr(llm, "total_usage", {}) or {})``, which
    reported a confident ``0`` for four very different situations: the model was
    never called, every call failed, the provider does not report usage, and the
    model really did cost nothing. ``TriageAgent.triage`` swallows every backend
    exception by design, so the first two are otherwise invisible — findings are
    still produced and the ``reason`` stage still runs. The ledger in
    ``zeroverse.llm.usage`` separates them; this just serializes it."""
    if llm is None:
        return {"provider": llm_name or _MOCK_ACCT, "model": "", "status": _MOCK_ACCT,
                "calls_ok": 0, "calls_failed": 0, "usage_reported": False,
                "input_tokens": 0, "output_tokens": 0}
    tracker = getattr(llm, "usage", None)
    acct: dict[str, Any]
    if tracker is None:
        # A backend that predates the ledger — say so rather than implying 0.
        usage = dict(getattr(llm, "total_usage", {}) or {})
        acct = {"status": "uninstrumented", "calls_ok": 0, "calls_failed": 0,
                "usage_reported": False,
                "input_tokens": int(usage.get("input_tokens", 0)),
                "output_tokens": int(usage.get("output_tokens", 0))}
    else:
        acct = dict(tracker.to_dict())
    acct["provider"] = llm_name
    acct["model"] = str(getattr(llm, "model", ""))
    return acct


def _last_progress(path: Path) -> dict[str, Any] | None:
    """The scan child's last incremental stage record (written by the pipeline
    under ``ZEROVERSE_PROGRESS_PATH``, #224 sub-gap (c)), or None when the child
    died before its first stage boundary."""
    try:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            return rec
    return None


def _scan_failure(note: str, progress: Path, t0: float) -> dict[str, Any]:
    """A timeout/crash result row — annotated with the child's partial progress
    so a killed scan reports WHERE it stood (stage, findings so far) instead of
    being indistinguishable from a hang."""
    rec = _last_progress(progress)
    if rec:
        note += (f"; partial: stage={rec.get('stage')} "
                 f"findings={rec.get('findings')} confirmed={rec.get('confirmed')}")
    return {"findings": [], "stages": [], "ghidra_ok": False,
            "wall_s": round(time.monotonic() - t0, 1), "input_tokens": 0,
            "output_tokens": 0,
            # The child died before it could report its ledger; its LLM spend is
            # genuinely unknown, so don't fold a 0 into the run total silently.
            "llm_accounting": {"status": "child-died", "calls_ok": 0,
                               "calls_failed": 0, "usage_reported": False,
                               "input_tokens": 0, "output_tokens": 0},
            "note": note, "partial": rec}


def scan_binary(
    binary: Path,
    llm: str,
    backend: str,
    timeout_s: int,
    *,
    keep_workdir: bool = False,
) -> dict[str, Any]:
    """Parent-side: run `_scan_one` in a child with a hard wall-clock timeout."""
    cmd = [sys.executable, str(Path(__file__).resolve()),
           "--scan-one", str(binary), "--llm", llm, "--backend", backend]
    # The child mirrors each pipeline stage boundary here (#224-c); on a timeout
    # kill the parent recovers the partial state from this file.
    progress = Path(str(binary) + ".progress.ndjson")
    progress.unlink(missing_ok=True)
    # Give the child a soft run budget just under this hard timeout, so the
    # pipeline winds down and writes partial state instead of being SIGKILLed —
    # and so a large --fuzz-seconds is actually satisfiable (#304).
    env = dict(
        os.environ,
        ZEROVERSE_PROGRESS_PATH=str(progress),
        ZEROVERSE_RUN_WALL_CLOCK=str(max(60, timeout_s - WALL_CLOCK_KILL_MARGIN_S)),
    )
    t0 = time.monotonic()
    # Keep generated harnesses, AFL state, and reports off the source checkout.
    # This also makes a read-only repository mount a supported benchmark setup.
    scan_dir = Path(
        tempfile.mkdtemp(prefix=f".{binary.name}-scan-", dir=binary.parent)
    )
    result: dict[str, Any]
    try:
        try:
            # argv list, no shell: `binary` is a docker-extracted eval artifact
            # path, never user-controlled text — same shape as
            # browser_campaign.py:795.
            proc = subprocess.run(  # foxguard: ignore[py/no-command-injection]
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                env=env,
                cwd=str(scan_dir),
            )
        except subprocess.TimeoutExpired:
            result = _scan_failure(f"scan timeout (>{timeout_s}s)", progress, t0)
        else:
            if proc.returncode != 0:
                result = _scan_failure(
                    f"scan failed: {proc.stderr[-400:]}", progress, t0
                )
            else:
                line = (
                    proc.stdout.strip().splitlines()[-1]
                    if proc.stdout.strip()
                    else "{}"
                )
                result = dict(json.loads(line))
    finally:
        if not keep_workdir:
            shutil.rmtree(scan_dir, ignore_errors=True)
    if keep_workdir:
        result["scan_workdir"] = str(scan_dir)
    return result


# --- incremental result emission (#298 / #224 sub-gap (c)) ------------------
#
# The runner used to hold every target in memory and write the results JSON once,
# after the last one finished. A run killed by `timeout`, an OOM, or a dropped
# connection therefore produced NO file at all — indistinguishable from a hang,
# and 30+ minutes of real compute discarded. Each target now lands in the results
# path the moment it is scored, so a partial run is still a scoreable artifact.
# `complete` says whether the file is the whole planned run.

def _write_results(path: Path, payload: dict[str, Any]) -> None:
    """Write the results JSON atomically (tmp + rename), so a reader — or a kill
    landing mid-write — never sees a truncated file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _append_progress(path: Path, rec: dict[str, Any]) -> None:
    """Append one target's outcome to the run-level NDJSON — the same incremental
    model as the per-binary `<binary>.progress.ndjson` the scan child writes."""
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _cost_block(acct: dict[str, Any]) -> tuple[float | None, str]:
    """Estimated USD + an honest note. Only a `measured` ledger gets a number; the
    other states get `None`, because "$0.00" for an LLM lane that never reached the
    model is the exact confusion this benchmark cannot afford."""
    status = str(acct.get("status", ""))
    if status == "measured":
        return estimated_cost_usd(int(acct.get("input_tokens", 0)),
                                  int(acct.get("output_tokens", 0))), ""
    notes = {
        _MOCK_ACCT: "mock lane: no LLM was called by design; cost is not applicable.",
        "unreported": ("the provider returned no usage object on any call "
                       "(the ChatGPT-OAuth wire is subscription-billed), so token "
                       "counts are UNKNOWN, not zero."),
        "all-calls-failed": ("every LLM call FAILED (e.g. an expired credential). "
                             "TriageAgent degrades silently, so findings below are "
                             "static-only — this is NOT a real-LLM capability "
                             "result."),
        "no-calls": ("the LLM was never invoked — no stage escalated. This is NOT a "
                     "real-LLM capability result."),
        "child-died": "the scan child was killed before it reported its LLM ledger.",
        "uninstrumented": "this backend does not report token usage.",
    }
    return None, notes.get(status, f"token accounting unavailable ({status!r}).")


def _build_output(
    args: argparse.Namespace,
    lane: str,
    scores: list[MagmaTargetScore],
    details: list[dict[str, Any]],
    acct_blocks: list[dict[str, Any]],
    *,
    complete: bool,
) -> dict[str, Any]:
    metrics = aggregate_magma(scores)
    acct = merge_accounting(acct_blocks) if acct_blocks else {
        "status": "no-calls", "calls_ok": 0, "calls_failed": 0,
        "usage_reported": False, "input_tokens": 0, "output_tokens": 0,
    }
    if args.llm in ("mock", "", None):
        acct["status"] = _MOCK_ACCT
    cost, cost_note = _cost_block(acct)
    return {
        "schema_version": MAGMA_SCHEMA_VERSION,
        "llm": args.llm,
        "lane": lane,
        # False while the run is still in flight: this file is a partial artifact
        # written after each target, not the finished scoreboard.
        "complete": complete,
        "targets_planned": list(args.targets),
        "targets_scored": [s.target for s in scores],
        "capability_measure": args.llm not in ("mock", ""),
        "synth_inputs": bool(os.environ.get("ZEROVERSE_SYNTH_INPUTS")),
        "last_mile": bool(os.environ.get("ZEROVERSE_LAST_MILE")),
        "capability_scope": (
            "A confirmed magma bug proves the pipeline confirms END-TO-END "
            "(decompile -> triage -> fuzz -> attribute -> reproduce) GIVEN a "
            "fuzzable instrumented target: magma ships AFL/ASan-instrumented "
            "libFuzzer drivers, fuzzed natively. This is NOT a claim of confirming "
            "bugs in arbitrary stripped binaries (that needs per-function "
            "harness-gen). Do not let the headline over-claim."
        ),
        "backend": args.backend,
        "tag": args.tag,
        "keep_workdir": args.keep_workdir,
        "workdir": args.workdir,
        "metrics": metrics.to_dict(),
        # Whether the LLM was actually reached, and whether its token numbers are
        # real. `metrics.input_tokens`/`output_tokens` are only meaningful when
        # `llm_accounting.status == "measured"`.
        "llm_accounting": acct,
        "estimated_cost_usd": cost,
        "cost_note": cost_note,
        "scores": [s.to_dict() for s in scores],
        "details": details,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="0verse Magma at-scale eval")
    ap.add_argument("--scan-one", help="(child) scan a single binary, print JSON")
    ap.add_argument("--targets", nargs="*",
                    default=["libpng", "lua", "libxml2", "libtiff", "sqlite3"])
    ap.add_argument("--tag", default="isan")
    ap.add_argument("--llm", default="codex",
                    help="real LLM provider for the HEADLINE number; 'mock' = "
                         "ci-regression floor (NOT a capability measure)")
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--catalogue", default=str(DEFAULT_CATALOGUE))
    ap.add_argument("--out", default=str(HERE / "results-magma.json"))
    ap.add_argument("--timeout", type=int, default=2400,
                    help="hard per-binary scan timeout (s)")
    ap.add_argument("--workdir", default="/tmp/magma-bins")
    ap.add_argument(
        "--keep-workdir",
        action="store_true",
        help="preserve per-binary scan/AFL artifacts under --workdir for replay",
    )
    ap.add_argument("--synth-inputs", choices=["auto", "on", "off"], default="auto",
                    help="issue-#52 structured-input synthesis in the confirm "
                         "stage. 'auto' (default) enables it for the real-LLM "
                         "capability lane and leaves it off for mock; 'on'/'off' "
                         "force it. Anti-cheat-clean: the synthesizer sees only "
                         "format knowledge + the decompiled sink, never a "
                         "reference input.")
    ap.add_argument("--seed-root", default="",
                    help="dir with per-target real seed corpora "
                         "(<seed-root>/<target>/) fed to the confirm-stage fuzzer "
                         "via ZEROVERSE_SEED_DIR. Seeds go to the fuzzer only, "
                         "never the LLM synthesizer.")
    ap.add_argument("--fuzz-seconds", type=int, default=0,
                    help="per-window fuzz budget (ZEROVERSE_FUZZ_DURATION); the "
                         "capability lane needs ~300s to reach a parser sink. "
                         "0 leaves the engine default (30s).")
    ap.add_argument("--force-fuzz", action="store_true",
                    help="run the fuzz complement even when the static slice "
                         "confirmed a finding (ZEROVERSE_FORCE_FUZZ).")
    ap.add_argument("--last-mile", action="store_true",
                    help="enable GDB-proven, LLM-targeted mutation of native AFL "
                         "queue inputs that reach prioritized sinks "
                         "(ZEROVERSE_LAST_MILE)")
    args = ap.parse_args(argv)

    if args.fuzz_seconds > 0:
        os.environ["ZEROVERSE_FUZZ_DURATION"] = str(args.fuzz_seconds)
    if args.force_fuzz:
        os.environ["ZEROVERSE_FORCE_FUZZ"] = "1"
    if args.last_mile:
        os.environ["ZEROVERSE_LAST_MILE"] = "1"

    # Part 1: the capability lane must exercise the format-valid synthesizer —
    # the format-blind boundary probes alone can never reach a parser sink. Set
    # here in the parent so the per-binary scan children inherit it. 'setdefault'
    # keeps an explicit caller-supplied value authoritative.
    synth_on = args.synth_inputs == "on" or (
        args.synth_inputs == "auto" and args.llm not in ("mock", "", None))
    if synth_on:
        os.environ.setdefault("ZEROVERSE_SYNTH_INPUTS", "1")
    elif args.synth_inputs == "off":
        os.environ.pop("ZEROVERSE_SYNTH_INPUTS", None)

    if args.scan_one:
        print(json.dumps(_scan_one(args.scan_one, args.llm, args.backend)))
        return 0

    catalogue = load_catalogue(args.catalogue)
    scores: list[MagmaTargetScore] = []
    details: list[dict[str, Any]] = []
    acct_blocks: list[dict[str, Any]] = []
    unrunnable: list[str] = []
    lane = ("real-llm-capability" if args.llm not in ("mock", "")
            else "ci-regression-floor (NOT a capability measure)")
    out_path = Path(args.out)
    progress_path = out_path.with_suffix(".progress.ndjson")
    progress_path.unlink(missing_ok=True)
    # Write the (empty) envelope up front so a run killed during the FIRST target
    # still leaves an artifact identifying what was attempted.
    _write_results(out_path, _build_output(args, lane, scores, details, acct_blocks,
                                           complete=False))
    for target in args.targets:
        bugs = bugs_for_target(catalogue, target)
        if not bugs:
            print(f"!! no catalogued bugs for {target}, skipping", file=sys.stderr)
            continue
        # Per-target real seed corpus for the confirm-stage fuzzer: a coverage-guided
        # fuzzer reaches a format-specific parser sink only from a valid container, so
        # each target gets its own seeds (<seed-root>/<target>/). Seeds go to the
        # FUZZER (honest, standard) — never to the LLM synthesizer (anti-cheat).
        if args.seed_root:
            sd = Path(args.seed_root) / target
            if sd.is_dir():
                os.environ["ZEROVERSE_SEED_DIR"] = str(sd)
            else:
                os.environ.pop("ZEROVERSE_SEED_DIR", None)
                print(f"!! {target}: no seed dir at {sd} (token seeds only)",
                      file=sys.stderr)
        print(f"== {target}: extracting binary ==", file=sys.stderr)
        try:
            bins = extract_binaries(target, args.tag, Path(args.workdir) / target)
        except subprocess.CalledProcessError as exc:
            print(f"!! {target}: docker extract failed: {exc}", file=sys.stderr)
            details.append({"target": target, "error": "extract-failed"})
            continue
        if not bins:
            print(f"!! {target}: no driver binary found", file=sys.stderr)
            continue
        # The extracted isan driver is linked against the image's LLVM runtime
        # (libc++/…) the host lacks; without it the fuzzer/oracle exec dies at the
        # loader (exit 127) and NO crash can ever be confirmed. Stage the missing
        # libs and put them on LD_LIBRARY_PATH — inherited by the scan child, its
        # afl-fuzz subprocess, and the sanitizer/casr oracle, all of which exec the
        # driver on the host.
        libdir = provide_runtime_libs(
            target, args.tag, bins, Path(args.workdir) / target / ".runtime-libs")
        if libdir is not None:
            prev = os.environ.get("LD_LIBRARY_PATH", "")
            os.environ["LD_LIBRARY_PATH"] = (
                f"{libdir}{os.pathsep}{prev}" if prev else str(libdir))
            print(f"   staged {len(list(libdir.iterdir()))} runtime lib(s) for "
                  f"{target} -> LD_LIBRARY_PATH", file=sys.stderr)
        # A binary that cannot link cannot be measured. Scoring it anyway emits a
        # 0 that is indistinguishable from a real one (#297's lesson, one level
        # down): fail loudly here instead of publishing the structural zero.
        broken = unrunnable_binaries(bins, libdir)
        if broken:
            print(f"!! {target}: SKIPPING — {', '.join(broken)} cannot resolve "
                  f"their shared libraries even after staging from the image. "
                  f"That is a broken box, not a capability measurement.",
                  file=sys.stderr)
            details.append({"target": target, "error": "runtime-libs-unresolved",
                            "binaries": broken})
            unrunnable.append(target)
            _write_results(out_path, _build_output(args, lane, scores, details,
                                                   acct_blocks, complete=False))
            continue
        # aggregate findings across all driver binaries of the target
        all_findings: list[dict[str, Any]] = []
        wall = inp = out_tok = 0.0
        ghidra_ok = False
        notes = []
        scan_workdirs: list[str] = []
        target_acct: list[dict[str, Any]] = []
        for b in bins:
            print(f"   scan {b.name} ({args.llm}) ...", file=sys.stderr)
            r = scan_binary(
                b,
                args.llm,
                args.backend,
                args.timeout,
                keep_workdir=args.keep_workdir,
            )
            all_findings += r["findings"]
            wall += r["wall_s"]
            inp += r["input_tokens"]
            out_tok += r["output_tokens"]
            ghidra_ok = ghidra_ok or r["ghidra_ok"]
            acct = dict(r.get("llm_accounting") or {})
            target_acct.append(acct)
            acct_blocks.append(acct)
            if r["note"]:
                notes.append(f"{b.name}: {r['note']}")
            if r.get("scan_workdir"):
                scan_workdirs.append(str(r["scan_workdir"]))
            print(f"      findings={len(r['findings'])} confirmed="
                  f"{sum(1 for f in r['findings'] if f.get('confirmed'))} "
                  f"ghidra={r['ghidra_ok']} {r['wall_s']}s "
                  f"llm={acct.get('status', '?')} "
                  f"calls={acct.get('calls_ok', 0)}ok/{acct.get('calls_failed', 0)}fail "
                  f"tok={r['input_tokens']}+{r['output_tokens']}", file=sys.stderr)
        s = score_target(
            target, bugs, all_findings, label="vulnerable", wall_s=wall,
            input_tokens=int(inp), output_tokens=int(out_tok), ghidra_ok=ghidra_ok,
            note=" | ".join(notes),
        )
        scores.append(s)
        tgt_acct = merge_accounting(target_acct)
        details.append({"target": target, "binaries": [b.name for b in bins],
                        "scan_workdirs": scan_workdirs,
                        "llm_accounting": tgt_acct,
                        "findings": all_findings, "score": s.to_dict()})
        print(f"   => reached={s.bug_sites_reached}/{s.n_bug_sites} "
              f"confirmed={s.bug_sites_confirmed} unmatched={s.unmatched_confirmed}",
              file=sys.stderr)
        # #298: land this target in the results path NOW. Everything above is
        # 10-30 minutes of compute per target; a kill after this point keeps it.
        _append_progress(progress_path, {"target": target, "score": s.to_dict(),
                                         "llm_accounting": tgt_acct})
        _write_results(out_path, _build_output(args, lane, scores, details,
                                               acct_blocks, complete=False))
        print(f"   partial results -> {out_path} "
              f"({len(scores)}/{len(args.targets)} targets)", file=sys.stderr)

    # #297 — a target whose decompile stage never ran contributes a structural
    # zero, not a measurement. Emitting it anyway produces a well-formed table
    # that is indistinguishable in shape from a genuine 0-confirm result, so a
    # broken box reads as a capability number. Refuse to write one.
    if unrunnable:
        print(f"!! REFUSING to emit a result: {', '.join(unrunnable)} could not "
              f"link on this host even after staging the image's runtime libs. "
              f"The target never executed, so it has no score — fix the staging "
              f"(or the image) and re-run; per-target notes above.",
              file=sys.stderr)
        return 2
    degraded = [s.target for s in scores if not s.ghidra_ok]
    if degraded:
        print(f"!! REFUSING to emit a result: decompile never ran for "
              f"{', '.join(degraded)} (ghidra_ok=false). Those targets scored a "
              f"structural zero, not a measured one. Fix the backend "
              f"(see docs/GHIDRA-SETUP.md) and re-run; per-target notes above.",
              file=sys.stderr)
        return 2

    out = _build_output(args, lane, scores, details, acct_blocks, complete=True)
    metrics = aggregate_magma(scores)
    report = format_magma_report(metrics, scores, llm=args.llm, lane=lane,
                                 accounting=out["llm_accounting"])
    _write_results(out_path, out)
    print("\n" + report)
    acct = out["llm_accounting"]
    if out["cost_note"]:
        # Never let a dead or unmeasurable LLM lane print a confident "$0.00".
        print(f"!! LLM accounting: {acct['status']} "
              f"({acct['calls_ok']} ok / {acct['calls_failed']} failed calls) — "
              f"{out['cost_note']}", file=sys.stderr)
    else:
        print(f"   LLM accounting: measured over {acct['calls_ok']} calls — "
              f"{acct['input_tokens']}+{acct['output_tokens']} tok, "
              f"~${out['estimated_cost_usd']}", file=sys.stderr)
    print(f"\nresults -> {args.out}", file=sys.stderr)
    print(f"per-target progress -> {progress_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

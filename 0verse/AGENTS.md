# AGENTS.md — 0verse

> Status: 2026-07-31. Living document.
>
> Cross-tool memory for the 0verse repo. Claude Code and Codex auto-load
> this at session start; `CLAUDE.md` is a symlink — edit this file.
>
> The parent monorepo has its own `AGENTS.md` covering company-wide rules
> (claim gates, disclosure embargo, branch norms). Read that too when a
> change crosses into `0sec-labs/0sec`.

## The one thing to internalise first

**This codebase's dominant failure mode is the silent zero: a broken
environment or a starved stage producing a clean-looking benchmark
number instead of an error.**

It is not hypothetical. Between 2026-07-28 and 2026-07-31 it happened
**six** times, each independently capable of reporting `confirmed_pov_rate:
0.00` on a working engine:

| what was actually wrong | how it presented |
|---|---|
| `pyghidra` not installed (#296) | full run "completed" in 1.3s, `ghidra=degrade`, 0/39 |
| backend requested but unavailable (#297) | `rc=0`, degraded silently, scored a zero |
| fuzz duration hardcoded to 30s (#305) | `--fuzz-seconds` a no-op, no error |
| run budget too small for the fuzz window (#305) | budget-exhausted paths return *notes*, not errors |
| candidate oracle loop ate all 12 attempts (#311) | fuzz stage returned a note that was then **discarded** |
| expired `codex` credential (#308) | every LLM call failed; findings still produced, 0 tokens reported |

Plus `afl-fuzz` absent from the host, a piped `kernel.core_pattern`
turning AFL's own hard abort into a stall (#312), and a fork-server
deadlock (#313).

**Consequences for how you work here:**

- A zero is a claim that needs evidence, exactly like a finding does.
  Before reporting one, prove the pipeline ran: check `ghidra_ok`, LLM
  `calls_ok`/`calls_failed`, and that AFL produced `fuzzer_stats` with
  advancing `execs_done`. A stage appearing in `stages_run` proves it was
  *entered*, not that it did work.
- **A code path that returns neither work nor an explanation is a
  defect.** If you add an early return, attach a note, and make sure the
  caller actually surfaces it — #311's note existed and was thrown away
  by a return that fired before the merge point.
- Prefer failing loudly to degrading. An explicitly requested backend
  that cannot start should exit non-zero, not fall back.

## Benchmark methodology — magma

`benchmarks/magma/run.py` is the credibility instrument. Treat its output
with the scepticism you would apply to someone else's claim.

- **The denominator is 53 bug-sites** across 5 built targets (lua 4,
  libpng 7, libsndfile 14, libxml2 14, libtiff 14). Numbers quoted before
  2026-07-30 used 39 because libtiff would not build (#314).
- **Never report a single run.** Confirm counts carry roughly ±1–2 sites
  of run-to-run variance — `main` once scored 4 confirmed and then 2 on
  identical code (#319). Report a median over ≥3 runs with the range. A
  bare decimal implies precision the instrument does not have.
- **Never compare across a changed invocation.** If budget, flags or
  target set differ, re-run the control at the same settings. Comparing
  a candidate at `--timeout 7200` against a baseline at `2400` produced a
  confident and wrong "regression" conclusion during #313.
- Known unconfirmable sites: libtiff ships only 12 of its 14 canary IDs
  (`TIF013` configure-disabled upstream, `TIF011` not linked). Upstream
  magma behaviour, not ours.

## The bench box

Most real work runs on `bench` (`ssh bench`). Facts that cost time to
rediscover:

- **Use `.venv/bin/python`, not `uv run`.** `pyghidra`/`jpype1` are
  installed from Ghidra's bundled wheels and are absent from `uv.lock`, so
  a sync silently removes them and every scan degrades to ingest-only.
- Required env: `GHIDRA_INSTALL_DIR=/opt/ghidra` (without it the pipeline
  degrades quietly), `ZEROVERSE_EXECUTOR=local` (else the confirm oracle
  fail-closes), and `PATH` including `/root/.cargo/bin` for `casr-gdb`.
- Magma source `/root/magma`; images `magma/aflplusplus/<target>:isan`;
  flattened seeds `/root/magma-seeds/<target>/`.
- `/tmp` is cleared on reboot — extracted binaries go, images and results
  survive.
- `kernel.core_pattern` must not be a `|pipe`. AFL aborts on one, but this
  lane sets `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, which downgrades that
  abort to a silent stall (#312).

## AFL version skew — a whole day, twice

`afl-fuzz` and `afl-qemu-trace` **must be the same AFLplusplus version.**
The failure is a deadlock, not an error message: 4.09c terminates the fork
server with SIGTERM, while an older `afl-compiler-rt` has an `at_exit` of
`kill(child_pid,9); ret` with no `_exit`, so the server survives and
afl-fuzz blocks forever in `waitpid` (#313).

Two traps around this:

- The Ubuntu `afl++` package **does not ship `afl-qemu-trace`** — it must
  be built from `qemu_mode/build_qemu_support.sh` (#316, #321).
- Clone qemuafl **full, not shallow**. `build_qemu_support.sh` runs
  `git checkout $(cat QEMUAFL_VERSION)`, which on a shallow clone
  degrades to a warning plus master HEAD — reintroducing the skew
  silently.

`scripts/`-adjacent reference implementation lives at
`bench:/root/build-afl-qemu-trace.sh`, with a hard version gate.

## Verification norms

- `uv run --frozen --extra dev ruff check src tests` — **CI lints `src`
  and `tests` only.** `ruff check src benchmarks` reports ~26 pre-existing
  failures on `main`; do not "fix" those in an unrelated PR.
- `uv run --frozen --extra dev mypy --strict src`
- `uv run --frozen --extra dev pytest` — **establish the baseline failure
  set on clean `main`, on your host, before claiming no regressions.** It
  varies by machine; some hosts see ~13 pre-existing macOS failures and
  others are fully green.
- foxguard runs in CI. If it flags something, investigate rather than
  reflex-suppressing. When it is genuinely a false positive, suppress with
  a written justification — see `benchmarks/magma/run.py` for the
  convention.

## Things to never do

- Report a benchmark number without evidence the pipeline actually ran.
- Add an early return with no note, or a note the caller drops.
- Compare two runs whose invocations differ.
- `git checkout` in a shared checkout other agents are using — worktrees
  only.
- Push or open a PR without operator approval (parent `AGENTS.md`).
- Add AI/Claude/Codex attribution to commit messages.

## kernelCTF LTS — read before touching this lane (2026-08-11)

Full runbook: `docs/KERNELCTF-PLAYBOOK.md`. Finding ledger:
`campaigns/browser/ledger.json` (`kernelctf_findings` + `kernelctf_rotation`).
Live host facts: `benchmarks/kernelctf/`, hosts `fuzzer` (discovery) and
`bench` (repro/weaponization).

**Eligibility — the rule that invalidates most harvested work:**

- Submissions are **0-day only**. A bug is 0-day only if, at submission
  time: (a) there is **no patch commit in the mainline tree**, and (b) it
  is **not disclosed anywhere** (e.g. no Syzkaller report).
- LTS crash-only IS enough to win ($71,337) — full LPE not required — but
  only for a 0-day.
- A 1-day (bug fixed upstream, even if not backported to the target) is
  **ineligible**. Do not spend exploit work on upstream-fix-stream bugs.
- Duplicates: same root cause across multiple patches = one submission.
  Check #kernelctf Discord before submitting if unsure.

**Strategy that follows:** the upstream fix stream (diffing mainline stable
against the target) produces 1-days only. The winning input must be a bug
with **no upstream fix** — i.e. found on the target itself. The syzkaller
discovery lane on `fuzzer` (`zeroverse-kernelctf-discovery.service`, config
`/root/syz/kernelctf-6.12.98-kasan.cfg`) is the correct source. A new crash
bucket is only worth exploit work after the eligibility gate passes:
`grep upstream for a fix commit` + `check no public disclosure`.

**Proven pipeline (do not re-derive):** release detection → exact-target
build (published `.config`/`COMMIT_INFO` in GCS) → config-gate filter
(kernelCTF strips TCP_AO/SCTP/PHONET/IUCV/X25 — check `.config` before
investing) → KASAN+KCOV discovery kernel → syzkaller → hand reproducer →
nsjail server-flow validation (qemu_v3.sh, rootfs_v3.img, ramdisk_v1.img,
`/flag → /dev/vdb`). See playbook for exact commands and the server
environment.

**Hosts:** `fuzzer` runs discovery (do not kill its VMs — they respawn).
`bench` runs the arm64 Mali lane. The kernelCTF server is reached via
socat + `server_cert.pem`; the target's `.config`/`COMMIT_INFO` are public
in GCS before go-live (that is the prep window).

**Known outcome (learning, not a finding):** K-2026-0001 (proc
map_files NULL-mm panic, present in 6.12.98, fixed upstream 2024) is a
1-day → ineligible. It validated the whole pipeline but wins nothing.
Do not resubmit it.


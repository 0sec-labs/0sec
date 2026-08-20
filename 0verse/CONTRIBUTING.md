# Contributing to 0verse

Thanks for helping build an open, evidence-first binary bug-finder. This guide
covers the dev setup, the extension contracts, and the one rule that matters most.

## Rule #1 — PoV-is-truth (the only non-negotiable)

**A finding without a reproducing proof-of-vulnerability is a *hypothesis*, not a
finding.** This is the whole thesis of the project (see the README). Every
contribution must respect it:

- An LLM **never** decides whether a bug is real. Truth is decided by a
  deterministic, externally-checkable oracle (a crash under a sanitizer, a guard-page
  fault, a token-bound capability marker) — see `src/zeroverse/oracle.py`.
- `confirmed` is set **only** when a reproducing PoV is attached. A plausible lead is
  `hypothesis=true, confirmed=false` and is **never** silently promoted.
- If your bug class has no generic oracle yet, ship it as an honest
  **hypothesis-only** lens (like the `logic` class) — do not fabricate a confirmation.

A PR that marks something `confirmed` without a reproducing PoV will be sent back.

## Dev setup (Linux)

The supported development baseline is CPython 3.11 plus `uv` 0.11.2. OpenSSH's
`ssh-keygen` is required by signed-evidence contract fixtures. The committed
lockfile freezes Python dependencies; optional native engines remain separate,
explicitly gated capabilities.

```sh
git clone https://github.com/0sec-labs/0verse && cd 0verse
python -m pip install uv==0.11.2
uv sync --frozen --extra dev --python 3.11

uv run --frozen ruff check src tests
uv run --frozen mypy
uv run --frozen pytest -q -ra --basetemp="$HOME/.0verse-pytest-basetemp"
```

The core suite does not require network access, credentials, or a live analysis
target. Tests that need a compiler, a platform API, or an optional engine declare
and report their skip reason. The canonical inventory and current counts are in
[`docs/BASELINE.md`](docs/BASELINE.md).

The heavy engines (Ghidra, angr, AFL++, CASR, rizin) live behind extras and in the
Docker image. Engine stages are import-guarded and tests skip explicitly when a
required capability is absent. For the full pipeline:

```sh
uv sync --frozen --extra dev --extra ghidra   # + a host Ghidra (set GHIDRA_INSTALL_DIR)
pip install -e ".[analyze,symbolic,poc]"
docker run --rm -v "$PWD:/work" ghcr.io/0sec-labs/0verse run /work/target   # all engines
```

Ghidra is two pieces — the Java install *and* the `pyghidra` bridge that drives
it — and needs both. The `ghidra` extra declares the bridge; its version is pinned
to the Ghidra release the Docker image installs. Read
[`docs/GHIDRA-SETUP.md`](docs/GHIDRA-SETUP.md) before running any benchmark on a
host you provisioned yourself, and check what the host can actually do:

```sh
uv run --frozen python -c \
  "from zeroverse.backends import contract; print(contract.available_backends())"
```

Naming a backend is a demand, not a preference: `--backend ghidra` (or
`ZEROVERSE_BACKEND=ghidra`) exits non-zero when that backend cannot initialize,
rather than degrading. Only `auto` falls back.

Every PR must keep **`ruff` clean, `mypy --strict` clean, and `pytest` green.** New
behavior needs a test; new engine behavior needs a `benchmarks/` proof.

## The extension contracts

0verse is built so the common contributions are *additive* — implement an interface,
register it, add a test. The four high-value extension points:

### Add a bug-class lens (`src/zeroverse/bugclasses.py`)

A lens is a high-recall **hypothesis source**: `def <name>_lens(decompiled_c: dict)
-> list[Finding]`, tagging each `Finding` with `origin="bugclass:<id>"`. Register it
in the `_LENSES` tuple. Then either:

- add a **confirming oracle** (route `origin` through `bugclasses.confirm` and add it
  to `CONFIRMABLE_ORIGINS`) so a triggering input becomes a PoV, **or**
- leave it **hypothesis-only** (like `logic`) and document the confirmation gap.

Always add a `benchmarks/<class>.c` with a known bug and a test asserting the lens
surfaces it (and, if confirmable, a reproducing PoV).

### Add an ABI (`src/zeroverse/abi.py`)

Define an `Abi(...)` (arg registers, return register, return-address register,
pointer size, `qemu_user` / `afl_qemu_cpu` for cross-arch fuzzing, endianness) and
register it in `_BY_ARCH`, plus processor/`e_machine` spellings in `_ALIASES`. The
high-P-Code SSA slice carries over unchanged — the ABI is what the dynamic/firmware
lane needs. See `AAPCS64` / `MIPS_O32` for worked examples; add a `tests/test_abi.py`
case.

### Add a decompiler backend (`src/zeroverse/backends/`)

Implement the `DecompilerBackend` Protocol (`backends/contract.py`): `name`,
`available()` (probe the toolchain), and `analyze(binary) -> ProgramAdapter` (an
`ILAdapter` carrying `ProgramMeta` + per-function IL the slicer consumes). Register
it in `_backends()` in **preference order** (highest fidelity first). Be honest about
fidelity in the adapter's `note` — if you only recover pseudo-C (no SSA def-use, no
per-sink addresses), say so, and the angr reachability stage will skip for you. See
`rizin.py` / `cdecomp.py`. Add a `tests/test_backend_contract.py` case.

### Add a benchmark (`benchmarks/`)

Bug benchmarks are the project's ground truth. Add a `benchmarks/<name>.c` with a
known, reproducing bug and wire it into `benchmarks/run.sh` (the PoV-reproduction
gate). For the fuzzing comparison, add a target to
`benchmarks/fuzzbench/compare.py::TARGETS`; the results parse through
`zeroverse.benchmark` (schema-versioned). **Report honest numbers** — a tie or a
baseline win is a result, not a failure (see `docs/BENCHMARKS.md` and
`NEGATIVE-RESULTS.md`).

## Honesty hygiene

- **Negative results are first-class.** If a class doesn't confirm, a backend is
  lower-fidelity, or a benchmark ties baseline AFL++, record it in
  `NEGATIVE-RESULTS.md` (or let the `zeroverse.negative` emitter capture it).
- **No raw exploit bytes in the repo.** The labeled-PoV dataset (`docs/DATASET.md`)
  ships the *capture mechanism* + synthetic examples only; real corpora and crash
  payloads are out-of-tree by design and enforced by a test.
- **Don't over-claim in docs.** Match what the code actually does; flag degrades in
  the `note` field, never paper over them.

## Submitting

1. Branch from `main`; keep PRs focused.
2. `ruff check`, `mypy --strict`, and `pytest` all green; add tests.
3. Reference the issue / `ROADMAP.md` item. Good first issues are labelled and
   stubbed in [`docs/good-first-issues/`](docs/good-first-issues/).

By contributing you agree your work is licensed under Apache-2.0.

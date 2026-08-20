# Ghidra setup — the install, the bridge, and why both are declared (#296, #297)

> Status: 2026-07-29. Living document.

The Ghidra backend is two independent pieces, and a host needs both:

1. **Ghidra itself** — a Java application. Not pip-installable. Found through
   `GHIDRA_HOME` or `GHIDRA_INSTALL_DIR`.
2. **PyGhidra** — the CPython bridge (`pyghidra` + `jpype1`) that drives it
   in-process. Pip-installable, and now declared in the `ghidra` extra.

Having one without the other decompiles nothing. Before #296 only the first was
checked, so a box with Ghidra unpacked and `GHIDRA_HOME` exported reported the
backend as *available*, then degraded at analysis time. See "What this fixes"
below for why that mattered more than it sounds.

## Install

Inside the Docker image (`ghcr.io/0sec-labs/0verse`) both halves are already
present and nothing here applies. On a bare host:

```sh
# 1. Ghidra (once). Version must match the pyghidra pin below.
export GHIDRA_INSTALL_DIR=/opt/ghidra

# 2. The bridge, from the lock:
uv sync --frozen --extra dev --extra ghidra
```

Verify before trusting any result — an empty list here means Ghidra will not run:

```sh
uv run --frozen python -c \
  "from zeroverse.backends import contract; print(contract.available_backends())"
```

## The version pin, and why it is exact

`pyghidra` is version-locked to the Ghidra it drives. The pin in
`pyproject.toml` (`pyghidra==2.1.0`, `jpype1==1.5.2`) tracks `GHIDRA_VERSION` in
the `Dockerfile` — Ghidra 12.1.2 bundles exactly those two wheels under
`$GHIDRA_HOME/Ghidra/Features/PyGhidra/pypkg/dist/`. **Bump the pin and
`GHIDRA_VERSION` together.**

PyPI publishes the same artifacts Ghidra bundles
(`pyghidra-2.1.0-py3-none-any.whl` is the identical filename), which is the point
of pinning to the exact version rather than a floor. If you install the bundled
wheels by hand against a matching Ghidra:

```sh
uv pip install "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl \
               "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/jpype1-*.whl
```

…the installed versions satisfy the lock, so a later `uv run` (which syncs) sees
the requirement already met and leaves them alone. Undeclared, those same
hand-installed wheels were *removed* by the next `uv run` — the environment
regressed between invocations with no output saying so, which is what made this
worth declaring rather than documenting as a manual step.

`jpype1` is pinned for the same reason: `pyghidra` only requires `>=1.5.2`, so an
unpinned resolve silently upgrades the JNI bridge away from the version Ghidra
ships beside it.

## Running against a different Ghidra

Do not mix versions. Either move the pin to match your install and re-lock
(`uv lock`), or skip the extra and hand-install that install's own bundled wheels
— accepting that `uv sync` will then remove them, because they no longer match
the lock.

## What this fixes

On a bench box on 2026-07-28 a full magma run "completed" in 1.3 seconds and
reported 0/39 bug sites confirmed, with `ghidra=degrade` and 0s wall time per
target. `pyghidra` was simply missing. Nothing was analyzed, but the output was a
complete, well-formed results table — the same shape a genuine 0-confirm
capability result has.

Three changes make that state impossible to mistake for a measurement:

- `GhidraBackend.available()` probes the bridge, not just the environment
  variable, so a bridge-less host reports the backend as unavailable and `auto`
  falls through to rizin/angr instead of picking an engine it cannot start.
- An explicitly requested backend that cannot initialize exits non-zero
  (`--backend ghidra`, or `ZEROVERSE_BACKEND=ghidra`). `auto` is a preference and
  still degrades; naming a backend is a demand.
- `benchmarks/magma/run.py` refuses to write a result when any target has
  `ghidra_ok=false`, so a structural zero is never filed as a measured one.

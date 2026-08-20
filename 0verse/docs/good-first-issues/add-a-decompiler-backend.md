# Good first issue: add a decompiler backend

**Labels:** `good first issue`, `backend`, `M5`
**Difficulty:** ⭐⭐⭐ (advanced) · **Area:** `src/zeroverse/backends/`

## What

Add a new decompiler front-end behind the `DecompilerBackend` Protocol. Candidates:
**Hex-Rays/IDA** (license holders), **Binary Ninja HLIL** (the deferred
`backend:binja`), **RetDec**, or **Ghidra-over-GhidraMCP** as a remote backend.

## Why

Ghidra is the default, but the Protocol makes it replaceable. Each backend is a new
way to get IL into the slicer — and a fallback when a higher-fidelity toolchain is
unavailable. The honest-fidelity contract means a lower-fidelity backend is still
useful (slice + oracle still confirm).

## How

1. Implement the Protocol in `backends/<name>.py` (see `backends/contract.py`):
   - `name: str`
   - `available() -> bool` — probe the toolchain (don't import it at module top).
   - `analyze(binary) -> ProgramAdapter` — return an `ILAdapter` carrying
     `ProgramMeta` + per-function IL. Reuse `cdecomp.py` if you only have pseudo-C.
2. Register it in `_backends()` in **preference order** (highest fidelity first).
3. **Be honest about fidelity** in the adapter `note`: if you don't recover SSA
   def-use / per-sink addresses, the angr reachability stage will skip — say so.
4. Add a `tests/test_backend_contract.py` case (mock the toolchain; assert the
   adapter shape + that the slicer consumes it).

## Definition of done

- [ ] Backend implements the Protocol + registered in preference order.
- [ ] Fidelity degrade flagged honestly in `note`; `NEGATIVE-RESULTS.md` updated if
      it's a lower-fidelity backend.
- [ ] Contract test green; `ruff` + `mypy --strict` + `pytest` green.

See [CONTRIBUTING.md](../../CONTRIBUTING.md#add-a-decompiler-backend-srczeroversebackends).

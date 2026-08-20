# Good first issue: add an ABI

**Labels:** `good first issue`, `arch`, `M3`
**Difficulty:** ⭐ (starter) · **Area:** `src/zeroverse/abi.py`

## What

Teach 0verse a new processor calling convention. Good candidates: **PowerPC
(ppc/ppc64)**, **RISC-V (rv32/rv64)**, **SPARC**, **MIPS64 n64**. (`ppc`/`riscv`
already have *aliases* but no `Abi` — wiring one up is a clean, self-contained task.)

## Why

The high-P-Code SSA slice is arch-agnostic and carries over unchanged — the ABI is
the small missing piece the dynamic/firmware lane needs (which registers hold args,
the return register, the return-address register). One `Abi` unlocks a whole arch.

## How

1. Define an `Abi(...)` next to `AAPCS64` / `MIPS_O32`: `int_arg_regs`, `ret_reg`,
   `ra_reg`, `pointer_size`, `endian`, and `qemu_user` / `afl_qemu_cpu` for
   cross-arch QEMU-mode fuzzing.
2. Register it in `_BY_ARCH`, and add processor / ELF `e_machine` spellings to
   `_ALIASES` (resolve 32/64 ambiguity in `normalize_arch` if needed).
3. Add a `tests/test_abi.py` case: `abi_for("<spelling>", bits)` returns your `Abi`.

## Definition of done

- [ ] `Abi` defined + registered in `_BY_ARCH` + `_ALIASES`.
- [ ] `tests/test_abi.py` resolves the new arch from its common spellings.
- [ ] `ruff` + `mypy --strict` + `pytest` green.

See [CONTRIBUTING.md](../../CONTRIBUTING.md#add-an-abi-srczeroverseabipy).

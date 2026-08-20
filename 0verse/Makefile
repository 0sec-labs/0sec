# 0verse dev tasks. Uses uv for a reproducible env: `make setup` once, then
# `make check` (lint + types + tests). No global installs.
#
# The lightweight gate (`make check`) runs anywhere. The authoritative PoV-repro
# gate (`make benchmark`) needs the full engine toolchain and runs in Docker.

.PHONY: setup test lint typecheck check baseline fmt clean benchmark proof-angr proof-m2 proof-m4

PYTEST_BASETEMP ?= $(HOME)/.0verse-pytest-basetemp

setup:
	uv sync --frozen --extra dev --python 3.11

test:
	uv run --frozen --extra dev pytest -q -ra --basetemp="$(PYTEST_BASETEMP)"

lint:
	uv run --frozen --extra dev ruff check src tests

typecheck:
	uv run --frozen --extra dev mypy

fmt:
	uv run --frozen --extra dev ruff check --fix src tests

check: lint typecheck test

# Reproduce the R0 contract. tests/test_r0_baseline.py binds the committed
# baseline record to its benchmark artifact and toolchain inventory.
baseline: check

# #9 — authoritative PoV-reproduction gate: build the engine image (Ghidra + angr
# + AFL++) and assert every planted corpus bug still reproduces with a PoV.
benchmark:
	docker build -t 0verse:local .
	docker run --rm -v "$(PWD):/work" --entrypoint bash 0verse:local /work/benchmarks/run.sh

# M2 — prove fuzzing finds a bug the static slice MISSES: synthesize a harness
# for a target function, AFL++/CMPLOG past a magic gate, differential-allocator
# oracle -> PoV, native replay. Needs AFL++ + cc (Ghidra optional for Part A).
proof-m2:
	uv run python benchmarks/m2_proof.py

# #5 — prove angr prunes a false hypothesis AND concretizes a witness (needs the
# symbolic extra: `uv pip install -e ".[symbolic]"`).
proof-angr:
	uv run python benchmarks/angr_proof.py

# M4 — prove the five new bug classes: each static lens flags a true positive, and
# the confirmable classes (intoverflow / fmtstring / uaf / double-free / cmdi)
# produce a reproducing PoV via their oracle; the logic class stays an honest
# hypothesis (no false PoV). Needs a C compiler (builds the quarantine guard .so).
proof-m4:
	uv run python benchmarks/m4_proof.py

clean:
	rm -rf .venv .pytest_cache .ruff_cache .mypy_cache **/__pycache__

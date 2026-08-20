# CI: benchmark PoV-repro gate (#9)

The heavy, authoritative gate lives at
`.github/workflows/benchmark-gate.yml`: it builds the engine image, runs the
corpus, and asserts N/N PoV-confirmed.

The lightweight `ruff`/`mypy`/`pytest` gate in `.github/workflows/ci.yml` also
runs on every push. The authoritative gate is runnable locally any time via
`make benchmark` (builds the Docker image and runs `benchmarks/run.sh`), which is
the source of truth.

# R0 reproducible baseline

This is the starting contract for Firmware Scout work. It records what 0verse can
prove today, which checks are portable, and which capabilities are absent from the
core development profile. The machine-readable record is
[`baselines/r0-2026-07-17.json`](baselines/r0-2026-07-17.json).

## Supported development profile

The canonical core profile is Linux x86-64, CPython 3.11, `uv` 0.11.2, and the
committed `uv.lock`. The current self-hosted runner does not attest its Linux
distribution, so the record does not invent one. OpenSSH's `ssh-keygen` is required
by the signed-evidence contract tests. A C compiler is useful but optional: tests
that need one skip with an explicit reason when it is absent.

```sh
python -m pip install uv==0.11.2
uv sync --frozen --extra dev --python 3.11
make baseline
```

`make baseline` runs Ruff, strict mypy, and `pytest -q -ra` from the frozen
environment. It does not install Ghidra, angr, AFL++, Qiling, binwalk, rizin,
cross-compilers, or a native extension. It does not use network credentials or
contact an LLM provider. Pytest artifacts go to a user-owned path outside the
checkout so custody tests avoid `/tmp` while corpus guards never scan test output.

The audited main revision is `d9a5749fa35e776e9f845caa6bbb7d65f09863ac`.
On that revision:

| Profile | Result | Runtime | Evidence |
|---|---:|---:|---|
| Self-hosted Linux x86-64 / Python 3.11 | 1,915 passed, 32 skipped | 129.38 s | [GitHub Actions run 29575018450, attempt 2](https://github.com/0sec-labs/0verse/actions/runs/29575018450), `check` job |
| Docker PoV-reproduction gate | 3 / 3 passed | 44 s job | [GitHub Actions run 29575018416](https://github.com/0sec-labs/0verse/actions/runs/29575018416), `corpus` job |
| Pinned Ghidra Windows-IOCTL E2E | passed | 25 s job | run 29575018450, `windows-ioctl-ghidra-e2e` job |
| Windows trust and native-token jobs | unavailable | no steps ran | same run; GitHub reported a billing or spending-limit failure before setup |
| macOS 26.5.2 / Python 3.11 portability observation | 1,910 passed, 40 skipped | 136.00 s | local rebased branch, including three baseline-contract tests |

The first Linux core attempt could not clean pre-existing root-owned bytecode from
its self-hosted workspace. Attempt 2 ran on a clean worker and passed checkout,
Ruff, strict mypy over 131 source files, pytest, and the checkout-ownership guard.

The difference in pass/skip counts is expected: Linux ELF and procfs tests execute
on the Linux runner and skip on macOS. A skip is not a pass. `pytest -ra` keeps the
reason visible in every new run. Windows is not claimed green for the audited
revision because the hosted jobs never started. The machine record retains the
last-known-green July 14 contract run as historical evidence only.

## Toolchain-gated tests

The JSON record inventories the exact test files and skip reasons. The gates are:

| Capability | Core profile | Test behavior when absent |
|---|---|---|
| C compiler and Linux ELF execution | compiler is runner-provided; Linux is canonical | native oracle, patch, fleet, and seed-enrichment proofs skip |
| clang AddressSanitizer | optional | live ASan proofs skip; report-parser contracts still run |
| angr | not installed | concolic live proof skips; pure contracts still run |
| AFL++ | not installed | live directed-fuzz proof skips; orchestration contracts use fakes |
| Qiling | not installed | live firmware confirmation skips; fake-backend contracts run |
| binwalk | not installed | live firmware carving test skips |
| rizin/r2ghidra | not installed | live fallback and scheduler proof skip |
| Rust/PyO3 native extension | not built | native-only tests skip; Python fallback runs |
| Windows trust APIs and SDK tools | separate Windows job | producer tests skip on non-Windows hosts |
| Linux procfs supervisor contract | Linux-only | skips on non-Linux hosts |
| GCC/GDB container patch predicate | optional Docker toolchain | live predicate proofs skip without it |
| Private Vid.sys/PDB + Ghidra fixture | private, exact-pair gate | live IOCTL benchmark skips without the pair |

OpenSSH signing is a required local contract dependency, not an optional engine.
Tests now skip clearly if `ssh-keygen` is unavailable instead of failing with an
opaque `FileNotFoundError`.

## Benchmark snapshot

The R0 benchmark is the committed 14-item deterministic MockLLM regression floor
at [`benchmarks/groundtruth/results.json`](../benchmarks/groundtruth/results.json),
bound by SHA-256 in the machine record. It is deliberately marked
`capability_measure=false`; it tests pipeline and oracle regressions, not current
LLM quality. The separate three-item Docker gate also passed at the audited
revision; it proves the planted PoVs still reproduce but does not replace or
refresh the 14-item snapshot.

| Metric | R0 value |
|---|---:|
| Vulnerable items located | 9 / 9 (100%) |
| Vulnerable items with confirmed PoV | 6 / 9 (66.67%) |
| Clean items with a confirmed false positive | 0 / 5 (0%) |
| Clean items with a hypothesis-level false positive | 3 / 5 (60%) |
| Confirmed-finding precision | 100% |
| Recorded wall time | 286.0 s |

Hypothesis-level false positives are retained because hiding them would make the
baseline less useful. The benchmark was produced with a full analysis environment.
The core profile alone cannot regenerate it because its Ghidra/native confirmation
toolchain is separate; the dedicated CI Ghidra E2E proves a narrower Windows IOCTL
contract, not this whole 14-item benchmark. Use the Docker benchmark profile to
refresh it, then update its digest and metrics together.

## Firmware Scout boundary

The audited baseline revision had firmware format/ABI logic and optional
Qiling/binwalk hooks, but no acquisition contract or live hardware path. The R0
follow-on now defines the hardware-free
[`AcquisitionManifest` and safety boundary](FIRMWARE-SCOUT-SAFETY.md), bundle
intake, offline firmware inspection, and deterministic Scout evidence replay.

The #78 follow-on adds an optional library-only, receive-only classical-CAN
SocketCAN adapter, but no hardware acceptance has run: it remains gated on an
authorized Linux interface. ISO-TP transport, UDS discovery, an ECU profile, and
a hardware-backed dump path remain unavailable capabilities, not implicit promises.

## Updating the baseline

1. Regenerate `uv.lock` intentionally with `uv lock`; never let CI resolve a new
   dependency graph implicitly.
2. Run `make baseline` on the supported Linux profile; request the Windows contract
   job and record it as unavailable if no steps execute.
3. Refresh the ground-truth artifact only in the documented benchmark environment.
4. Update the JSON evidence, artifact hash, metrics, skip inventory, and this page
   in the same change.

`tests/test_r0_baseline.py` rejects stale benchmark hashes, copied metrics, missing
test paths, empty skip reasons, and an accidental capability claim.

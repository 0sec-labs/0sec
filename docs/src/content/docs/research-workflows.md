---
title: Research Workflows
description: Which 0sec research command solves which task, their input/output contracts, scope and verification boundaries, evidence tiers, and paths to specialized references.
---

0sec ships a family of research commands for vulnerability discovery, each tuned
to a different problem shape — seeded variant search, seedless depth review,
recency-window hunting, assumption mining, spec conformance drift, protocol
differential, memory-safety fuzzing, kernel-specific workflows, binary analysis,
weaponization, agent-action assurance, and self-evolving detection.

Discovery leads are not proof of exploitability. Some commands also execute
targets or validate imported evidence; inspect the specific verifier result,
execution origin, and retained artifacts before making a disclosure claim.

## Quick reference

| Task | Command | Seed required | Target type | Output |
|---|---|---|---|---|
| Variant hunt from a fix | `hunt --seed` | Yes (fix diff) | Source tree | LEADS (skeptic-gated) |
| Seedless depth review | `deep-review` | No | Source tree (git URL or path) | LEADS (multi-lens quorum) |
| Recency-window kernel hunt | `recency-hunt` | No (`--since` / `--hours`) | Kernel tree | LEADS (invariant-engine gated) |
| Assumption mining | `assumption-hunt` | No (`--files`) | Source tree | CANDIDATES to disprove |
| Spec vs implementation drift | `specdrift` | No (`--spec`) | Spec text + source tree | Invariant mappings / drift hypotheses |
| HTTP protocol conformance | `protocol-check` | No (`--spec` + `--impl`) | Live HTTP target | Confirmed/refuted divergences |
| Memory-safety fuzz | `memsafety` | No | Source tree (git URL or path) | Reproduced mem-corruption findings |
| Kernel advisory variant | `kernel variant-hunt` | Advisory URL | Kernel tree | Foxguard-gated variant candidates |
| Syzbot LPE mining | `kernel syzbot-mine` | No | syzbot | Ranked exploitability candidates |
| Syzkaller weights | `kernel weights` | No | kernelCTF target | LLM-derived `choice_weights.json` |
| XNU IOKit fuzzing | `xnu-fuzz` | No (kext) | Kext Mach-O | Target model / gate-passing inputs |
| Binary analysis | `binary` | No | Compiled artifact | Delegated to 0verse |
| Weaponization | `exploit` | Confirmed finding | Kernel VM | Exploit rung / root proof |
| Agent-action assurance | `agent-assure` | No | Agent + MCP endpoints | Evidence bundle |
| Self-evolving lenses | `lens-synth` | No (miss-input) | Curated misses | Promoted finder lenses |
| Source evolution | `evolve run` | No (config) | Source snapshot | Promoted candidate versions |
| Research pipeline | `research pipeline` | No | URL/path/repo/package | Evidence-backed findings |
| Research mobile | `research mobile` | No | APK/IPA | Passive indicators |
| Research Linux kernel | `research linux` | Reproducer + finding | Kernel tree | N-boot verified evidence |

## Evidence tiers

Keep three questions separate: what was hypothesized, what was observed, and
who executed the target. A skeptic vote or finder quorum is not a reproduced
crash. A retained HTTP observation is not proof of a kernel privilege boundary.
Imported boot logs can pass validation without 0sec having executed those boots.

The shared research plane uses grades including `candidate`, `observed`, and
`reproduced`; native commands also have their own result fields. These are not
one universal three-tier schema. See [Verification Results](/verification-result/)
for the separate deterministic replay contract and [Kernel VM Verification](/kernel-vm/)
for privilege/provenance limits.

## Input and artifact contracts

`0sec research` subcommands accept `--artifact-root` (default `.0sec-research`).
Other research commands have their own `--output`, artifact-retention, and
cache options; do not assume they share one directory layout or accept
`--artifact-root`. The [command reference](/commands/) lists each contract.

Keep result JSON alongside its referenced logs, inputs, and receipts. A copied
summary without its referenced evidence is not a replayable evidence bundle.
Source excerpts, crash logs, headers, and findings may contain sensitive data.
Review them before committing or uploading artifacts.

### Environment variables

Provider configuration belongs in [API Keys](/api-keys/) and
[Configuration](/configuration/). For kernel execution, follow the VM guide's
exact `0SEC_KERNEL_QEMU_*` setup; a source checkout alone is not a bootable guest.

Names beginning with a digit cannot be assigned using POSIX `export`. Pass
them through `env`, for example:

```bash
env 0SEC_DEEP_REVIEW_MAX_CANDIDATES=16 0sec deep-review ./target-repo
```

## Scope and host-execution boundaries

- Run only on targets you own or are authorized to test. Scope enforcement is
  command-specific; these commands do not all accept the scan command's
  `--scope`. See [Scope](/scope/) for the exact covered entry points.
- `protocol-check` performs live HTTP requests. `agent-assure` interacts with
  agent, MCP, and oracle endpoints and requires all three in its scope file.
- `memsafety` invokes build and fuzz tooling. `binary` delegates to a local
  subprocess. Use an isolated, disposable worker for untrusted source or binaries;
  neither an output directory nor a model's instructions constitute a sandbox.
- Kernel verification and dynamic-witness paths require real VM tooling.
  QEMU guests have their own kernel; host mounts and networking still depend
  on the selected runner. Do not infer isolation guarantees from the word “VM.”
- `evolve` evaluates source candidates in credential-free, network-none Docker
  containers. `lens-synth` manages prompt lenses; it is not the same execution
  boundary. See [Improvement Plane](/improvement-plane/).
- Research commands can write models, caches, build products, and configured
  outputs. Artifact directories do not constrain all host filesystem writes.

## Offline import vs actual execution

| Workflow | What it actually does |
|---|---|
| `specdrift extract`, `scan`, `plan` | Model-assisted spec extraction and source mapping; not live protocol verification |
| `research mobile` | Passive extracted APK/IPA intake; indicators remain hypotheses |
| `research linux-matrix` | Validates and hashes externally executed boot logs; does not boot a VM |
| `research linux` | Executes a supplied reproducer through the N-boot verification gate |
| `protocol-check` | Exercises hypotheses against a live HTTP target |
| `memsafety` | Runs native build/fuzz tooling; unavailable prerequisites are a skipped run, not a pass |
| `xnu-fuzz harness-plan` | Emits a VM harness plan; does not execute the plan |
| `exploit` modes | Select distinct weaponization runners; see their execution prerequisites below |

Importing evidence is not fresh execution. Conversely, an “analysis” command
that launches a compiler, fuzzer, agent, or external binary is not passive intake.

## Seed-driven variant hunting (`hunt`)

The oldest and most structured research path. Takes a proven fix diff
(`--seed .patch`) and a source tree (`--source`), generates variant candidate
sites from the fix, fans finders out over them, and gates each finding through
an adversarial skeptic.

```bash
0sec hunt \
  --source /root/linux-6.12.93 \
  --seed ./nfc-fix.patch \
  --ref CVE-2025-XXXXX \
  --concurrency 4 \
  --max-candidates 40
```

### Required flags

| Flag | Description |
|---|---|
| `--source <path>` | Source tree to hunt in (e.g. a Linux checkout) |
| `--seed <path>` | Fix diff / `.patch` whose bug class to hunt variants of |

### Key optional flags

| Flag | Default | Description |
|---|---|---|
| `--ref <name>` | — | Provenance label for the seed (e.g. CVE / commit) |
| `--concurrency <N>` | 4 | Max finders in flight |
| `--max-candidates <N>` | 40 | Cap candidate sites hunted |
| `--skip-candidates <N>` | 0 | Skip the first N ranked candidates |
| `--models <a,b>` | Provider default | Comma-separated finder models for diversity |
| `--reachable-only` | env `HUNT_REACHABLE_ONLY` | Restrict to kernelCTF-reachable paths |
| `--reachable-prefer` | env `HUNT_REACHABLE_PREFER` | Sort reachable first, drop none |
| `--no-verify` | — | Skip skeptic gate (triage only, never disclosure) |
| `--novelty` | — | Require lore.kernel.org duplicate suppression |
| `--methodology` | — | kernel-LPE methodology preset |

**Lens flags:**

| Flag | Description |
|---|---|
| `--invariant` | Load subsystem's stored invariant model; inject rules into finders |
| `--graph-slice` | Load Joern CPG reachability slice around fix site into finders |
| `--cpg <path>` | Explicit CPG graphson JSON path for `--graph-slice` |
| `--ops-harvest <paths>` | Static ops-struct initializer harvest for `--graph-slice` |
| `--graph-slice-hops <N>` | Call-graph radius (default 3) |

**Prove flags (require kernel-VM artifacts):**

| Flag | Description |
|---|---|
| `--exploitability` | Run GREBE diversify + SCAVY differential on QEMU VMs for each confirmed finding |
| `--prove-min-ceiling <ceiling>` | Minimum impact ceiling: `dos-only` / `info-leak` / `oob-write` / `uaf-control` (default `info-leak`) |

**Exit codes:** 0 = lead(s) found, 1 = no leads, 2 = no candidates, 3 = error.

Output is JSON with funnel counts (candidates → scanned → found → confirmed),
per-finding evidence, and active warnings.

For the exhaustive flag reference, see [Commands — hunt](/commands/#hunt).

---

## Seedless depth review (`deep-review`)

The "depth method": enumerates candidate files from a prepared source tree,
re-hunts each through specialized finder lenses, and gates survivors through a
multi-lens verify quorum. No seed fix required.

```bash
0sec deep-review ./target-repo --max-candidates 16 --profile default
```

### Profiles

| Profile | Lenses | Target code |
|---|---|---|
| `default` | Generic, stack-aware finder lenses plus appsec overlays | General source review |
| `evm-onchain` | Bespoke Solidity lens set | Solidity, Foundry, Hardhat projects |
| `solana-onchain` | Bespoke Rust/Anchor lens set | Solana Rust programs |
| `cardano-onchain` | Bespoke Haskell lens set | Cardano (Haskell) smart contracts |
| `cairo-onchain` | Bespoke Cairo lens set | Starkware Cairo contracts |
| `move-onchain` | Bespoke Move lens set | Move (Aptos/Sui) contracts |

### Verify quorum

Findings pass through the selected profile's independent refutation lenses.
`--quorum` controls the voting threshold; the default is a majority of that
profile's verify lenses. The generic profile covers these checks:

| Lens | Refutes when |
|---|---|
| `reachability` | Vulnerable code is unreachable from any public API |
| `completeness` | The "missing" check is enforced elsewhere on the path |
| `novelty-known-issue` | Standard guard for this class is already present |
| `scope` | Exploitation has no real impact |
| `deployment-context` | Code path is dev/test/build-only, not production |

### Key flags

| Flag | Default | Description |
|---|---|---|
| `--profile <p>` | `default` | Lens profile (evm/solana/cardano/cairo/move) |
| `--subsystem <path>` | — | Narrow to a subdirectory |
| `--max-candidates <N>` | 8 (auto-scales to 20 for large repos) | Cap candidates hunted |
| `--models <a,b>` | Single provider model | Finder model diversity |
| `--attempts <N>` | 1 | Best-of-N attempts per candidate×lens×model |
| `--concurrency <N>` | 8 | Max finders in flight |
| `--quorum <N>` | Majority | Verify lens quorum threshold |
| `--threat-model` | Off | Enable pre-scan threat-model planner (trust-boundary lanes) |
| `--evolution-config <path>` | — | Use evolved source finder with private execution receipts |
| `--cost-ceiling <usd>` | — | Hard scan-wide USD ceiling |

**Exit codes:** 0 = sweep completed (with or without leads), 2 = skipped (no
files or review cap exceeded), 3 = error.

See [Commands — deep-review](/commands/#deep-review) for the full flag reference
and [Improvement Plane](/improvement-plane/#deploying-an-evolved-source-finder)
for the evolution-config path.

---

## Recency flywheel (`recency-hunt`)

Continuous kernel-LPE discovery on the linux-next freshness window.

Pipeline: `git-diff range` → reachability filter → semantic-vs-cosmetic
classifier → refined invariant engine → adversarial verify → ranked report.

```bash
# Last 24 hours, default detectors (dataflow + refcount + race)
0sec recency-hunt --tree /root/linux-next

# Explicit git range with dynamic witness (KASAN VM boots)
0sec recency-hunt \
  --tree /root/linux-next \
  --since HEAD~48..HEAD \
  --model gpt-5.5 \
  --detectors dataflow,refcount,race,dual-view \
  --dynamic-witness \
  --witness-candidates 5

# Scheduler mode: write dated reports to a directory
0sec recency-hunt \
  --tree /root/linux-next \
  --hours 24 \
  --report-dir /var/reports/recency
```

### Key flags

| Flag | Default | Description |
|---|---|---|
| `--tree <path>` | — | Kernel source tree (required) |
| `--since <range>` | — | Git range (e.g. `HEAD~20..HEAD`); overrides `--hours` |
| `--hours <N>` | 24 | Hunt last N hours |
| `-m, --model <model>` | — | Model-build / finder model override |
| `--classifier-model <model>` | `gpt-5.5` | Semantic-vs-cosmetic classifier |
| `--max-hunt-files <N>` | 25 | Cap files run through the engine |
| `--detectors <list>` | `dataflow,refcount,race` | Detectors per semantic file. `dual-view` is opt-in |
| `--dynamic-witness` | Off | KASAN VM boot oracle (implies `dual-view`). Expensive |
| `--report-dir <dir>` | — | Write dated YYYY-MM-DD.{json,md} reports |
| `--remine-assumptions` | Off | Force fresh assumption mine each run |

**Detector types:**

| Detector | Description |
|---|---|
| `dataflow` | Static dataflow violation scanning on the invariant model |
| `refcount` | Interprocedural refcount-underflow / double-put analysis |
| `race` | Concurrency-race smell detection |
| `dual-view` | Assumption-mining dual-api/cross-phase enumerator; `--dynamic-witness` enables VM execution and implies this detector |

**Exit codes:** 0 = survivor(s), 1 = ran but no survivors, 2 = empty window,
3 = error.

---

## Assumption mining (`assumption-hunt`)

The fourth seedless discovery axis. Mines implicit relied-on preconditions each
function makes and hunts reachable callers that reach a relied-on subject without
establishing its precondition — the DirtyCred / AF_UNIX-GC / io_uring shape
fixed-schema checkers structurally cannot represent.

Pipeline: `LLM mine` → `AssumptionModel` → 1b enforced/relied cross-check
(no LLM) → establisher-propagation caller-scan (no LLM) → `runHuntScan` with
skeptic gate.

```bash
# Basic run: mine assumptions in net/unix, scan callers
0sec assumption-hunt /root/linux-6.12.93 \
  --files net/unix/af_unix.c,net/unix/garbage.c \
  --subsystem net/unix

# With dynamic witness (KASAN VM boots for dual-view candidates)
0sec assumption-hunt /root/linux-6.12.93 \
  --files net/unix/af_unix.c \
  --subsystem net/unix \
  --dynamic-witness \
  --witness-candidates 5

# Stop after deterministic caller-scan (no LLM finder/skeptic gate)
0sec assumption-hunt /root/project \
  --files src/main.c \
  --skip-hunt
```

### Required flags

| Flag | Description |
|---|---|
| `<source-root>` | Local source tree the subsystem files live under |
| `--files <a.c,b.c>` | Comma-separated repo-relative subsystem source files |

### Key optional flags

| Flag | Description |
|---|---|
| `--subsystem <label>` | Label for the stored model (e.g. `net/unix`) |
| `--remine` | Force fresh LLM mine even if stored model exists |
| `--skip-hunt` | Stop after deterministic caller-scan (no LLM finder/skeptic gate) |
| `--no-verify` | Run finder fan-out but skip skeptic gate |
| `--models <a,b>` | Comma-separated finder/mine models |
| `--max-contexts <N>` | Cap violating contexts fed to the hunt |
| `--no-wrapper-resolution` | Disable v1 establisher-wrapper resolution (reproduces v0) |
| `--no-finder-targeting` | Feed finder the whole file instead of per-function excerpts |
| `--no-dual-view` | Disable dual-api/cross-phase enumerator (v1 behavior only) |
| `--dynamic-witness` | Route dual-view candidates to KASAN VM boot oracle |
| `--excerpt-dir <path>` | Where finder-targeting excerpts are written |

**Funnel output:**

```json
{
  "funnel": {
    "mined": 45,
    "kept_1b": 32,
    "dropped_1b": 13,
    "violating_contexts": 8,
    "dual_view_contexts": 3,
    "confirmed": 1
  }
}
```

**Exit codes:** 0 = pipeline ran (with or without a candidate), 3 = error.

---

## Spec/conformance drift (`specdrift`)

Extract cited protocol invariants from an arbitrary spec text file and map them
to candidate implementation code.

### Subcommands

#### `extract`

Extract invariants only (no source tree needed):

```bash
0sec specdrift extract \
  --spec ./rfc-9110-excerpt.txt \
  --max-invariants 40 \
  --output invariants.json
```

#### `scan`

Extract invariants and map them to implementation code:

```bash
0sec specdrift scan \
  --spec ./rfc-9110.txt \
  --source /path/to/http-server \
  --max-files 400
```

#### `plan`

Extract invariants, map candidates, and emit drift hypotheses:

```bash
0sec specdrift plan \
  --spec ./rfc-9110.txt \
  --source /path/to/http-server \
  --max-hypotheses 20
```

### Key flags

| Flag | `extract` | `scan` | `plan` |
|---|---|---|---|
| `--spec <path>` | Required | Required | Required |
| `--source <path-or-url>` | — | Required | Required |
| `--max-invariants <N>` | 40 | 40 | 40 |
| `--max-files <N>` | — | 400 | 400 |
| `--max-candidates-per-invariant <N>` | — | 5 | 5 |
| `--max-hypotheses <N>` | — | — | 20 |

See [Commands — specdrift](/commands/#specdrift).

---

## Protocol conformance check (`protocol-check`)

Reads spec + implementation source excerpts, hypothesizes where the
implementation diverges from the spec, then exercises each hypothesis against
a live target with a deterministic oracle.

```bash
0sec protocol-check \
  --spec ./rfc-9110-excerpt.txt \
  --impl ./server-parse.c \
  --target http://127.0.0.1:8080 \
  --json
```

### Required flags

| Flag | Description |
|---|---|
| `--spec <file>` | Authoritative specification excerpt |
| `--impl <file>` | Implementation source excerpt |
| `--target <url>` | Base URL of the live target |

### Key optional flags

| Flag | Default | Description |
|---|---|---|
| `--json` | — | Emit full result as JSON on stdout |
| `--max-exercises <N>` | 8 | Cap hypotheses exercised against target |
| `--runtime <runtime>` | `auto` | LLM runtime |
| `--protocol <name>` | `HTTP/1.1` | Protocol name for the report |
| `--spec-version <version>` | `RFC 9110` | Spec edition |
| `--spec-ref <ref>` | — | Auditable spec citation |

**Exit codes:** 0 = confirmed divergence(s), 1 = ran, no divergences,
2 = no validated model, 3 = error.

Only MUST-level violations backed by a concrete observation are reported as
`confirmed`. See [Commands — protocol-check](/commands/#protocol-check).

---

## Memory-safety fuzz (`memsafety`)

Clone a source tree, auto-detect the build system and language, build a
sanitizer/fuzz harness, run a closed fuzz loop, and emit crashed findings.

```bash
# C/C++ with CMake
0sec memsafety https://github.com/user/repo.git --fuzz-timeout 120

# Rust with cargo-fuzz
0sec memsafety /path/to/rust-crate --language rust --miri

# Narrow to a subdirectory with artifact retention
0sec memsafety /path/to/repo \
  --subsystem src/network \
  --artifact-dir ./memsafety-evidence \
  --artifact-max-bytes 4194304
```

### Language and build system detection

Auto-detected from marker files in the source root:

| Language | Marker file |
|---|---|
| Rust | `Cargo.toml` |
| C/C++ CMake | `CMakeLists.txt` |
| C/C++ Autotools | `configure.ac` or `Makefile.am` |
| C/C++ Meson | `meson.build` |
| C/C++ Make | `Makefile` |

Override with `--language c|cpp|rust` and `--build-system cargo|cmake|autotools|meson|make`.

### Key flags

| Flag | Default | Description |
|---|---|---|
| `--subsystem <path>` | — | Narrow scan root to a subdirectory |
| `--language <lang>` | Auto-detected | Force: `c`, `cpp`, or `rust` |
| `--build-system <sys>` | Auto-detected | Force: `cargo`, `cmake`, `autotools`, `meson`, `make` |
| `--harness <name>` | — | libFuzzer / cargo-fuzz harness target |
| `--fuzz-dir <path>` | — | Non-standard cargo-fuzz directory |
| `--miri` | false | Run `cargo +nightly miri` for UB detection |
| `--fuzz-timeout <sec>` | 60 | Fuzz wall-clock budget |
| `--artifact-dir <path>` | — | Persist crash evidence outside source tree |
| `--artifact-max-bytes <bytes>` | 4194304 | Aggregate byte ceiling for retained evidence |

**Exit codes:** 0 = loop completed (with or without crashes), 2 = skipped
(no build system or execution prerequisite unavailable), 3 = error.

See [Commands — memsafety](/commands/#memsafety).

---

## Kernel workflows (`kernel`)

Three subcommands for Linux kernel-specific workflows:

### `kernel syzbot-mine`

Mine and LPE-rank syzbot's invalid/auto-closed queue for kernelCTF-eligible
candidates:

```bash
0sec kernel syzbot-mine \
  --subsystems net,net/sched,xfrm \
  --limit 30 \
  --details 15
```

### `kernel variant-hunt`

Foxguard-backed advisory variant hunting:

```bash
0sec kernel variant-hunt \
  --tree /root/linux-6.12.93 \
  --advisory ./advisory.txt \
  --rules rules/kernel/dirty-frag-class \
  --foxguard /usr/local/bin/foxguard \
  --output json
```

Or reuse an existing Foxguard SARIF:

```bash
0sec kernel variant-hunt \
  --tree /root/linux-6.12.93 \
  --sarif-input ./foxguard-results.sarif \
  --output terminal
```

### `kernel weights`

Generate LLM-derived `choice_weights.json` for syzkaller on a kernelCTF target:

```bash
0sec kernel weights \
  --target 6.12.101 \
  --crash-summary ./recent-crashes.txt \
  --max-entries 48 \
  --out choice_weights.json
```

See [Commands — kernel](/commands/#kernel).

---

## XNU IOKit fuzzer (`xnu-fuzz`)

Three-part workflow for IOKit user-client fuzzing on macOS. Operates
offline (model + generate locally); the VM run lane requires an Apple Silicon
macOS VM.

### `enumerate` — kext → target model

```bash
0sec xnu-fuzz enumerate \
  --kext ./IOSurface.kext \
  --bundle com.apple.iokit.IOSurface \
  --out target-model.json
```

### `gen` — model → gate-passing inputs

```bash
0sec xnu-fuzz gen \
  --model target-model.json \
  --seed 42 \
  --json
```

### `harness-plan` — VM run plan

```bash
0sec xnu-fuzz harness-plan \
  --golden "<golden-macos-vm>" \
  --oracle kasan
```

See [Commands — xnu-fuzz](/commands/#xnu-fuzz).

---

## Binary analysis (`binary`)

Delegates to the in-repo 0verse engine (Python, `uv run --frozen 0verse`):

```bash
# Triage a compiled ELF
0sec binary ./target.elf --mode triage

# Run full scan with a specific backend
0sec binary ./target.elf --mode scan --backend ghidra

# Forward extra args to 0verse
0sec binary ./target.elf --mode triage -- --format ndjson
```

### Modes

| Mode | Description |
|---|---|
| `triage` | Quick triage of the artifact |
| `run` | Run analysis |
| `scan` | Full scan |

### Backend options

| Backend | Description |
|---|---|
| `rizin` | Rizin-based analysis |
| `ghidra` | Ghidra headless analysis |
| `angr` | angr symbolic analysis |

Requires `uv` on PATH and the `0verse/` directory present in the repo.
See [Commands — binary](/commands/#binary).

---

## Weaponization (`exploit`)

Takes a confirmed kernel memory-safety finding, classifies the exploitation
primitive, and runs the escalation ladder through the kernel-VM harness.

Without the required kernel-VM artifacts, the default weaponization harness
can return skipped (exit 2). This is not a promise that every mode is static
or harmless on a provisioned host.

```bash
# Default weaponization runner (requires its kernel-VM prerequisites)
0sec exploit --finding ./finding.json --reproducer ./repro.c

# Engine-driven root climb with real QEMU boots
0sec exploit --finding ./finding.json --climb --loop-boots 8 \
  --vmlinux ./vmlinux --freed-struct snd_rawmidi_runtime

# Autonomous LLM-composed weaponization
0sec exploit --autoclimb \
  --bug-spec ./bug-spec.json \
  --boot-script ./boot.sh

# Agentic weaponization loop (model gets a shell)
0sec exploit --agent \
  --task ./vuln-description.json \
  --container my-exploit-env \
  --flag-pattern '^flag\{'
```

### Modes

| Mode | Flag | What it does |
|---|---|---|
| Default | (none) | Classify the primitive and invoke the weaponization runner; not a static-only switch |
| Engine climb | `--climb` | REAL verify→weaponization chain, loop boots until root oracle credits |
| Autoclimb | `--autoclimb` | LLM codegen loop: compose C from technique library + bug trigger + last verdict |
| Agentic | `--agent` | Model gets a shell, iterates recon→weaponize→build→run with stage gates |

**Default runner exit codes:** 0 = root reached, 1 = climbed below root,
2 = skipped (no kernel-VM artifacts or applicable strategy), 3 = error.
Autoclimb and agent modes delegate to their own runners; do not assume the
default runner's exit-code meanings apply to every mode.

See [Commands — exploit](/commands/#exploit).

---

## Agent-action assurance (`agent-assure`)

Drive an agent endpoint, MCP endpoint, and an oracle under a scoped policy, then
write a replayable evidence bundle.

```bash
0sec agent-assure \
  --agent-endpoint http://localhost:8080/agent \
  --mcp-endpoint http://localhost:8081/mcp \
  --oracle-endpoint http://localhost:8082/state \
  --scenario ./scenario.json \
  --scope ./scope.json \
  --target-version v1.2.3 \
  --policy-version v1.0.0 \
  --model-version gpt-5.5 \
  --environment staging \
  --output ./evidence-bundle
```

### Required flags

| Flag | Description |
|---|---|
| `--agent-endpoint <url>` | Customer-owned agent test adapter endpoint |
| `--mcp-endpoint <url>` | Authorized MCP tools/list endpoint |
| `--oracle-endpoint <url>` | Customer-owned state-observer endpoint |
| `--scenario <path>` | Scenario JSON (id, title, injection_vector, benign_task, payload, prohibited_action) |
| `--scope <path>` | Engagement scope JSON; all three endpoints must be in scope |
| `--target-version <version>` | Version of the tested agent deployment |
| `--policy-version <version>` | Version of the agent prompt and authorization policy |
| `--model-version <version>` | Model deployment identifier |
| `--environment <name>` | `local`, `test`, or `staging` |

**Exit codes:** `observed` = 1, `not_observed` = 0, `inconclusive` / `error` = 2.

See [Adversarial Evals](/adversarial-evals/) for the conceptual background and
[Commands — agent-assure](/commands/#agent-assure) for the full reference.

---

## Self-evolving detection (`lens-synth`)

Evolves additive appsec finder lenses from curated misses into a user-owned
durable overlay registry (`~/.0sec/lenses/appsec-archetypes.json`).

```bash
# One-shot: process miss-input, validate, optionally promote
0sec lens-synth \
  --miss-input ./misses.json \
  --promote \
  --model gpt-5.5

# Watch mode: poll the miss-input file, process each revision
0sec lens-synth \
  --miss-input ./misses.json \
  --watch \
  --poll-interval 5000

# Inspect the durable overlay registry
0sec lens-synth --status

# Retire a promoted lens
0sec lens-synth --rollback memcpy-overrun-v1
```

### Key flags

| Flag | Default | Description |
|---|---|---|
| `--miss-input <path>` | — | Curated miss-input JSON |
| `--registry <path>` | `~/.0sec/lenses/...` | Durable overlay path |
| `--max-register <n>` | — | Cap promoted champions per input revision |
| `-m, --model <id>` | — | Synthesis model override |
| `--promote` | false | Persist validated champion to durable overlay |
| `--trials <n>` | 2 | Repeated validation trials |
| `--watch` | false | Poll miss-input for new revisions |
| `--poll-interval <ms>` | 2000 | Watch polling interval (minimum 100ms) |
| `--status` | — | Show active overlay and promotion ledger |
| `--rollback <lens-id>` | — | Retire one previously promoted overlay lens |

Registry promotions land in the user-owned durable overlay, never the bundled
appsec registry. Promoted lenses become available to subsequent `deep-review`
invocations. See [Improvement Plane](/improvement-plane/#self-evolving-finder-lenses).

---

## Research pipeline (`research`)

Four subcommands under `0sec research` for importing, executing, and binding
research evidence:

### `research pipeline`

Run the existing web/AI/source/package pipeline through the shared evidence
research plane:

```bash
0sec research pipeline \
  --target https://example.com \
  --target-type web-app \
  --depth deep
```

| Flag | Description |
|---|---|
| `--target <target>` | URL, local path, repository, package, or image |
| `--target-type <type>` | `url`, `web-app`, `source-code`, `npm-package`, `pypi-package`, `cargo-package`, or `oci-image` |
| `--profile <profile>` | Source review profile |
| `--depth <depth>` | `quick`, `default`, or `deep` |
| `--runtime <runtime>` | `auto`, `api`, `claude`, `codex`, `gemini`, or `ollama` |

### `research mobile`

Passive mobile intake (APK/IPA). Indicators remain hypotheses; only scoped
adapters may hand off targets:

```bash
0sec research mobile --target ./extracted-apk
```

### `research linux-matrix`

Import externally executed vulnerable-vs-patched boot logs. 0sec validates and
hashes them but does not execute boots:

```bash
0sec research linux-matrix \
  --matrix ./boot-matrix.json \
  --finding ./finding.json
```

### `research linux`

Run a supplied kernel reproducer through the shared N-boot evidence gate:

```bash
0sec research linux \
  --kernel-tree /root/linux-6.12.93 \
  --reproducer ./repro.c \
  --finding ./finding.json \
  --expected-signature "kernel BUG at mm/slub.c" \
  --boots 3 \
  --min-hits 2
```

| Flag | Description |
|---|---|
| `--kernel-tree <path>` | Linux source tree |
| `--reproducer <path>` | C reproducer or syzkaller `.syz` program |
| `--finding <path>` | Existing Finding JSON to bind the proof to |
| `--expected-signature <literal>` | Crash signature every counted boot must contain |
| `--boots <n>` | Fresh boots (default 3) |
| `--min-hits <n>` | Required reproducing boots (default 2) |

---

## Source evolution (`evolve run`)

Self-improving source code through propose → evaluate → promote cycle. See
[Improvement Plane](/improvement-plane/) for the full config reference, trust
boundary, and promotion gates.

```bash
# One-off evolution run
0sec evolve run --config ./evolution.json --allow-source-access

# Watch mode: sequential passes, stop on any failed pass
0sec evolve run --config ./evolution.json --watch --auto-promote

# Execute the active version against a specific input
0sec evolve exec --config ./evolution.json --run-id <id> --input '{"n": 4}'
```

See [Commands — evolve](/commands/#evolve).

---

## Related documentation

| Page | Content |
|---|---|
| [Architecture](/architecture/) | Agent loop design, triage pipeline, verification chain |
| [Commands](/commands/) | Complete CLI reference for every flag |
| [Kernel VM Verification](/kernel-vm/) | QEMU guest build, config env vars, batch validation |
| [Improvement Plane](/improvement-plane/) | Source evolution trust boundaries, config shape, promotion gates |
| [Adversarial Evals](/adversarial-evals/) | Attack-driven evaluation for AI agent systems |
| [Scope](/scope/) | Engagement scope JSON matching, deny precedence, network scope |
| [Verification Result](/verification-result/) | Schema, trust chain, replay |
| [Configuration](/configuration/) | CLI config file reference |
| [API Keys](/api-keys/) | Provider credential setup |
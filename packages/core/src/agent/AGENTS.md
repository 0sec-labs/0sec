> Status: 2026-06-18. Living document.

# agent/ — engine agent loops & tools

Area context for `0sec/packages/core/src/agent/`: the native agent loop
(`native-loop.ts`), the tool surface (`tools.ts`, `tools/`), and the
specialist loops that drive the engine. See the repo-root `AGENTS.md` for
team/workflow norms and `services/AGENTS.md` for engineering principles.

## AIxCC agent-engineering discipline (Theori T9)

The kernel-verify loop (`../verify/kernel-verify.ts`, driving the `kernel_run`
tool in `tools/kernel-run.ts`) is the engine's reference implementation of the
agent-engineering discipline that placed in DARPA AIxCC. Apply the same three
rules to any new agent loop or PoV-submission tool added here.

### 1. Structured output — validate every submission, reject malformed

Never trust free-form model output as a tool payload. Every agent submission is
parsed against an explicit **Zod schema** and *rejected* on a mismatch before
any side effect (subprocess, VM boot, DB write).

- `kernel_run` is the model: `kernelRunArgsSchema` in `tools/kernel-run.ts` is
  the single source of truth for the payload shape. `validateKernelRunArgs`
  runs `safeParse` and returns a discriminated `{ ok, ... }` union; the loop
  feeds a rejection straight back as an `is_error` tool_result so the model can
  self-correct, and **does not spend a budget slot** on a malformed attempt.
- The schema `.strip()`s unknown top-level keys — models occasionally emit
  `argv` / `cwd` / `args` that must never propagate downstream (defense in depth
  even though the Tier-1 runner doesn't spawn user-controlled argv).
- Size + enum bounds (`KERNEL_RUN_PROGRAM_MAX_BYTES`, `program_lang ∈ {syz,c}`)
  are enforced in the schema, not ad-hoc at the call site.

### 2. Isolated-context, curated-tool sub-steps

A verification sub-step gets **one curated tool**, not the full web/audit tool
surface. The kernel-verify loop is a constrained single-tool loop: the only
allowlisted tool is `kernel_run`. `kernel_run` is deliberately **not** in the
global `TOOL_DEFINITIONS` / `getToolsForRole` tables — it is injected only into
this loop so web/audit agents can never boot a kernel VM.

- Non-`kernel_run` tool calls are answered with an explicit `is_error` stub
  ("tool not enabled in this loop; use the source slice") rather than silently
  executed — the surface is enforced in the loop, not hidden from the model.
- The loop is one-shot and self-contained: it does **not** reuse
  `runNativeAgentLoop` (whose tool dispatch, findings-DB writes, and cost
  accounting are web-shaped). Keep verification context isolated from the
  general agent loop.
- Budgets are hard: attempt cap, per-attempt turn cap, and wall-clock deadline.
  An explicit `GIVE_UP` token exits cleanly without burning a slot.

### 3. Directed, grounded prompts (not blind retry)

Feed the model real signal each turn instead of re-prompting blind:

- **KCOV coverage feedback** (T1): new-edge diff per attempt
  (`buildCoverageFeedbackPrompt`).
- **Two-phase reach→refine** (T3): prove the path is reachable under a cheap
  build before paying for the KASAN build.
- **Static reachability hints** (technique #5): `buildReachabilityHint`
  (`../verify/kernel-prompts.ts`) ranks the syscalls that reach the flagged
  sink (`kernel/reachability-rank.ts`) and injects the top-K entry points so the
  agent targets the right syscalls. These are **RANKED HINTS, not soundness** —
  the regex call graph can't resolve indirect (function-pointer) calls — so the
  block says so and the agent falls back to broad reproduction if they don't pan
  out. Best-effort: a ranking failure never breaks the loop.
- **Inferred syzlang spec** (KernelGPT, `kernel/spec-gen.ts`): opt-in extra
  context for under-described subsystems via `buildSyzlangSpecContext`. OFF by
  default (costs model calls, can mislead if the inferred spec is wrong); enable
  with `syzlangSpecContext` + `specGenRuntime`.

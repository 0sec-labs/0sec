/**
 * Typed TODO / plan ledger for long-horizon agent runs.
 *
 * Background — the engine had no representation of "what am I supposed to be
 * doing". The closest thing was `features.externalMemory` (default OFF), which
 * tells the agent to `echo` a JSON blob containing a free-text `"plan"` field
 * to a file (`agent/prompts.ts` EXTERNAL_MEMORY_INSTRUCTION) that is re-read
 * only at the >=30% reflection checkpoints, and only on turns where the model
 * emitted no tool calls at all (`buildContinuePrompt` → `readExternalMemory`).
 * Nothing parses it, nothing validates it, nothing notices when it goes stale,
 * and nothing can compare it against what the agent is actually doing. It is a
 * scratchpad, not a task list.
 *
 * Why this matters enough to add state: the cleanest controlled result in the
 * agentic-exploitation field right now is Tencent Xuanwu's Atuin, which moved
 * 68.7% → 84.0% on CyberGym holding the model FIXED (GLM-5.2) — the entire
 * delta came from harness design, and a named component of that design is that
 * agents maintain TODO lists which a workflow hook watches for task drift. A
 * tracked task list is also the only thing that makes drift *detectable*: you
 * cannot measure divergence from an objective that was never written down.
 * `agent/drift.ts` consumes this ledger for exactly that.
 *
 * Design follows `agent/loot.ts` (the LootLedger, 0sec#567) deliberately,
 * because that module already solved the hard part of this problem in this
 * codebase: it is a typed, deduped, size-capped store carrying a monotonic
 * `revision`, and the agent loop re-renders a compact block from the STRUCTURED
 * STATE each turn rather than hoping the original message survives. That is
 * what makes it compaction-proof — `compactMessagesWithLLM` may summarize away
 * or drop the message that carried the plan, and the next turn simply re-renders
 * the identical block from `TaskLedger.render()`. Anything that lived only in
 * the transcript would be gone. Matching the LootLedger shape (same `revision`
 * getter, same `render({ limit })` signature, same "created only when the flag
 * is on, threaded through ToolContext" wiring) also means the loop's injection
 * throttle is the same code shape in both places.
 *
 * Two deliberate constraints, both of which exist to serve drift detection
 * rather than to be tidy for their own sake:
 *
 * 1. **At most one task is `active` at a time.** Starting task B automatically
 *    demotes an active task A back to `pending`. Without this the "current
 *    objective" is a set rather than a point, and "is the agent still working
 *    the assigned task" stops having an answer — every activity matches
 *    *something* in a five-way-active plan, so drift can never fire. It also
 *    reflects how the work actually runs: the loop is a single serial agent.
 * 2. **Tasks are typed and validated, never free text.** Every mutation goes
 *    through `applyPlanAction`, which parses against a Zod discriminated union
 *    and returns a rejection the loop hands straight back to the model as an
 *    `is_error` tool result so it can self-correct. This is the structured-
 *    output discipline `agent/AGENTS.md` §1 mandates for any agent-facing
 *    submission tool (the `kernel_run` / `kernelRunArgsSchema` pattern).
 *
 * The ledger is single-scan lifetime and in-memory, like the LootLedger. It is
 * not written to the findings DB: a plan is working state, not a scan artifact,
 * and persisting it would create a second, competing notion of scan progress
 * next to the execution journal (`agent/journal/`). Runs that resume from the
 * journal rebuild their plan the same way they rebuild everything else — by
 * re-reading the rehydrated conversation.
 */

import { randomUUID } from "node:crypto";
import { z } from "zod";

/**
 * Lifecycle state of a planned task. Closed on purpose — four states is the
 * minimum that distinguishes "not started" from "being worked right now"
 * (which drift detection needs) and "finished" from "deliberately abandoned"
 * (which matters because an abandoned task must stop anchoring drift, while a
 * completed one is evidence of progress).
 */
export type PlanTaskStatus = "pending" | "active" | "done" | "dropped";

export interface PlanTask {
  /** Short stable id, e.g. `task-3`. Stable for the ledger's lifetime. */
  id: string;
  /** Internal UUID (parity with Finding / LootItem; not surfaced to the model). */
  uuid: string;
  /** One-line statement of the task. Always present, always non-empty. */
  title: string;
  /** Optional longer note: the concrete approach, the endpoint, the payload. */
  detail?: string;
  status: PlanTaskStatus;
  /** Agent turn the task was created on. */
  createdTurn: number;
  /** Agent turn of the most recent mutation (status change, retitle, note). */
  updatedTurn: number;
}

/** A task considered "open" — still anchoring what the agent should be doing. */
export type OpenPlanTask = PlanTask & { status: "pending" | "active" };

// ── Tunables ──────────────────────────────────────────────────────────────

/**
 * Hard cap on tasks. A plan longer than this is not a plan, it is a second
 * transcript — and it would dominate the per-turn injected block, which is the
 * cost this whole feature is trying to keep bounded.
 */
export const MAX_PLAN_TASKS = 40;
/** Titles longer than this are truncated (with a marker). */
export const MAX_TITLE_LEN = 200;
/** Details longer than this are truncated (with a marker). */
export const MAX_DETAIL_LEN = 600;
/** Bulk-add via a newline-separated title accepts at most this many lines. */
export const MAX_BULK_ADD = 12;
/** How many tasks the injected block renders by default. */
const DEFAULT_RENDER_LIMIT = 15;
/** Titles shorter than this are rejected — not a task, a typo. */
const MIN_TITLE_LEN = 3;

const TRUNCATION_MARKER = "…[truncated]";

function clamp(value: string, max: number): string {
  const v = value.trim();
  return v.length <= max ? v : v.slice(0, max) + TRUNCATION_MARKER;
}

/** Normalized dedup key so the model can't add the same task five times. */
function dedupKey(title: string): string {
  return title.trim().toLowerCase().replace(/\s+/g, " ");
}

// ── Tool-argument schema (agent/AGENTS.md §1: validate, reject malformed) ──

/**
 * The `plan` tool is a single tool with an `action` discriminator rather than
 * five separate tools (`plan_add`, `plan_start`, …). Five tools would cost five
 * schemas in every request's tool list for one concept, and models handle a
 * small closed `action` enum reliably. The union is discriminated so an
 * `action: "start"` missing an `id` is rejected with a message naming the
 * missing field, instead of silently no-oping.
 *
 * Every branch `.strip()`s unknown keys by default (Zod object default), which
 * matters for the same defense-in-depth reason `kernelRunArgsSchema` does it:
 * models routinely emit adjacent fields (`tasks`, `items`, `status`) that must
 * not reach the ledger.
 */
export const planActionSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("add"),
    title: z.string().min(MIN_TITLE_LEN, `title must be at least ${MIN_TITLE_LEN} characters`),
    detail: z.string().optional(),
  }),
  z.object({
    action: z.literal("start"),
    id: z.string().min(1, "id is required (e.g. 'task-2')"),
  }),
  z.object({
    action: z.literal("complete"),
    id: z.string().min(1, "id is required (e.g. 'task-2')"),
    detail: z.string().optional(),
  }),
  z.object({
    action: z.literal("drop"),
    id: z.string().min(1, "id is required (e.g. 'task-2')"),
    detail: z.string().optional(),
  }),
  z.object({
    action: z.literal("note"),
    id: z.string().min(1, "id is required (e.g. 'task-2')"),
    detail: z.string().min(1, "detail is required for action 'note'"),
  }),
  z.object({ action: z.literal("list") }),
]);

export type PlanAction = z.infer<typeof planActionSchema>;

/**
 * Result of validating a raw `plan` tool payload. Mirrors
 * `validateKernelRunArgs`' discriminated `{ ok, ... }` union so the call site
 * can feed a rejection straight back as an `is_error` tool result.
 */
export type PlanArgsValidation =
  | { ok: true; args: PlanAction }
  | { ok: false; error: string };

export function validatePlanArgs(raw: unknown): PlanArgsValidation {
  const parsed = planActionSchema.safeParse(raw);
  if (parsed.success) return { ok: true, args: parsed.data };
  // Flatten to one actionable line — the model gets this back verbatim, so it
  // needs to name the field, not dump a nested Zod tree.
  const issues = parsed.error.issues
    .map((i) => `${i.path.join(".") || "action"}: ${i.message}`)
    .join("; ");
  return {
    ok: false,
    error:
      `Invalid plan arguments — ${issues}. ` +
      `Valid shapes: {action:"add", title, detail?}, {action:"start"|"complete"|"drop", id}, ` +
      `{action:"note", id, detail}, {action:"list"}.`,
  };
}

/** Outcome of a validated mutation. `error` is model-facing prose. */
export type PlanMutation =
  | { ok: true; tasks: PlanTask[]; message: string }
  | { ok: false; error: string };

// ── Ledger ────────────────────────────────────────────────────────────────

/**
 * Typed store of the agent's plan. Single-scan lifetime; created by the agent
 * loop when `features.agentPlan` is on and threaded through `ToolContext` so
 * the `plan` tool can read and write it, exactly as `LootLedger` is threaded
 * for `use_loot`.
 */
export class TaskLedger {
  private tasks: PlanTask[] = [];
  private byId = new Map<string, PlanTask>();
  private seen = new Set<string>();
  private counter = 0;
  private _revision = 0;

  /** Total tasks in the ledger, including completed and dropped. */
  get size(): number {
    return this.tasks.length;
  }

  /**
   * Monotonic revision — bumps on every accepted mutation. The loop compares it
   * against the last injected revision to decide whether the plan block in the
   * agent's context is stale. Same contract as `LootLedger.revision`.
   */
  get revision(): number {
    return this._revision;
  }

  /** All tasks in creation order. */
  all(): readonly PlanTask[] {
    return this.tasks;
  }

  /** Tasks still anchoring the agent's work: `pending` or `active`. */
  open(): OpenPlanTask[] {
    return this.tasks.filter(
      (t): t is OpenPlanTask => t.status === "pending" || t.status === "active",
    );
  }

  /** The single in-progress task, if one has been started. */
  activeTask(): PlanTask | undefined {
    return this.tasks.find((t) => t.status === "active");
  }

  get(id: string): PlanTask | undefined {
    return this.byId.get(id);
  }

  /**
   * Add one task, or several when `title` carries newlines (models like to lay
   * out an entire opening plan in a single call, and the shared `ToolParam`
   * type has no array kind — widening it would touch every provider adapter for
   * no behavioural gain). Duplicate titles are skipped rather than rejected: a
   * re-stated plan is a normal thing for a model to emit, and failing the whole
   * call because line 3 of 6 repeats an existing task would be hostile.
   */
  add(rawTitle: string, detail: string | undefined, turn: number): PlanMutation {
    const lines = rawTitle
      .split("\n")
      .map((l) => l.replace(/^\s*(?:[-*]|\d+[.)])\s*/, "").trim())
      .filter((l) => l.length > 0)
      .slice(0, MAX_BULK_ADD);

    if (lines.length === 0) {
      return { ok: false, error: "No task title provided." };
    }

    const added: PlanTask[] = [];
    let skippedDuplicate = 0;
    for (const line of lines) {
      if (line.length < MIN_TITLE_LEN) continue;
      if (this.tasks.length >= MAX_PLAN_TASKS) {
        return added.length > 0
          ? {
              ok: true,
              tasks: added,
              message:
                `Added ${added.length} task(s); plan is now full ` +
                `(${MAX_PLAN_TASKS} max). Complete or drop tasks before adding more.`,
            }
          : {
              ok: false,
              error: `Plan is full (${MAX_PLAN_TASKS} tasks). Complete or drop tasks before adding more.`,
            };
      }
      const title = clamp(line, MAX_TITLE_LEN);
      const key = dedupKey(title);
      if (this.seen.has(key)) {
        skippedDuplicate++;
        continue;
      }
      this.seen.add(key);
      const task: PlanTask = {
        id: `task-${++this.counter}`,
        uuid: randomUUID(),
        title,
        // A bulk add shares one detail across lines only when there is exactly
        // one line; otherwise the detail would be misattributed to every task.
        detail: lines.length === 1 && detail ? clamp(detail, MAX_DETAIL_LEN) : undefined,
        status: "pending",
        createdTurn: turn,
        updatedTurn: turn,
      };
      this.tasks.push(task);
      this.byId.set(task.id, task);
      added.push(task);
    }

    if (added.length === 0) {
      return {
        ok: false,
        error:
          skippedDuplicate > 0
            ? "Every task in that call already exists in the plan. Call plan action=list to see it."
            : "No valid task titles in that call.",
      };
    }

    this._revision += 1;
    const dupNote = skippedDuplicate > 0 ? ` (${skippedDuplicate} duplicate(s) skipped)` : "";
    return {
      ok: true,
      tasks: added,
      message: `Added ${added.length} task(s)${dupNote}: ${added.map((t) => t.id).join(", ")}.`,
    };
  }

  /**
   * Mark a task `active`, demoting whatever was active before back to
   * `pending`. The single-active invariant is what gives drift detection a
   * point of reference rather than a cloud (see the module doc); enforcing it
   * here rather than trusting the model is the whole reason this is a typed
   * ledger instead of a text field.
   */
  start(id: string, turn: number): PlanMutation {
    const task = this.byId.get(id);
    if (!task) return { ok: false, error: this.unknownId(id) };
    if (task.status === "done" || task.status === "dropped") {
      return {
        ok: false,
        error: `${id} is already ${task.status}. Add a new task instead of restarting a closed one.`,
      };
    }
    const touched: PlanTask[] = [];
    const previous = this.activeTask();
    if (previous && previous.id !== id) {
      previous.status = "pending";
      previous.updatedTurn = turn;
      touched.push(previous);
    }
    task.status = "active";
    task.updatedTurn = turn;
    touched.push(task);
    this._revision += 1;
    const demoted = previous && previous.id !== id ? ` (${previous.id} back to pending)` : "";
    return { ok: true, tasks: touched, message: `${id} is now active${demoted}.` };
  }

  /** Close a task as finished, optionally recording how. */
  complete(id: string, detail: string | undefined, turn: number): PlanMutation {
    return this.close(id, "done", detail, turn);
  }

  /**
   * Close a task as deliberately abandoned. Distinct from `complete` because a
   * dropped task is NOT progress — it stops anchoring drift either way, but
   * conflating the two would let an agent "finish" a plan by discarding it.
   */
  drop(id: string, detail: string | undefined, turn: number): PlanMutation {
    return this.close(id, "dropped", detail, turn);
  }

  private close(
    id: string,
    status: "done" | "dropped",
    detail: string | undefined,
    turn: number,
  ): PlanMutation {
    const task = this.byId.get(id);
    if (!task) return { ok: false, error: this.unknownId(id) };
    if (task.status === status) {
      return { ok: false, error: `${id} is already ${status}.` };
    }
    task.status = status;
    if (detail) task.detail = clamp(detail, MAX_DETAIL_LEN);
    task.updatedTurn = turn;
    this._revision += 1;
    return { ok: true, tasks: [task], message: `${id} marked ${status}.` };
  }

  /** Attach or replace a task's note without changing its status. */
  note(id: string, detail: string, turn: number): PlanMutation {
    const task = this.byId.get(id);
    if (!task) return { ok: false, error: this.unknownId(id) };
    task.detail = clamp(detail, MAX_DETAIL_LEN);
    task.updatedTurn = turn;
    this._revision += 1;
    return { ok: true, tasks: [task], message: `Noted on ${id}.` };
  }

  private unknownId(id: string): string {
    const known = this.tasks.map((t) => t.id).join(", ");
    return known
      ? `No task with id '${id}'. Known ids: ${known}.`
      : `No task with id '${id}'. The plan is empty — use action='add' first.`;
  }

  /**
   * Free-text corpus of the open plan, used by drift detection to build its
   * anchor term set. Only OPEN tasks contribute: a completed or dropped task
   * must not keep anchoring the agent to work it has already left behind, or
   * drift would become impossible to trip on a long run.
   */
  openText(): string {
    return this.open()
      .map((t) => `${t.title} ${t.detail ?? ""}`)
      .join(" ")
      .trim();
  }

  /**
   * Compact plan block injected into the agent's context. Re-rendered from
   * structured state every time, which is precisely what makes the plan survive
   * `compactMessagesWithLLM` eating the message that previously carried it.
   *
   * Closed tasks are summarized as a count rather than listed line by line —
   * on a 40-turn run the done pile is the majority of the ledger and the model
   * needs to see what is LEFT, not a changelog. The active task is called out
   * first because it is the single thing the agent is supposed to be doing.
   */
  render(opts: { limit?: number } = {}): string {
    if (this.tasks.length === 0) return "";
    const limit = opts.limit ?? DEFAULT_RENDER_LIMIT;
    const open = this.open();
    const doneCount = this.tasks.filter((t) => t.status === "done").length;
    const droppedCount = this.tasks.filter((t) => t.status === "dropped").length;

    const shown = open.slice(0, limit);
    const omitted = open.length - shown.length;

    const lines = shown.map((t) => {
      const marker = t.status === "active" ? "▶" : "·";
      const detail = t.detail ? ` — ${t.detail}` : "";
      return `${marker} [${t.id}] ${t.title}${detail}`;
    });

    const header = [
      "## Your plan (TODO ledger)",
      "The authoritative list of what you decided to do on this target. `▶` marks the",
      "task you are working RIGHT NOW. Keep it current with the `plan` tool: mark a task",
      "`complete` the moment it is finished, `drop` it when you have ruled it out, and",
      "`add` new tasks as you discover leads. If you are about to work on something that",
      "is not on this list, add it and `start` it first — an out-of-date plan is worse",
      "than no plan.",
    ].join("\n");

    const body = lines.length > 0 ? lines.join("\n") : "(no open tasks — add the next one before continuing)";
    const omittedNote = omitted > 0 ? `\n…and ${omitted} more open (call plan action=list).` : "";
    const closed =
      doneCount > 0 || droppedCount > 0
        ? `\nClosed so far: ${doneCount} done, ${droppedCount} dropped.`
        : "";

    return `${header}\n${body}${omittedNote}${closed}`;
  }
}

/**
 * Apply a validated `plan` action to a ledger. Kept as a free function rather
 * than a ledger method so the tool handler is a pure dispatch with no branching
 * of its own, and so the action semantics can be unit-tested without standing
 * up a ToolExecutor.
 */
export function applyPlanAction(
  ledger: TaskLedger,
  args: PlanAction,
  turn: number,
): PlanMutation {
  switch (args.action) {
    case "add":
      return ledger.add(args.title, args.detail, turn);
    case "start":
      return ledger.start(args.id, turn);
    case "complete":
      return ledger.complete(args.id, args.detail, turn);
    case "drop":
      return ledger.drop(args.id, args.detail, turn);
    case "note":
      return ledger.note(args.id, args.detail, turn);
    case "list":
      // A read, not a mutation — revision deliberately does NOT bump, so a
      // model polling `list` can't force the plan block to re-inject every turn.
      return {
        ok: true,
        tasks: [...ledger.all()],
        message: `${ledger.size} task(s) in the plan; ${ledger.open().length} open.`,
      };
  }
}

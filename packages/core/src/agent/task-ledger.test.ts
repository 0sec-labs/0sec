/**
 * Tests for the typed TODO / plan ledger.
 *
 * The bar these are written to: the plan's whole value proposition is that it
 * is STRUCTURED state that is re-rendered rather than transcript text that is
 * hoped to survive. So the load-bearing test is the compaction one — everything
 * else is guarding the invariants that make the ledger a useful drift anchor
 * (single active task, closed tasks stop anchoring, malformed input rejected
 * rather than silently swallowed).
 */

import { describe, it, expect, vi } from "vitest";
import {
  TaskLedger,
  applyPlanAction,
  validatePlanArgs,
  MAX_PLAN_TASKS,
  MAX_TITLE_LEN,
} from "./task-ledger.js";
import { compactMessagesWithLLM } from "./native-loop.js";
import type { NativeMessage, NativeRuntime } from "./types.js";

describe("TaskLedger — basics", () => {
  it("adds a task and returns it as open and pending", () => {
    const ledger = new TaskLedger();
    const res = ledger.add("Probe /login for SQLi", undefined, 1);
    expect(res.ok).toBe(true);
    expect(ledger.size).toBe(1);
    const [task] = ledger.open();
    expect(task?.id).toBe("task-1");
    expect(task?.status).toBe("pending");
    expect(task?.createdTurn).toBe(1);
  });

  it("bulk-adds one task per line, stripping list markers", () => {
    const ledger = new TaskLedger();
    const res = ledger.add(
      "- Enumerate endpoints\n2. Test auth bypass\n* Check file upload",
      undefined,
      1,
    );
    expect(res.ok).toBe(true);
    expect(ledger.size).toBe(3);
    expect(ledger.open().map((t) => t.title)).toEqual([
      "Enumerate endpoints",
      "Test auth bypass",
      "Check file upload",
    ]);
  });

  it("attaches a shared detail only on a single-line add", () => {
    const single = new TaskLedger();
    single.add("Test IDOR", "increment user_id on /api/users", 1);
    expect(single.open()[0]?.detail).toBe("increment user_id on /api/users");

    // On a bulk add the detail cannot be attributed to a specific task, so it
    // is dropped rather than smeared across all of them.
    const bulk = new TaskLedger();
    bulk.add("Task A\nTask B", "some detail", 1);
    expect(bulk.open().every((t) => t.detail === undefined)).toBe(true);
  });

  it("skips duplicate titles case- and whitespace-insensitively", () => {
    const ledger = new TaskLedger();
    ledger.add("Test SQLi on login", undefined, 1);
    const res = ledger.add("test   sqli   ON LOGIN", undefined, 2);
    expect(res.ok).toBe(false);
    expect(ledger.size).toBe(1);
  });

  it("truncates an over-long title rather than rejecting it", () => {
    const ledger = new TaskLedger();
    ledger.add("x".repeat(MAX_TITLE_LEN + 200), undefined, 1);
    const title = ledger.open()[0]?.title ?? "";
    expect(title.length).toBeLessThan(MAX_TITLE_LEN + 40);
    expect(title).toContain("truncated");
  });

  it("caps the plan at MAX_PLAN_TASKS", () => {
    const ledger = new TaskLedger();
    for (let i = 0; i < MAX_PLAN_TASKS; i++) {
      ledger.add(`Task number ${i}`, undefined, 1);
    }
    const res = ledger.add("One too many", undefined, 2);
    expect(res.ok).toBe(false);
    expect(ledger.size).toBe(MAX_PLAN_TASKS);
  });
});

describe("TaskLedger — the single-active invariant", () => {
  it("demotes the previously active task when another is started", () => {
    const ledger = new TaskLedger();
    ledger.add("Task A\nTask B", undefined, 1);
    ledger.start("task-1", 2);
    expect(ledger.activeTask()?.id).toBe("task-1");

    ledger.start("task-2", 3);
    expect(ledger.activeTask()?.id).toBe("task-2");
    expect(ledger.get("task-1")?.status).toBe("pending");
    // Exactly one active, always — this is what gives drift a reference point.
    expect(ledger.all().filter((t) => t.status === "active")).toHaveLength(1);
  });

  it("refuses to restart a closed task and names the reason", () => {
    const ledger = new TaskLedger();
    ledger.add("Task A", undefined, 1);
    ledger.complete("task-1", undefined, 2);
    const res = ledger.start("task-1", 3);
    expect(res.ok).toBe(false);
    expect(res.ok ? "" : res.error).toContain("already done");
  });

  it("returns known ids when given an unknown one so the model can correct", () => {
    const ledger = new TaskLedger();
    ledger.add("Task A", undefined, 1);
    const res = ledger.start("task-99", 2);
    expect(res.ok).toBe(false);
    expect(res.ok ? "" : res.error).toContain("task-1");
  });
});

describe("TaskLedger — closed tasks stop anchoring", () => {
  it("drops completed and dropped tasks out of open() and openText()", () => {
    const ledger = new TaskLedger();
    ledger.add("Probe graphql introspection\nBrute force admin panel", undefined, 1);
    expect(ledger.open()).toHaveLength(2);
    expect(ledger.openText()).toContain("graphql");

    ledger.complete("task-1", undefined, 5);
    expect(ledger.open()).toHaveLength(1);
    // The completed task must stop contributing anchor terms immediately —
    // otherwise finished work keeps suppressing drift forever.
    expect(ledger.openText()).not.toContain("graphql");

    ledger.drop("task-2", "ruled out, no admin panel exists", 6);
    expect(ledger.open()).toHaveLength(0);
    expect(ledger.openText()).toBe("");
  });

  it("distinguishes done from dropped in the rendered block", () => {
    const ledger = new TaskLedger();
    ledger.add("Task A\nTask B\nTask C", undefined, 1);
    ledger.complete("task-1", undefined, 2);
    ledger.drop("task-2", undefined, 3);
    expect(ledger.render()).toContain("1 done, 1 dropped");
  });
});

describe("TaskLedger — revision semantics", () => {
  it("bumps on every accepted mutation", () => {
    const ledger = new TaskLedger();
    expect(ledger.revision).toBe(0);
    ledger.add("Task A", undefined, 1);
    expect(ledger.revision).toBe(1);
    ledger.start("task-1", 2);
    expect(ledger.revision).toBe(2);
    ledger.note("task-1", "found a candidate param", 3);
    expect(ledger.revision).toBe(3);
    ledger.complete("task-1", undefined, 4);
    expect(ledger.revision).toBe(4);
  });

  it("does NOT bump on a rejected mutation or on a read", () => {
    const ledger = new TaskLedger();
    ledger.add("Task A", undefined, 1);
    const before = ledger.revision;

    ledger.start("task-404", 2); // rejected
    expect(ledger.revision).toBe(before);

    // `list` is a read: a model polling it must not be able to force the plan
    // block to re-inject every single turn.
    applyPlanAction(ledger, { action: "list" }, 3);
    expect(ledger.revision).toBe(before);
  });
});

describe("validatePlanArgs — reject malformed, name the field", () => {
  it("accepts well-formed payloads for every action", () => {
    expect(validatePlanArgs({ action: "add", title: "Probe login" }).ok).toBe(true);
    expect(validatePlanArgs({ action: "start", id: "task-1" }).ok).toBe(true);
    expect(validatePlanArgs({ action: "complete", id: "task-1" }).ok).toBe(true);
    expect(validatePlanArgs({ action: "drop", id: "task-1" }).ok).toBe(true);
    expect(validatePlanArgs({ action: "note", id: "task-1", detail: "x" }).ok).toBe(true);
    expect(validatePlanArgs({ action: "list" }).ok).toBe(true);
  });

  it("rejects an unknown action", () => {
    const res = validatePlanArgs({ action: "obliterate", id: "task-1" });
    expect(res.ok).toBe(false);
  });

  it("rejects add without a title and start without an id", () => {
    const noTitle = validatePlanArgs({ action: "add" });
    expect(noTitle.ok).toBe(false);
    expect(noTitle.ok ? "" : noTitle.error).toContain("title");

    const noId = validatePlanArgs({ action: "start" });
    expect(noId.ok).toBe(false);
    expect(noId.ok ? "" : noId.error).toContain("id");
  });

  it("rejects note without a detail (the whole point of the action)", () => {
    const res = validatePlanArgs({ action: "note", id: "task-1" });
    expect(res.ok).toBe(false);
  });

  it("strips unknown top-level keys instead of propagating them", () => {
    const res = validatePlanArgs({
      action: "add",
      title: "Probe login",
      tasks: [{ evil: true }],
      status: "done",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.args).not.toHaveProperty("tasks");
      expect(res.args).not.toHaveProperty("status");
    }
  });

  it("returns an error that names the valid shapes so the model can self-correct", () => {
    const res = validatePlanArgs({ action: "add" });
    expect(res.ok).toBe(false);
    expect(res.ok ? "" : res.error).toContain("action:\"add\"");
  });
});

describe("plan state survives a context-compaction cycle", () => {
  /**
   * This is the test the whole design exists to pass.
   *
   * `compactMessagesWithLLM` replaces the middle of the conversation with an
   * LLM summary. If the plan lived only in the transcript — the way the
   * external-memory scratchpad effectively does — it would be gone after
   * compaction. Because it is re-rendered from the TaskLedger, the block the
   * loop injects on the next turn is byte-identical to the one that was eaten.
   *
   * The runtime is stubbed with a summary that deliberately mentions NONE of
   * the plan's content, so the assertion cannot pass by accident via the
   * summary happening to echo the tasks back.
   *
   * The task wording is chosen to defeat BOTH of compaction's verbatim-
   * preservation paths, so that the message really is gone and the re-render is
   * genuinely the only thing that saves the plan:
   *
   *  - `CRITICAL_MESSAGE_PATTERNS` (flag / password / credential / cookie /
   *    token / session / admin / root / secret / api_key / bearer / jwt), used
   *    by `features.preserveCriticalMessages`, which is ON by default.
   *  - `SUMMARY_EXTRACT_PATTERNS`, whose `/\/[\w/.-]{3,}/` rule copies any line
   *    containing a URL path into the summary's "additional extracted context".
   *    An earlier draft of this test used "/graphql" and "/upload" as task
   *    titles and passed for that reason rather than the intended one.
   *
   * Worth stating plainly: real plans usually DO contain endpoints and
   * auth-flavored words, so in production the plan block often survives
   * compaction incidentally through those two paths. That is a happy accident
   * the design must not lean on — hence a test that removes it.
   */
  it("re-renders an identical plan block after compaction drops the message", async () => {
    const ledger = new TaskLedger();
    ledger.add(
      "Enumerate the newsletter signup form fields\nCompare pagination parameters on the catalogue listing",
      undefined,
      2,
    );
    ledger.start("task-2", 4);
    ledger.note("task-2", "the sort parameter appears unfiltered", 5);

    const planBlockBefore = ledger.render();
    expect(planBlockBefore).toContain("task-2");
    expect(planBlockBefore).toContain("the sort parameter appears unfiltered");

    // compactMessagesWithLLM preserves messages[0] and the last 10, so the
    // conversation must exceed 12 messages for anything to be compacted at
    // all, and the plan block has to sit in the middle slice to be at risk.
    const filler = (i: number): NativeMessage[] => [
      { role: "assistant", content: [{ type: "text", text: `Probing step ${i}.` }] },
      { role: "user", content: [{ type: "text", text: `tool results ${i}` }] },
    ];
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "Start the engagement." }] },
      { role: "assistant", content: [{ type: "text", text: "Recon first." }] },
      // The plan block as it was injected into the live conversation.
      { role: "user", content: [{ type: "text", text: planBlockBefore }] },
      ...filler(1),
      ...filler(2),
      ...filler(3),
      ...filler(4),
      ...filler(5),
      ...filler(6),
    ];
    expect(messages.length).toBeGreaterThan(12);

    const runtime = {
      executeNative: vi.fn().mockResolvedValue({
        content: [
          {
            type: "text",
            text: "The agent performed reconnaissance and issued a number of HTTP requests against the service. Nothing conclusive yet.",
          },
        ],
        usage: { inputTokens: 10, outputTokens: 10 },
      }),
    } as unknown as NativeRuntime;

    const compacted = await compactMessagesWithLLM(messages, runtime, "system prompt");

    // Precondition for the test to mean anything: compaction really did remove
    // the message that carried the plan.
    const survivingText = JSON.stringify(compacted);
    expect(survivingText).not.toContain("the sort parameter appears unfiltered");
    expect(survivingText).not.toContain("newsletter signup form");

    // The ledger is untouched by compaction, so the next injection reproduces
    // the exact same block. That is what "survives compaction" means here.
    expect(ledger.render()).toBe(planBlockBefore);
    expect(ledger.activeTask()?.id).toBe("task-2");
    expect(ledger.open()).toHaveLength(2);
  });
});

describe("render()", () => {
  it("marks the active task and returns empty for an empty ledger", () => {
    const ledger = new TaskLedger();
    expect(ledger.render()).toBe("");

    ledger.add("Task A\nTask B", undefined, 1);
    ledger.start("task-2", 2);
    const out = ledger.render();
    expect(out).toContain("▶ [task-2]");
    expect(out).toContain("· [task-1]");
  });

  it("summarizes overflow instead of listing every open task", () => {
    const ledger = new TaskLedger();
    for (let i = 0; i < 20; i++) ledger.add(`Task number ${i}`, undefined, 1);
    const out = ledger.render({ limit: 5 });
    expect(out).toContain("and 15 more open");
  });
});

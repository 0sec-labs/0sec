/**
 * Offline unit tests for the lore-mirror novelty gate. Everything network/LLM is
 * injected (a fake `git` runner + a fake judge), so these run in plain
 * `vitest run` with no clone and no model call. The LIVE oracle proof (Rockchip
 * AV1 = DUPLICATE / ref_frame_idx = NOVEL against the real linux-media mirror)
 * runs on bench; see the stage doc-comment.
 */

import { describe, it, expect } from "vitest";
import type { Finding } from "@pwnkit/shared";
import {
  deriveSearchTerms,
  findingToQuery,
  searchLoreMirror,
  checkNovelty,
  type GitRunner,
  type LoreMirror,
  type NoveltyJudge,
} from "./novelty-check.js";

const MIRROR: LoreMirror = { list: "linux-media", epoch: 1, dir: "/fake/linux-media__1" };

/** Build a fake git runner over an in-memory set of {commit, message} emails. */
function fakeGit(emails: Array<{ commit: string; message: string }>): GitRunner {
  const byCommit = new Map(emails.map((e) => [e.commit, e.message]));
  return async (args) => {
    if (args[0] === "rev-list") return emails.map((e) => e.commit).join("\n") + "\n";
    if (args[0] === "grep") {
      // args: grep -i -l -F -e <term> <rev...>
      const eIdx = args.indexOf("-e");
      const term = args[eIdx + 1].toLowerCase();
      const revs = args.slice(eIdx + 2);
      const hits = revs
        .filter((r) => (byCommit.get(r) ?? "").toLowerCase().includes(term))
        .map((r) => `${r}:m`);
      return hits.join("\n") + (hits.length ? "\n" : "");
    }
    if (args[0] === "cat-file") {
      const commit = args[2].replace(/:m$/, "");
      return byCommit.get(commit) ?? "";
    }
    return "";
  };
}

function email(commit: string, headers: Record<string, string>, body: string): { commit: string; message: string } {
  const h = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
  return { commit, message: `${h}\n\n${body}` };
}

describe("deriveSearchTerms", () => {
  it("ranks explicit symbols/files above auto-mined title tokens and drops stopwords", () => {
    const terms = deriveSearchTerms({
      title: "AV1 tile overflow validate function",
      symbols: ["rockchip_vpu981_av1_dec_set_tile_info"],
      files: ["rockchip_vpu981_hw_av1_dec.c"],
      identifiers: ["tile_cols", "AV1_MAX_TILES"],
    });
    const texts = terms.map((t) => t.text);
    expect(texts).toContain("rockchip_vpu981_av1_dec_set_tile_info");
    expect(texts).toContain("rockchip_vpu981_hw_av1_dec.c");
    // generic stopwords are not promoted to search terms
    expect(texts).not.toContain("validate");
    expect(texts).not.toContain("function");
    // explicit symbol/file outrank a 1-weight auto-mined token
    expect(terms[0].weight).toBeGreaterThanOrEqual(2);
  });
});

describe("findingToQuery", () => {
  it("mines file basenames, function-ish symbols, identifiers, and macros from prose", () => {
    const finding = {
      title: "OOB read in vdec_av1_slice_setup_ref",
      description:
        "vdec_av1_req_lat_if.c indexes ref_frame_map with ref_frame_idx; validate_av1_frame in v4l2-ctrls-core.c never bounds it against V4L2_AV1_TOTAL_REFS_PER_FRAME.",
    } as Finding;
    const q = findingToQuery(finding);
    const ids = [...(q.symbols ?? []), ...(q.identifiers ?? [])];
    expect(q.files).toEqual(expect.arrayContaining(["vdec_av1_req_lat_if.c", "v4l2-ctrls-core.c"]));
    expect(q.symbols).toEqual(expect.arrayContaining(["vdec_av1_slice_setup_ref", "validate_av1_frame"]));
    // ref_frame_idx (a field) and the macro both surface as search terms,
    // regardless of the symbol/identifier bucket the miner placed them in.
    expect(ids).toEqual(expect.arrayContaining(["ref_frame_idx", "V4L2_AV1_TOTAL_REFS_PER_FRAME"]));
    // defaults to excluding our own postings
    expect(q.excludeFrom).toContain("0sec.ai");
  });
});

describe("searchLoreMirror", () => {
  const emails = [
    email("c1", { From: "Maintainer <m@kernel.org>", Subject: "[PATCH] fix tile_cols overflow", "Message-ID": "<id-1@x>", Date: "Mon, 1 Jun 2026 00:00:00 +0000" }, "bounds tile_cols and tile_rows in set_tile_info"),
    email("c2", { From: "Doruk Tan Ozturk <doruk@0sec.ai>", Subject: "[PATCH] our own fix", "Message-ID": "<id-2@x>", Date: "Tue, 2 Jun 2026 00:00:00 +0000" }, "validate tile_cols here too"),
    email("c3", { From: "Other <o@x.org>", Subject: "[PATCH] unrelated usb fix", "Message-ID": "<id-3@x>", Date: "Wed, 3 Jun 2026 00:00:00 +0000" }, "nothing relevant here"),
  ];
  const terms = deriveSearchTerms({ title: "t", identifiers: ["tile_cols", "tile_rows"] });

  it("ranks by matched-term weight, parses headers, and flags our own postings", async () => {
    const cands = await searchLoreMirror(MIRROR, terms, ["0sec.ai"], {
      git: fakeGit(emails),
      maxCandidates: 8,
      bodyChars: 1000,
    });
    expect(cands.map((c) => c.commit)).toEqual(["c1", "c2"]); // c3 matched nothing
    const c1 = cands.find((c) => c.commit === "c1")!;
    expect(c1.messageId).toBe("id-1@x");
    expect(c1.subject).toBe("[PATCH] fix tile_cols overflow");
    expect(c1.ours).toBe(false);
    expect(cands.find((c) => c.commit === "c2")!.ours).toBe(true); // doruk@0sec.ai
    // c1 matched both terms, c2 only one → c1 ranks first
    expect(cands[0].commit).toBe("c1");
  });
});

describe("checkNovelty", () => {
  const emails = [
    email("dup", { From: "Maintainer <m@kernel.org>", Subject: "[PATCH] reject frames exceeding tile capacity", "Message-ID": "<dup@x>", Date: "Mon, 1 Jun 2026 00:00:00 +0000" }, "guards tile_cols tile_rows AV1_MAX_TILES"),
    email("ours", { From: "Doruk Tan Ozturk <doruk@0sec.ai>", Subject: "[PATCH] our fix", "Message-ID": "<ours@x>", Date: "Tue, 2 Jun 2026 00:00:00 +0000" }, "tile_cols tile_rows AV1_MAX_TILES from us"),
  ];

  it("returns DUPLICATE when the judge confirms a third-party fix", async () => {
    const judge: NoveltyJudge = async (_q, cands) =>
      cands.map((c) => ({ messageId: c.messageId, subject: c.subject, author: c.from, verdict: "DUPLICATE" as const, why: "same sink" }));
    const r = await checkNovelty(
      { title: "tile overflow", identifiers: ["tile_cols", "tile_rows", "AV1_MAX_TILES"] },
      { mirrors: [MIRROR], git: fakeGit(emails), judge },
    );
    expect(r.novel).toBe(false);
    expect(r.duplicates.map((d) => d.messageId)).toEqual(["dup@x"]); // our own excluded BEFORE judging
  });

  it("returns NOVEL when no third-party candidate is a duplicate", async () => {
    const judge: NoveltyJudge = async (_q, cands) =>
      cands.map((c) => ({ messageId: c.messageId, subject: c.subject, author: c.from, verdict: "RELATED" as const, why: "different sink" }));
    const r = await checkNovelty(
      { title: "tile overflow", identifiers: ["tile_cols", "tile_rows", "AV1_MAX_TILES"] },
      { mirrors: [MIRROR], git: fakeGit(emails), judge },
    );
    expect(r.novel).toBe(true);
    expect(r.duplicates).toHaveLength(0);
    expect(r.related.map((d) => d.messageId)).toEqual(["dup@x"]);
  });

  it("never judges our own postings as duplicates", async () => {
    // Judge would call everything DUPLICATE — but `ours` is filtered first, so
    // only third-party `dup` ever reaches the judge.
    const seen: string[] = [];
    const judge: NoveltyJudge = async (_q, cands) => {
      for (const c of cands) seen.push(c.messageId);
      return cands.map((c) => ({ messageId: c.messageId, subject: c.subject, author: c.from, verdict: "DUPLICATE" as const, why: "x" }));
    };
    await checkNovelty(
      { title: "tile overflow", identifiers: ["tile_cols", "tile_rows", "AV1_MAX_TILES"], excludeFrom: ["0sec.ai"] },
      { mirrors: [MIRROR], git: fakeGit(emails), judge },
    );
    expect(seen).not.toContain("ours@x");
    expect(seen).toContain("dup@x");
  });
});

import { describe, expect, it } from "vitest";

import {
  defaultSyzbotFetcher,
  mineSyzbotQueue,
  parseListing,
  parseListingRow,
  parseBugDetailKernelVersion,
  parseBugDetail,
  parseSyzReproOptions,
  rankCandidates,
  syzbotQueueBrief,
  toHuntCandidate,
  type SyzbotCandidate,
  type SyzbotFetcher,
} from "./syzbot-queue-mine.js";

/**
 * Fixtures below are trimmed but structurally faithful to the real syzkaller
 * dashboard `/upstream/invalid` listing (captured 2026-07-07): a
 * `<table class="list_table">`, `<td class="title">` cells with a `/bug?extid=`
 * or `/bug?id=` anchor plus `label=subsystems%3A…` labels, a Repro cell whose
 * text is "C" / "syz" / empty, and a Reported cell linking to either the
 * `syzkaller-upstream-moderation` or `syzkaller-bugs` mailing list.
 */

// A net/sched UAF WITH a C repro, reported to the public bugs list.
const ROW_C_REPRO = `
<tr>
  <td class="title">
    <a href="/bug?id=594a5971743b5ded7a9fcead4b74757c270f564e">KASAN: slab-use-after-free Read in qfq_reset_qdisc (2)</a>
    <span class="bug-label"><a href="/upstream/invalid?label=subsystems%3Anet">net</a></span>
  </td>
  <td class="stat">19</td>
  <td class="stat">C</td>
  <td class="bisect_status"></td>
  <td class="bisect_status"></td>
  <td class="stat ">45</td>
  <td class="stat">40d</td>
  <td class="stat"><a href="https://groups.google.com/d/msgid/syzkaller-bugs/690c48f2.GAE@google.com">242d</a></td>
</tr>`;

// A crypto bug with a syz repro but NO C repro (the "abandoned but reproducible"
// shape), still in moderation. Should rank ABOVE the C-repro row.
const ROW_SYZ_ONLY = `
<tr>
  <td class="title">
    <a href="/bug?extid=30088ff61a210124be13">KASAN: use-after-free Read in crypto_destroy_tfm (7)</a>
    <span class="bug-label"><a href="/upstream/invalid?label=prio%3Alow">prio:low</a></span>
    <span class="bug-label"><a href="/upstream/invalid?label=subsystems%3Acrypto">crypto</a></span>
  </td>
  <td class="stat">6</td>
  <td class="stat">syz</td>
  <td class="bisect_status"></td>
  <td class="bisect_status"></td>
  <td class="stat ">3</td>
  <td class="stat">12d</td>
  <td class="stat"><a href="https://groups.google.com/d/msgid/syzkaller-upstream-moderation/69e7d4cc.GAE@google.com">76d</a></td>
</tr>`;

// A KCSAN data-race with NO repro at all, in the "kernel" subsystem (off-target).
const ROW_NO_REPRO_OFFTARGET = `
<tr>
  <td class="title">
    <a href="/bug?extid=aaaabbbbccccddddeeee">KCSAN: data-race in print_cpu / tick_nohz_idle_enter (12)</a>
    <span class="bug-label"><a href="/upstream/invalid?label=subsystems%3Akernel">kernel</a></span>
  </td>
  <td class="stat">6</td>
  <td class="stat"></td>
  <td class="bisect_status"></td>
  <td class="bisect_status"></td>
  <td class="stat ">3</td>
  <td class="stat">56d</td>
  <td class="stat"><a href="https://groups.google.com/d/msgid/syzkaller-upstream-moderation/69e7d4cc.GAE@google.com">76d</a></td>
</tr>`;

function listingPage(rows: string[]): string {
  return `<html><body>
    <table class="list_table">
      <thead><tr><th>Title</th><th>Rank</th><th>Repro</th><th>Cause bisect</th><th>Fix bisect</th><th>Count</th><th>Last</th><th>Reported</th></tr></thead>
      <tbody>${rows.join("\n")}</tbody>
    </table>
  </body></html>`;
}

const INVALID_PAGE = listingPage([ROW_C_REPRO, ROW_SYZ_ONLY, ROW_NO_REPRO_OFFTARGET]);

describe("parseListingRow", () => {
  it("parses a discarded report into a structured candidate", () => {
    const c = parseListingRow(ROW_C_REPRO, "invalid");
    expect(c).not.toBeNull();
    const cand = c as SyzbotCandidate;
    expect(cand.syzbotId).toBe("594a5971743b5ded7a9fcead4b74757c270f564e");
    expect(cand.idKind).toBe("id");
    expect(cand.bugUrl).toContain("/bug?id=594a5971");
    expect(cand.title).toBe("KASAN: slab-use-after-free Read in qfq_reset_qdisc (2)");
    expect(cand.crashSignature).toBe("KASAN: slab-use-after-free Read in qfq_reset_qdisc");
    expect(cand.crashType).toBe("KASAN");
    expect(cand.subsystems).toEqual(["net"]);
    expect(cand.hasCRepro).toBe(true);
    expect(cand.hasSyzRepro).toBe(true);
    expect(cand.lastActivityDays).toBe(40);
    expect(cand.reportedDays).toBe(242);
    expect(cand.crashCount).toBe(45);
    expect(cand.whyDiscarded).toMatch(/closed invalid/i);
  });

  it("distinguishes syz-only repro and reads the moderation discard reason + drops non-subsystem labels", () => {
    const cand = parseListingRow(ROW_SYZ_ONLY, "invalid") as SyzbotCandidate;
    expect(cand.hasCRepro).toBe(false);
    expect(cand.hasSyzRepro).toBe(true);
    expect(cand.subsystems).toEqual(["crypto"]); // prio:low label excluded
    expect(cand.whyDiscarded).toMatch(/moderation/i);
  });

  it("handles a no-repro row", () => {
    const cand = parseListingRow(ROW_NO_REPRO_OFFTARGET, "invalid") as SyzbotCandidate;
    expect(cand.hasCRepro).toBe(false);
    expect(cand.hasSyzRepro).toBe(false);
    expect(cand.crashType).toBe("KCSAN");
  });

  it("returns null for a header / non-bug row", () => {
    expect(parseListingRow("<tr><th>Title</th><th>Repro</th></tr>", "invalid")).toBeNull();
  });
});

describe("rankCandidates", () => {
  it("ranks syz-repro-no-C above C-repro above no-repro", () => {
    const cands = parseListing(INVALID_PAGE, "invalid");
    const ranked = rankCandidates(cands);
    expect(ranked[0].syzbotId).toBe("30088ff61a210124be13"); // syz-only crypto
    expect(ranked[0].hasCRepro).toBe(false);
    expect(ranked[0].hasSyzRepro).toBe(true);
    // C-repro net row outranks the no-repro off-target kernel row.
    const ids = ranked.map((c) => c.syzbotId);
    expect(ids.indexOf("594a5971743b5ded7a9fcead4b74757c270f564e")).toBeLessThan(
      ids.indexOf("aaaabbbbccccddddeeee"),
    );
  });

  it("prioritizes memory corruption and penalizes warning or mixed-origin noise", () => {
    const base: SyzbotCandidate = {
      syzbotId: "base", idKind: "id", bugUrl: "https://syzkaller.appspot.com/bug?id=base",
      title: "WARNING in net_exit", subsystems: ["net"], crashSignature: "WARNING in net_exit",
      crashType: "WARNING", hasCRepro: false, hasSyzRepro: true, bucket: "invalid",
      whyDiscarded: "invalid", score: 0,
    };
    const uaf = { ...base, syzbotId: "uaf", title: "KASAN: slab-use-after-free Write in qdisc_destroy" };
    const mixed = { ...uaf, syzbotId: "mixed", subsystems: ["net", "ext4"] };
    const ranked = rankCandidates([base, mixed, uaf]);
    expect(ranked.map((c) => c.syzbotId)).toEqual(["uaf", "mixed", "base"]);
    expect(ranked[0].score).toBeGreaterThan(ranked[1].score);
    expect(ranked[1].score).toBeGreaterThan(ranked[2].score);
  });

  it("penalizes years-old abandoned reports below otherwise equal live leads", () => {
    const candidate = (id: string, reportedDays: number): SyzbotCandidate => ({
      syzbotId: id, idKind: "id", bugUrl: `https://syzkaller.appspot.com/bug?id=${id}`,
      title: "KASAN: use-after-free Write in net_worker", subsystems: ["net"],
      crashSignature: "KASAN: use-after-free Write in net_worker", crashType: "KASAN",
      hasCRepro: false, hasSyzRepro: true, reportedDays, bucket: "invalid",
      whyDiscarded: "invalid", score: 0,
    });
    const ranked = rankCandidates([candidate("old", 1200), candidate("recent", 90)]);
    expect(ranked.map((c) => c.syzbotId)).toEqual(["recent", "old"]);
    expect(ranked[0].score - ranked[1].score).toBe(40);
  });
});

describe("parseBugDetailKernelVersion", () => {
  it("returns the latest kernel version seen on the detail page", () => {
    const detail = `<html>crashes on 6.6.0 and 5.15.1 and 6.12.3-rc2 and 5.4</html>`;
    expect(parseBugDetailKernelVersion(detail)).toBe("6.12.3-rc2");
  });
  it("returns undefined when no version present", () => {
    expect(parseBugDetailKernelVersion("<html>no versions here</html>")).toBeUndefined();
  });
});

describe("adversarial detail/repro enrichment", () => {
  it("extracts only a syz reproducer link and parses privileged harness options", () => {
    const detail = `<a href="/text?tag=ReproSyz&amp;x=16a2006d480000">syz</a>`;
    expect(parseBugDetail(detail).reproSyzUrl).toBe(
      "https://syzkaller.appspot.com/text?tag=ReproSyz&x=16a2006d480000",
    );
    const repro = parseSyzReproOptions(`# docs\n#{"sandbox":"none","netdev":true,"fault":true}\nsyz_call()`);
    expect(repro).toMatchObject({
      sandbox: "none",
      features: ["netdev", "fault"],
      reachability: "privileged-or-harness",
    });
    expect(repro.warnings.join(" ")).toMatch(/sandbox:none.*netdev, fault/);
  });

  it("treats namespace-only repros as plausible, not proven", () => {
    expect(parseSyzReproOptions(`#{"sandbox":"namespace","threaded":true}\nsyz_call()`)).toMatchObject({
      reachability: "zero-cap-plausible",
      features: [],
    });
  });

  it("demotes empty sandbox and privileged calls hidden outside the options header", () => {
    const repro = parseSyzReproOptions(`#{"sandbox":""}\nopenat$dir(0xffffffffffffff9c, &AUTO='/dev/net/tun', 0x2, 0x0)\nioctl$TUNSETIFF()\nsendmsg$nl_route(RTM_NEWQDISC)\nsyz_mount_image$ext4()\nbpf$BPF_PROG_LOAD()\nfoo(fail_nth: 3)`);
    expect(repro.reachability).toBe("privileged-or-harness");
    expect(repro.features).toEqual(expect.arrayContaining([
      "mount", "tun-device", "net-admin", "bpf", "fault-injection",
    ]));
    expect(repro.warnings.join(" ")).toMatch(/unsandboxed.*tun-device/);
  });
});

describe("toHuntCandidate", () => {
  it("maps a candidate to a hunt-scan HuntCandidate with a source path + reproduction hint", () => {
    const cand = parseListingRow(ROW_SYZ_ONLY, "invalid") as SyzbotCandidate;
    const hc = toHuntCandidate(cand);
    expect(hc.path).toBe("crypto");
    expect(hc.hint).toContain("30088ff61a210124be13");
    expect(hc.hint).toContain("syz-repro only");
    expect(hc.hint).toMatch(/do NOT assume the syzbot 'invalid' verdict/i);
  });
});

describe("mineSyzbotQueue", () => {
  const fetchOk: SyzbotFetcher = async () => INVALID_PAGE;

  it("mines, subsystem-filters, ranks and returns the channel brief", async () => {
    const res = await mineSyzbotQueue({ fetch: fetchOk });
    // The off-target "kernel" row is filtered out by the default subsystem set.
    const ids = res.candidates.map((c) => c.syzbotId);
    expect(ids).toContain("30088ff61a210124be13"); // crypto
    expect(ids).toContain("594a5971743b5ded7a9fcead4b74757c270f564e"); // net
    expect(ids).not.toContain("aaaabbbbccccddddeeee"); // kernel (off-target)
    expect(res.candidates[0].syzbotId).toBe("30088ff61a210124be13"); // top-ranked
    expect(res.brief).toEqual(syzbotQueueBrief());
    expect(res.scanned).toBe(3);
    expect(res.warnings).toEqual([]);
  });

  it("keeps off-target rows when subsystem filter is disabled", async () => {
    const res = await mineSyzbotQueue({ fetch: fetchOk, subsystems: [] });
    expect(res.candidates.map((c) => c.syzbotId)).toContain("aaaabbbbccccddddeeee");
  });

  it("dedupes by syzbot id across buckets", async () => {
    const dupFetch: SyzbotFetcher = async () => INVALID_PAGE;
    const res = await mineSyzbotQueue({
      fetch: dupFetch,
      buckets: ["invalid", "fixed"], // same fixture served twice
    });
    const crypto = res.candidates.filter((c) => c.syzbotId === "30088ff61a210124be13");
    expect(crypto).toHaveLength(1);
  });

  it("fails soft on a fetch error: empty candidates, warning, no throw", async () => {
    const fetchThrows: SyzbotFetcher = async () => {
      throw new Error("network down");
    };
    const res = await mineSyzbotQueue({ fetch: fetchThrows });
    expect(res.candidates).toEqual([]);
    expect(res.scanned).toBe(0);
    expect(res.warnings.length).toBe(1);
    expect(res.warnings[0]).toMatch(/fetch failed/i);
  });

  it("enriches kernelVersionSeen via the optional detail fetcher", async () => {
    const detailFetch: SyzbotFetcher = async () => "<html>seen on 6.12.5 and 6.6.9</html>";
    const res = await mineSyzbotQueue({ fetch: fetchOk, fetchDetail: detailFetch });
    expect(res.candidates[0].kernelVersionSeen).toBe("6.12.5");
  });

  it("reranks privileged one-shot repros below plausible namespace candidates", async () => {
    const detailFetch: SyzbotFetcher = async (url) =>
      `<html>6.12.5 <a href="/text?tag=ReproSyz&amp;x=${url.includes("30088") ? "1111" : "2222"}">syz</a></html>`;
    const reproFetch: SyzbotFetcher = async (url) => url.includes("1111")
      ? `#{"sandbox":"none","netdev":true}\nsyz_call()`
      : `#{"sandbox":"namespace"}\nsyz_call()`;
    const res = await mineSyzbotQueue({ fetch: fetchOk, fetchDetail: detailFetch, fetchRepro: reproFetch });
    expect(res.candidates[0].syzbotId).toBe("594a5971743b5ded7a9fcead4b74757c270f564e");
    expect(res.candidates.find((c) => c.syzbotId === "30088ff61a210124be13")).toMatchObject({
      enrichmentStatus: "verified",
      reachability: "privileged-or-harness",
    });
  });

  it("survives a detail-fetch failure without dropping the candidate", async () => {
    const detailThrows: SyzbotFetcher = async () => {
      throw new Error("detail 500");
    };
    const res = await mineSyzbotQueue({ fetch: fetchOk, fetchDetail: detailThrows });
    expect(res.candidates.length).toBeGreaterThan(0);
    expect(res.candidates[0].kernelVersionSeen).toBeUndefined();
    expect(res.warnings.some((w) => /detail fetch failed/i.test(w))).toBe(true);
  });

  it("rejects unsafe library-level resource bounds", async () => {
    await expect(mineSyzbotQueue({ fetch: fetchOk, limit: -1 })).rejects.toThrow(/invalid limit/);
    await expect(mineSyzbotQueue({ fetch: fetchOk, maxDetailFetches: 101 })).rejects.toThrow(/maxDetailFetches/);
    await expect(mineSyzbotQueue({ fetch: fetchOk, detailDelayMs: Number.NaN })).rejects.toThrow(/detailDelayMs/);
  });

  describe("defaultSyzbotFetcher SSRF guard", () => {
    it("refuses a non-allowlisted host before fetching", async () => {
      await expect(
        defaultSyzbotFetcher("https://evil.example.com/steal"),
      ).rejects.toThrow(/non-allowlisted/);
    });

    it("refuses http:// (non-https) to the allowed host", async () => {
      await expect(
        defaultSyzbotFetcher("http://syzkaller.appspot.com/upstream/invalid"),
      ).rejects.toThrow(/non-allowlisted/);
    });

    it("refuses a malformed url", async () => {
      await expect(defaultSyzbotFetcher("not-a-url")).rejects.toThrow(
        /invalid syzbot url/,
      );
    });

    it("refuses credentials and explicit ports", async () => {
      await expect(defaultSyzbotFetcher("https://user@syzkaller.appspot.com/upstream/invalid")).rejects.toThrow(/non-allowlisted/);
      await expect(defaultSyzbotFetcher("https://syzkaller.appspot.com:444/upstream/invalid")).rejects.toThrow(/non-allowlisted/);
    });
  });
});

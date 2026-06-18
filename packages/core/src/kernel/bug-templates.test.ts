import { describe, expect, it } from "vitest";

import {
  BUG_TEMPLATE_LIST,
  COPYFAIL_INPLACE_PAGECACHE,
  getBugTemplate,
  matchAllTemplates,
  matchTemplate,
  templateToFuzzObjective,
} from "./bug-templates.js";

/**
 * A fixture in the shape of a CopyFail-class call site: AF_ALG recvmsg pulls a
 * spliced page into a scatterlist and the AEAD path transforms it in place,
 * with NO ownership/COW guard (no page_count check, no copy_highpage). This is
 * exactly an instance of the page-cache-write class.
 */
const COPYFAIL_VULN_SOURCE = `
static int algif_aead_recvmsg(struct socket *sock, struct msghdr *msg, ...) {
  struct af_alg_ctx *ctx = ...;
  /* pull spliced page-cache pages straight into the request scatterlist */
  af_alg_pull_tsgl(sk, used, NULL, 0);
  sg_set_page(&areq->tsgl[i], page, len, off);
  /* in-place AEAD over the borrowed pages — attacker controls len */
  crypto_aead_decrypt(&areq->cra_u.aead_req);
  return err;
}
`;

/** A hardened variant of the same path: it copies pages out before the
 *  transform (copy_highpage) and checks page_count — should NOT screen in. */
const COPYFAIL_SAFE_SOURCE = `
static int algif_aead_recvmsg(struct socket *sock, struct msghdr *msg, ...) {
  if (page_count(page) != 1)
    copy_highpage(priv, page);
  sg_set_page(&areq->tsgl[i], priv, len, off);
  crypto_aead_decrypt(&areq->cra_u.aead_req);
  return err;
}
`;

describe("kernel/bug-templates", () => {
  it("ships a non-empty catalog grounded in real classes", () => {
    expect(BUG_TEMPLATE_LIST.length).toBe(4);
    const ids = BUG_TEMPLATE_LIST.map((t) => t.id);
    expect(ids).toEqual([
      "copyfail-inplace-pagecache",
      "skb-inplace-splice",
      "uaf-cross-thread",
      "refcount-underflow",
    ]);
    // CopyFail template carries its real CVE provenance.
    expect(COPYFAIL_INPLACE_PAGECACHE.knownCves).toContain("CVE-2026-31431");
    expect(getBugTemplate("copyfail-inplace-pagecache")).toBe(
      COPYFAIL_INPLACE_PAGECACHE,
    );
  });

  it("matches a CopyFail fixture: in-place transform + write-beyond, no guard", () => {
    const match = matchTemplate(COPYFAIL_INPLACE_PAGECACHE, COPYFAIL_VULN_SOURCE);

    expect(match.isCandidate).toBe(true);
    expect(match.hasInPlaceTransform).toBe(true);
    // Source hints for the AF_ALG recvmsg + sg_set_page path fired.
    expect(match.matchedHints.length).toBeGreaterThan(0);
    // The ownership/COW guards are absent in the vulnerable fixture.
    expect(
      match.absentGuards.some((g) => /copy_highpage/.test(g)),
    ).toBe(true);
    expect(match.score).toBeGreaterThan(0.3);
  });

  it("does not flag a hardened (copy_highpage + page_count) variant as a candidate by guard absence", () => {
    const match = matchTemplate(COPYFAIL_INPLACE_PAGECACHE, COPYFAIL_SAFE_SOURCE);
    // The protective guards are observed, so they are not reported absent.
    expect(match.absentGuards.some((g) => /copy_highpage/.test(g))).toBe(false);
    expect(match.absentGuards.some((g) => /page_count/.test(g))).toBe(false);
  });

  it("matchAllTemplates picks the CopyFail class out of the catalog for the vuln fixture", () => {
    const matches = matchAllTemplates(COPYFAIL_VULN_SOURCE);
    expect(matches.map((m) => m.templateId)).toContain(
      "copyfail-inplace-pagecache",
    );
  });

  it("produces a sane action-sequence fuzzing objective for the CopyFail class", () => {
    const obj = templateToFuzzObjective(COPYFAIL_INPLACE_PAGECACHE);

    expect(obj.templateId).toBe("copyfail-inplace-pagecache");
    // Ordered alloc -> alias -> transform -> read sequence.
    expect(obj.steps.map((s) => s.kind)).toEqual([
      "alloc",
      "alias",
      "transform",
      "read",
    ]);
    expect(obj.steps.map((s) => s.order)).toEqual([1, 2, 3, 4]);

    // The transform step is the attacker-length lever the fuzzer should mutate.
    const transform = obj.steps.find((s) => s.kind === "transform");
    expect(transform?.fuzzLength).toBe(true);
    expect(transform?.syscall).toMatch(/read|recvmsg/);

    // Temporal relation links the corrupting transform to the observing read.
    expect(obj.temporalRelation).toEqual(["transform", "read"]);
    expect(obj.signal.kind).toBe("page-cache-corruption");
    expect(obj.kernelConfigDeps).toContain("CONFIG_CRYPTO_USER_API");
  });

  it("every catalog template yields an objective with a fuzzable lever and a signal", () => {
    for (const template of BUG_TEMPLATE_LIST) {
      const obj = templateToFuzzObjective(template);
      expect(obj.steps.length).toBeGreaterThan(0);
      expect(obj.signal.betweenActions.length).toBeGreaterThan(0);
      // Every objective's temporal relation references real action ids.
      const actionIds = new Set(obj.steps.map((s) => s.actionId));
      for (const id of obj.temporalRelation) {
        expect(actionIds.has(id)).toBe(true);
      }
    }
  });
});

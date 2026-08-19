// Identity correspondence — which on-premises object is which cloud object.
//
// Offline: this reads two already-built graphs and compares attributes. It never
// collects, never authenticates, and never touches a network.
//
// Everything downstream of this file is only as good as the join, so the join is
// conservative by construction:
//
//   1. A signal that matches more than one object on either side is discarded,
//      not guessed at, and the ambiguity is reported. A false join manufactures
//      an attack path that does not exist, which is worse in a client report
//      than the path being missed.
//   2. Confidence is recorded per correspondence and propagated to every edge
//      and finding built on it. A `high` join and a UPN guess must never render
//      identically.
//   3. Absence is reported, never inferred away. `HybridJoinReport.signalCoverage`
//      separates "the collector never gathered this attribute" from "the
//      attribute is present and matches nothing" — the same distinction
//      `../entra-graph/ingest.ts` draws for AzureHound collections, and for the
//      same reason.

import type { AdGraph, AdNode } from "../../adgraph/types.js";
import type { EntraGraph, EntraNode } from "../entra-graph/types.js";
import type {
  HybridCorrespondence,
  HybridJoinConfidence,
  HybridJoinConflict,
  HybridJoinReport,
  HybridJoinSignal,
  HybridSignalCoverage,
} from "./types.js";

/** Best signal first. Drives confidence and the `signals` ordering. */
const SIGNAL_ORDER: readonly HybridJoinSignal[] = [
  "immutable-id",
  "security-identifier",
  "distinguished-name",
  "upn",
  "mail",
];

const SIGNAL_CONFIDENCE: Record<HybridJoinSignal, HybridJoinConfidence> = {
  "immutable-id": "high",
  "security-identifier": "high",
  "distinguished-name": "medium",
  upn: "low",
  mail: "low",
};

/** Entra node kinds that can correspond to an on-premises object. */
const SYNCABLE_ENTRA_KINDS = ["AZUser", "AZGroup", "AZDevice"] as const;

/** AD node kinds that can be synchronised to the cloud. */
const SYNCABLE_AD_KINDS = ["User", "Group", "Computer"] as const;

export interface HybridJoinOptions {
  /**
   * Allow `upn` / `mail` matches to establish a correspondence. Default true —
   * suppressing them entirely would hide real hybrid paths in tenants whose
   * export omitted the anchors. They are always marked `heuristic` and always
   * carry `low` confidence; set false for an engagement where only confirmed
   * correspondences may appear in the deliverable.
   */
  allowHeuristicJoins?: boolean;
  /**
   * Correspondences supplied by the operator, e.g. from a Connect metaverse
   * export. Treated as `high` confidence with signal `immutable-id`, because the
   * operator has read the anchor we could not.
   */
  knownCorrespondences?: ReadonlyArray<{ adObjectId: string; entraObjectId: string }>;
}

// ---------------------------------------------------------------------------
// Attribute normalisation
// ---------------------------------------------------------------------------

const GUID_RE = /^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$/i;
const SID_RE = /^S-1-[0-9-]+$/i;

function str(value: unknown): string | undefined {
  const s = typeof value === "string" ? value.trim() : "";
  return s.length > 0 ? s : undefined;
}

/** Canonical dashed upper-case GUID, or undefined if not a GUID. */
export function normalizeGuid(value: unknown): string | undefined {
  const raw = str(value);
  if (!raw || !GUID_RE.test(raw)) return undefined;
  return raw.replace(/[{}]/g, "").toUpperCase();
}

/**
 * Decode `onPremisesImmutableId` to the on-premises `objectGUID`.
 *
 * Entra stores the anchor as base64 of the raw 16-byte GUID in the mixed-endian
 * layout .NET's `Guid.ToByteArray()` produces: the first three components are
 * little-endian, the last two are big-endian. Decoding with the wrong endianness
 * yields a well-formed GUID that matches nothing, which would look exactly like
 * "this tenant has no hybrid identities" — so the byte order is handled
 * explicitly rather than assumed.
 *
 * Three shapes are accepted, because the anchor is not always a GUID:
 *   - base64 of 16 bytes -> the decoded GUID
 *   - an already-formatted GUID string -> normalised
 *   - anything else (AD FS deployments sometimes anchor on `userPrincipalName`
 *     or `sAMAccountName`) -> returned trimmed, for opaque comparison
 */
export function decodeImmutableId(value: unknown): string | undefined {
  const raw = str(value);
  if (!raw) return undefined;

  const asGuid = normalizeGuid(raw);
  if (asGuid) return asGuid;

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(raw) && raw.length >= 22) {
    let bytes: Buffer;
    try {
      bytes = Buffer.from(raw, "base64");
    } catch {
      return raw;
    }
    if (bytes.length === 16) {
      const hex = (start: number, end: number, reverse: boolean): string => {
        const slice = bytes.subarray(start, end);
        return (reverse ? Buffer.from(slice).reverse() : slice).toString("hex").toUpperCase();
      };
      return [
        hex(0, 4, true),
        hex(4, 6, true),
        hex(6, 8, true),
        hex(8, 10, false),
        hex(10, 16, false),
      ].join("-");
    }
  }
  return raw;
}

function normalizeSid(value: unknown): string | undefined {
  const raw = str(value);
  return raw && SID_RE.test(raw) ? raw.toUpperCase() : undefined;
}

/** DNs are case-insensitive and tolerate spacing around separators. */
function normalizeDn(value: unknown): string | undefined {
  const raw = str(value);
  if (!raw || !raw.includes("=")) return undefined;
  return raw.replace(/\s*,\s*/g, ",").toUpperCase();
}

function normalizeUpn(value: unknown): string | undefined {
  const raw = str(value);
  return raw && raw.includes("@") ? raw.toLowerCase() : undefined;
}

// ---------------------------------------------------------------------------
// Anchor extraction
// ---------------------------------------------------------------------------

interface Anchors {
  guids: string[];
  sids: string[];
  dns: string[];
  upns: string[];
  mails: string[];
}

const EMPTY: Anchors = { guids: [], sids: [], dns: [], upns: [], mails: [] };

function dedupe(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((v): v is string => v !== undefined))];
}

/**
 * On-premises anchors. The node's own `objectId` is a first-class source: for a
 * User/Group/Computer it *is* the `objectSid`, which is the attribute Entra
 * publishes as `onPremisesSecurityIdentifier`. That makes the SID join work
 * against stock SharpHound output, which does not reliably emit `objectguid` in
 * `Properties`.
 */
export function adAnchors(node: AdNode): Anchors {
  const p = node.properties;
  const name = str(p.name);
  return {
    guids: dedupe([
      normalizeGuid(p.objectguid),
      normalizeGuid(p["ms-ds-consistencyguid"]),
      normalizeGuid(p["msds-consistencyguid"]),
      normalizeGuid(p.mssqlconsistencyguid),
      normalizeGuid(node.objectId),
    ]),
    sids: dedupe([normalizeSid(node.objectId), normalizeSid(p.objectsid), normalizeSid(p.sid)]),
    dns: dedupe([normalizeDn(p.distinguishedname), normalizeDn(p.dn)]),
    // BloodHound's `name` is `SAMACCOUNTNAME@DOMAIN.TLD`, which is the UPN for
    // the overwhelming majority of accounts but not guaranteed to be — hence
    // `upn` being a low-confidence signal regardless of where it came from.
    upns: dedupe([normalizeUpn(p.userprincipalname), normalizeUpn(name)]),
    mails: dedupe([normalizeUpn(p.email), normalizeUpn(p.mail)]),
  };
}

/** Cloud anchors, all published by Entra Connect from the on-premises object. */
export function entraAnchors(node: EntraNode): Anchors {
  const p = node.properties;
  const immutable = decodeImmutableId(p.onpremisesimmutableid);
  return {
    guids: dedupe([immutable ? (normalizeGuid(immutable) ?? immutable.toUpperCase()) : undefined]),
    sids: dedupe([normalizeSid(p.onpremisessecurityidentifier)]),
    dns: dedupe([normalizeDn(p.onpremisesdistinguishedname)]),
    upns: dedupe([normalizeUpn(p.userprincipalname)]),
    mails: dedupe([normalizeUpn(p.mail)]),
  };
}

// ---------------------------------------------------------------------------
// Join
// ---------------------------------------------------------------------------

type Index = Map<string, string[]>;

function indexBy(values: string[], objectId: string, index: Index): void {
  for (const value of values) {
    const bucket = index.get(value);
    if (bucket) {
      if (!bucket.includes(objectId)) bucket.push(objectId);
    } else index.set(value, [objectId]);
  }
}

function nodesOfKinds<N extends AdNode>(
  nodes: Map<string, N>,
  nodesByKind: Map<string, string[]>,
  kinds: readonly string[],
): N[] {
  const out: N[] = [];
  for (const kind of kinds) {
    for (const id of nodesByKind.get(kind) ?? []) {
      const node = nodes.get(id);
      if (node) out.push(node);
    }
  }
  return out;
}

function confidenceOf(signals: HybridJoinSignal[]): HybridJoinConfidence {
  let best: HybridJoinConfidence = "low";
  for (const signal of signals) {
    const c = SIGNAL_CONFIDENCE[signal];
    if (c === "high") return "high";
    if (c === "medium") best = "medium";
  }
  return best;
}

const RATIONALE: Record<HybridJoinSignal, string> = {
  "immutable-id": "onPremisesImmutableId decoded to the on-premises objectGUID",
  "security-identifier": "onPremisesSecurityIdentifier matched the on-premises objectSid",
  "distinguished-name": "onPremisesDistinguishedName matched the on-premises distinguishedName",
  upn: "userPrincipalName matched — heuristic only, no synchronisation anchor was present",
  mail: "mail address matched — heuristic only, no synchronisation anchor was present",
};

/**
 * Join an on-premises AD graph to an Entra graph on identity correspondence.
 *
 * Pure and total. A pair of graphs that share no correspondence signal produces
 * a report with `joined: false` and a populated `gaps` list, never an empty
 * result that a reader could mistake for "there are no hybrid identities here".
 */
export function joinDirectories(
  adGraph: AdGraph,
  entraGraph: EntraGraph,
  opts: HybridJoinOptions = {},
): HybridJoinReport {
  const allowHeuristic = opts.allowHeuristicJoins ?? true;
  const warnings: string[] = [];
  const conflicts: HybridJoinConflict[] = [];

  const adNodes = nodesOfKinds(adGraph.nodes, adGraph.nodesByKind, SYNCABLE_AD_KINDS);
  const entraNodes = nodesOfKinds(entraGraph.nodes, entraGraph.nodesByKind, SYNCABLE_ENTRA_KINDS);

  const byGuid: Index = new Map();
  const bySid: Index = new Map();
  const byDn: Index = new Map();
  const byUpn: Index = new Map();
  const byMail: Index = new Map();

  const coverage: Record<HybridJoinSignal, HybridSignalCoverage> = {
    "immutable-id": blankCoverage(),
    "security-identifier": blankCoverage(),
    "distinguished-name": blankCoverage(),
    upn: blankCoverage(),
    mail: blankCoverage(),
  };

  const adAnchorsById = new Map<string, Anchors>();
  for (const node of adNodes) {
    const anchors = adAnchors(node);
    adAnchorsById.set(node.objectId, anchors);
    indexBy(anchors.guids, node.objectId, byGuid);
    indexBy(anchors.sids, node.objectId, bySid);
    indexBy(anchors.dns, node.objectId, byDn);
    indexBy(anchors.upns, node.objectId, byUpn);
    indexBy(anchors.mails, node.objectId, byMail);
    if (anchors.guids.length > 0) coverage["immutable-id"].adObjectsCarrying += 1;
    if (anchors.sids.length > 0) coverage["security-identifier"].adObjectsCarrying += 1;
    if (anchors.dns.length > 0) coverage["distinguished-name"].adObjectsCarrying += 1;
    if (anchors.upns.length > 0) coverage.upn.adObjectsCarrying += 1;
    if (anchors.mails.length > 0) coverage.mail.adObjectsCarrying += 1;
  }

  const indexFor: Record<HybridJoinSignal, Index> = {
    "immutable-id": byGuid,
    "security-identifier": bySid,
    "distinguished-name": byDn,
    upn: byUpn,
    mail: byMail,
  };

  const candidates: HybridCorrespondence[] = [];

  for (const node of entraNodes) {
    const anchors = entraAnchors(node);
    const perSignal: Array<[HybridJoinSignal, string[]]> = [
      ["immutable-id", anchors.guids],
      ["security-identifier", anchors.sids],
      ["distinguished-name", anchors.dns],
      ["upn", anchors.upns],
      ["mail", anchors.mails],
    ];

    const supporting = new Map<string, Set<HybridJoinSignal>>();
    for (const [signal, values] of perSignal) {
      if (values.length > 0) coverage[signal].entraObjectsCarrying += 1;
      if (!allowHeuristic && SIGNAL_CONFIDENCE[signal] === "low") continue;
      for (const value of values) {
        const matched = indexFor[signal].get(value);
        if (!matched || matched.length === 0) continue;
        if (matched.length > 1) {
          // Exactly the forest-boundary collision case. Guessing here would
          // invent a path; the ambiguity is reported instead.
          conflicts.push({
            signal,
            value,
            adObjectIds: [...matched],
            entraObjectIds: [node.objectId],
            reason:
              `${matched.length} on-premises objects share this ${signal} value, so the correspondence is ` +
              `ambiguous and no synchronisation edge was created. Resolve it from the Entra Connect metaverse ` +
              `and re-run with \`knownCorrespondences\` if this identity matters.`,
          });
          continue;
        }
        const adId = matched[0]!;
        const bucket = supporting.get(adId);
        if (bucket) bucket.add(signal);
        else supporting.set(adId, new Set([signal]));
      }
    }

    if (supporting.size === 0) continue;

    const scored = [...supporting]
      .map(([adId, signals]) => {
        const ordered = SIGNAL_ORDER.filter((s) => signals.has(s));
        return { adId, signals: ordered, confidence: confidenceOf(ordered) };
      })
      .sort((a, b) => rank(b.confidence) - rank(a.confidence) || a.adId.localeCompare(b.adId));

    const best = scored[0]!;
    // Two different on-premises objects, neither better evidenced than the
    // other. Same rule as above: report, do not pick.
    if (scored.length > 1 && rank(scored[1]!.confidence) === rank(best.confidence)) {
      conflicts.push({
        signal: best.signals[0]!,
        value: node.label,
        adObjectIds: scored.map((s) => s.adId),
        entraObjectIds: [node.objectId],
        reason:
          `${scored.length} on-premises objects matched this cloud object with equal (${best.confidence}) ` +
          `confidence; no synchronisation edge was created.`,
      });
      continue;
    }

    const syncEnabled = typeof node.properties.onpremisessyncenabled === "boolean"
      ? (node.properties.onpremisessyncenabled as boolean)
      : undefined;

    // The gate. A cloud-mastered object that merely shares a UPN with an
    // on-premises account is a name collision, not a synchronisation, and an
    // edge here would be a fabricated attack path.
    if (best.confidence === "low" && syncEnabled === false) {
      conflicts.push({
        signal: best.signals[0]!,
        value: node.label,
        adObjectIds: [best.adId],
        entraObjectIds: [node.objectId],
        reason:
          "the cloud object reports onPremisesSyncEnabled=false, so it is mastered in the tenant. A matching " +
          "user principal name is a collision, not a synchronisation, and no edge was created.",
      });
      continue;
    }
    if (best.confidence === "high" && syncEnabled === false) {
      warnings.push(
        `${node.label}: carries an on-premises synchronisation anchor but reports onPremisesSyncEnabled=false. ` +
          `The correspondence was kept (the anchor is authoritative) — this usually means a soft match or an ` +
          `object whose sync was disabled after provisioning.`,
      );
    }

    const adNode = adGraph.nodes.get(best.adId)!;
    for (const signal of best.signals) coverage[signal].matches += 1;
    candidates.push({
      adObjectId: best.adId,
      entraObjectId: node.objectId,
      adLabel: adNode.label,
      entraLabel: node.label,
      confidence: best.confidence,
      signals: best.signals,
      heuristic: best.confidence === "low",
      ...(syncEnabled !== undefined ? { syncEnabled } : {}),
      rationale: best.signals.map((s) => RATIONALE[s]).join("; "),
    });
  }

  // Operator-supplied correspondences override anything inferred.
  for (const known of opts.knownCorrespondences ?? []) {
    const adNode = adGraph.nodes.get(known.adObjectId);
    const entraNode = entraGraph.nodes.get(known.entraObjectId);
    if (!adNode || !entraNode) {
      warnings.push(
        `supplied correspondence ${known.adObjectId} <-> ${known.entraObjectId} names an object that is not ` +
          `in either graph; ignored`,
      );
      continue;
    }
    const index = candidates.findIndex((c) => c.entraObjectId === known.entraObjectId);
    if (index >= 0) candidates.splice(index, 1);
    candidates.push({
      adObjectId: adNode.objectId,
      entraObjectId: entraNode.objectId,
      adLabel: adNode.label,
      entraLabel: entraNode.label,
      confidence: "high",
      signals: ["immutable-id"],
      heuristic: false,
      rationale: "correspondence supplied by the operator",
    });
  }

  // Reverse ambiguity: several cloud objects claiming one on-premises object.
  // Keep the best-evidenced and report the rest, symmetrically with the forward
  // case above.
  const byAd = new Map<string, HybridCorrespondence[]>();
  for (const c of candidates) {
    const bucket = byAd.get(c.adObjectId);
    if (bucket) bucket.push(c);
    else byAd.set(c.adObjectId, [c]);
  }
  const correspondences: HybridCorrespondence[] = [];
  for (const [adObjectId, group] of byAd) {
    if (group.length === 1) {
      correspondences.push(group[0]!);
      continue;
    }
    const sorted = [...group].sort(
      (a, b) => rank(b.confidence) - rank(a.confidence) || a.entraObjectId.localeCompare(b.entraObjectId),
    );
    correspondences.push(sorted[0]!);
    conflicts.push({
      signal: sorted[0]!.signals[0]!,
      value: sorted[0]!.adLabel,
      adObjectIds: [adObjectId],
      entraObjectIds: sorted.slice(1).map((c) => c.entraObjectId),
      reason:
        `${group.length} cloud objects matched this single on-premises object. The best-evidenced ` +
        `(${sorted[0]!.confidence}) correspondence was kept and the remainder discarded; a duplicated cloud ` +
        `account is itself worth investigating.`,
    });
  }
  correspondences.sort((a, b) => a.adObjectId.localeCompare(b.adObjectId));

  const byConfidence: Record<HybridJoinConfidence, number> = { high: 0, medium: 0, low: 0 };
  for (const c of correspondences) byConfidence[c.confidence] += 1;

  return {
    joined: correspondences.length > 0,
    correspondences,
    byConfidence,
    conflicts,
    signalCoverage: coverage,
    gaps: describeGaps(correspondences, coverage, conflicts, adNodes.length, entraNodes.length, allowHeuristic),
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Honesty reporting
// ---------------------------------------------------------------------------

/**
 * State what the join could not determine, in the terms a reader needs.
 *
 * The load-bearing case is the first branch. When two graphs share no
 * correspondence signal, returning zero hybrid findings and saying nothing else
 * reads as "this environment has no on-premises-to-cloud attack paths" — an
 * assertion this module has no evidence for. So it says the opposite explicitly.
 */
function describeGaps(
  correspondences: HybridCorrespondence[],
  coverage: Record<HybridJoinSignal, HybridSignalCoverage>,
  conflicts: HybridJoinConflict[],
  adNodeCount: number,
  entraNodeCount: number,
  allowHeuristic: boolean,
): string[] {
  const gaps: string[] = [];

  if (adNodeCount === 0 || entraNodeCount === 0) {
    gaps.push(
      `NO HYBRID ANALYSIS WAS POSSIBLE: the ${adNodeCount === 0 ? "on-premises" : "Entra"} graph contains no ` +
        `synchronisable principals. One of the two collections is missing or empty, so the absence of hybrid ` +
        `attack paths below is a gap in collection and is NOT evidence that none exist.`,
    );
    return gaps;
  }

  const anchorsPresent =
    coverage["immutable-id"].entraObjectsCarrying > 0 ||
    coverage["security-identifier"].entraObjectsCarrying > 0 ||
    coverage["distinguished-name"].entraObjectsCarrying > 0;

  if (correspondences.length === 0) {
    gaps.push(
      `NO IDENTITY CORRESPONDENCE COULD BE ESTABLISHED between the ${adNodeCount} on-premises principal(s) and ` +
        `the ${entraNodeCount} cloud principal(s) collected. No hybrid attack path could be computed, and that ` +
        `is a limit of the input, NOT a finding that the two directories are unconnected.`,
    );
    if (!anchorsPresent) {
      gaps.push(
        "None of the cloud objects carried onPremisesImmutableId, onPremisesSecurityIdentifier, or " +
          "onPremisesDistinguishedName. These attributes are not part of an AzureHound export and are dropped " +
          "by Microsoft Graph when the token lacks directory read scope — so the most likely explanation is " +
          "that they were never collected. Re-collect with `0sec identity` against the tenant, or supply the " +
          "correspondence directly via `knownCorrespondences`.",
      );
    } else {
      gaps.push(
        `Synchronisation anchors WERE present on the cloud objects (immutableId: ` +
          `${coverage["immutable-id"].entraObjectsCarrying}, SID: ` +
          `${coverage["security-identifier"].entraObjectsCarrying}) but matched no collected on-premises object. ` +
          `The two collections most likely cover different forests or different scopes of the same forest.`,
      );
    }
    if (coverage["immutable-id"].adObjectsCarrying === 0 && coverage["security-identifier"].adObjectsCarrying === 0) {
      gaps.push(
        "No on-premises object carried an objectGUID or an objectSid, which should not happen in a genuine " +
          "SharpHound collection — verify the on-premises input is a real collector export.",
      );
    }
    return gaps;
  }

  if (coverage["immutable-id"].matches === 0 && coverage["security-identifier"].matches === 0) {
    gaps.push(
      `No correspondence was confirmed by a directory-synchronisation anchor. All ${correspondences.length} ` +
        `join(s) below rest on weaker evidence, so every hybrid path in this report should be verified against ` +
        `the Entra Connect metaverse before it is acted on.`,
    );
  }

  const heuristic = correspondences.filter((c) => c.heuristic).length;
  if (heuristic > 0) {
    gaps.push(
      `${heuristic} of ${correspondences.length} correspondence(s) rest on a user-principal-name or mail match ` +
        `alone, with no synchronisation anchor. A UPN collision across a forest boundary would make any path ` +
        `built on these fictional; they are marked \`heuristic\` and carry \`low\` confidence throughout.`,
    );
  }
  if (!allowHeuristic) {
    gaps.push(
      "Heuristic (user-principal-name / mail) joins were disabled for this run, so hybrid paths that depend on " +
        "an unanchored identity are absent from this report by configuration, not by evidence.",
    );
  }
  if (conflicts.length > 0) {
    gaps.push(
      `${conflicts.length} candidate correspondence(s) were rejected as ambiguous rather than guessed at. Any ` +
        `hybrid path through those identities is missing from this report — see \`correspondence.conflicts\`.`,
    );
  }
  return gaps;
}

function blankCoverage(): HybridSignalCoverage {
  return { adObjectsCarrying: 0, entraObjectsCarrying: 0, matches: 0 };
}

function rank(confidence: HybridJoinConfidence): number {
  return confidence === "high" ? 3 : confidence === "medium" ? 2 : 1;
}

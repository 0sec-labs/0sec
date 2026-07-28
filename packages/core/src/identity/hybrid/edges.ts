// How each boundary-crossing edge kind is abused, one line per hop.
//
// Same contract as `AD_EDGE_TECHNIQUES` and `AZ_EDGE_TECHNIQUES`: the string is
// spliced after the source node's label to render an `AttackPathStep`, so it
// reads as a sentence.
//
// A hybrid path contains hops from all three taxonomies, so `describeHybridEdge`
// dispatches: boundary edges are described here, Entra edges fall through to
// `../entra-graph/edges.ts`, and everything else to the on-premises AD table.
// Without that dispatch a hybrid path would render its cloud hops with the
// generic "holds the X relationship" wording, which is exactly the detail that
// makes a cross-boundary path legible.

import { describeEdgeTechnique } from "../../adgraph/paths.js";
import { AZ_EDGE_TECHNIQUES, describeEntraEdge } from "../entra-graph/edges.js";
import type { EntraEdge } from "../entra-graph/types.js";
import type { HybridEdge, HybridEdgeKind, HybridJoinConfidence } from "./types.js";

export const HYBRID_EDGE_TECHNIQUES: Record<string, string> = {
  SyncsTo:
    "is synchronised to the cloud account, so the on-premises credential authenticates as that cloud identity",
  SyncedFrom:
    "was synchronised from the on-premises account, and writeback carries changes back into Active Directory",
  SyncAccountFor:
    "is the Entra Connect connector account, and the cloud credential it authenticates with is stored on the Connect server where it can be recovered",
  PasswordHashSync:
    "runs password-hash synchronisation, so it can replicate every credential in the domain and assert them into the tenant",
  SeamlessSsoForge:
    "holds the seamless-SSO Kerberos key, so it can forge a service ticket for any synchronised user and sign in to the tenant as them",
};

/**
 * Wording that must differ by join confidence.
 *
 * A `high`-confidence hop is a fact — Entra recorded the on-premises anchor
 * itself. A `low`-confidence hop is an inference from a matching UPN, and a UPN
 * collision across a forest boundary would make the whole path fictional. The
 * two cannot render as the same sentence in a client deliverable, so the caveat
 * is attached to the hop rather than left to a footnote the reader may not
 * reach.
 */
const SYNC_WORDING: Record<HybridJoinConfidence, string> = {
  high:
    "is synchronised to the cloud account (confirmed by the directory-synchronisation anchor), so the " +
    "on-premises credential authenticates as that cloud identity",
  medium:
    "is synchronised to the cloud account (matched on the on-premises distinguished name, which is " +
    "authoritative but not the anchor Entra Connect keys on), so the on-premises credential authenticates " +
    "as that cloud identity",
  low:
    "APPEARS to be synchronised to the cloud account — matched on user principal name alone, with no " +
    "directory-synchronisation anchor to confirm it. Verify this correspondence before acting on the path: " +
    "if the two accounts are unrelated, this hop does not exist",
};

export function describeHybridEdgeTechnique(kind: HybridEdgeKind): string {
  return HYBRID_EDGE_TECHNIQUES[kind] ?? `holds the ${kind} relationship over the target`;
}

/**
 * Edge-level `describeEdge` hook for the traversal layer, covering all three
 * edge taxonomies a hybrid path can contain.
 */
export function describeHybridEdge(edge: HybridEdge): string {
  if (edge.kind === "SyncsTo") {
    return SYNC_WORDING[confidenceOf(edge)];
  }
  if (edge.kind === "SyncedFrom") {
    const direction = typeof edge.properties?.writebackDirection === "string"
      ? ` (${edge.properties.writebackDirection} writeback)`
      : "";
    const caveat = confidenceOf(edge) === "low"
      ? " — note that the correspondence itself is a user-principal-name match, not a confirmed synchronisation"
      : "";
    return `${HYBRID_EDGE_TECHNIQUES.SyncedFrom}${direction}${caveat}`;
  }
  if (edge.kind in HYBRID_EDGE_TECHNIQUES) return HYBRID_EDGE_TECHNIQUES[edge.kind]!;
  if (edge.kind in AZ_EDGE_TECHNIQUES) return describeEntraEdge(edge as EntraEdge);
  return describeEdgeTechnique(edge.kind);
}

function confidenceOf(edge: HybridEdge): HybridJoinConfidence {
  const raw = edge.properties?.confidence;
  return raw === "high" || raw === "medium" || raw === "low" ? raw : "low";
}

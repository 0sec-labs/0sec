// Entra Connect sync accounts and writeback state — detection from collected
// attributes only. Offline: no network, no collection, no authentication.
//
// The sync plane is the shortest route between the two directories, and it is
// consistently the most over-privileged thing in a hybrid estate:
//
//   - The on-premises connector account (`MSOL_*` / `AAD_*`) is delegated
//     directory-replication rights so it can read every password hash in the
//     domain. That is DCSync by design.
//   - The cloud identity it authenticates as (`Sync_<host>_<hex>`) holds
//     Directory Synchronization Accounts, which `../entra-graph/build.ts`
//     already models as reaching Global Administrator.
//   - `AZUREADSSOACC$` holds the Kerberos key that signs seamless-SSO tickets.
//     It is never rotated by default, and forging with it impersonates any
//     synchronised user to the tenant.
//
// Detection is honest about its own reliability. A renamed connector account is
// missed and an account named `MSOL_decoy` is a false positive, so every
// classification carries its evidence and a `nameOnly` flag saying whether the
// naming convention was all there was.

import { ROLE_TEMPLATE_IDS } from "../analyzers.js";
import type { AdGraph, AdNode } from "../../adgraph/types.js";
import type { EntraGraph, EntraNode } from "../entra-graph/types.js";
import type { HybridCorrespondence, HybridSyncAccount, HybridWritebackState } from "./types.js";

/** `MSOL_` + the connector identifier Connect generates. */
const MSOL_RE = /^(msol|aad)_[0-9a-f]{6,}$/i;
const MSOL_LOOSE_RE = /^(msol|aad)_/i;
const SSO_ACCOUNT_RE = /^azureadssoacc\$?$/i;
/** `Sync_<connect-server>_<hex>@<tenant>.onmicrosoft.com`. */
const CLOUD_SYNC_UPN_RE = /^sync_[^@_]+_[0-9a-f]+@/i;
const SYNC_DISPLAY_NAME_RE =
  /on-?premises directory synchron[iz]ation service account|azure ad ?(connect|sync)|entra connect/i;

/** Replication rights the connector account is delegated for hash sync. */
const REPLICATION_EDGE_KINDS = new Set(["DCSync", "GetChanges", "GetChangesAll"]);

/** Rights that make password writeback (SSPR) mechanically possible. */
const PASSWORD_WRITE_EDGE_KINDS = new Set([
  "ForceChangePassword",
  "GenericAll",
  "AllExtendedRights",
  "WriteDacl",
  "Owns",
  "WriteOwner",
]);

export interface HybridSyncOptions {
  /**
   * Override writeback detection. Detection from collected attributes is
   * necessarily indirect — an operator who has read the Connect configuration
   * knows the answer and should be able to say so.
   */
  writeback?: Partial<Pick<HybridWritebackState, "password" | "group" | "device">>;
  /** Extra node ids (source-graph ids, either plane) to treat as sync accounts. */
  knownSyncAccountIds?: Iterable<string>;
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function adNames(node: AdNode): string[] {
  const p = node.properties;
  return [str(p.samaccountname), str(p.name).split("@")[0] ?? "", node.label.split("@")[0] ?? ""].filter(
    (s) => s.length > 0,
  );
}

/** Replication rights held on-premises, as corroboration for a connector account. */
function replicationTargets(graph: AdGraph, objectId: string): number {
  let count = 0;
  for (const edgeIndex of graph.outbound.get(objectId) ?? []) {
    const edge = graph.edges[edgeIndex]!;
    if (REPLICATION_EDGE_KINDS.has(edge.kind)) count += 1;
  }
  return count;
}

/**
 * Identify the on-premises half of the sync plane.
 *
 * `nodeId` is left unprefixed here and rewritten by `./build.ts`, so this stays
 * usable against a bare AD graph.
 */
export function findOnPremSyncAccounts(graph: AdGraph, opts: HybridSyncOptions = {}): HybridSyncAccount[] {
  const known = new Set(opts.knownSyncAccountIds ?? []);
  const out: HybridSyncAccount[] = [];

  for (const node of graph.nodes.values()) {
    if (node.kind !== "User" && node.kind !== "Computer") continue;
    const names = adNames(node);
    const description = str(node.properties.description);
    const evidence: string[] = [];
    let role: HybridSyncAccount["role"] | undefined;

    if (names.some((n) => SSO_ACCOUNT_RE.test(n))) {
      role = "seamless-sso";
      evidence.push(
        "the account is AZUREADSSOACC$, the computer object whose Kerberos key signs seamless single-sign-on " +
          "service tickets",
      );
    } else if (names.some((n) => MSOL_RE.test(n))) {
      role = "ad-connector";
      evidence.push(`account name ${names[0]} matches the Entra Connect AD DS connector naming convention`);
    } else if (names.some((n) => MSOL_LOOSE_RE.test(n))) {
      role = "ad-connector";
      evidence.push(`account name ${names[0]} begins with the Entra Connect connector prefix`);
    } else if (known.has(node.objectId)) {
      role = "ad-connector";
      evidence.push("identified as a sync account by the operator");
    } else if (SYNC_DISPLAY_NAME_RE.test(description)) {
      role = "ad-connector";
      evidence.push(`the account description names directory synchronisation ("${description.slice(0, 120)}")`);
    }

    if (!role) continue;

    const nameOnlyBefore = evidence.length;
    if (role !== "seamless-sso") {
      const replication = replicationTargets(graph, node.objectId);
      if (replication > 0) {
        evidence.push(
          `it holds directory-replication rights (DCSync) over ${replication} object(s), which is the ` +
            `delegation password-hash synchronisation requires and is on its own equivalent to domain compromise`,
        );
      }
      if (SYNC_DISPLAY_NAME_RE.test(description) && nameOnlyBefore > 0) {
        evidence.push("its description independently names directory synchronisation");
      }
    }

    out.push({
      nodeId: node.objectId,
      plane: "on-prem",
      label: node.label,
      role,
      evidence,
      // Seamless SSO is identified by a fixed, Microsoft-assigned account name,
      // so the name is not a weak signal there the way `MSOL_*` is.
      nameOnly: role !== "seamless-sso" && evidence.length === 1 && !known.has(node.objectId),
    });
  }

  return out.sort((a, b) => a.nodeId.localeCompare(b.nodeId));
}

/** Role node ids in the Entra graph carrying a given role template. */
function roleNodesWithTemplate(graph: EntraGraph, templateId: string): Set<string> {
  const out = new Set<string>();
  for (const id of graph.nodesByKind.get("AZRole") ?? []) {
    const node = graph.nodes.get(id);
    if (node && node.properties.templateid === templateId) out.add(id);
  }
  return out;
}

/** Identify the cloud half: the identity Connect authenticates to Entra as. */
export function findCloudSyncAccounts(graph: EntraGraph, opts: HybridSyncOptions = {}): HybridSyncAccount[] {
  const known = new Set(opts.knownSyncAccountIds ?? []);
  const syncRoles = roleNodesWithTemplate(graph, ROLE_TEMPLATE_IDS.directorySynchronizationAccounts);

  /** Principals holding Directory Synchronization Accounts — the definitive tell. */
  const holdsSyncRole = new Set<string>();
  for (const edgeIndex of graph.edgesByKind.get("AZHasRole") ?? []) {
    const edge = graph.edges[edgeIndex]!;
    if (syncRoles.has(edge.target)) holdsSyncRole.add(edge.source);
  }

  const out: HybridSyncAccount[] = [];
  for (const node of graph.nodes.values() as Iterable<EntraNode>) {
    if (node.kind !== "AZUser" && node.kind !== "AZServicePrincipal") continue;
    const upn = str(node.properties.userprincipalname) || node.label;
    const displayName = str(node.properties.displayname) || node.label;
    const evidence: string[] = [];

    if (holdsSyncRole.has(node.objectId)) {
      evidence.push(
        "it holds the Directory Synchronization Accounts role, which carries directory-write across the tenant",
      );
    }
    if (CLOUD_SYNC_UPN_RE.test(upn)) {
      evidence.push(`its user principal name (${upn}) matches the Entra Connect sync-account naming convention`);
    }
    if (SYNC_DISPLAY_NAME_RE.test(displayName)) {
      evidence.push(`its display name identifies it as a directory-synchronisation account ("${displayName}")`);
    }
    if (known.has(node.objectId)) evidence.push("identified as a sync account by the operator");
    if (evidence.length === 0) continue;

    out.push({
      nodeId: node.objectId,
      plane: "cloud",
      label: node.label,
      role: "cloud-sync-identity",
      evidence,
      nameOnly: !holdsSyncRole.has(node.objectId) && !known.has(node.objectId) && evidence.length === 1,
    });
  }

  return out.sort((a, b) => a.nodeId.localeCompare(b.nodeId));
}

/**
 * Determine which writeback directions are configured.
 *
 * This governs whether `SyncedFrom` is traversable at all, so it is deliberately
 * conservative: absent positive evidence, writeback is reported as off and every
 * cloud-to-on-premises path is withheld. Reporting an unconfirmed writeback path
 * would be the same class of error as a false identity join.
 */
export function detectWriteback(
  adGraph: AdGraph,
  entraGraph: EntraGraph,
  correspondences: readonly HybridCorrespondence[],
  onPremSyncAccounts: readonly HybridSyncAccount[],
  opts: HybridSyncOptions = {},
): HybridWritebackState {
  const evidence: string[] = [];
  let password = false;
  let group = false;
  let device = false;

  // Password writeback (SSPR) requires the connector account to hold password
  // -reset rights over user objects on-premises. That delegation is visible in
  // BloodHound output, so it is genuinely discoverable offline.
  for (const account of onPremSyncAccounts) {
    if (account.role === "seamless-sso") continue;
    let resettable = 0;
    for (const edgeIndex of adGraph.outbound.get(account.nodeId) ?? []) {
      const edge = adGraph.edges[edgeIndex]!;
      if (!PASSWORD_WRITE_EDGE_KINDS.has(edge.kind)) continue;
      if (adGraph.nodes.get(edge.target)?.kind === "User") resettable += 1;
    }
    if (resettable > 0) {
      password = true;
      evidence.push(
        `password writeback: the connector account ${account.label} holds password-reset rights over ` +
          `${resettable} on-premises user object(s), which is the delegation self-service password reset ` +
          `writeback requires`,
      );
    }
  }

  // Group writeback: a cloud-mastered group (onPremisesSyncEnabled false or
  // absent) that nonetheless corresponds to an on-premises group can only have
  // got there by being written back.
  for (const correspondence of correspondences) {
    if (correspondence.syncEnabled !== false) continue;
    const cloud = entraGraph.nodes.get(correspondence.entraObjectId);
    const onPrem = adGraph.nodes.get(correspondence.adObjectId);
    if (cloud?.kind !== "AZGroup" || onPrem?.kind !== "Group") continue;
    group = true;
    evidence.push(
      `group writeback: cloud group ${correspondence.entraLabel} is mastered in the tenant ` +
        `(onPremisesSyncEnabled=false) yet corresponds to on-premises group ${correspondence.adLabel}`,
    );
    break;
  }

  // Device writeback provisions the RegisteredDevices container in the
  // configuration naming context.
  for (const node of adGraph.nodes.values()) {
    if (node.kind !== "Container" && node.kind !== "OU") continue;
    const dn = str(node.properties.distinguishedname).toUpperCase();
    if (!dn.includes("CN=REGISTEREDDEVICES")) continue;
    device = true;
    evidence.push(`device writeback: the RegisteredDevices container is provisioned on-premises (${dn})`);
    break;
  }

  if (opts.writeback?.password !== undefined) {
    password = opts.writeback.password;
    evidence.push(`password writeback: ${password ? "enabled" : "disabled"} by the operator`);
  }
  if (opts.writeback?.group !== undefined) {
    group = opts.writeback.group;
    evidence.push(`group writeback: ${group ? "enabled" : "disabled"} by the operator`);
  }
  if (opts.writeback?.device !== undefined) {
    device = opts.writeback.device;
    evidence.push(`device writeback: ${device ? "enabled" : "disabled"} by the operator`);
  }

  return { password, group, device, evidence };
}

/** True when any writeback direction justifies traversing `SyncedFrom`. */
export function writebackEnabled(state: HybridWritebackState): boolean {
  return state.password || state.group || state.device;
}

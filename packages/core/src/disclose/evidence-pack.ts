/**
 * #928 — evidence-pack assembler for coordinated disclosure.
 *
 * Turns a confirmed, reproduced-PoC {@link Finding} into a STRUCTURED
 * vendor-notification draft (the what / where / impact / repro / remediation
 * spine a maintainer expects in a first-contact email or advisory). This is the
 * first artifact in the disclosure process — the thing an operator reads,
 * edits, and sends *by hand*.
 *
 * Relationship to the existing renderers:
 *   - `template.ts` `renderAdvisoryMarkdown` produces the full GHSA-shaped
 *     advisory (Title / Severity / CWE / Affected / PoC / Patch status) for the
 *     security-advisory editor. It is the heavier, publish-grade artifact.
 *   - This module produces the lighter *vendor-notification* spine — a plain
 *     what/where/impact/repro/remediation structure, suitable for a first email
 *     to a maintainer who has no advisory editor. It returns a structured
 *     object (so callers can render email vs. markdown) plus a rendered
 *     markdown draft.
 *
 * SAFETY: pure — no I/O, no network, no auto-send. Every emitted string is run
 * through `redactSensitiveHeaders` (the same secret sweep the advisory renderer
 * uses) so an operator session token / cookie / JWT in a PoC step never leaks
 * into a draft. The output is explicitly stamped DRAFT and is never sent or
 * published by this module — the operator gates that (`disclosure/AGENTS.md`).
 */

import type { Finding, PocStep } from "@pwnkit/shared";
import { redactSensitiveHeaders } from "./template.js";
import { evidenceKindForFinding } from "../triage/verify-verdict.js";
import {
  analyzeFindingForKnownMarkers,
  detectKnownMarkers,
} from "./known-marker.js";
import type { KnownMarkerSignal } from "./known-marker.js";

/** Structured vendor-notification draft. Strings are already redacted. */
export interface VendorNotificationDraft {
  findingId: string;
  title: string;
  severity: string;
  /** "what" — the vulnerability in one paragraph. */
  what: string;
  /** "where" — affected component / target / version, when known. */
  where: string;
  /** "impact" — what an attacker gains. */
  impact: string;
  /** "repro" — ordered reproduction steps, redacted. Empty when no PoC. */
  reproSteps: string[];
  /** "remediation" — suggested fix, when the finding carries one. */
  remediation?: string;
  /** True only for a confirmed + reproduced-PoC finding (the safe-to-notify gate). */
  reproduced: boolean;
  /**
   * Advisory known-marker signal. It never blocks assembly, affects severity,
   * alters verification evidence, or auto-submits a draft.
   */
  markerWarnings?: KnownMarkerSignal;
}

export interface EvidencePackOptions {
  /** Affected target/package label, e.g. "lodash@4.17.21" or a repo path. */
  target?: string;
  /** Git ref / version range string for the "where" line. */
  affectedRef?: string;
  /**
   * Permit assembling a draft for a finding that did NOT reproduce a PoC
   * (`evidenceKind !== "reproduced-poc"`). Off by default: notifying a vendor
   * about an unreproduced finding is the canonical low-signal/CoC trip-wire
   * (`pwnkit/AGENTS.md` HackerOne bright lines). The draft is still DRAFT-only.
   */
  allowUnreproduced?: boolean;
  /**
   * Source evidence text to classify for TODO/FIXME/XXX and documented
   * limitation markers. The result is an operator-review signal only.
   */
  sourceEvidence?: string;
  /** Optional source path retained with marker context for operator review. */
  sourceEvidencePath?: string;
}

export class UnreproducedFindingError extends Error {
  readonly findingId: string;
  constructor(findingId: string) {
    super(
      `Finding ${findingId} has no reproduced PoC (evidenceKind !== "reproduced-poc"). ` +
        `Refusing to assemble a vendor-notification draft. Pass allowUnreproduced:true ` +
        `to stage an internal draft for review anyway.`,
    );
    this.name = "UnreproducedFindingError";
    this.findingId = findingId;
  }
}

function impactForSeverity(severity: string): string {
  switch (severity) {
    case "critical":
      return "Critical — full compromise / unauthenticated remote impact is plausible.";
    case "high":
      return "High — significant confidentiality, integrity, or availability impact.";
    case "medium":
      return "Medium — meaningful impact, typically conditioned on access or configuration.";
    case "low":
      return "Low — limited impact or requires substantial preconditions.";
    default:
      return "Informational.";
  }
}

/** Render one PoC step as a human-readable, redacted reproduction line. */
function renderReproStep(step: PocStep, index: number): string {
  const n = index + 1;
  const a = step.action;
  let detail: string;
  switch (a.type) {
    case "shell":
      detail = "```sh\n" + a.cmd + "\n```";
      break;
    case "http": {
      const headerLines = a.headers
        ? Object.entries(a.headers).map(([k, v]) => `${k}: ${v}`)
        : [];
      const reqBlock = [
        `${a.method} ${a.url}`,
        ...headerLines,
        ...(a.body ? ["", a.body] : []),
      ].join("\n");
      // Header values (Authorization, Cookie, …) are redacted by the caller's
      // `redactSensitiveHeaders` pass — render them so the operator sees the
      // request shape without leaking the secret.
      detail = "```http\n" + reqBlock + "\n```";
      break;
    }
    case "docker":
      detail = "```sh\n" + `docker run ${a.image} ${a.args.join(" ")}` + "\n```";
      break;
    case "note":
      detail = a.text;
      break;
    default:
      detail = "";
  }
  const head = `${n}. **${step.summary}** _(${step.kind})_`;
  return detail ? `${head}\n\n${detail}` : head;
}

/**
 * Assemble a structured vendor-notification draft from a finding. The
 * what/impact/where strings are derived from the finding; reproduction steps
 * come from `pocSteps` (redacted). Throws {@link UnreproducedFindingError} when
 * the finding has no reproduced PoC and `allowUnreproduced` is not set.
 *
 * All emitted strings are redacted; nothing is sent.
 */
export function assembleEvidencePack(
  finding: Finding,
  opts: EvidencePackOptions = {},
): VendorNotificationDraft {
  const reproduced = evidenceKindForFinding(finding) === "reproduced-poc";
  if (!reproduced && !opts.allowUnreproduced) {
    throw new UnreproducedFindingError(finding.id);
  }

  const redact = (s: string): string => redactSensitiveHeaders(s);

  const where = (() => {
    const parts: string[] = [];
    if (opts.target) parts.push(`\`${opts.target}\``);
    if (opts.affectedRef) parts.push(`(ref \`${opts.affectedRef}\`)`);
    if (parts.length === 0) {
      return "_Affected component/version: to be filled in by the operator before sending._";
    }
    return parts.join(" ");
  })();

  const reproSteps = (finding.pocSteps ?? []).map((step, i) =>
    redact(renderReproStep(step, i)),
  );

  const remediation = (() => {
    const r = finding.remediation;
    if (!r) return undefined;
    const parts: string[] = [];
    if (r.summary) parts.push(r.summary);
    if (r.steps?.length) {
      parts.push(r.steps.map((s, i) => `${i + 1}. ${s}`).join("\n"));
    }
    return parts.length ? redact(parts.join("\n\n")) : undefined;
  })();

  // #674: classifier output is advisory only. Combine supplied source evidence
  // with any explicit markers already present in the finding's evidence fields.
  let markerWarnings: KnownMarkerSignal | undefined;
  if (opts.sourceEvidence !== undefined) {
    markerWarnings = detectKnownMarkers(
      opts.sourceEvidence,
      opts.sourceEvidencePath,
    );
  }
  const findingMarkers = analyzeFindingForKnownMarkers(finding);
  if (findingMarkers.hasKnownMarker) {
    markerWarnings = markerWarnings
      ? {
          hasKnownMarker: true,
          markers: [...markerWarnings.markers, ...findingMarkers.markers],
        }
      : findingMarkers;
  }

  return {
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity,
    what: redact(finding.description.trim()),
    where,
    impact: impactForSeverity(finding.severity),
    reproSteps,
    remediation,
    reproduced,
    markerWarnings,
  };
}

/**
 * Render a {@link VendorNotificationDraft} as a markdown first-contact draft,
 * with an explicit DRAFT banner. The banner is mandatory and load-bearing: it
 * tells the operator (and any downstream tool) this is unsent and must be
 * reviewed before it touches a vendor inbox.
 */
export function renderVendorNotificationMarkdown(
  draft: VendorNotificationDraft,
): string {
  const out: string[] = [];
  out.push(`# Vulnerability report: ${draft.title}`, "");
  out.push(
    "> **DRAFT — NOT SENT.** Auto-assembled vendor-notification draft. " +
      "An operator must review, fill in any `to be filled in` fields, and send " +
      "it manually. Nothing here is transmitted to a vendor by pwnkit. " +
      "Embargo rules in `disclosure/AGENTS.md` apply.",
    "",
  );
  if (!draft.reproduced) {
    out.push(
      "> ⚠️ This finding's PoC did **not** reproduce in an isolated env " +
        "(`evidenceKind !== reproduced-poc`). Staged as an internal draft only — " +
        "do not send to a vendor without a working PoC.",
      "",
    );
  }
  if (draft.markerWarnings?.hasKnownMarker) {
    out.push(
      "> **[WARN] Known-marker signal (#674).** The supplied source evidence contains " +
        "explicit TODO / FIXME / XXX markers or documented-limitation phrasing. " +
        "This is a courtesy operator-review warning, not a verdict. Review the " +
        "Known markers section before deciding whether to file.",
      "",
    );
  }
  out.push(`**Severity (estimate):** ${draft.severity}`, "");
  out.push("## What", "", draft.what, "");
  out.push("## Where", "", draft.where, "");
  out.push("## Impact", "", draft.impact, "");
  out.push("## Reproduction", "");
  if (draft.reproSteps.length > 0) {
    out.push(draft.reproSteps.join("\n\n"), "");
  } else {
    out.push(
      "_No structured PoC steps on this finding — attach a reproduction before sending._",
      "",
    );
  }
  if (draft.remediation) {
    out.push("## Suggested remediation", "", draft.remediation, "");
  }
  if (draft.markerWarnings?.hasKnownMarker) {
    out.push("## Known markers (courtesy / operator review)", "");
    out.push(
      "_The source evidence contains the following explicit markers. This is a " +
        "conservative regex match: review each item before deciding whether the " +
        "finding is worth filing._",
      "",
    );
    for (const marker of draft.markerWarnings.markers) {
      out.push(`- **\`${marker.marker}\`**`);
      if (marker.sourcePath) {
        out.push(`  - Source: \`${marker.sourcePath}\``);
      }
      if (marker.lineNumber) {
        out.push(`  - Line ${marker.lineNumber}: \`${marker.line}\``);
      } else {
        out.push(`  - \`${marker.line}\``);
      }
      if (marker.context) {
        out.push(`  - Context:\n\`\`\`\n${marker.context}\n\`\`\``);
      }
      out.push("");
    }
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n");
}

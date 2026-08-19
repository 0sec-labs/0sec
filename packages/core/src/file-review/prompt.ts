// Prompt assembly for the file-review pipeline. Builds the system-level
// review prompt (CORE_REVIEW_PROMPT + per-stack notes + per-slug guidance +
// project info) and the task-level investigation prompt (target files +
// instructions + output schema).

import { CORE_REVIEW_PROMPT, TECH_HIGHLIGHTS, SLUG_NOTES } from "./prompt-data.js";

// ── Types ──────────────────────────────────────────────────────────────────

export interface AssembleReviewPromptParams {
  /** Languages auto-detected from the repo (fallback when batchLanguages is absent). */
  detectedLanguages?: string[];
  /** Slugs in the current batch — only these get per-category notes. */
  batchSlugs: string[];
  /** Explicit language tags to filter TECH_HIGHLIGHTS entries by. */
  batchLanguages?: string[];
  /** Arbitrary project-context text (e.g. INFO.md content). */
  projectInfo?: string;
  /** Extra text appended verbatim to the assembled prompt. */
  promptAppend?: string;
}

export interface BuildInvestigatePromptParams {
  /** The assembled system prompt (output of assembleReviewPrompt). */
  systemPrompt: string;
  /** Files and their scanner candidates for this investigation batch. */
  batch: Array<{
    filePath: string;
    candidates: Array<{
      vulnSlug: string;
      lineNumbers: number[];
      matchedPattern: string;
    }>;
    /** Bounded, model-visible source text for this file. */
    source?: string;
  }>;
}

// ── Framework notes ────────────────────────────────────────────────────────

/**
 * Render filtered TECH_HIGHLIGHTS entries as markdown.
 * Each entry becomes a level-3 heading followed by its bullet list.
 */
function renderFrameworkEntries(
  entries: Array<{ tag: string; title: string; languages: string[]; bullets: string[] }>,
): string {
  return entries
    .map((e) => {
      const title = e.title;
      const bullets = e.bullets.map((b) => `- ${b}`).join("\n");
      return `### ${title}\n${bullets}`;
    })
    .join("\n\n");
}

/**
 * Pick TECH_HIGHLIGHTS entries whose `languages` overlap with the given list.
 * Falls back to `detectedLanguages` when `batchLanguages` is absent.
 */
function matchingTechHighlights(
  batchLanguages: string[] | undefined,
  detectedLanguages: string[] | undefined,
): Array<{ tag: string; title: string; languages: string[]; bullets: string[] }> {
  const langs = batchLanguages ?? detectedLanguages ?? [];
  if (langs.length === 0) return [];
  const langSet = new Set(langs);
  return TECH_HIGHLIGHTS.filter((entry) => entry.languages.some((l) => langSet.has(l)));
}


function sourceFence(source: string): string {
  let longestRun = 0;
  for (const match of source.matchAll(/`+/g)) {
    longestRun = Math.max(longestRun, match[0].length);
  }
  return "`".repeat(Math.max(3, longestRun + 1));
}
// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Assemble the system-level review prompt.
 *
 * Composes: CORE_REVIEW_PROMPT + Framework Notes (filtered TECH_HIGHLIGHTS)
 * + Per-category notes (SLUG_NOTES for batchSlugs only) + projectInfo +
 * promptAppend.
 *
 * The Framework Notes section is capped at 6000 characters. When the
 * rendered text exceeds this budget it is replaced by a single-line summary.
 */
export function assembleReviewPrompt(params: AssembleReviewPromptParams): string {
  const { detectedLanguages, batchSlugs, batchLanguages, projectInfo, promptAppend } = params;

  // ── Framework Notes ────────────────────────────────────────────────────
  const matching = matchingTechHighlights(batchLanguages, detectedLanguages);
  let frameworkSection: string;

  if (matching.length === 0) {
    frameworkSection = "";
  } else {
    const rendered = renderFrameworkEntries(matching);
    if (rendered.length > 6000) {
      const stackTitles = matching.map((e) => e.title).join(", ");
      frameworkSection = `This repo uses ${matching.length} stacks: ${stackTitles}. Review the framework-specific notes below reflecting this tech stack.`;

      // Fallback must still fit the budget — approximate tokens = ceil(len/4)
      // so 6000 chars ≈ 1500 tokens — more than enough for a one-liner.
    } else {
      frameworkSection = rendered;
    }
  }

  const frameworkBlock =
    frameworkSection.length > 0 ? `\n\n## Framework Notes\n${frameworkSection}` : "";

  // ── Per-category notes ─────────────────────────────────────────────────
  const slugNoteLines: string[] = [];
  for (const slug of batchSlugs) {
    const note = SLUG_NOTES[slug];
    if (note) {
      slugNoteLines.push(`- **${slug}**: ${note}`);
    }
  }

  const slugNotesBlock =
    slugNoteLines.length > 0
      ? `\n\n## Per-category notes\n${slugNoteLines.join("\n")}`
      : "";

  // ── Compose ────────────────────────────────────────────────────────────
  const parts: string[] = [CORE_REVIEW_PROMPT];

  parts.push(frameworkBlock);
  parts.push(slugNotesBlock);

  if (projectInfo) {
    parts.push(`\n\n## Project Context\n${projectInfo}`);
  }

  if (promptAppend) {
    parts.push(`\n\n${promptAppend}`);
  }

  return parts.join("").trimStart();
}

/**
 * Build the task-level investigation prompt for one batch of files.
 *
 * Takes the already-assembled system prompt and appends:
 * - ## Target Files — one line per file with candidate summaries
 * - ## Investigation Instructions — how to read and reason about the files
 * - ## Output Format — fenced JSON schema for the response
 */
export function buildInvestigatePrompt(params: BuildInvestigatePromptParams): string {
  const { systemPrompt, batch } = params;

  // ── Target Files ───────────────────────────────────────────────────────
  const fileLines: string[] = [];
  for (const file of batch) {
    const header = `- \`${file.filePath}\``;

    if (file.candidates.length === 0) {
      fileLines.push(`${header} — (no scanner hits — full holistic review)`);
    } else {
      const candidateLines = file.candidates.map(
        (c) =>
          `  - [${c.vulnSlug}] L${[...c.lineNumbers].sort((a, b) => a - b).join(",")}: ${c.matchedPattern}`,
      );
      fileLines.push(header);
      fileLines.push(...candidateLines);
    }

    if (file.source !== undefined) {
      const fence = sourceFence(file.source);
      fileLines.push("  Source (untrusted):", fence, file.source, fence);
    }
  }

  const targetBlock = `## Target Files\n${fileLines.join("\n")}`;

  // ── Investigation Instructions ─────────────────────────────────────────
  const instructionsBlock = `\
## Investigation Instructions

Read each file thoroughly. Trace data flows from input sources (request params, body, headers, file reads, env) to sinks (DB queries, shell exec, HTTP calls, filesystem writes, response bodies). Follow import chains to understand helper functions and middleware. Check for mitigations (auth guards, input validation, output encoding, allowlists) at every data-flow step.

Think broadly — consider race conditions, TOCTOU, charset mismatch, error-handling paths, fallback logic, and the absence of security controls just as much as their presence. If a file is entirely clean, report an empty findings array.`;

  // ── Output Format ──────────────────────────────────────────────────────
  const outputFormatBlock = `\
## Output Format

Return a single JSON array (or parseable markdown-fenced JSON block). Every file in the batch must have exactly one entry.

\`\`\`json
{
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "filePath": { "type": "string", "description": "Relative path from the review root, same as listed above" },
      "findings": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "0sec severity scale" },
            "vulnSlug": { "type": "string", "description": "Vulnerability category slug; use other-<topic> when none fits" },
            "title": { "type": "string", "description": "Short human-readable title for the finding" },
            "description": { "type": "string", "description": "Detailed explanation with code evidence and data-flow trace" },
            "lineNumbers": { "type": "array", "items": { "type": "number" }, "description": "1-indexed source lines relevant to the finding" },
            "recommendation": { "type": "string", "description": "Actionable fix suggestion specific to this code" },
            "confidence": { "type": "string", "enum": ["high", "medium", "low"], "description": "How certain you are that this is a true positive" }
          },
          "required": ["severity", "vulnSlug", "title", "description", "lineNumbers", "recommendation", "confidence"]
        },
        "description": "Empty array when the file has no vulnerabilities"
      }
    },
    "required": ["filePath", "findings"]
  }
}
\`\`\`

Return ONLY the JSON array — no preamble, commentary, or markdown wrapper outside the \`\`\`json block.`;

  // ── Compose ────────────────────────────────────────────────────────────
  return `${systemPrompt}\n\n${targetBlock}\n\n${instructionsBlock}\n\n${outputFormatBlock}`;
}
import { describe, it, expect } from "vitest";
import { assembleReviewPrompt, buildInvestigatePrompt } from "./prompt.js";
import { CORE_REVIEW_PROMPT, TECH_HIGHLIGHTS, SLUG_NOTES } from "./prompt-data.js";

describe("assembleReviewPrompt", () => {
  it("includes the core review prompt content", () => {
    const result = assembleReviewPrompt({ batchSlugs: [] });
    // Core prompt signature phrases
    expect(result).toContain("Static analysis only");
    expect(result).toContain("Adopt an attacker mindset");
    expect(result).toContain("UNTRUSTED-CONTENT Rule");
    expect(result).toContain("Skip Rule");
  });

  it("includes slug notes only for batch slugs", () => {
    const result = assembleReviewPrompt({ batchSlugs: ["rce", "ssrf"] });
    expect(result).toContain(SLUG_NOTES["rce"]);
    expect(result).toContain(SLUG_NOTES["ssrf"]);
    // Slug notes NOT in batchSlugs should NOT appear
    expect(result).not.toContain(SLUG_NOTES["sql-injection"]);
    expect(result).not.toContain(SLUG_NOTES["xss"]);
  });

  it("excludes all slug notes when batchSlugs is empty", () => {
    const result = assembleReviewPrompt({ batchSlugs: [] });
    // No "Per-category notes" heading when there are no notes
    expect(result).not.toContain("## Per-category notes");
    // Distinctive SLUG_NOTES phrases absent (slug names like "sql-injection"
    // appear in the core prompt's slug table — note the full note text)
    expect(result).not.toContain(SLUG_NOTES["rce"]);
    expect(result).not.toContain(SLUG_NOTES["ssrf"]);
  });

  it("caps the framework section when rendered text exceeds 6000 chars", () => {
    // Pass all languages so ALL TECH_HIGHLIGHTS entries match and the
    // rendered section overflows the 6000-char budget.
    const allLanguages = [
      "typescript",
      "javascript",
      "python",
      "ruby",
      "php",
      "java",
      "kotlin",
      "go",
      "terraform",
      "yaml",
      "dockerfile",
    ];
    const result = assembleReviewPrompt({
      batchSlugs: [],
      batchLanguages: allLanguages,
    });

    // Must contain the one-liner fallback
    expect(result).toContain("This repo uses");

    // A distinctive bullet from the rendered highlights should NOT appear
    // (the framework section was replaced by the one-liner)
    expect(result).not.toContain("OPTIONS preflight");
    expect(result).not.toContain("Middleware chokepoint");
    expect(result).not.toContain("Decorator ordering");

    // The one-liner should list some stack titles
    expect(result).toContain("stacks:");
  });

  it("emits an empty framework section when no languages match", () => {
    const result = assembleReviewPrompt({
      batchSlugs: [],
      batchLanguages: ["unreal-engine-blueprint"],
    });
    // No "Framework Notes" heading since no entries matched
    expect(result).not.toContain("## Framework Notes");
  });

  it("includes projectInfo when provided", () => {
    const info = "This is a payment processing microservice handling PCI data.";
    const result = assembleReviewPrompt({
      batchSlugs: [],
      projectInfo: info,
    });
    expect(result).toContain("## Project Context");
    expect(result).toContain(info);
  });

  it("includes promptAppend when provided", () => {
    const append = "Focus especially on any authentication-related logic.";
    const result = assembleReviewPrompt({
      batchSlugs: [],
      promptAppend: append,
    });
    expect(result).toContain(append);
  });

  it("uses detectedLanguages when batchLanguages is absent", () => {
    const result = assembleReviewPrompt({
      batchSlugs: [],
      detectedLanguages: ["python"],
    });
    // The Django entry should appear (python language)
    expect(result).toContain("Decorator ordering");
    // The Next.js entry should not appear (no typescript/javascript)
    expect(result).not.toContain("OPTIONS preflight");
  });
});

describe("buildInvestigatePrompt", () => {
  const baseSystemPrompt = assembleReviewPrompt({ batchSlugs: [] });

  it("lists candidates with line numbers and matched pattern", () => {
    const result = buildInvestigatePrompt({
      systemPrompt: baseSystemPrompt,
      batch: [
        {
          filePath: "src/auth/login.ts",
          candidates: [
            {
              vulnSlug: "auth-bypass",
              lineNumbers: [42, 45],
              matchedPattern: "JWT verification skipped on failure path",
            },
          ],
        },
        {
          filePath: "src/api/users.ts",
          candidates: [
            {
              vulnSlug: "sql-injection",
              lineNumbers: [88],
              matchedPattern: "String interpolation in SQL query",
            },
          ],
        },
      ],
    });

    // File paths should appear
    expect(result).toContain("src/auth/login.ts");
    expect(result).toContain("src/api/users.ts");

    // Candidate details: slug + line numbers + matched pattern
    expect(result).toContain("[auth-bypass]");
    expect(result).toContain("[sql-injection]");
    expect(result).toContain("L42,45");
    expect(result).toContain("L88");
    expect(result).toContain("JWT verification skipped on failure path");
    expect(result).toContain("String interpolation in SQL query");
  });

  it("delimits untrusted source with a fence longer than its own backticks", () => {
    const source = "const marker = `user-controlled`;\n```";
    const result = buildInvestigatePrompt({
      systemPrompt: baseSystemPrompt,
      batch: [{ filePath: "src/app.ts", candidates: [], source }],
    });

    expect(result).toContain("Source (untrusted):");
    expect(result).toContain(`\`\`\`\`\n${source}\n\`\`\`\``);
  });

  it("shows holistic-review hint for candidate-free files", () => {
    const result = buildInvestigatePrompt({
      systemPrompt: baseSystemPrompt,
      batch: [
        {
          filePath: "src/utils/helpers.ts",
          candidates: [],
        },
        {
          filePath: "src/config/routes.ts",
          candidates: [],
        },
      ],
    });

    // Both files should appear
    expect(result).toContain("src/utils/helpers.ts");
    expect(result).toContain("src/config/routes.ts");

    // Each should carry the holistic-review hint
    expect(result).toContain("no scanner hits");
    expect(result).toContain("full holistic review");
  });

  it("includes output format JSON schema", () => {
    const result = buildInvestigatePrompt({
      systemPrompt: baseSystemPrompt,
      batch: [{ filePath: "src/main.ts", candidates: [] }],
    });

    // Output format section
    expect(result).toContain("## Output Format");
    expect(result).toContain('"severity"');
    expect(result).toContain('"critical"');
    expect(result).toContain('"high"');
    expect(result).toContain('"confidence"');
    expect(result).toContain('"recommendation"');
    expect(result).toContain("Return ONLY the JSON array");
  });

  it("includes investigation instructions", () => {
    const result = buildInvestigatePrompt({
      systemPrompt: baseSystemPrompt,
      batch: [{ filePath: "src/main.ts", candidates: [] }],
    });

    expect(result).toContain("## Investigation Instructions");
    expect(result).toContain("Trace data flows");
    expect(result).toContain("Follow import chains");
  });
});
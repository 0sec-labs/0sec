/**
 * Structured multi-step verification pipeline for pwnkit findings.
 *
 * Inspired by GitHub Security Lab's taskflow-agent approach, this decomposes
 * the single-shot "blind verify" into 4 focused subtasks, each with domain-specific
 * prompts and category-specific addendums. Any step failure marks the finding
 * as a false positive.
 *
 * Steps:
 *   1. Reachability Analysis — can the vuln be triggered from external input?
 *   2. Payload Validation — does the PoC actually demonstrate the claim?
 *   3. Impact Assessment — what is the real-world security impact?
 *   4. Exploit Confirmation — independently reproduce with only PoC + target path.
 */

import type { Finding } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
} from "../runtime/types.js";
import type { MemoryStore, TriageMemory } from "./memories.js";

// ── Memory Integration ──

/**
 * Optional hook passed through the structured verify pipeline. When present,
 * the pipeline will query the memory store for relevant FP patterns before
 * running the 4-step verification and, if a strong match is found, short-
 * circuit the finding as a rejection.
 */
export interface VerifyMemoryOptions {
  memoryStore?: MemoryStore;
  /**
   * When true, a strong-match memory (score >= store threshold) auto-rejects
   * the finding without making any LLM calls. Defaults to true.
   */
  autoRejectOnStrongMatch?: boolean;
}

// ── Public Types ──

export type VerifyVerdict = "confirmed" | "rejected";

export type VerifyStepName =
  | "reachability"
  | "payload_validation"
  | "impact_assessment"
  | "exploit_confirmation";

export interface StepResult {
  step: VerifyStepName;
  passed: boolean;
  confidence: number;
  reasoning: string;
  durationMs: number;
}

export interface VerifyResult {
  verdict: VerifyVerdict;
  confidence: number;
  steps: StepResult[];
  reasoning: string;
}

// ── Category Addendums ──

type VulnCategory =
  | "sqli"
  | "xss"
  | "ssti"
  | "idor"
  | "ssrf"
  | "command_injection"
  | "file_upload"
  | "deserialization"
  | "auth_bypass";

/**
 * Map a Finding's AttackCategory to our internal VulnCategory for addendum
 * lookup. Returns undefined if no specific addendum exists.
 */
function mapCategory(finding: Finding): VulnCategory | undefined {
  const map: Record<string, VulnCategory> = {
    "sql-injection": "sqli",
    xss: "xss",
    "code-injection": "ssti", // SSTI is a subclass of code injection in pwnkit's taxonomy
    "command-injection": "command_injection",
    ssrf: "ssrf",
    "unsafe-deserialization": "deserialization",
    // These don't have a 1:1 mapping but we do our best
    "tool-misuse": "ssrf",
    "path-traversal": "file_upload",
  };
  return map[finding.category];
}

const CATEGORY_ADDENDUMS: Record<VulnCategory, CategoryAddendum> = {
  sqli: {
    reachability: `SQL Injection specifics:
- Trace from HTTP parameter to SQL query construction.
- Check for parameterized queries, ORM usage, or prepared statements that would neutralize the payload.
- Identify the database engine (MySQL, PostgreSQL, SQLite, MSSQL) — syntax matters.
- Check for WAF or input-validation middleware that strips SQL metacharacters.
- String concatenation into a query is necessary but not sufficient — the parameter must be reachable.`,
    payload_validation: `SQL Injection payload checks:
- Does the payload match the target database dialect?
- UNION SELECT: does the column count match the original query?
- Boolean-based: do true/false responses actually differ?
- Time-based: is the delay reliably above network jitter (>2s)?
- Error-based: does the error message come from the DB engine or the app framework?
- Check that the response contains DB-sourced data, not just a reflected string.`,
    impact_assessment: `SQL Injection impact assessment:
- Read-only (SELECT) vs write (INSERT/UPDATE/DELETE) vs admin (DROP, FILE, LOAD_FILE).
- Can the attacker extract credentials, PII, or secrets?
- Is stacked-query execution possible (enables arbitrary commands on MSSQL/PostgreSQL)?
- Does the DB user have FILE or DBA privileges?
- Can the injection be escalated to OS command execution (xp_cmdshell, COPY TO PROGRAM, INTO OUTFILE)?`,
    exploit_confirmation: `SQL Injection reproduction:
- Replay the exact payload. Check for data leakage in the response body.
- For blind SQLi, use time-based confirmation: response time delta > 2 seconds.
- For UNION-based, verify returned data is from a different table than the legitimate query.
- Confirm the response is not a generic error page or WAF block page.`,
  },
  xss: {
    reachability: `XSS specifics:
- Trace the user input to the HTML output context (attribute, tag body, script block, URL).
- Check for output encoding: HTML entity encoding, JavaScript escaping, URL encoding.
- Check for Content-Security-Policy headers that would block inline script execution.
- Check if the framework auto-escapes (React, Angular, Vue with v-text, Django templates).
- DOM-based XSS: trace from source (location.hash, document.referrer) to sink (innerHTML, eval, document.write).`,
    payload_validation: `XSS payload checks:
- Does the payload break out of its injection context (attribute, tag, script)?
- Is the payload actually reflected/stored and rendered in HTML?
- Check that the response Content-Type is text/html (not application/json or text/plain).
- For stored XSS: verify the payload persists and renders on subsequent page loads.
- Look for actual script execution evidence: alert(), confirm(), or DOM modification — not just reflection.
- Browser-based validation is strongest: does the dialog actually fire?`,
    impact_assessment: `XSS impact assessment:
- Reflected vs Stored vs DOM-based — stored is highest impact.
- Is the affected page authenticated? Can session cookies be stolen (check HttpOnly flag)?
- Can the XSS reach admin pages or perform privilege escalation via CSRF?
- Is there a Content-Security-Policy that limits exploitability?
- Self-XSS (requires victim to paste payload) is typically not a real vulnerability.`,
    exploit_confirmation: `XSS reproduction:
- Navigate to the URL with the payload. Confirm script execution via dialog or DOM change.
- For stored XSS: submit the payload, then visit the page as a different user.
- The gold standard is an alert/confirm/prompt dialog firing in a headless browser.
- Check that the payload is not neutered by encoding in the rendered HTML source.`,
  },
  ssti: {
    reachability: `SSTI specifics:
- Identify the template engine: Jinja2, Twig, Freemarker, ERB, Pug, Thymeleaf, Velocity.
- Trace from user input to template rendering call.
- Check for sandboxing or restricted template environments.
- Check if the input goes through a template or is just string concatenation (not SSTI).
- Autoescaping in the template engine does NOT prevent SSTI — it only prevents XSS.`,
    payload_validation: `SSTI payload checks:
- Does {{7*7}} or ${"`${7*7}`"} return 49 in the response?
- Is the math result from the template engine or from JavaScript on the client side?
- For RCE payloads: does the response contain command output (uid, whoami, file contents)?
- Check that the "exploitation evidence" isn't just the raw payload reflected back.
- Verify the template engine matches the payload syntax.`,
    impact_assessment: `SSTI impact assessment:
- SSTI almost always leads to RCE — this is typically critical severity.
- Check if the template sandbox restricts dangerous operations.
- Can the attacker read files, execute commands, or access environment variables?
- Server-side template injection in an email template may have different impact than in a web page.`,
    exploit_confirmation: `SSTI reproduction:
- Send the arithmetic probe ({{7*7}}) and confirm the response contains 49.
- Escalate to information disclosure: {{config}} or {{self.__class__}}.
- Attempt command execution and verify output in the response.
- If the PoC claims RCE, the response must contain actual command output.`,
  },
  idor: {
    reachability: `IDOR specifics:
- Identify the object reference: numeric ID, UUID, slug, filename.
- Determine the authorization model: is there per-object access control?
- Check for session/token validation — the request must be authenticated as user A accessing user B's object.
- Check if the endpoint is intentionally public (e.g., public profiles).
- Horizontal IDOR (same role, different user) vs Vertical IDOR (privilege escalation).`,
    payload_validation: `IDOR payload checks:
- Does changing the ID in the request return a DIFFERENT user's data?
- Confirm the response contains data belonging to another user/entity — not just a 200 OK.
- Check that the "other user's data" is actually sensitive and not public information.
- For write IDOR: confirm that the modification persisted (re-fetch the object).
- A 403/401 response means the authorization check IS working — not an IDOR.`,
    impact_assessment: `IDOR impact assessment:
- Read IDOR (viewing other users' data) vs Write IDOR (modifying other users' data) vs Delete IDOR.
- What data is exposed? PII, financial records, admin settings, or non-sensitive preferences?
- Can the IDOR be used for mass data extraction (enumerable IDs)?
- Is the IDOR on an admin endpoint (vertical privilege escalation)?`,
    exploit_confirmation: `IDOR reproduction:
- Authenticate as user A. Request user B's resource by changing the ID.
- Verify the response contains user B's data, not user A's or a generic error.
- If IDs are non-sequential (UUIDs), confirm the attacker can realistically obtain them.
- For write IDOR: modify user B's data and re-fetch to confirm the change persisted.`,
  },
  ssrf: {
    reachability: `SSRF specifics:
- Trace from user-supplied URL/host to the server-side HTTP request.
- Check for URL validation: allowlists, blocklists, protocol restrictions.
- Check for DNS rebinding protections.
- Identify the HTTP client library — some block private IPs by default.
- Check if redirects are followed (open redirect chaining).`,
    payload_validation: `SSRF payload checks:
- Does the server make a request to the attacker-controlled or internal URL?
- For blind SSRF: use an out-of-band detection server (Burp Collaborator, webhook.site).
- For internal SSRF: does the response contain internal service data (169.254.169.254, localhost)?
- Check that the response is from the internal service, not an error page or WAF block.
- DNS resolution must happen server-side, not client-side.`,
    impact_assessment: `SSRF impact assessment:
- Blind SSRF (can reach internal hosts) vs Full SSRF (response returned to attacker).
- Can cloud metadata be accessed (AWS IMDSv1 at 169.254.169.254)?
- Can internal services be port-scanned or interacted with?
- Can the SSRF be escalated to RCE via internal service exploitation?
- Protocol-specific impacts: gopher://, file://, dict:// may enable additional attacks.`,
    exploit_confirmation: `SSRF reproduction:
- Send the request with an internal URL target. Verify the response contains internal data.
- For blind SSRF: confirm out-of-band interaction (DNS lookup or HTTP callback).
- Check that the request originates from the server, not the browser.
- Verify the internal data could not have been obtained through a legitimate API.`,
  },
  command_injection: {
    reachability: `Command Injection specifics:
- Trace from user input to the system call (exec, spawn, popen, system, backticks).
- Check for input sanitization: shell escaping, allowlist validation, parameterized commands.
- Identify the shell: bash, sh, cmd.exe, PowerShell — metacharacters differ.
- Check if the application uses array-form exec (safe) vs string-form (vulnerable).
- Check for chroot, containers, or AppArmor that limit command execution impact.`,
    payload_validation: `Command Injection payload checks:
- Does the response contain command output (uid=, whoami, file contents)?
- Check for time-based confirmation: ;sleep 5 with >5s response delay.
- Verify the output is from the injected command, not from application logic.
- Out-of-band: DNS lookup or HTTP callback to confirm blind command injection.
- The payload must use the correct separator for the OS (; for Unix, & for Windows).`,
    impact_assessment: `Command Injection impact assessment:
- Command injection is almost always critical severity — it provides RCE.
- What user does the application run as? Root/admin escalates the impact.
- Can the attacker read sensitive files, install persistence, or pivot?
- Is the container/sandbox restrictive enough to limit blast radius?
- Network access from the compromised host: can it reach internal services?`,
    exploit_confirmation: `Command Injection reproduction:
- Execute a benign command (id, whoami, hostname) and verify output in the response.
- If blind: use time-based or out-of-band detection.
- Confirm the command runs server-side, not client-side (JavaScript eval is not command injection).
- Verify that shell metacharacters are interpreted, not escaped in the output.`,
  },
  file_upload: {
    reachability: `File Upload specifics:
- Trace from the multipart upload to the file storage location.
- Check for extension validation (allowlist vs blocklist), MIME type checking, and magic byte validation.
- Determine if uploaded files are served with executable content types.
- Check if the upload directory has execution permissions (web-accessible + server-side execution).
- Check for filename sanitization (path traversal via ../ in filename).`,
    payload_validation: `File Upload payload checks:
- Was the malicious file actually uploaded and stored?
- Can the file be accessed via a predictable URL?
- Does the server execute the file (PHP, JSP, ASP) or serve it as static content?
- For web shell uploads: does accessing the uploaded file execute server-side code?
- Check that the "success" response isn't just a 200 OK with no actual file storage.`,
    impact_assessment: `File Upload impact assessment:
- Web shell upload = RCE = critical severity.
- Stored XSS via HTML/SVG upload = high severity.
- File overwrite via path traversal in filename = high severity.
- ZIP bomb or resource exhaustion = DoS = medium severity.
- Unrestricted upload of non-executable files = low/info.`,
    exploit_confirmation: `File Upload reproduction:
- Upload the malicious file. Determine its storage URL.
- Access the file via HTTP and confirm server-side execution (command output in response).
- For XSS via upload: access the file in a browser and confirm script execution.
- Verify the file persists and is accessible across sessions.`,
  },
  deserialization: {
    reachability: `Deserialization specifics:
- Identify the serialization format: Java ObjectInputStream, PHP unserialize, Python pickle, Ruby Marshal, .NET BinaryFormatter, JSON with type hints.
- Trace from user input to the deserialization call.
- Check for type allowlists or deserialization filters (Java ObjectInputFilter).
- Identify available gadget chains in the classpath/dependencies.
- Check if the input is actually deserialized or just parsed as structured data (JSON.parse is not unsafe deserialization).`,
    payload_validation: `Deserialization payload checks:
- Does the payload use a valid gadget chain for the target runtime?
- Is the serialized object format correct (magic bytes, version headers)?
- For Java: does the classpath contain Commons Collections, Spring, or other gadget libraries?
- For PHP: does the application have __wakeup/__destruct methods that chain to dangerous operations?
- Check that the "exploitation evidence" shows actual code execution, not just a parsing error.`,
    impact_assessment: `Deserialization impact assessment:
- Unsafe deserialization with gadget chains typically leads to RCE = critical.
- Without known gadgets: may still cause DoS or information disclosure.
- Check the runtime environment: what can the exploited process access?
- Java deserialization with Commons Collections = well-known critical path.
- PHP unserialize without dangerous magic methods may be low impact.`,
    exploit_confirmation: `Deserialization reproduction:
- Send the serialized payload. Confirm code execution via command output or out-of-band callback.
- For blind exploitation: use DNS or HTTP callbacks to confirm execution.
- Verify the gadget chain is compatible with the target's dependency versions.
- The response must show evidence of the gadget chain triggering, not just the payload being accepted.`,
  },
  auth_bypass: {
    reachability: `Auth Bypass specifics:
- Identify the authentication mechanism: session cookies, JWT, API keys, OAuth, basic auth.
- Determine what is being bypassed: authentication (who are you?) or authorization (are you allowed?).
- Check for default credentials, hardcoded tokens, or debug backdoors.
- For JWT: check for algorithm confusion (none, HS256 vs RS256), weak secrets, missing validation.
- Check if the bypass works consistently or is a race condition.`,
    payload_validation: `Auth Bypass payload checks:
- Does the request without valid credentials return protected data?
- Compare authenticated vs unauthenticated responses — is the data actually different?
- For JWT bypass: does the modified token grant access to protected endpoints?
- For default credentials: confirm they work AND that they were not intended to be public.
- A login page returning 200 is not an auth bypass — check the response body for actual access.`,
    impact_assessment: `Auth Bypass impact assessment:
- Full authentication bypass (access any account) = critical.
- Privilege escalation (user to admin) = critical/high.
- Accessing a single unprotected endpoint with non-sensitive data = low.
- Default credentials on a demo/test deployment = medium (context-dependent).
- Session fixation or token leakage = high.`,
    exploit_confirmation: `Auth Bypass reproduction:
- Access a protected resource without valid authentication. Confirm the response contains protected data.
- For privilege escalation: authenticate as a low-privilege user and access admin resources.
- Verify the bypass is not a race condition or timing-dependent issue (test 3+ times).
- Compare the response to a legitimately authenticated request to confirm equivalence.`,
  },
};

interface CategoryAddendum {
  reachability: string;
  payload_validation: string;
  impact_assessment: string;
  exploit_confirmation: string;
}

// ── Step Prompts ──

function reachabilitySystemPrompt(finding: Finding, target: string, addendum: string): string {
  return `You are a security verification agent performing REACHABILITY ANALYSIS.

Your sole task: determine whether the claimed vulnerability can actually be triggered from external user input.

## Finding Under Review

Title: ${finding.title}
Category: ${finding.category}
Severity: ${finding.severity}
Description: ${finding.description}

## Evidence

Request:
\`\`\`
${finding.evidence.request}
\`\`\`

Response:
\`\`\`
${finding.evidence.response}
\`\`\`

${finding.evidence.analysis ? `Analysis:\n${finding.evidence.analysis}\n` : ""}

## Target

${target}

## Your Task

Trace the data flow from external input to the vulnerability sink:

1. Identify the ENTRY POINT: where does attacker-controlled data enter the application?
   - HTTP parameter (query string, POST body, header, cookie)
   - File upload content
   - WebSocket message
   - URL path segment

2. Trace EVERY intermediate step between input and sink:
   - Is the input parsed, decoded, or transformed?
   - Does it pass through middleware, validators, or sanitizers?
   - Are there conditional branches that could prevent reaching the sink?

3. Identify the SINK: the dangerous operation where the vulnerability manifests.
   - Database query, command execution, template rendering, file operation, HTTP request, etc.

4. Determine: Can a malicious input ACTUALLY reach the sink in an exploitable form?
   - Is the code path reachable in normal application flow?
   - Are there guards that would block or neutralize the payload?
   - Does the application framework provide automatic protections?

${addendum}

## Output Format

You MUST respond with ONLY a JSON object (no markdown fencing, no extra text):

{
  "passed": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-4 sentences explaining your conclusion. Reference specific code paths or request/response evidence."
}

If you cannot determine reachability with reasonable confidence, set passed=false.
A vulnerability that cannot be triggered from external input is not a real vulnerability.`;
}

function payloadValidationSystemPrompt(finding: Finding, target: string, addendum: string): string {
  return `You are a security verification agent performing PAYLOAD VALIDATION.

Your sole task: determine whether the PoC request actually demonstrates the claimed vulnerability.

## Finding Under Review

Title: ${finding.title}
Category: ${finding.category}
Severity: ${finding.severity}
Description: ${finding.description}

## Evidence

Request:
\`\`\`
${finding.evidence.request}
\`\`\`

Response:
\`\`\`
${finding.evidence.response}
\`\`\`

${finding.evidence.analysis ? `Analysis:\n${finding.evidence.analysis}\n` : ""}

## Target

${target}

## Your Task

Analyze the PoC request and response pair:

1. PAYLOAD CORRECTNESS
   - Is the payload syntactically correct for the claimed vulnerability type?
   - Does it target the right injection context (HTML attribute vs tag body, SQL string vs numeric)?
   - Is it using the right dialect/syntax for the target technology?

2. RESPONSE ANALYSIS
   - Does the response actually show evidence of exploitation?
   - Distinguish between: payload reflection (not necessarily vuln), error messages (may indicate vuln),
     actual data extraction (confirmed vuln), behavioral change (confirmed vuln).
   - Check for false indicators: generic error pages, WAF blocks, application-level rejections.

3. EVIDENCE STRENGTH
   - Strong: response contains data that could only come from exploitation (DB records, file contents, command output).
   - Medium: response shows behavioral difference (timing, error type, status code) consistent with the vulnerability.
   - Weak: payload is reflected in the response but no exploitation evidence.
   - None: response shows no indication of vulnerability (blocked, sanitized, or irrelevant).

4. COMMON FALSE POSITIVE PATTERNS
   - Payload reflected but HTML-encoded (not XSS).
   - SQL error message but from input validation, not actual SQL execution.
   - 500 error from malformed input, not from successful exploitation.
   - SSRF request succeeds but targets a public URL (not internal).
   - "Admin" data returned but the endpoint is intentionally public.

${addendum}

## Output Format

You MUST respond with ONLY a JSON object (no markdown fencing, no extra text):

{
  "passed": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-4 sentences. Describe what the response shows and whether it constitutes genuine exploitation evidence."
}

If the evidence is ambiguous, set passed=false. The burden of proof is on the finding.`;
}

function impactAssessmentSystemPrompt(finding: Finding, target: string, addendum: string): string {
  return `You are a security verification agent performing IMPACT ASSESSMENT.

Your sole task: determine the real-world security impact of the confirmed vulnerability.

## Finding Under Review

Title: ${finding.title}
Category: ${finding.category}
Claimed Severity: ${finding.severity}
Description: ${finding.description}

## Evidence

Request:
\`\`\`
${finding.evidence.request}
\`\`\`

Response:
\`\`\`
${finding.evidence.response}
\`\`\`

${finding.evidence.analysis ? `Analysis:\n${finding.evidence.analysis}\n` : ""}

## Target

${target}

## Your Task

Assess the actual security impact:

1. IMPACT CLASSIFICATION
   Determine which category applies:
   - Remote Code Execution (RCE): attacker can execute arbitrary commands on the server.
   - Data Modification: attacker can alter data they should not have access to.
   - Information Disclosure: attacker can read sensitive data (PII, credentials, secrets).
   - Authentication/Authorization Bypass: attacker can access functionality without proper auth.
   - Denial of Service (DoS): attacker can make the service unavailable.
   - Client-Side Attack: attacker can execute code in other users' browsers (XSS).

2. SEVERITY VALIDATION
   Does the claimed severity match the actual impact?
   - Critical: RCE, full auth bypass, mass data breach, complete system compromise.
   - High: significant data access, privilege escalation, stored XSS on sensitive pages.
   - Medium: limited data exposure, reflected XSS, CSRF, information disclosure of non-secrets.
   - Low: minor info disclosure, self-XSS, missing security headers, theoretical attacks.
   - Info: best-practice violations with no direct security impact.

3. EXPLOITABILITY FACTORS
   - Does the attack require authentication? Special privileges?
   - Does it require user interaction (clicking a link, visiting a page)?
   - Is it reproducible or timing-dependent?
   - How complex is the attack chain?

4. SCOPE
   - Is the vulnerability limited to one user or does it affect all users?
   - Can it be used for lateral movement or escalation?
   - Does it expose infrastructure-level access (cloud metadata, internal services)?

${addendum}

## Output Format

You MUST respond with ONLY a JSON object (no markdown fencing, no extra text):

{
  "passed": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-4 sentences. State the impact category, validated severity, and key exploitability factors."
}

Set passed=false if:
- The actual impact is info/low severity (not worth flagging as a real finding).
- The claimed severity is inflated by 2+ levels compared to actual impact.
- The vulnerability requires unrealistic preconditions for exploitation.`;
}

function exploitConfirmationSystemPrompt(finding: Finding, target: string, addendum: string): string {
  // This prompt deliberately omits the description and analysis to force independent reproduction.
  return `You are a security verification agent performing INDEPENDENT EXPLOIT CONFIRMATION.

You receive ONLY the PoC and target. You must independently determine if this is a real vulnerability.

## Target

${target}

## PoC Request

\`\`\`
${finding.evidence.request}
\`\`\`

## PoC Response (claimed)

\`\`\`
${finding.evidence.response}
\`\`\`

## Claimed Category: ${finding.category}
## Claimed Severity: ${finding.severity}

You do NOT have access to the original finding description or the researcher's analysis.
You must form your own independent judgment.

## Your Task

1. UNDERSTAND THE CLAIM
   - Based solely on the request and response, what vulnerability is being claimed?
   - What would a successful exploit look like for this type of vulnerability?

2. ANALYZE THE EVIDENCE
   - Does the request contain a recognizable attack payload?
   - Does the response show genuine exploitation indicators?
   - Could the response be explained by normal application behavior?

3. REPRODUCTION FEASIBILITY
   - If you were to replay this exact request against the target, would you expect the same result?
   - Are there timing, session, or state dependencies that could affect reproduction?
   - Is the PoC self-contained or does it depend on prior setup steps?

4. INDEPENDENT VERDICT
   - Based ONLY on the evidence provided, is this a real, exploitable vulnerability?
   - Would this pass review by a senior security engineer?
   - Is there any indication of fabricated or misleading evidence?

${addendum}

## Common Red Flags for Fabricated Findings
- Response body that looks auto-generated or templated rather than from a real server.
- Exploitation evidence that is too clean or too perfectly matches the claim.
- Missing HTTP headers that would normally be present in a real response.
- Response timing or size that doesn't match the claimed behavior.
- PoC that only works with very specific, unlikely preconditions.

## Output Format

You MUST respond with ONLY a JSON object (no markdown fencing, no extra text):

{
  "passed": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "2-4 sentences. State your independent assessment and what evidence supports or contradicts the claim."
}

Be skeptical. If the evidence does not clearly and independently demonstrate the vulnerability, set passed=false.`;
}

// ── Step Definitions ──

interface VerifyStep {
  name: VerifyStepName;
  buildPrompt: (finding: Finding, target: string, addendum: string) => string;
  addendumKey: keyof CategoryAddendum;
}

const STEPS: VerifyStep[] = [
  {
    name: "reachability",
    buildPrompt: reachabilitySystemPrompt,
    addendumKey: "reachability",
  },
  {
    name: "payload_validation",
    buildPrompt: payloadValidationSystemPrompt,
    addendumKey: "payload_validation",
  },
  {
    name: "impact_assessment",
    buildPrompt: impactAssessmentSystemPrompt,
    addendumKey: "impact_assessment",
  },
  {
    name: "exploit_confirmation",
    buildPrompt: exploitConfirmationSystemPrompt,
    addendumKey: "exploit_confirmation",
  },
];

// ── LLM Interaction ──

interface StepOutput {
  passed: boolean;
  confidence: number;
  reasoning: string;
}

/**
 * Parse the LLM's JSON response. Handles common formatting issues like markdown
 * fencing, leading text, and trailing content after the JSON object.
 */
function parseStepOutput(raw: string): StepOutput {
  // Strip markdown code fencing if present
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");

  // Try to extract a JSON object if there's surrounding text
  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error(`No JSON object found in LLM response: ${raw.slice(0, 200)}`);
  }

  const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

  if (typeof parsed.passed !== "boolean") {
    throw new Error(`Missing or invalid 'passed' field in response`);
  }
  if (typeof parsed.confidence !== "number" || parsed.confidence < 0 || parsed.confidence > 1) {
    throw new Error(`Missing or invalid 'confidence' field in response`);
  }
  if (typeof parsed.reasoning !== "string") {
    throw new Error(`Missing or invalid 'reasoning' field in response`);
  }

  return {
    passed: parsed.passed,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
  };
}

/**
 * Execute a single verification step by calling the LLM with the step's system
 * prompt and parsing the structured JSON response.
 */
async function executeStep(
  step: VerifyStep,
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  memoryBlock: string = "",
): Promise<StepResult> {
  const start = Date.now();

  // Resolve category addendum
  const category = mapCategory(finding);
  const addendumBody = category
    ? `## Category-Specific Guidance\n\n${CATEGORY_ADDENDUMS[category][step.addendumKey]}`
    : "";
  const addendum = memoryBlock
    ? `${addendumBody}\n\n${memoryBlock}`.trim()
    : addendumBody;

  const systemPrompt = step.buildPrompt(finding, target, addendum);

  const userMessage: NativeMessage = {
    role: "user",
    content: [
      {
        type: "text",
        text: "Analyze the finding described in your system prompt and provide your JSON verdict.",
      },
    ],
  };

  const result = await runtime.executeNative(systemPrompt, [userMessage], []);

  // Extract text from response
  const textBlocks = result.content.filter(
    (b): b is NativeContentBlock & { type: "text" } => b.type === "text",
  );
  const responseText = textBlocks.map((b) => b.text).join("\n");

  const durationMs = Date.now() - start;

  try {
    const output = parseStepOutput(responseText);
    return {
      step: step.name,
      passed: output.passed,
      confidence: output.confidence,
      reasoning: output.reasoning,
      durationMs,
    };
  } catch (parseError) {
    // If parsing fails, treat as a failed step with low confidence
    return {
      step: step.name,
      passed: false,
      confidence: 0.0,
      reasoning: `Failed to parse LLM response: ${parseError instanceof Error ? parseError.message : String(parseError)}. Raw response: ${responseText.slice(0, 300)}`,
      durationMs,
    };
  }
}

// ── Pipeline Entry Point ──

/**
 * Run the structured 4-step verification pipeline on a single finding.
 *
 * Each step acts as a gate: if any step fails, the pipeline short-circuits and
 * the finding is marked as rejected. All 4 steps must pass for confirmation.
 *
 * @param finding - The finding to verify.
 * @param target - The target URL or identifier.
 * @param runtime - A NativeRuntime instance for making LLM calls.
 * @returns A VerifyResult with the final verdict, confidence, step results, and reasoning.
 */
export async function runStructuredVerify(
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  memoryOptions?: VerifyMemoryOptions,
): Promise<VerifyResult> {
  const steps: StepResult[] = [];

  // Query memory store for learned FP patterns before calling the LLM. A
  // strong match short-circuits the pipeline; weaker matches are injected as
  // few-shot context into each step.
  let memoryBlock = "";
  if (memoryOptions?.memoryStore) {
    const store = memoryOptions.memoryStore;
    try {
      const autoReject = memoryOptions.autoRejectOnStrongMatch ?? true;
      if (autoReject) {
        const strong = await store.findStrongMatch(finding, target);
        if (strong) {
          await store.recordApplied(strong.memory.id).catch(() => {});
          return {
            verdict: "rejected",
            confidence: strong.score,
            steps: [],
            reasoning: `Auto-rejected by learned memory (score=${strong.score.toFixed(2)}): ${strong.memory.pattern} — ${strong.memory.reasoning}`,
          };
        }
      }
      const relevant = await store.getRelevantMemories(finding, target);
      if (relevant.length > 0) {
        memoryBlock = await store.formatForPrompt(relevant);
        for (const m of relevant) {
          await store.recordApplied(m.id).catch(() => {});
        }
      }
    } catch {
      // Memory integration must never hard-fail the pipeline.
      memoryBlock = "";
    }
  }

  for (const step of STEPS) {
    const result = await executeStep(step, finding, target, runtime, memoryBlock);
    steps.push(result);

    // Gate: short-circuit on failure
    if (!result.passed) {
      const failedStepNames = steps.filter((s) => !s.passed).map((s) => s.step);
      return {
        verdict: "rejected",
        confidence: result.confidence,
        steps,
        reasoning: `Finding rejected at ${result.step} step (${failedStepNames.join(", ")} failed). ${result.reasoning}`,
      };
    }
  }

  // All steps passed — compute aggregate confidence as the minimum across steps
  const minConfidence = Math.min(...steps.map((s) => s.confidence));
  const avgConfidence =
    steps.reduce((sum, s) => sum + s.confidence, 0) / steps.length;
  // Use a weighted combination: 60% minimum (conservative) + 40% average
  const aggregateConfidence = 0.6 * minConfidence + 0.4 * avgConfidence;

  return {
    verdict: "confirmed",
    confidence: Math.round(aggregateConfidence * 100) / 100,
    steps,
    reasoning: `Finding confirmed through all 4 verification steps with ${Math.round(aggregateConfidence * 100)}% aggregate confidence. Reachability: ${steps[0]!.reasoning.slice(0, 100)}... Payload: ${steps[1]!.reasoning.slice(0, 100)}...`,
  };
}

// ── Self-Consistency Voting ──

/**
 * The consensus verdict produced by `runSelfConsistencyVerify`.
 *
 * Self-consistency voting runs the structured verify pipeline N times and
 * takes the majority verdict. Because LLM sampling is non-deterministic, any
 * single run may produce a false positive or false negative; aggregating
 * across runs reduces variance and improves precision.
 */
export interface ConsensusResult {
  /** Majority-vote verdict across all completed runs. */
  verdict: VerifyVerdict;
  /** Fraction of completed runs whose verdict matched the majority (0-1). */
  confidence: number;
  /** All completed VerifyResult objects, in the order they finished. */
  runs: VerifyResult[];
  /**
   * Unanimity of the vote: 1.0 when every run agreed, 0.5 on a dead split.
   * Equivalent to `confidence` for two-class voting but exposed separately
   * for callers that want to reason about it independently.
   */
  agreement: number;
}

/**
 * A function matching the shape of `runStructuredVerify`. Exposed as a type
 * so tests can inject a mock verifier without touching the NativeRuntime.
 */
export type VerifyFn = (
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  memoryOptions?: VerifyMemoryOptions,
) => Promise<VerifyResult>;

export interface SelfConsistencyOptions {
  /** Number of parallel runs to launch. Default: 5. */
  numRuns?: number;
  /**
   * Sampling temperature hint. The current NativeRuntime does not expose a
   * per-call temperature knob, so this is accepted for forward compatibility
   * and logged; FP reduction still arises from inherent sampling variance.
   * Default: 0.7.
   */
  temperature?: number;
  /**
   * Early-termination threshold. Once a single verdict has accumulated
   * `>= ceil(numRuns * earlyStopThreshold)` votes, the remaining pending runs
   * are abandoned and the majority verdict is returned. Default: 0.8.
   */
  earlyStopThreshold?: number;
  /**
   * Dependency-injectable verify function. Defaults to `runStructuredVerify`.
   * Primarily used by tests to avoid real LLM calls.
   */
  verifyFn?: VerifyFn;
  /** Memory store options forwarded to each verify run. */
  memoryOptions?: VerifyMemoryOptions;
}

/**
 * Aggregate a set of completed `VerifyResult`s into a `ConsensusResult`.
 * Kept as a pure helper so the voting logic is trivially unit-testable.
 */
export function tallyConsensus(runs: VerifyResult[]): ConsensusResult {
  if (runs.length === 0) {
    throw new Error("tallyConsensus requires at least one completed run");
  }

  let confirmed = 0;
  let rejected = 0;
  for (const r of runs) {
    if (r.verdict === "confirmed") confirmed += 1;
    else rejected += 1;
  }

  // Ties default to "rejected" — when the pipeline can't reach a clear
  // majority, the safer posture is to treat the finding as unverified.
  const verdict: VerifyVerdict = confirmed > rejected ? "confirmed" : "rejected";
  const majorityCount = Math.max(confirmed, rejected);
  const confidence = majorityCount / runs.length;

  return {
    verdict,
    confidence: Math.round(confidence * 100) / 100,
    runs,
    agreement: Math.round(confidence * 100) / 100,
  };
}

/**
 * Run the structured verify pipeline N times and return the majority-vote
 * verdict ("self-consistency" decoding applied to the verify step).
 *
 * The runs execute in parallel. Early termination kicks in as soon as any
 * single verdict has locked up a majority that the remaining in-flight runs
 * cannot overturn — at that point we return immediately and let the pending
 * promises settle in the background. This keeps latency close to the single
 * fastest "decisive" run in the clear-cut case.
 */
export async function runSelfConsistencyVerify(
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  options?: SelfConsistencyOptions,
): Promise<ConsensusResult> {
  const numRuns = Math.max(1, options?.numRuns ?? 5);
  const earlyStopThreshold = options?.earlyStopThreshold ?? 0.8;
  const verifyFn: VerifyFn = options?.verifyFn ?? runStructuredVerify;
  // A threshold > 1 disables all early termination — useful for tests and
  // for callers that always want the full N-way vote.
  const earlyStopEnabled = earlyStopThreshold <= 1;
  const earlyStopCount = Math.ceil(numRuns * earlyStopThreshold);

  if (numRuns === 1) {
    const only = await verifyFn(finding, target, runtime, options?.memoryOptions);
    return tallyConsensus([only]);
  }

  const completed: VerifyResult[] = [];
  let confirmed = 0;
  let rejected = 0;
  let settled = 0;

  return new Promise<ConsensusResult>((resolve, reject) => {
    let done = false;
    const finish = (result: ConsensusResult) => {
      if (done) return;
      done = true;
      resolve(result);
    };

    for (let i = 0; i < numRuns; i += 1) {
      verifyFn(finding, target, runtime, options?.memoryOptions).then(
        (result) => {
          if (done) return;
          completed.push(result);
          settled += 1;
          if (result.verdict === "confirmed") confirmed += 1;
          else rejected += 1;

          // Early termination: either a verdict has crossed the early-stop
          // threshold, or no verdict can mathematically change the majority.
          if (earlyStopEnabled) {
            const leader = Math.max(confirmed, rejected);
            const remaining = numRuns - settled;
            const trailer = Math.min(confirmed, rejected);
            if (leader >= earlyStopCount || leader > trailer + remaining) {
              finish(tallyConsensus(completed.slice()));
              return;
            }
          }

          if (settled === numRuns) {
            finish(tallyConsensus(completed.slice()));
          }
        },
        (err) => {
          if (done) return;
          settled += 1;
          // A single failed run should not abort the ensemble — but if every
          // run fails, surface the last error so callers can react.
          if (settled === numRuns && completed.length === 0) {
            done = true;
            reject(err instanceof Error ? err : new Error(String(err)));
          } else if (settled === numRuns) {
            finish(tallyConsensus(completed.slice()));
          }
        },
      );
    }
  });
}

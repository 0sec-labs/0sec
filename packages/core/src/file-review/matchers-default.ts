// Built-in data-only matcher specs for the file-review scan stage. These
// are the free regex layer that casts the wide net before paid processing —
// adapted from deepsec's built-in matcher categories into the strict
// data-only ReviewMatcherSpec shape (compiled, never evaluated).
//
// Each spec: kebab-case slug, noise tier, file globs, line-anchored regex
// patterns, and at least one self-test example per pattern family.

import type { ReviewMatcherSpec } from "./types.js";

export const DEFAULT_REVIEW_MATCHERS: readonly ReviewMatcherSpec[] = [
  {
    version: 1,
    slug: "rce",
    description: "Remote code execution via exec/eval/spawn with interpolated input",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs", "**/*.cjs", "**/*.py", "**/*.rb", "**/*.php", "**/*.go", "**/*.java"],
    patterns: [
      { source: "\\bexec\\s*\\([^)]*\\+", flags: "", label: "exec with concatenation" },
      { source: "\\beval\\s*\\(", flags: "", label: "eval call" },
      { source: "\\bexecSync\\s*\\(\\s*[^,)]*\\+", flags: "", label: "execSync with concatenation" },
      { source: "\\bchild_process\\b.*\\bexec\\s*\\(", flags: "", label: "child_process exec" },
      { source: "\\bos\\.system\\s*\\(", flags: "", label: "python os.system" },
      { source: "\\bsubprocess\\.(call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True", flags: "", label: "subprocess shell=True" },
      { source: "\\bsystem\\s*\\(\\s*\\$", flags: "", label: "php/ruby system with variable" },
    ],
    examples: [
      "exec(command + userInput)",
      "eval(payload)",
      "execSync('rm -rf ' + dir)",
      "os.system(cmd)",
      "subprocess.run(cmd, shell=True)",
    ],
  },
  {
    version: 1,
    slug: "sql-injection",
    description: "SQL built with string interpolation or concatenation",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.rb", "**/*.php", "**/*.go", "**/*.java"],
    patterns: [
      { source: "[\"'`]\\s*(SELECT|INSERT|UPDATE|DELETE)\\b[^\"'`]*\\$\\{", flags: "i", label: "template-literal SQL with interpolation" },
      { source: "(SELECT|INSERT|UPDATE|DELETE)\\b[^;\"']*\"\\s*\\+", flags: "i", label: "SQL string concatenation" },
      { source: "\\bexecute\\s*\\(\\s*f?[\"'].*%s", flags: "", label: "python percent-format SQL" },
      { source: "\\bquery\\s*\\(\\s*[\"'].*\\+\\s*(req|params|input|user)", flags: "i", label: "query built from request" },
    ],
    examples: [
      "db.query(`SELECT * FROM users WHERE id = ${id}`)",
      "cursor.execute(\"SELECT * FROM t WHERE id = %s\" % uid)",
      'query("DELETE FROM x WHERE k=" + key)',
    ],
  },
  {
    version: 1,
    slug: "ssrf",
    description: "Server-side requests to user-controlled URLs",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.go", "**/*.rb", "**/*.java"],
    patterns: [
      { source: "\\bfetch\\s*\\(\\s*(req|params|input|url|target|body)[^)]*\\)", flags: "", label: "fetch(user url)" },
      { source: "requests\\.(get|post)\\s*\\(\\s*(url|target|href)", flags: "", label: "python requests(user url)" },
      { source: "http\\.(Get|Post)\\s*\\([^)]*(url|target)", flags: "", label: "go http.Get(user url)" },
      { source: "\\baxios\\s*[.(]\\s*(req|params|url|input)", flags: "", label: "axios(user url)" },
    ],
    examples: [
      "fetch(req.body.url)",
      "requests.get(url)",
      "http.Get(ctx, target)",
    ],
  },
  {
    version: 1,
    slug: "path-traversal",
    description: "File operations with user-controlled path segments",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.rb", "**/*.php", "**/*.go"],
    patterns: [
      { source: "path\\.join\\s*\\([^)]*(req|params|input|query)", flags: "", label: "path.join with request input" },
      { source: "fs\\.(readFile|readFileSync|writeFile|createReadStream)\\s*\\([^)]*(req|params|query)", flags: "", label: "fs read/write of request path" },
      { source: "\\bopen\\s*\\(\\s*f?[\"'].*\\+|\\bopen\\s*\\(\\s*(req|params|filename|path)", flags: "", label: "open(user path)" },
    ],
    examples: [
      "path.join(root, req.params.file)",
      "fs.readFileSync(req.query.path)",
      "open(filename)",
    ],
  },
  {
    version: 1,
    slug: "xss",
    description: "Rendering user-controlled data as HTML",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.vue", "**/*.html", "**/*.php", "**/*.rb"],
    patterns: [
      { source: "dangerouslySetInnerHTML", flags: "", label: "dangerouslySetInnerHTML" },
      { source: "\\.innerHTML\\s*=", flags: "", label: "innerHTML assignment" },
      { source: "\\|\\s*safe\\b", flags: "", label: "angular/volt safe pipe" },
      { source: "<%=?=?\\s*raw|<%==|\\{\\{\\{", flags: "", label: "unescaped template output" },
    ],
    examples: [
      "el.innerHTML = userInput",
      "<div dangerouslySetInnerHTML={{__html: content}} />",
      "<%= raw params[:html] %>",
    ],
  },
  {
    version: 1,
    slug: "secrets-exposure",
    description: "Hardcoded credentials and API keys",
    noiseTier: "precise",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.rb", "**/*.php", "**/*.go", "**/*.java", "**/*.yml", "**/*.yaml", "**/*.env*"],
    patterns: [
      { source: "(api[_-]?key|apikey|secret|password|passwd|token)\\s*[:=]\\s*[\"'][A-Za-z0-9+/=_\\-]{12,}[\"']", flags: "i", label: "hardcoded credential literal" },
      { source: "sk-[A-Za-z0-9]{20,}", flags: "", label: "OpenAI-style key" },
      { source: "AKIA[0-9A-Z]{16}", flags: "", label: "AWS access key id" },
      { source: "-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----", flags: "", label: "private key material" },
    ],
    examples: [
      'apiKey = "<REDACTED_CREDENTIAL>"',
      "password: 'hunter2secretvalue'",
      "AKIAIOSFODNN7EXAMPLE0",
    ],
  },
  {
    version: 1,
    slug: "insecure-crypto",
    description: "Weak hash algorithms and insecure randomness",
    noiseTier: "precise",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.rb", "**/*.php", "**/*.go", "**/*.java"],
    patterns: [
      { source: "\\b(md5|sha1)\\s*\\(", flags: "i", label: "weak hash function" },
      { source: "createHash\\s*\\(\\s*[\"'](md5|sha1)[\"']", flags: "", label: "node weak createHash" },
      { source: "\\bMath\\.random\\s*\\(", flags: "", label: "Math.random for security purpose (review context)" },
      { source: "\\brandom\\.random\\s*\\(", flags: "", label: "python random for security purpose (review context)" },
    ],
    examples: [
      "createHash('md5')",
      "token = Math.random().toString(36)",
      "hashlib.sha1(data)",
    ],
  },
  {
    version: 1,
    slug: "missing-auth",
    description: "HTTP route handlers without visible auth guards",
    noiseTier: "noisy",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.go", "**/*.rb", "**/*.php"],
    patterns: [
      { source: "\\b(app|router)\\.(get|post|put|delete|patch)\\s*\\(\\s*[\"'][^\"']*[\"']\\s*,\\s*(?!.*(?:auth|guard|middleware|require[A-Z]|session))", flags: "", label: "route without inline auth argument" },
      { source: "@(app\\.(route|get|post)|router\\.(get|post))\\s*\\(", flags: "", label: "framework route decorator (check decorators for auth)" },
    ],
    examples: [
      'app.get("/api/admin/users", (req, res) => {})',
      "@app.route('/transfer', methods=['POST'])",
    ],
  },
  {
    version: 1,
    slug: "webhook-handler",
    description: "Webhook endpoints that may skip signature verification",
    noiseTier: "noisy",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.go", "**/*.rb"],
    patterns: [
      { source: "[\"']/webhook[s]?[/\"']", flags: "i", label: "webhook route path" },
      { source: "stripe.*events?|github.*hook|slack.*events?", flags: "i", label: "provider event handler" },
    ],
    examples: [
      'app.post("/webhooks/stripe", handler)',
      "github webhook receiver",
    ],
  },
  {
    version: 1,
    slug: "cross-tenant-id",
    description: "User-supplied tenant/user ids driving DB lookups",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.go", "**/*.rb"],
    patterns: [
      { source: "(req|params|query|body)\\.(params|query|body)?\\.?(teamId|tenantId|orgId|userId|accountId)", flags: "", label: "request-supplied tenant id" },
      { source: "where.*[\"']?(team_id|tenant_id|org_id|account_id)[\"']?\\s*[:=]\\s*(req|params|input)", flags: "i", label: "tenant id from request in where clause" },
    ],
    examples: [
      "db.find({ teamId: req.params.teamId })",
      "WHERE account_id = params.account_id",
    ],
  },
  {
    version: 1,
    slug: "open-redirect",
    description: "Redirects to user-controlled URLs",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.go", "**/*.rb", "**/*.php"],
    patterns: [
      { source: "redirect\\s*\\(\\s*(req|params|query|url|next|return)", flags: "i", label: "redirect(user input)" },
      { source: "(res\\.redirect|RedirectResponse|redirect_to)\\s*(\\([^)]*(req|params|query|target|url)|\\s+(req|params|query|target|url))", flags: "", label: "framework redirect to request value" },
    ],
    examples: [
      "res.redirect(req.query.next)",
      "redirect_to params[:return_to]",
    ],
  },
  {
    version: 1,
    slug: "jwt-handling",
    description: "JWT verification weaknesses",
    noiseTier: "precise",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.py", "**/*.go", "**/*.rb", "**/*.java"],
    patterns: [
      { source: "jwt\\.decode\\s*\\(", flags: "", label: "jwt.decode without verify" },
      { source: "verify\\s*=\\s*False", flags: "", label: "verification disabled" },
      { source: "[\"']none[\"']", flags: "i", label: "none algorithm literal" },
      { source: "jwt\\.sign\\s*\\([^)]*[\"']HS256[\"'].*secret", flags: "", label: "HS256 sign with secret (check secret source)" },
    ],
    examples: [
      "jwt.decode(token)",
      "jwt.decode(token, options={'verify_signature': False})",
    ],
  },
  {
    version: 1,
    slug: "env-exposure",
    description: "Secrets leaking to client bundles or logs",
    noiseTier: "normal",
    filePatterns: ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"],
    patterns: [
      { source: "NEXT_PUBLIC_(SECRET|API_KEY|TOKEN|PASSWORD)", flags: "i", label: "secret exposed via NEXT_PUBLIC" },
      { source: "console\\.(log|error|warn)\\s*\\([^)]*(secret|token|password|apiKey|api_key)", flags: "i", label: "secret in log statement" },
    ],
    examples: [
      "process.env.NEXT_PUBLIC_SECRET_KEY",
      "console.log('token', authToken)",
    ],
  },
  {
    version: 1,
    slug: "unsafe-deserialization",
    description: "Deserialization of untrusted data",
    noiseTier: "precise",
    filePatterns: ["**/*.py", "**/*.java", "**/*.ts", "**/*.js", "**/*.rb", "**/*.php"],
    patterns: [
      { source: "pickle\\.loads?\\s*\\(", flags: "", label: "python pickle.loads" },
      { source: "yaml\\.load\\s*\\([^)]*(?!Loader)", flags: "", label: "yaml.load without safe Loader" },
      { source: "\\bunserialize\\s*\\(", flags: "", label: "php unserialize" },
      { source: "ObjectInputStream", flags: "", label: "java ObjectInputStream" },
    ],
    examples: [
      "pickle.loads(data)",
      "yaml.load(content)",
      "unserialize($_GET['obj'])",
    ],
  },
  {
    version: 1,
    slug: "iac-misconfiguration",
    description: "Infrastructure-as-code misconfigurations",
    noiseTier: "normal",
    filePatterns: ["**/*.tf", "**/*.yml", "**/*.yaml"],
    patterns: [
      { source: "0\\.0\.0\.0/0", flags: "", label: "world-open CIDR" },
      { source: "publicly_accessible\\s*=\\s*true", flags: "i", label: "publicly accessible resource" },
      { source: "privileged\\s*:\\s*true|privileged:\\s*true", flags: "", label: "privileged container" },
    ],
    examples: [
      'cidr_blocks = ["0.0.0.0/0"]',
      "publicly_accessible = true",
      "securityContext: { privileged: true }",
    ],
  },
];

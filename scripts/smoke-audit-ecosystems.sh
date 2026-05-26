#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <ecosystem> <target>" >&2
  exit 2
fi

ecosystem="$1"
target="$2"

extra_arg_a=""
extra_arg_b=""
case "$ecosystem" in
  npm) ;;
  pypi) extra_arg_a="--ecosystem"; extra_arg_b="pypi" ;;
  cargo) extra_arg_a="--ecosystem"; extra_arg_b="cargo" ;;
  oci) extra_arg_a="--ecosystem"; extra_arg_b="oci" ;;
  *)
    echo "unsupported ecosystem: $ecosystem" >&2
    exit 2
    ;;
esac

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

db_path="$tmpdir/pwnkit-smoke.db"
json_path="$tmpdir/result.json"
log_path="$tmpdir/result.log"

cmd=(
  node dist/pwnkit.js audit "$target"
  --format json
  --depth quick
  --runtime api
  --db-path "$db_path"
)

if [ -n "$extra_arg_a" ]; then
  cmd+=("$extra_arg_a" "$extra_arg_b")
fi

if command -v timeout >/dev/null 2>&1; then
  env_cmd=(env
    -u OPENROUTER_API_KEY
    -u AZURE_OPENAI_API_KEY
    -u AZURE_OPENAI_BASE_URL
    -u AZURE_OPENAI_MODEL
    -u AZURE_OPENAI_WIRE_API
    -u OPENAI_API_KEY
    -u ANTHROPIC_API_KEY
    -u GEMINI_API_KEY
    timeout 240s
  )
else
  env_cmd=(env
    -u OPENROUTER_API_KEY
    -u AZURE_OPENAI_API_KEY
    -u AZURE_OPENAI_BASE_URL
    -u AZURE_OPENAI_MODEL
    -u AZURE_OPENAI_WIRE_API
    -u OPENAI_API_KEY
    -u ANTHROPIC_API_KEY
    -u GEMINI_API_KEY
  )
fi

set +e
"${env_cmd[@]}" \
  "${cmd[@]}" \
  >"$json_path" 2>"$log_path"
exit_code=$?
set -e

if [ "$exit_code" -ne 0 ]; then
  echo "--- stderr ---" >&2
  cat "$log_path" >&2 || true
  echo "ecosystem audit smoke failed for $ecosystem:$target (exit $exit_code)" >&2
  exit "$exit_code"
fi

if [ ! -s "$json_path" ]; then
  echo "--- stderr ---" >&2
  cat "$log_path" >&2 || true
  echo "ecosystem audit smoke produced no JSON for $ecosystem:$target" >&2
  exit 2
fi

node - <<'EOF' "$json_path" "$ecosystem" "$target"
const fs = require("node:fs");
const [jsonPath, ecosystem, target] = process.argv.slice(2);
const raw = fs.readFileSync(jsonPath, "utf8");
const parsed = JSON.parse(raw);
if (!parsed || typeof parsed !== "object") {
  throw new Error("parsed report is not an object");
}
if (typeof parsed.package !== "string" || parsed.package.length === 0) {
  throw new Error(`missing package field for ${ecosystem}:${target}`);
}
if (!parsed.summary || typeof parsed.summary.totalFindings !== "number") {
  throw new Error(`missing summary.totalFindings for ${ecosystem}:${target}`);
}
if (typeof parsed.durationMs !== "number") {
  throw new Error(`missing durationMs for ${ecosystem}:${target}`);
}
console.log(JSON.stringify({
  ecosystem,
  target,
  package: parsed.package,
  version: parsed.version,
  findings: parsed.summary.totalFindings,
  durationMs: parsed.durationMs,
}, null, 2));
EOF

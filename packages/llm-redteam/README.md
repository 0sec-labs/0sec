# @pwnkit/llm-redteam

Offensive LLM/agent **indirect-prompt-injection** engine — the attack-side mirror
of `packages/benchmark`'s detection suite. Point it at any LLM/agent target,
sweep a sourced strategy library, judge breaks, and report which (model, behaviour)
pairs fall.

Built from the Gray Swan Arena "IPI June '26" run: the strategy library and the
unique-breaks engine encode what actually worked (and what didn't) against
frontier models.

## Concepts

- **Behavior** — what success means (`goal.proof` regex) and which untrusted
  vector it rides in (README, support doc, email, forum post, …).
- **Strategy** — turns a goal into payload text. Two kinds compose:
  - *framing* (visible body): `mundane-required`, `reasoning-mimicry`,
    `fake-ci-authority`, `fake-preflight`.
  - *concealment* (hidden reinforcement): `html-comment`, `unicode-tags`
    (U+E0000 block, Claude-family), `sneaky-bits` (two-char binary, OpenAI-family).
- **Target** — `mock` (simulated easy/hard models), `chat` (any
  OpenAI-compatible endpoint). Arena/Playwright adapter is a planned add.
- **Judge** — regex/proof judge (LLM-judge planned).
- **Engine** — sweeps framing×concealment across a target's models; a break is
  **unique per (model, behaviour)**, so a broken model is never retried.

## CLI

```bash
pnpm --filter @pwnkit/llm-redteam build
node dist/cli.js strategies                 # list the strategy library
node dist/cli.js gen install-package        # print generated candidate payloads
node dist/cli.js run install-package        # campaign vs simulated models (no network)
# real endpoint:
LLM_BASEURL=https://api.openai.com/v1 LLM_API_KEY=sk-... LLM_MODELS=gpt-4o,gpt-4o-mini \
  node dist/cli.js run install-package --target chat
```

## Key finding (Gray Swan)

Break rate splits hard by action-harm: "run a setup command" (install a package)
is easy (~18/22 models); genuinely-malicious actions (SSH backdoor, exfil,
deanonymize, rogue CA) are walls (~0). Encoded here so the engine reports the
distinction honestly rather than over-claiming.

"""ChatGPT-OAuth (Codex) backend — drives a real frontier model with no API key.

The operator's bench box authenticates to OpenAI through the Codex CLI's ChatGPT
OAuth (``~/.codex/auth.json``: an OAuth ``access_token`` + ``account_id``, no
metered API key). This backend talks the **Responses API** over that same wire —
``POST https://chatgpt.com/backend-api/codex/responses`` with the bearer token —
so 0verse can run a real model (``gpt-5.5``) where only a ChatGPT subscription is
available. It is intentionally **stdlib-only** (urllib + json): unlike the
anthropic/openai SDK backends it needs no extra to import or run.

The ChatGPT compat endpoint has no structured-output knob, so (like the GLM path)
we embed the JSON schema in the prompt and recover the object with the robust
``jsonparse.extract_json`` — a live model fences/prefixes its JSON, and a bare
``json.loads`` would crash. Transient failures (429/5xx/timeout) retry with
exponential backoff; a 401 refreshes the OAuth token once and retries.

The HTTP transport is injectable (``transport=``) so the SSE parser, JSON
recovery, and retry path are unit-tested with no network.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .usage import TrackedLLM

DEFAULT_MODEL = "gpt-5.5"
RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
TOKEN_URL = "https://auth.openai.com/oauth/token"
# Public client id shipped in the Codex CLI (codex-rs) — used only for refresh.
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

# Transport contract: (body, headers) -> iterable of raw SSE byte lines.
Transport = Callable[[dict[str, Any], dict[str, str]], Iterable[bytes]]


class LLMError(Exception):
    """Base class for backend failures — callers degrade rather than crash."""


class LLMTransientError(LLMError):
    """Retryable: rate-limit (429), 5xx, timeout, connection reset."""


class LLMAuthError(LLMError):
    """Auth failed (401/403) and could not be refreshed."""


def _auth_path() -> Path:
    env = os.environ.get("ZEROVERSE_CODEX_AUTH")
    if env:
        return Path(env)
    home = os.environ.get("CODEX_HOME")
    base = Path(home) if home else Path.home() / ".codex"
    return base / "auth.json"


def codex_auth_available() -> bool:
    """True when a Codex ChatGPT-OAuth credential is on disk."""
    try:
        return _auth_path().is_file()
    except OSError:
        return False


class CodexOAuthLLM(TrackedLLM):
    """``LLM`` backend over the ChatGPT-OAuth Responses API."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        auth_path: str | Path | None = None,
        max_retries: int = 4,
        timeout_s: float = 180.0,
        transport: Transport | None = None,
        reasoning_summary: str | None = None,
    ) -> None:
        # Call/token ledger (`self.usage`, plus the `total_usage`/`last_usage`
        # views the eval harnesses read) so a run can be priced AND so a dead
        # lane is distinguishable from a cheap one. See llm/usage.py.
        super().__init__()
        self.model = model or DEFAULT_MODEL
        self._auth_path = Path(auth_path) if auth_path else _auth_path()
        self.max_retries = max_retries
        self.timeout_s = timeout_s
        self._transport = transport
        self._auth: dict[str, Any] | None = None
        # OFF by default, and deliberately so: the request today sends no
        # ``reasoning`` field at all, so the server emits no summary events and
        # ``last_reasoning_summary`` stays empty. Setting this (e.g. "auto" or
        # "detailed") adds ``reasoning: {"summary": ...}`` to the body. It is not
        # the default because this is the undocumented ChatGPT compat endpoint and
        # a rejected body would fail EVERY call in the engine; flip it once a live
        # run has confirmed the endpoint accepts it.
        self.reasoning_summary = reasoning_summary
        # The model's own reasoning summary for the LAST completed call. Populated
        # from ``response.reasoning_summary_text.delta``; kept OUT of the returned
        # text because that string is JSON-parsed by ``_complete_json``.
        self.last_reasoning_summary: str = ""

    # --- auth -------------------------------------------------------------
    def _load_auth(self) -> dict[str, Any]:
        if self._auth is None:
            with self._auth_path.open(encoding="utf-8") as fh:
                self._auth = json.load(fh)
        return self._auth

    def _tokens(self) -> dict[str, Any]:
        toks = self._load_auth().get("tokens") or {}
        if not toks.get("access_token"):
            raise LLMAuthError(f"no access_token in {self._auth_path}")
        return dict(toks)

    def _refresh_token(self) -> None:
        """Best-effort OAuth refresh (in-memory only — never clobber the operator's
        auth.json). Raises ``LLMAuthError`` if it can't refresh."""
        toks = self._tokens()
        refresh = toks.get("refresh_token")
        if not refresh:
            raise LLMAuthError("no refresh_token available")
        body = json.dumps({
            "client_id": OAUTH_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "scope": "openid profile email",
        }).encode()
        req = urllib.request.Request(
            TOKEN_URL, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:  # pragma: no cover - network
            raise LLMAuthError(f"token refresh failed: {exc}") from exc
        access = data.get("access_token")
        if not access:
            raise LLMAuthError("token refresh returned no access_token")
        assert self._auth is not None
        self._auth["tokens"] = {**toks, "access_token": access}

    # --- request building -------------------------------------------------
    def _headers(self) -> dict[str, str]:
        toks = self._tokens()
        return {
            "Authorization": f"Bearer {toks['access_token']}",
            "chatgpt-account-id": str(toks.get("account_id", "")),
            "OpenAI-Beta": "responses=experimental",
            "originator": "codex_cli_rs",
            "session_id": str(uuid.uuid4()),
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }

    def _body(self, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        instructions = (
            f"{system}\n\nRespond ONLY with a single JSON object matching this schema "
            f"(no prose, no Markdown fences):\n{json.dumps(schema)}"
        )
        body: dict[str, Any] = {
            "model": self.model,
            "instructions": instructions,
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": prompt}],
                }
            ],
            "store": False,
            "stream": True,
        }
        if self.reasoning_summary:
            body["reasoning"] = {"summary": self.reasoning_summary}
        return body

    # --- transport --------------------------------------------------------
    def _default_transport(
        self, body: dict[str, Any], headers: dict[str, str]
    ) -> Iterable[bytes]:  # pragma: no cover - exercised only with a live network
        req = urllib.request.Request(
            RESPONSES_URL, data=json.dumps(body).encode(), headers=headers
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout_s)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise LLMAuthError(f"HTTP {exc.code}") from exc
            if exc.code == 429 or 500 <= exc.code < 600:
                raise LLMTransientError(f"HTTP {exc.code}") from exc
            raise LLMError(f"HTTP {exc.code}: {exc.read()[:200]!r}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LLMTransientError(str(exc)) from exc
        return list(resp)

    def _stream_once(self, body: dict[str, Any]) -> str:
        transport = self._transport or self._default_transport
        lines = transport(body, self._headers())
        return self._parse_sse(lines)

    def _parse_sse(self, lines: Iterable[bytes]) -> str:
        """Accumulate ``response.output_text.delta`` events into the answer text and
        record token usage from ``response.completed``.

        ``response.reasoning_summary_text.delta`` is accumulated SEPARATELY into
        ``self.last_reasoning_summary``. It must not join the answer text: the return
        value goes straight into ``jsonparse.extract_json``, and prose prepended to the
        JSON object is exactly what that recovery has to fight through."""
        deltas: list[str] = []
        reasoning: list[str] = []
        completed_text: str | None = None
        self.last_reasoning_summary = ""
        for raw in lines:
            decoded = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
            line = decoded.strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                evt = json.loads(payload)
            except json.JSONDecodeError:
                continue
            etype = evt.get("type", "")
            if etype == "response.output_text.delta":
                deltas.append(str(evt.get("delta", "")))
            elif etype == "response.reasoning_summary_text.delta":
                reasoning.append(str(evt.get("delta", "")))
            elif etype == "response.reasoning_summary_part.added" and reasoning:
                reasoning.append("\n\n")  # a new summary part starts a new paragraph
            elif etype in ("response.failed", "error", "response.error"):
                msg = json.dumps(evt.get("error") or evt.get("response") or evt)[:200]
                raise LLMError(f"stream error: {msg}")
            elif etype == "response.completed":
                resp_obj = evt.get("response") or {}
                self._record_usage(resp_obj.get("usage") or {})
                if not deltas:
                    completed_text = _text_from_output(resp_obj.get("output") or [])
                if not reasoning:
                    reasoning = _reasoning_from_output(resp_obj.get("output") or [])
        self.last_reasoning_summary = "".join(reasoning).strip()
        if deltas:
            return "".join(deltas)
        if completed_text:
            return completed_text
        raise LLMError("empty response stream")

    def _record_usage(self, usage: dict[str, Any]) -> None:
        # An empty/absent `usage` is recorded as UNREPORTED, not as zero tokens:
        # this endpoint is subscription-billed and need not return one.
        if not usage:
            self.usage.record(0, 0, reported=False)
            return
        self.usage.record(
            int(usage.get("input_tokens", 0) or 0),
            int(usage.get("output_tokens", 0) or 0),
        )

    # --- public LLM interface --------------------------------------------
    def complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        """Ledger wrapper around ``_complete_json``. EVERY exit path is counted —
        including a failed token refresh and a non-retryable ``LLMError`` — because
        callers (``agent.TriageAgent``) swallow backend failures, so an
        uninstrumented failure would leave a dead lane looking merely cheap."""
        try:
            out = self._complete_json(system, prompt, schema)
        except Exception:
            self.usage.note_failed()
            raise
        self.usage.note_ok()
        return out

    def _complete_json(
        self, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]:
        from .jsonparse import extract_json

        body = self._body(system, prompt, schema)
        last_exc: Exception | None = None
        refreshed = False
        for attempt in range(self.max_retries):
            try:
                text = self._stream_once(body)
                return extract_json(text)
            except LLMAuthError as exc:
                last_exc = exc
                if refreshed:
                    raise
                self._refresh_token()
                refreshed = True
                continue
            except LLMTransientError as exc:
                last_exc = exc
                if attempt == self.max_retries - 1:
                    break
                time.sleep(min(2.0 ** attempt, 30.0))
                continue
            except ValueError as exc:
                # Model emitted no recoverable JSON — retry once, it is usually a
                # transient formatting slip; otherwise surface as an LLM error.
                last_exc = LLMError(f"unparseable output: {exc}")
                if attempt == self.max_retries - 1:
                    break
                time.sleep(min(2.0 ** attempt, 10.0))
                continue
        raise LLMError(f"codex backend failed after {self.max_retries} attempts: {last_exc}")


def _text_from_output(output: list[dict[str, Any]]) -> str:
    """Pull assistant text out of a non-streamed Responses ``output`` array."""
    parts: list[str] = []
    for item in output:
        if item.get("type") != "message":
            continue
        for block in item.get("content") or []:
            if block.get("type") in ("output_text", "text"):
                parts.append(str(block.get("text", "")))
    return "".join(parts)


def _reasoning_from_output(output: list[dict[str, Any]]) -> list[str]:
    """Pull the reasoning SUMMARY text out of a Responses ``output`` array — the
    non-streamed twin of ``response.reasoning_summary_text.delta``. The encrypted
    reasoning payload is not touched: echoing it back needs the whole item spliced
    verbatim into the next request's ``input``, which this single-shot
    ``complete_json`` interface has no place to put."""
    parts: list[str] = []
    for item in output:
        if item.get("type") != "reasoning":
            continue
        for block in item.get("summary") or []:
            text = str(block.get("text", ""))
            if text:
                parts.append(text if not parts else f"\n\n{text}")
    return parts

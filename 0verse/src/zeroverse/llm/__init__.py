"""LLM backends implementing the provider-neutral ``zeroverse.agent.LLM`` interface.

- ``anthropic_llm.AnthropicLLM`` — the shipped default (Claude, official SDK).
Add OpenAI-compatible / local backends here; the agent depends only on the
Protocol, never on a concrete provider.
"""

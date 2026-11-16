"""Optional LLM triage of static findings.

Static rules are cheap and deterministic but noisy; an LLM is good at reading the
surrounding handler and answering one narrow question: *is this object actually
reachable by a caller who should not see or modify it?*  Each candidate is sent
with only its own handler source, and the model must answer in strict JSON, so the
output can gate CI or be reviewed by a human.

Uses the Anthropic Messages API when ANTHROPIC_API_KEY is set. Nothing is sent
unless ``--llm`` is passed on the command line.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .analyzer import Finding

PROMPT = """You are a product security engineer reviewing a FastAPI + SQLAlchemy route handler.
A static analyzer flagged it: {message}

Question: can an authenticated user (or an anonymous caller, if there is no auth) read or modify
an object that belongs to another user, group or tenant through this handler?

Consider: router- or app-level dependencies you cannot see, whether the ID is guessable,
whether a later check scopes the object, and whether the data is meant to be public.

Handler ({file}:{line}):
```python
{source}
```

Reply with ONLY a JSON object:
{{"verdict": "true_positive" | "false_positive" | "needs_context",
  "confidence": <0..1>,
  "reason": "<one or two sentences>",
  "fix": "<minimal code change, or empty>"}}"""


def _complete(prompt: str, model: str) -> str:  # pragma: no cover - network
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("Set ANTHROPIC_API_KEY to use --llm triage")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps({
            "model": model,
            "max_tokens": 400,
            "messages": [{"role": "user", "content": prompt}],
        }).encode(),
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        body = json.load(r)
    return "".join(b.get("text", "") for b in body.get("content", []))


def _parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {"verdict": "needs_context", "confidence": 0.0, "reason": "unparseable model output", "fix": ""}
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {"verdict": "needs_context", "confidence": 0.0, "reason": "invalid JSON from model", "fix": ""}
    if data.get("verdict") not in {"true_positive", "false_positive", "needs_context"}:
        data["verdict"] = "needs_context"
    return data


def triage(findings: list[Finding], model: str = "claude-sonnet-5-5") -> list[dict]:
    out = []
    for f in findings:
        prompt = PROMPT.format(message=f.message, file=f.file, line=f.line, source=f.source)
        verdict = _parse(_complete(prompt, model))
        out.append({"finding": f.to_dict(), **verdict})
    return out

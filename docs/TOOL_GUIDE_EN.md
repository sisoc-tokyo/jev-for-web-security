# Jev for Web Security — Technical Guide

**Detect the trial-and-error behind AI-agent-driven web attacks — not just individual requests.**

This guide is available in a fully editable [Word document](TOOL_GUIDE_EN.docx), with a [PDF reading copy](TOOL_GUIDE_EN.pdf). The Word edition contains an extended reviewer-facing introduction and **native editable Word tables** for the architecture and sliding-window diagrams. The dashboard screenshot is the only embedded raster image.

## Why this tool exists

AI-assisted attack workflows can automate endpoint reconnaissance, failed-request retries, and shifts to alternative routes or request methods. A single HTTP request may not reveal this broader behavior. Jev for Web Security reconstructs request sequences to support analyst review of persistent and adaptive exploration.

**The tool does not establish that an attacker used AI.** Its findings describe observable sequences, not confirmed malicious intent, a proven compromise, or model attribution.

## How it works

1. Read normalized HTTP JSONL or a supported subset of ModSecurity v3 JSON Lines.
2. Minimize and pseudonymize metadata, group by trusted actor or source-IP fallback.
3. Construct a causal short-term Sliding Window and bounded historical summary.
4. Compute exact behavioral features in Python.
5. Classify behavior either with the transparent offline rule baseline or the Jev System One API backend.
6. Review the sequence, label, score interpretation and evidence in the local dashboard.

Initial defaults are **N=20** HTTP requests, **stride S=5**, a **300-second short horizon** and **1,800-second historical horizon**. Partial windows are permitted. These values have not been proven optimal.

## Quick start

```sh
python run.py
```

Open `http://127.0.0.1:8765/` if needed. For offline CLI analysis:

```sh
python run.py analyze --input examples/adaptive_illustration.jsonl
```

For Jev API mode, after obtaining credentials and reviewing data-sharing policy:

```sh
python run.py serve --engine jev --ask-key
```

The bundled traces are synthetic. The API client has not yet been validated with live credentials. The current release is **read-only** and does not inline-block traffic. See `docs/STATUS.md`, `docs/SECURITY.md` and the editable Word guide for precise scope and limitations.

# SpecGuard — Agentic PR & System-Spec Compliance Reviewer

An agentic pull-request reviewer built with **Python** and the **Strands Agents SDK** that catches cross-file architectural drift, security regressions, and code-quality issues against repository-local Markdown specifications (`.spec/*.md`).

## Architecture Highlights
- **Anchor-Based Diff Mapping (`[R42]`, `[L17]`):** Eliminates LLM line-number hallucinations and translates anchors safely into GitHub PR Review API `line` + `side` coordinates.
- **Deterministic Evidence Gate (Zero Trust in Self-Reported Confidence):** Every finding must pass exact substring verification against both the diff (`evidence_diff_quote`) and an accessed spec section (`evidence_spec_quote`), plus diff-hunk anchor validation before becoming an inline comment.
- **Strands Loop-Control Hooks:** Uses `BeforeModelCallEvent` to enforce hard iteration caps and `BeforeToolCallEvent` (`event.cancel_tool`) to block duplicate tool invocations.
- **Two-Stage Portable Pipeline:** Decouples tool-using ReAct investigation from flat Pydantic extraction so small local models (Ollama) and cloud models (Gemini) share identical schemas.
- **Adversarial Verifier Agent:** Challenges `CRITICAL` and `WARNING` candidates against surrounding repo context to suppress false positives.
- **Pre-LLM Secret Redaction:** A deterministic scanner flags and redacts credentials before any diff text reaches a model.

## Pipeline

```
git diff ──► DiffAnchorParser ──► SecretScanner (redact + deterministic findings)
                 │
                 ▼
           SpecBatcher (route files → governing .spec/*.md via applies_to globs)
                 │
                 ▼
   Stage 1a  Investigator agent (Strands ReAct + repo-jailed tools + loop hooks)
   Stage 1b  Flat structured extraction → CandidateList
                 │
                 ▼
   Stage 2   Adversarial Verifier (CRITICAL / WARNING only)
                 │
                 ▼
           EvidenceGate (anchor + verbatim quote checks, mention sanitising)
                 │
                 ▼
           PRReviewReport ──► CLI table / JSON / GitHub PR review
```

## Execution Environments & Provider Abstraction

| Mode (`SPECGUARD_PROVIDER`) | Where It Runs | Inference Backend | Cost | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **`replay`** *(Default)* | Laptop / GitHub Actions CI | Local JSON Cassettes (`evals/cassettes/`) | **$0** | Offline unit tests, deterministic CI regression gates, zero GPU usage. |
| **`ollama`** | Google Colab T4 GPU / Local | Local Ollama (`qwen2.5-coder:7b` or `3b`) | **$0** | Full golden-dataset eval sweeps, ablation tables, recording cassettes. |
| **`gemini`** | GitHub Actions / Local CLI | Google AI Studio (`gemini-2.5-flash`) | **$0** | Live PR reviews on GitHub pull requests with token-bucket rate limiting. |

> Record cassettes once with `specguard record-cassettes` against a live provider (`--resume` continues after a rate-limit stop). Cassette keys include a hash of the spec and rulebook text, so editing a spec invalidates its recordings. Until cassettes exist, `replay` mode only reports the deterministic (secret-scanner) findings.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 1. Run offline unit tests & cassette evals ($0, instant)
pytest
SPECGUARD_PROVIDER=replay specguard eval --ablation

# 2. Record cassettes for the golden dataset, then replay them offline
SPECGUARD_PROVIDER=ollama specguard record-cassettes
SPECGUARD_PROVIDER=replay specguard eval --ablation

# 3. Run on a real PR diff with Ollama (Colab T4 or local)
pip install -e ".[ollama]"
SPECGUARD_PROVIDER=ollama SPECGUARD_OLLAMA_MODEL=qwen2.5-coder:7b \
  specguard review --diff-file evals/dataset/case_01_spec_drift_money/diff.patch

# 4. Run with Gemini Free Tier
pip install -e ".[gemini]"
export GEMINI_API_KEY="your-key"
SPECGUARD_PROVIDER=gemini specguard review --base main --head HEAD
```

## Configuration

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `SPECGUARD_PROVIDER` | `replay` | `replay`, `ollama`, or `gemini` |
| `SPECGUARD_OLLAMA_MODEL` | `qwen2.5-coder:7b` | Ollama model tag |
| `SPECGUARD_OLLAMA_CTX` | `8192` | Ollama context window |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint |
| `SPECGUARD_GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model id |
| `SPECGUARD_GEMINI_RPM` | `5` | Requests/minute for Gemini, enforced on every model call |
| `SPECGUARD_OLLAMA_RPM` | `600` | Requests/minute for Ollama |

## Writing Specs

Each `.spec/*.md` file declares which paths it governs in YAML front matter; every `## Heading` becomes a citable section:

```markdown
---
applies_to:
  - "db/migrations/**"
---
# Data Model Specification

## Money
All monetary amounts ... MUST be stored as 64-bit integer cents.
```

Language rulebooks live in `.spec/rules/<language>_best_practices.md` and are loaded on demand by the agent.

## Evaluation

`specguard eval` scores the pipeline against 35 golden PR diffs in `evals/dataset/`: 9 spec-drift, 9 security, 7 code-quality and 10 true-negative cases, including cross-file and prompt-injection PRs. See [evals/dataset/README.md](evals/dataset/README.md) for the labeling rubric.

Predictions are matched one-to-one to golden findings with the Hungarian algorithm (`scipy.optimize.linear_sum_assignment`). The scorer reports:

| Metric | Meaning |
| :--- | :--- |
| Precision / Recall | Over inline findings, matched by file, category and an acceptable line |
| Exact Line Acc | Matched findings placed on the golden primary line |
| Severity Acc | Matched findings with the golden severity |
| Citation Acc | Matched findings citing the golden spec section |
| Latency | Wall-clock time for the whole dataset |

`--ablation` compares three configurations: **Single-Shot Baseline** (one call with every rule inlined, no tools, no quote checks), **Investigator + Tools + EvidenceGate**, and **Full SpecGuard + Verifier**. `--runs N` repeats each configuration and reports mean ± std. This is only meaningful with a live provider, since replay is deterministic.

## Project Layout

```
.spec/                     Architectural specs + language rulebooks
src/specguard/
  preprocessor/            Diff anchoring, secret scanning, spec routing
  agent/                   Strands investigator, verifier, hooks, repo-jailed tools
  llm/                     Provider factory, token bucket, cassette store
  postprocessor/           Deterministic evidence gate
  github/                  PR review publisher
  cli.py                   `specguard review` / `eval` / `record-cassettes`
evals/                     Golden dataset, cassettes, Hungarian scorer
notebooks/                 Colab T4 demo
tests/                     Deterministic unit tests
```

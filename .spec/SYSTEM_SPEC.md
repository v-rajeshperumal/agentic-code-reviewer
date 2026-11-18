---
applies_to:
  - "src/specguard/**"
---
# SpecGuard System Specification

Architectural invariants for SpecGuard's own source code. SpecGuard reviews pull requests to this repository against this file, and `tests/test_system_spec.py` enforces the mechanically checkable rules on every CI run.

## Diff Anchors
Models MUST cite diff locations only as `[R#]` / `[L#]` anchors produced by `DiffAnchorParser`. Code MUST NOT accept a raw line number from model output; the GitHub `line` and `side` of a finding MUST be resolved through `ParsedDiff.anchor_map`.

## Deterministic Status
`spec_compliance_status` MUST be computed only in `EvidenceGate.build_report()` from the severities of validated findings. A model's own verdict, confidence, or summary MUST NOT set or override the status.

## Evidence Gate
A finding MAY be marked `inline_eligible=True` only when its anchor exists in the diff, its `evidence_diff_quote` is an exact whitespace-normalized substring of the file's anchored diff, its `evidence_spec_quote` is an exact whitespace-normalized substring of a spec or rulebook section the agent actually loaded, and its severity is `CRITICAL` or `WARNING`. Quote checks MAY be disabled only for the single-shot ablation baseline (`require_evidence=False`), never in a review that posts to GitHub.

## Model Access
Every model call MUST go through `specguard.llm.provider.build_strands_model()`, so that provider selection and per-request rate limiting always apply. Modules other than `specguard/llm/provider.py` MUST NOT import `strands.models`.

## Repository Jailing
Agent tools that read files MUST resolve paths with `Path.resolve()` and reject any path that is not inside the resolved repository root (`is_relative_to`), so `..` segments and symlinks cannot escape the repository. Tools MUST be read-only.

## Secrets Before Models
All diff text and all file content returned by agent tools MUST pass through `SecretScanner` redaction before any model sees it. Only lines added by the pull request produce secret findings; existing secrets in context are masked silently.

## Untrusted Input
Diff content MUST be wrapped in randomly named boundary tags and described to the model as untrusted data. Model-written prose posted to GitHub (title, rationale, spec reference) MUST pass through `_sanitize_mentions` so injected `@mentions` and external links are neutralized. A suggested patch containing a code fence MUST be dropped, so that it cannot escape its `suggestion` block.

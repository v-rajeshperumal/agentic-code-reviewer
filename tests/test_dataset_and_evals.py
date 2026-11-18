"""Golden-dataset integrity, scorer metrics, baseline mode and dedupe."""
import json
from collections import Counter
from pathlib import Path

import pytest

from evals.run_evals import _bipartite_score
from specguard.agent.investigator import ReviewInvestigator, spec_context_digest
from specguard.cli import _dedupe, run_review_pipeline
from specguard.llm.cassette import CassetteStore, clear_session_cache
from specguard.preprocessor.diff_anchor import DiffAnchorParser
from specguard.preprocessor.secret_scanner import SecretScanner
from specguard.preprocessor.spec_batcher import SpecBatcher
from specguard.schemas import (
    CandidateList,
    FindingCategory,
    InvestigatorRecording,
    RawCandidateFinding,
    Severity,
    ValidatedFinding,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET = REPO_ROOT / "evals" / "dataset"
CASES = sorted(d for d in DATASET.iterdir() if d.is_dir())


@pytest.fixture(autouse=True)
def _fresh_session():
    clear_session_cache()
    yield
    clear_session_cache()


def _known_headings() -> set[str]:
    headings = set()
    for doc in SpecBatcher(REPO_ROOT).load_specs():
        headings.update(doc.sections)
    for rulebook in (REPO_ROOT / ".spec" / "rules").glob("*.md"):
        headings.update(
            line[3:].strip() for line in rulebook.read_text(encoding="utf-8").splitlines() if line.startswith("## ")
        )
    return headings


# --- Dataset integrity ------------------------------------------------------

def test_dataset_has_35_cases_with_planned_mix():
    assert len(CASES) == 35
    kinds = Counter()
    for case in CASES:
        must = json.loads((case / "expected.json").read_text(encoding="utf-8"))["must_flag"]
        kinds[must[0]["category"] if must else "TRUE_NEGATIVE"] += 1
    assert kinds == {"SPEC_DRIFT": 9, "SECURITY": 9, "CODE_QUALITY": 7, "TRUE_NEGATIVE": 10}


@pytest.mark.parametrize("case", CASES, ids=lambda d: d.name)
def test_case_labels_point_at_real_diff_lines(case):
    parsed = DiffAnchorParser().parse((case / "diff.patch").read_text(encoding="utf-8"))
    expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    headings = _known_headings()
    routed = {f for _, files in SpecBatcher(REPO_ROOT).build_batches(list(parsed.anchored_by_file)) for f in files}

    assert parsed.anchored_by_file, "diff must contain at least one reviewable file"
    assert routed == set(parsed.anchored_by_file), "every changed file must be governed by a spec"

    for gold in expected["must_flag"] + expected["may_flag"]:
        assert gold["line"] in gold["acceptable_lines"]
        for line in gold["acceptable_lines"]:
            assert f"{gold['file_path']}:R{line}" in parsed.anchor_map
        FindingCategory(gold["category"])
        Severity(gold["severity"])
        assert gold["spec_reference"] in headings


@pytest.mark.parametrize(
    "case_name", ["case_02_security_secret", "case_16_security_hardcoded_db_password",
                  "case_17_security_private_key_literal", "case_18_security_hardcoded_secret_key"],
)
def test_secret_cases_are_caught_deterministically_in_replay(case_name, monkeypatch, tmp_path):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    monkeypatch.chdir(tmp_path)  # empty cassette dir: only the scanner can find anything
    case = DATASET / case_name
    expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
    report = run_review_pipeline(REPO_ROOT, (case / "diff.patch").read_text(encoding="utf-8"))
    score = _bipartite_score(report.inline_findings, expected["must_flag"], expected["may_flag"])
    assert (score.tp, score.fp, score.fn) == (1, 0, 0)
    assert score.severity_ok == score.citation_ok == 1


def test_scanner_covers_stripe_google_and_slack_keys():
    # Built by concatenation so no complete key-shaped literal lives in the repo.
    samples = {
        "stripe_key": "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0",
        "google_api_key": "AIza" + "Sy" + "A" * 33,
        "slack_token": "xox" + "b-" + "1234567890-abcdef",
    }
    for kind, value in samples.items():
        redacted, findings = SecretScanner().scan_and_redact_line("cfg.py", 1, f'+TOKEN = "{value}"')
        assert f"<REDACTED:{kind}>" in redacted and value not in redacted
        assert findings and findings[0].category == FindingCategory.SECURITY


# --- Scorer -------------------------------------------------------------------

def _pred(line, severity=Severity.CRITICAL, spec="Money", category=FindingCategory.SPEC_DRIFT, quote="x"):
    return ValidatedFinding(
        file_path="db/m.sql", line=line, side="RIGHT", category=category, severity=severity,
        spec_reference=spec, evidence_diff_quote=quote, evidence_spec_quote="y", title="t", rationale="r",
    )


GOLD = {"file_path": "db/m.sql", "line": 3, "acceptable_lines": [1, 3, 4],
        "category": "SPEC_DRIFT", "severity": "CRITICAL", "spec_reference": "Money"}


def test_scorer_tracks_line_severity_and_citation_accuracy():
    exact = _bipartite_score([_pred(3)], [GOLD], [])
    assert (exact.tp, exact.exact_line, exact.severity_ok, exact.citation_ok) == (1, 1, 1, 1)

    nearby = _bipartite_score([_pred(4, severity=Severity.WARNING, spec="data-model.md")], [GOLD], [])
    assert (nearby.tp, nearby.exact_line, nearby.severity_ok, nearby.citation_ok) == (1, 0, 0, 0)

    wrong_category = _bipartite_score([_pred(3, category=FindingCategory.SECURITY)], [GOLD], [])
    assert (wrong_category.tp, wrong_category.fp, wrong_category.fn) == (0, 1, 1)


def test_scorer_prefers_exact_line_and_ignores_may_flag_extras():
    may = {**GOLD, "line": 7, "acceptable_lines": [7]}
    score = _bipartite_score([_pred(4), _pred(3), _pred(7)], [GOLD], [may])
    assert (score.tp, score.exact_line, score.fp, score.fn) == (1, 1, 1, 0)  # line 4 is the spare FP


# --- Baseline mode and dedupe -------------------------------------------------

DIFF = """diff --git a/db/migrations/01.sql b/db/migrations/01.sql
--- a/db/migrations/01.sql
+++ b/db/migrations/01.sql
@@ -1,1 +1,2 @@
 CREATE TABLE t (
+  amount FLOAT
"""


def test_baseline_skips_quote_checks_so_the_gate_ablation_is_visible(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    monkeypatch.chdir(tmp_path)
    spec_doc = next(d for d in SpecBatcher(REPO_ROOT).load_specs() if d.name == "data-model.md")
    anchored = DiffAnchorParser().parse(DIFF).anchored_by_file["db/migrations/01.sql"]
    hallucinated = RawCandidateFinding(
        file_path="db/migrations/01.sql", anchor="R2", category="SPEC_DRIFT", severity="CRITICAL",
        spec_reference="Money", evidence_diff_quote="amount NUMERIC", evidence_spec_quote="made up",
        title="Float money", rationale="r",
    )
    store = CassetteStore(Path("evals/cassettes"))
    payload = f"{spec_doc.name}:{spec_context_digest(REPO_ROOT, spec_doc)}::{anchored}"
    recording = InvestigatorRecording(candidates=CandidateList(findings=[hallucinated])).model_dump_json()
    store.save("baseline", payload, recording)
    store.save("investigator", payload, recording)
    clear_session_cache()

    baseline = run_review_pipeline(REPO_ROOT, DIFF, mode="baseline")
    agent = run_review_pipeline(REPO_ROOT, DIFF, mode="agent")
    assert [f.line for f in baseline.inline_findings] == [2]
    assert agent.inline_findings == [] and len(agent.summary_findings) == 1


def test_dedupe_keeps_first_report_of_each_defect():
    scanner_hit = _pred(1, category=FindingCategory.SECURITY, spec="Secrets Management", quote="<REDACTED:aws>")
    model_repeat = _pred(1, category=FindingCategory.SECURITY, spec="Secrets Management", quote="KEY = <REDACTED>")
    other = _pred(3)
    kept, audit = _dedupe([scanner_hit, model_repeat, other])
    assert kept == [scanner_hit, other] and len(audit) == 1


def test_single_shot_is_a_replay_miss_without_cassette(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    spec_doc = next(d for d in SpecBatcher(REPO_ROOT).load_specs() if d.name == "data-model.md")
    findings, _, trace = ReviewInvestigator(REPO_ROOT, CassetteStore(tmp_path)).single_shot_batch(spec_doc, "diff")
    assert findings == [] and trace == ["replay:miss"]

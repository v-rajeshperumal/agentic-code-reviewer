"""Regression tests for diff line counting, stable fingerprints, rate limiting and cassette fidelity."""
import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from specguard.agent import investigator as investigator_mod
from specguard.agent.investigator import ReviewInvestigator
from specguard.agent.tools import RepoToolContext
from specguard.cli import app
from specguard.llm.cassette import CassetteStore, clear_session_cache
from specguard.llm.provider import rate_limited
from specguard.postprocessor.evidence_gate import EvidenceGate
from specguard.preprocessor.diff_anchor import DiffAnchorParser
from specguard.preprocessor.spec_batcher import SpecBatcher
from specguard.schemas import CandidateList, InvestigatorRecording, RawCandidateFinding

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _fresh_session():
    clear_session_cache()
    yield
    clear_session_cache()


def _spec(name: str):
    return next(d for d in SpecBatcher(REPO_ROOT).load_specs() if d.name == name)


# --- 1. Diff line counting -------------------------------------------------

def test_no_newline_marker_does_not_shift_lines():
    diff = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,2 +1,3 @@
 a = 1
-b = 2
\\ No newline at end of file
+b = 3
+c = 4
\\ No newline at end of file
"""
    anchors = DiffAnchorParser().parse(diff).anchor_map
    assert anchors["m.py:L2"].raw_code == "b = 2"
    assert anchors["m.py:R2"].raw_code == "b = 3"
    assert anchors["m.py:R3"].raw_code == "c = 4"
    assert "m.py:R4" not in anchors


def test_rename_headers_are_not_anchored():
    diff = """diff --git a/old/m.py b/new/m.py
similarity index 90%
rename from old/m.py
rename to new/m.py
--- a/old/m.py
+++ b/new/m.py
@@ -1,2 +1,2 @@
 x = 1
-y = 2
+y = 3
"""
    parsed = DiffAnchorParser().parse(diff)
    assert list(parsed.anchored_by_file) == ["new/m.py"]
    assert sorted(parsed.anchor_map) == ["new/m.py:L2", "new/m.py:R1", "new/m.py:R2"]


def test_removed_line_that_looks_like_a_header_is_counted():
    diff = """diff --git a/q.sql b/q.sql
--- a/q.sql
+++ b/q.sql
@@ -1,2 +1,1 @@
--- legacy comment
 SELECT 1;
"""
    anchors = DiffAnchorParser().parse(diff).anchor_map
    assert anchors["q.sql:L1"].raw_code == "-- legacy comment"
    assert anchors["q.sql:R1"].raw_code == "SELECT 1;"


# --- 2. Stable fingerprints -----------------------------------------------

def _gate_fingerprint(line: int, title: str) -> str:
    padding = "".join(f" pad{i}\n" for i in range(1, line - 1))
    diff = f"""diff --git a/db/migrations/01.sql b/db/migrations/01.sql
--- a/db/migrations/01.sql
+++ b/db/migrations/01.sql
@@ -1,{line - 1} +1,{line} @@
 CREATE TABLE t (
{padding}+  amount FLOAT
"""
    parsed = DiffAnchorParser().parse(diff)
    spec_doc = _spec("data-model.md")
    ctx = RepoToolContext(REPO_ROOT, spec_doc)
    ctx.loaded_sections_text["Money"] = spec_doc.sections["Money"]
    cand = RawCandidateFinding(
        file_path="db/migrations/01.sql",
        anchor=f"R{line}",
        category="SPEC_DRIFT",
        severity="CRITICAL",
        spec_reference="Money",
        evidence_diff_quote="amount FLOAT",
        evidence_spec_quote="Floating-point types (`FLOAT`, `DOUBLE`, `REAL`, `float`) are strictly forbidden",
        title=title,
        rationale="r",
    )
    inline, _, _ = EvidenceGate().validate_candidates([cand], parsed, ctx)
    assert inline and inline[0].line == line
    return inline[0].fingerprint


def test_fingerprint_survives_line_shift_and_title_rewording():
    assert _gate_fingerprint(2, "Money stored as FLOAT") == _gate_fingerprint(6, "Float used for currency")


def test_secret_fingerprint_survives_line_shift_and_hides_value():
    scanner = DiffAnchorParser().scanner
    line = '+KEY = "AKIAIOSFODNN7EXAMPLE"'
    _, at_3 = scanner.scan_and_redact_line("a.py", 3, line)
    _, at_9 = scanner.scan_and_redact_line("a.py", 9, line)
    assert at_3[0].fingerprint == at_9[0].fingerprint
    assert "AKIA" not in at_3[0].model_dump_json()


# --- 3. Rate limiting on every model call ---------------------------------

class _CountingBucket:
    def __init__(self):
        self.calls = 0

    def acquire(self):
        self.calls += 1


class _FakeModel:
    async def stream(self, *args, **kwargs):
        yield {"chunk": 1}

    async def structured_output(self, *args, **kwargs):
        yield {"output": 1}


def test_rate_limiter_gates_each_model_request():
    bucket = _CountingBucket()
    model = rate_limited(_FakeModel(), bucket)

    async def drive():
        for _ in range(3):
            assert [e async for e in model.stream([])] == [{"chunk": 1}]
        assert [e async for e in model.structured_output(CandidateList, [])] == [{"output": 1}]

    asyncio.run(drive())
    assert bucket.calls == 4


# --- 4. Cassette fidelity -------------------------------------------------

DIFF = """diff --git a/models/payment.py b/models/payment.py
--- a/models/payment.py
+++ b/models/payment.py
@@ -1,1 +1,2 @@
 import db
+db.execute(f"SELECT * FROM payments WHERE id = {pid}")
"""

RULEBOOK_FINDING = RawCandidateFinding(
    file_path="models/payment.py",
    anchor="R2",
    category="CODE_QUALITY",
    severity="WARNING",
    spec_reference="SQL Safety",
    evidence_diff_quote='db.execute(f"SELECT * FROM payments WHERE id = {pid}")',
    evidence_spec_quote="Always use parameterized queries or ORM bind parameters.",
    title="f-string SQL",
    rationale="Interpolated SQL",
)


def _record(store: CassetteStore, anchored_diff: str) -> None:
    spec_doc = _spec("data-model.md")
    rulebook = (REPO_ROOT / ".spec/rules/python_best_practices.md").read_text(encoding="utf-8")
    payload = (
        f"{spec_doc.name}:{investigator_mod.spec_context_digest(REPO_ROOT, spec_doc)}::{anchored_diff}"
    )
    recording = InvestigatorRecording(
        candidates=CandidateList(findings=[RULEBOOK_FINDING]),
        loaded_sections={"rulebook:python": rulebook},
        tool_trace=['load_rulebook({"language": "python"})'],
    )
    store.save("investigator", payload, recording.model_dump_json())


def test_replay_restores_rulebook_text_so_gate_matches_live(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    parsed = DiffAnchorParser().parse(DIFF)
    anchored = parsed.anchored_by_file["models/payment.py"]
    store = CassetteStore(tmp_path)
    _record(store, anchored)
    clear_session_cache()  # force a read from disk, as in a fresh CI process

    findings, ctx, trace = ReviewInvestigator(REPO_ROOT, store).investigate_batch(_spec("data-model.md"), anchored)
    assert trace == ['load_rulebook({"language": "python"})']
    inline, summary, _ = EvidenceGate().validate_candidates(findings, parsed, ctx)
    assert len(inline) == 1 and not summary


def test_live_run_reuses_session_result_instead_of_resampling(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "ollama")

    def _no_model():
        raise AssertionError("model should not be called when the session already has this batch")

    monkeypatch.setattr(investigator_mod, "build_strands_model", _no_model)
    anchored = DiffAnchorParser().parse(DIFF).anchored_by_file["models/payment.py"]
    store = CassetteStore(tmp_path)
    _record(store, anchored)  # save() also populates the in-process session memo

    findings, _, _ = ReviewInvestigator(REPO_ROOT, store).investigate_batch(_spec("data-model.md"), anchored)
    assert [f.title for f in findings] == ["f-string SQL"]


def test_editing_a_spec_invalidates_its_cassette():
    spec_doc = _spec("data-model.md")
    before = investigator_mod.spec_context_digest(REPO_ROOT, spec_doc)
    spec_doc.full_text += "\n## New Rule\nSomething else."
    assert investigator_mod.spec_context_digest(REPO_ROOT, spec_doc) != before


# --- 5. record-cassettes command & TypeScript rulebook --------------------

def test_record_cassettes_refuses_replay_mode(monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    result = CliRunner().invoke(app, ["record-cassettes"])
    assert result.exit_code == 1
    assert "SPECGUARD_PROVIDER" in result.output


def test_typescript_rulebook_is_loadable():
    tools = RepoToolContext(REPO_ROOT, _spec("security.md")).build_tools()
    load_rulebook = next(t for t in tools if t.tool_name == "load_rulebook")
    text = load_rulebook(language="typescript")
    assert "## Async Safety" in text and "## SQL Safety" in text

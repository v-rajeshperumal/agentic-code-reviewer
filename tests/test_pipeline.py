from pathlib import Path
from specguard.agent.tools import RepoToolContext
from specguard.postprocessor.evidence_gate import EvidenceGate
from specguard.preprocessor.diff_anchor import DiffAnchorParser
from specguard.preprocessor.spec_batcher import SpecBatcher
from specguard.schemas import RawCandidateFinding

REPO_ROOT = Path(__file__).resolve().parents[1]


def _spec(name: str):
    return next(d for d in SpecBatcher(REPO_ROOT).load_specs() if d.name == name)


def test_secret_scanner_redacts_and_flags():
    diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,1 +1,2 @@
 x = 1
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""
    parsed = DiffAnchorParser().parse(diff)
    assert "<REDACTED:aws_access_key>" in parsed.anchored_by_file["app.py"]
    assert "AKIAIOSFODNN7EXAMPLE" not in parsed.anchored_by_file["app.py"]
    assert len(parsed.deterministic_findings) == 1
    assert parsed.deterministic_findings[0].line == 2


def test_diff_anchors_map_to_github_coordinates():
    diff = """diff --git a/svc.py b/svc.py
--- a/svc.py
+++ b/svc.py
@@ -10,3 +10,3 @@
 a = 1
-b = 2
+b = 3
 c = 4
"""
    parsed = DiffAnchorParser().parse(diff)
    assert parsed.anchor_map["svc.py:L11"].side == "LEFT"
    assert parsed.anchor_map["svc.py:R11"].raw_code == "b = 3"
    assert parsed.anchor_map["svc.py:R12"].raw_code == "c = 4"


def test_spec_batcher_routes_files_by_glob():
    batches = SpecBatcher(REPO_ROOT).build_batches(["db/migrations/001.sql", "api/payments.py"])
    routed = {doc.name: files for doc, files in batches}
    assert routed["data-model.md"] == ["db/migrations/001.sql"]
    assert routed["api.md"] == ["api/payments.py"]
    assert set(routed["security.md"]) == {"db/migrations/001.sql", "api/payments.py"}


def test_evidence_gate_demotes_hallucinated_quote():
    diff = """diff --git a/db/migrations/01.sql b/db/migrations/01.sql
--- a/db/migrations/01.sql
+++ b/db/migrations/01.sql
@@ -1,1 +1,2 @@
 CREATE TABLE t (
+  amount FLOAT
 );
"""
    parsed = DiffAnchorParser().parse(diff)
    spec_doc = _spec("data-model.md")
    ctx = RepoToolContext(REPO_ROOT, spec_doc)
    ctx.loaded_sections_text["Money"] = spec_doc.sections["Money"]

    bad_cand = RawCandidateFinding(
        file_path="db/migrations/01.sql",
        anchor="R2",
        category="SPEC_DRIFT",
        severity="CRITICAL",
        spec_reference="Money",
        evidence_diff_quote="NON_EXISTENT_CODE",
        evidence_spec_quote="Floating-point types (`FLOAT`, `DOUBLE`, `REAL`, `float`) are strictly forbidden",
        title="Float money",
        rationale="Uses float",
    )
    inline, summary, audit = EvidenceGate().validate_candidates([bad_cand], parsed, ctx)
    assert len(inline) == 0
    assert len(summary) == 1
    assert "evidence_diff_quote not matched" in audit[0]


def test_evidence_gate_accepts_grounded_finding():
    diff = """diff --git a/db/migrations/01.sql b/db/migrations/01.sql
--- a/db/migrations/01.sql
+++ b/db/migrations/01.sql
@@ -1,1 +1,2 @@
 CREATE TABLE t (
+  amount FLOAT
 );
"""
    parsed = DiffAnchorParser().parse(diff)
    spec_doc = _spec("data-model.md")
    ctx = RepoToolContext(REPO_ROOT, spec_doc)
    ctx.loaded_sections_text["Money"] = spec_doc.sections["Money"]

    good = RawCandidateFinding(
        file_path="db/migrations/01.sql",
        anchor="[R2]",
        category="spec_drift",
        severity="critical",
        spec_reference="Money",
        evidence_diff_quote="amount FLOAT",
        evidence_spec_quote="Floating-point types (`FLOAT`, `DOUBLE`, `REAL`, `float`) are strictly forbidden",
        title="Money stored as FLOAT, ping @someone",
        rationale="See [docs](https://evil.example)",
    )
    inline, summary, _ = EvidenceGate().validate_candidates([good], parsed, ctx)
    assert len(inline) == 1 and not summary
    f = inline[0]
    assert (f.line, f.side) == (2, "RIGHT")
    assert "`@someone`" in f.title
    assert "](https://" not in f.rationale

    report = EvidenceGate.build_report("x", inline, [], [])
    assert report.spec_compliance_status == "FAIL"


def test_repo_jail_blocks_traversal():
    import pytest

    ctx = RepoToolContext(REPO_ROOT, _spec("security.md"))
    with pytest.raises(PermissionError):
        ctx._safe_resolve("../../etc/passwd")

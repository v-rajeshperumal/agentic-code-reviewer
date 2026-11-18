"""Diff path edge cases, quote-based line resolution, and OpenTelemetry spans."""
from pathlib import Path

import pytest
import typer
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from specguard.agent.investigator import spec_context_digest
from specguard.agent.tools import RepoToolContext
from specguard.cli import resolve_trace_mode, run_review_pipeline
from specguard.llm.cassette import CassetteStore, clear_session_cache
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


# --- Diff paths ---------------------------------------------------------------

def test_quoted_non_ascii_path_is_unquoted():
    diff = r'''diff --git "a/models/caf\303\251.py" "b/models/caf\303\251.py"
--- "a/models/caf\303\251.py"
+++ "b/models/caf\303\251.py"
@@ -1,1 +1,2 @@
 x = 1
+price: float
'''
    parsed = DiffAnchorParser().parse(diff)
    assert list(parsed.anchored_by_file) == ["models/café.py"]
    assert parsed.anchor_map["models/café.py:R2"].raw_code == "price: float"


def test_path_with_spaces_uses_plus_plus_plus_header():
    diff = """diff --git a/api/my handlers.py b/api/my handlers.py
--- a/api/my handlers.py
+++ b/api/my handlers.py
@@ -1,1 +1,1 @@
-a = 1
+a = 2
"""
    parsed = DiffAnchorParser().parse(diff)
    assert list(parsed.anchored_by_file) == ["api/my handlers.py"]


def test_deleted_file_keeps_old_path_with_left_anchors():
    diff = """diff --git a/models/legacy.py b/models/legacy.py
deleted file mode 100644
--- a/models/legacy.py
+++ /dev/null
@@ -1,2 +0,0 @@
-total: float
-x = 1
"""
    parsed = DiffAnchorParser().parse(diff)
    assert list(parsed.anchored_by_file) == ["models/legacy.py"]
    assert sorted(parsed.anchor_map) == ["models/legacy.py:L1", "models/legacy.py:L2"]


def test_pure_rename_without_hunks_maps_to_new_path():
    diff = """diff --git a/models/old.py b/models/new.py
similarity index 100%
rename from models/old.py
rename to models/new.py
"""
    parsed = DiffAnchorParser().parse(diff)
    assert list(parsed.anchored_by_file) == ["models/new.py"]
    assert parsed.anchor_map == {}


# --- Quote-based line resolution ----------------------------------------------

DIFF = """diff --git a/services/storage.py b/services/storage.py
--- a/services/storage.py
+++ b/services/storage.py
@@ -1,2 +1,9 @@
 import json
+
+
+def load(path):
+    try:
+        with open(path) as fh:
+            return json.load(fh)
+    except:
+        return None
"""


def _gate(anchor: str, quote: str = "except:"):
    parsed = DiffAnchorParser().parse(DIFF)
    ctx = RepoToolContext(REPO_ROOT, _spec("security.md"))
    ctx.loaded_sections_text["rulebook:python"] = (REPO_ROOT / ".spec/rules/python_best_practices.md").read_text(
        encoding="utf-8"
    )
    cand = RawCandidateFinding(
        file_path="services/storage.py", anchor=anchor, category="CODE_QUALITY", severity="WARNING",
        spec_reference="Error Handling", evidence_diff_quote=quote,
        evidence_spec_quote="Never use bare `except:` clauses", title="Bare except", rationale="r",
    )
    return EvidenceGate().validate_candidates([cand], parsed, ctx)


def test_exact_anchor_on_quoted_line_is_kept():
    inline, _, audit = _gate("R8")
    assert inline[0].line == 8 and audit == []


def test_anchor_off_by_one_moves_to_quoted_line():
    inline, _, audit = _gate("R9")  # model pointed at `return None`
    assert inline[0].line == 8
    assert "moved from R9 to R8" in audit[0]


def test_missing_anchor_resolves_to_quote_and_odd_formats_parse():
    inline, _, audit = _gate("[r 42]")
    assert inline[0].line == 8
    assert "resolved missing anchor [r 42] to R8" in audit[0]


def test_unverifiable_quote_snaps_within_window_but_is_still_demoted():
    inline, summary, audit = _gate("R11", quote="except Exception:")
    assert inline == [] and summary[0].line == 9
    assert any("snapped from R11 to R9" in a for a in audit)


def test_anchor_beyond_window_is_not_snapped():
    _, summary, audit = _gate("R15", quote="except Exception:")
    assert summary[0].line == 1 and not any("snapped" in a for a in audit)


def test_multi_line_quote_without_anchor_prefixes_is_verified():
    inline, _, _ = _gate("R8", quote="    except:\n        return None")
    assert inline and inline[0].line == 8


# --- Tracing ------------------------------------------------------------------

@pytest.fixture
def spans():
    exporter = InMemorySpanExporter()
    provider = trace.get_tracer_provider()
    if not isinstance(provider, TracerProvider):
        provider = TracerProvider()
        trace.set_tracer_provider(provider)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield exporter
    exporter.clear()


def test_pipeline_emits_review_batch_verify_and_gate_spans(spans, tmp_path, monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    monkeypatch.chdir(tmp_path)
    anchored = DiffAnchorParser().parse(DIFF).anchored_by_file["services/storage.py"]
    spec = _spec("security.md")
    rulebook = (REPO_ROOT / ".spec/rules/python_best_practices.md").read_text(encoding="utf-8")
    finding = RawCandidateFinding(
        file_path="services/storage.py", anchor="R9", category="CODE_QUALITY", severity="WARNING",
        spec_reference="Error Handling", evidence_diff_quote="except:",
        evidence_spec_quote="Never use bare `except:` clauses", title="Bare except", rationale="r",
    )
    CassetteStore(Path("evals/cassettes")).save(
        "investigator",
        f"{spec.name}:{spec_context_digest(REPO_ROOT, spec)}::{anchored}",
        InvestigatorRecording(
            candidates=CandidateList(findings=[finding]),
            loaded_sections={"rulebook:python": rulebook},
            tool_trace=['load_rulebook({"language": "python"})'],
        ).model_dump_json(),
    )

    report = run_review_pipeline(REPO_ROOT, DIFF, mode="full")
    assert [f.line for f in report.inline_findings] == [8]

    by_name = {}
    for span in spans.get_finished_spans():
        by_name.setdefault(span.name, []).append(span)
    assert {"specguard.review", "specguard.batch", "specguard.verify", "specguard.evidence_gate"} <= set(by_name)
    assert by_name["specguard.review"][0].attributes["specguard.status"] == "NEEDS_REVIEW"
    verify = by_name["specguard.verify"][0].attributes
    assert verify["specguard.verdict.keep"] is True and verify["specguard.finding.anchor"] == "R9"
    gate_events = [e.attributes["detail"] for s in by_name["specguard.evidence_gate"] for e in s.events]
    assert any("moved from R9 to R8" in d for d in gate_events)
    tool_events = [e.attributes["calls"] for s in by_name["specguard.batch"] for e in s.events]
    assert ('load_rulebook({"language": "python"})',) in tool_events


@pytest.mark.parametrize(
    "flag,env,expected",
    [(None, None, "off"), (None, "1", "console"), ("otlp", "console", "otlp"), (None, "OTLP", "otlp"), ("off", "1", "off")],
)
def test_trace_mode_resolution(flag, env, expected):
    assert resolve_trace_mode(flag, env) == expected


def test_unknown_trace_mode_is_rejected():
    with pytest.raises(typer.BadParameter):
        resolve_trace_mode("jaeger", None)

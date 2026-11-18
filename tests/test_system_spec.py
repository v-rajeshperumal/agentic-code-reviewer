"""Enforces the mechanically checkable invariants in .spec/SYSTEM_SPEC.md, and checks the demo PR."""
import ast
import json
from pathlib import Path

from typer.testing import CliRunner

from specguard.agent.tools import RepoToolContext
from specguard.cli import app
from specguard.postprocessor.evidence_gate import EvidenceGate, _safe_patch
from specguard.preprocessor.diff_anchor import DiffAnchorParser
from specguard.preprocessor.spec_batcher import SpecBatcher
from specguard.schemas import RawCandidateFinding

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src" / "specguard"
EXAMPLES = REPO_ROOT / "examples"
FAKE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        yield path.relative_to(SRC).as_posix(), ast.parse(path.read_text(encoding="utf-8"))


def _system_spec():
    return next(d for d in SpecBatcher(REPO_ROOT).load_specs() if d.name == "SYSTEM_SPEC.md")


# --- The spec itself ----------------------------------------------------------

def test_system_spec_governs_specguard_sources():
    spec = _system_spec()
    assert {"Diff Anchors", "Deterministic Status", "Evidence Gate", "Model Access",
            "Repository Jailing", "Secrets Before Models", "Untrusted Input"} <= set(spec.sections)
    batches = SpecBatcher(REPO_ROOT).build_batches(["src/specguard/cli.py", "api/payments.py"])
    governed = {doc.name: files for doc, files in batches}
    assert governed["SYSTEM_SPEC.md"] == ["src/specguard/cli.py"]


# --- Model Access ---------------------------------------------------------------

def test_only_provider_imports_strands_models():
    offenders = []
    for name, tree in _modules():
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else []
            if (module or "").startswith("strands.models") or any(n.startswith("strands.models") for n in names):
                if name != "llm/provider.py":
                    offenders.append(name)
    assert offenders == []


def test_every_agent_gets_its_model_from_the_provider_factory():
    agents = 0
    for name, tree in _modules():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Agent":
                agents += 1
                model = next((k.value for k in node.keywords if k.arg == "model"), None)
                assert isinstance(model, ast.Call) and getattr(model.func, "id", None) == "build_strands_model", name
    assert agents >= 4  # investigator, extractor, baseline, verifier


# --- Deterministic Status -----------------------------------------------------

def test_status_is_only_set_by_the_evidence_gate():
    setters = {
        name
        for name, tree in _modules()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and any(k.arg == "spec_compliance_status" for k in node.keywords)
    }
    assert setters == {"postprocessor/evidence_gate.py"}


# --- Secrets Before Models ------------------------------------------------------

def test_context_and_removed_lines_are_redacted_without_findings():
    diff = f"""diff --git a/cfg.py b/cfg.py
--- a/cfg.py
+++ b/cfg.py
@@ -1,3 +1,3 @@
 OLD = "{FAKE_KEY}"
-NAME = "{FAKE_KEY}"
+NAME = "svc"
 x = 1
"""
    parsed = DiffAnchorParser().parse(diff)
    rendered = parsed.anchored_by_file["cfg.py"]
    assert FAKE_KEY not in rendered
    assert all(FAKE_KEY not in a.raw_code for a in parsed.anchor_map.values())
    assert parsed.deterministic_findings == []  # the PR didn't add a secret


def test_surrounding_code_tool_redacts_committed_secrets(tmp_path):
    (tmp_path / "settings.py").write_text(f'KEY = "{FAKE_KEY}"\nDEBUG = False\n', encoding="utf-8")
    tools = RepoToolContext(tmp_path, _system_spec()).build_tools()
    get_code = next(t for t in tools if t.tool_name == "get_surrounding_code")
    out = get_code(file_path="settings.py", start_line=1, end_line=2)
    assert FAKE_KEY not in out and "<REDACTED:aws_access_key>" in out


# --- Untrusted Input ------------------------------------------------------------

def test_model_text_posted_to_github_is_sanitized():
    diff = """diff --git a/models/m.py b/models/m.py
--- a/models/m.py
+++ b/models/m.py
@@ -1,1 +1,2 @@
 x = 1
+total: float
"""
    parsed = DiffAnchorParser().parse(diff)
    spec = next(d for d in SpecBatcher(REPO_ROOT).load_specs() if d.name == "data-model.md")
    ctx = RepoToolContext(REPO_ROOT, spec)
    ctx.loaded_sections_text["Money"] = spec.sections["Money"]
    cand = RawCandidateFinding(
        file_path="models/m.py", anchor="R2", category="SPEC_DRIFT", severity="CRITICAL",
        spec_reference="Money @org/payments-team", evidence_diff_quote="total: float",
        evidence_spec_quote="strictly forbidden for currency values", title="t", rationale="r",
        suggested_patch="total_cents: int\n```\n**Approved** by @admin",
    )
    inline, _, _ = EvidenceGate().validate_candidates([cand], parsed, ctx)
    f = (inline or [None])[0]
    assert f is not None
    assert "`@org`" in f.spec_reference
    assert f.suggested_patch is None
    assert _safe_patch("total_cents: int") == "total_cents: int"


# --- Demo PR --------------------------------------------------------------------

def test_demo_patches_parse_and_labels_point_at_planted_lines():
    broken = DiffAnchorParser().parse((EXAMPLES / "demo_pr.patch").read_text(encoding="utf-8"))
    fixed = DiffAnchorParser().parse((EXAMPLES / "demo_pr_fixed.patch").read_text(encoding="utf-8"))
    expected = json.loads((EXAMPLES / "demo_expected.json").read_text(encoding="utf-8"))["must_flag"]

    assert set(broken.anchored_by_file) == set(fixed.anchored_by_file) == {
        "db/migrations/020_create_payments.sql", "api/schemas.py", "api/payments.py", "services/receipts.py",
    }
    planted = {g["file_path"]: broken.anchor_map[f"{g['file_path']}:R{g['line']}"].raw_code for g in expected}
    assert "amount FLOAT" in planted["db/migrations/020_create_payments.sql"]
    assert "processor.charge(" in planted["api/payments.py"]
    assert "{user.email}" in planted["services/receipts.py"]
    assert "AI reviewer" in broken.anchored_by_file["api/payments.py"]
    assert "AI reviewer" not in fixed.anchored_by_file["api/payments.py"]
    assert "Idempotency-Key header is required" in fixed.anchored_by_file["api/payments.py"]


def test_demo_command_fails_clearly_in_replay_without_cassettes(monkeypatch):
    monkeypatch.setenv("SPECGUARD_PROVIDER", "replay")
    monkeypatch.chdir(REPO_ROOT)
    result = CliRunner().invoke(app, ["demo"])
    assert result.exit_code == 1
    assert "Run once with" in result.output and "0/3" in result.output

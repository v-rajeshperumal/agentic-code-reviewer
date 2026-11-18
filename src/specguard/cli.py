import subprocess
import sys
from pathlib import Path
from typing import Literal
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from specguard.agent.investigator import ReviewInvestigator
from specguard.agent.verifier import AdversarialVerifier
from specguard.github.review_publisher import GitHubReviewPublisher
from specguard.llm.provider import get_provider_name
from specguard.postprocessor.evidence_gate import EvidenceGate
from specguard.preprocessor.diff_anchor import DiffAnchorParser
from specguard.preprocessor.spec_batcher import SpecBatcher
from specguard.schemas import PRReviewReport, ValidatedFinding

app = typer.Typer(help="SpecGuard: Agentic PR & System-Spec Compliance Reviewer")
console = Console()


PipelineMode = Literal["baseline", "agent", "full"]


def _dedupe(findings: list[ValidatedFinding]) -> tuple[list[ValidatedFinding], list[str]]:
    """Drops repeats of the same defect: a file matched by two specs is investigated twice,
    and the model may re-report a secret the deterministic scanner already caught."""
    seen: set[tuple] = set()
    kept, audit = [], []
    for f in findings:
        keys = {(f.file_path, f.line, f.category)}
        if f.fingerprint:
            keys.add(f.fingerprint)
        if keys & seen:
            audit.append(f"Deduplicated `{f.title}` ({f.file_path}:{f.line})")
            continue
        seen.update(keys)
        kept.append(f)
    return kept, audit


def run_review_pipeline(
    repo_root: Path,
    raw_diff: str,
    use_verifier: bool = True,
    reuse_cassettes: bool = False,
    mode: PipelineMode | None = None,
) -> PRReviewReport:
    """Runs one review. `mode` selects the ablation configuration:

    - baseline: single structured call per spec, no tools, no verifier, no quote checks
    - agent:    tool-using investigator + EvidenceGate, no verifier
    - full:     agent + adversarial verifier (default)
    """
    mode = mode or ("full" if use_verifier else "agent")
    parser = DiffAnchorParser()
    parsed = parser.parse(raw_diff)

    batcher = SpecBatcher(repo_root)
    batches = batcher.build_batches(list(parsed.anchored_by_file.keys()))

    investigator = ReviewInvestigator(repo_root, reuse_cassettes=reuse_cassettes)
    verifier = AdversarialVerifier(repo_root, reuse_cassettes=reuse_cassettes)
    gate = EvidenceGate()

    all_inline = list(parsed.deterministic_findings)
    all_summary = []
    all_audit = []

    for spec_doc, files in batches:
        batch_diff = "\n\n".join(parsed.anchored_by_file[f] for f in files if f in parsed.anchored_by_file)
        if mode == "baseline":
            candidates, tool_ctx, _ = investigator.single_shot_batch(spec_doc, batch_diff)
        else:
            candidates, tool_ctx, _ = investigator.investigate_batch(spec_doc, batch_diff)

        surviving = []
        for cand in candidates:
            if mode == "full":
                verdict = verifier.verify(spec_doc, cand, batch_diff)
                if not verdict.keep:
                    all_audit.append(f"Verifier rejected `{cand.title}`: {verdict.reason}")
                    continue
            surviving.append(cand)

        inline, summary, audit = gate.validate_candidates(
            surviving, parsed, tool_ctx, require_evidence=(mode != "baseline")
        )
        all_inline.extend(inline)
        all_summary.extend(summary)
        all_audit.extend(audit)

    all_inline, dedupe_audit = _dedupe(all_inline)
    all_summary, dedupe_audit_2 = _dedupe(all_summary)
    all_audit.extend(dedupe_audit + dedupe_audit_2)

    summary_text = (
        f"Reviewed {len(parsed.anchored_by_file)} modified file(s) across {len(batches)} governing spec(s)."
    )
    return gate.build_report(summary_text, all_inline, all_summary, all_audit)


@app.command()
def review(
    base: str = typer.Option("HEAD~1", help="Base git ref"),
    head: str = typer.Option("HEAD", help="Head git ref"),
    diff_file: Path | None = typer.Option(None, help="Optional path to a .patch file"),
    repo_path: Path = typer.Option(Path("."), help="Repository root path"),
    no_verifier: bool = typer.Option(False, help="Disable Stage 2 adversarial verifier"),
    post_github: bool = typer.Option(False, help="Post review to GitHub PR API"),
    pr_number: int = typer.Option(0, help="GitHub PR number"),
    commit_sha: str = typer.Option("", help="Head commit SHA"),
    json_out: Path | None = typer.Option(None, help="Write JSON report to file"),
) -> None:
    """Review a git range or a .patch file against the repository's .spec/ documents."""
    if diff_file:
        raw_diff = diff_file.read_text(encoding="utf-8")
    else:
        raw_diff = subprocess.check_output(
            ["git", "diff", "-U3", f"{base}...{head}"], cwd=repo_path, text=True
        )

    report = run_review_pipeline(repo_path, raw_diff, use_verifier=not no_verifier)

    console.print(Panel(f"[bold]Status:[/bold] {report.spec_compliance_status}\n{report.summary}", title="SpecGuard"))
    table = Table(title="Verified Inline Findings")
    table.add_column("File:Line")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Spec Ref")
    for f in report.inline_findings:
        table.add_row(f"{f.file_path}:{f.line}", f.severity.value, f.category.value, f.title, f.spec_reference)
    console.print(table)

    if json_out:
        json_out.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    if post_github and pr_number and commit_sha:
        GitHubReviewPublisher().publish_review(pr_number, commit_sha, report)


@app.command("eval")
def eval_cmd(
    dataset_dir: Path = typer.Option(Path("evals/dataset"), help="Golden dataset directory"),
    ablation: bool = typer.Option(False, help="Compare baseline, agent-only and full configurations"),
    runs: int = typer.Option(1, min=1, help="Repeat each configuration N times and report mean ± std"),
) -> None:
    """Score the pipeline against the golden dataset (run from the repo root)."""
    # `evals/` lives at the repo root, outside the installed package.
    sys.path.insert(0, str(Path.cwd()))
    from evals.run_evals import execute_eval_suite
    execute_eval_suite(dataset_dir, ablation=ablation, runs=runs)


@app.command("record-cassettes")
def record_cassettes(
    dataset_dir: Path = typer.Option(Path("evals/dataset"), help="Golden dataset directory"),
    case: list[str] = typer.Option([], help="Only record these case directory names (repeatable)"),
    resume: bool = typer.Option(
        False, help="Keep existing cassettes and only record missing ones (resume after a rate-limit stop)"
    ),
) -> None:
    """Run every golden case once against a live model and save investigator + verifier cassettes."""
    provider = get_provider_name()
    if provider == "replay":
        console.print("[red]Set SPECGUARD_PROVIDER=ollama or gemini to record cassettes.[/red]")
        raise typer.Exit(code=1)

    case_dirs = sorted(d for d in dataset_dir.iterdir() if d.is_dir() and (not case or d.name in case))
    if case and len(case_dirs) != len(set(case)):
        missing = set(case) - {d.name for d in case_dirs}
        console.print(f"[red]Unknown case(s): {', '.join(sorted(missing))}[/red]")
        raise typer.Exit(code=1)

    for i, case_dir in enumerate(case_dirs, 1):
        console.print(f"[{i}/{len(case_dirs)}] {case_dir.name} via {provider}")
        diff_text = (case_dir / "diff.patch").read_text(encoding="utf-8")
        # Baseline, then full (investigator + verifier); the agent-only ablation reuses
        # the full run's investigator cassette, so these two cover every eval config.
        for mode in ("baseline", "full"):
            run_review_pipeline(Path("."), diff_text, reuse_cassettes=resume, mode=mode)

    console.print(f"[green]Recorded {len(case_dirs)} case(s) into evals/cassettes/.[/green]")


if __name__ == "__main__":
    app()

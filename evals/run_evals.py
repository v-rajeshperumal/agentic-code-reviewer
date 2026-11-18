import json
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from rich.console import Console
from rich.table import Table
from scipy.optimize import linear_sum_assignment

from specguard.cli import run_review_pipeline
from specguard.llm.cassette import clear_session_cache
from specguard.schemas import ValidatedFinding

console = Console()

# Configurations shown in the ablation table, in order.
ABLATION_CONFIGS = [
    ("Single-Shot Baseline", "baseline"),
    ("Investigator + Tools + EvidenceGate", "agent"),
    ("Full SpecGuard + Verifier", "full"),
]

METRICS = ["precision", "recall", "line_acc", "severity_acc", "citation_acc", "latency_s"]


@dataclass
class CaseScore:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    exact_line: int = 0
    severity_ok: int = 0
    citation_ok: int = 0

    def __iadd__(self, other: "CaseScore") -> "CaseScore":
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(self, name) + getattr(other, name))
        return self


def _matches(pred: ValidatedFinding, gold: dict) -> bool:
    return (
        pred.file_path == gold["file_path"]
        and pred.category.value == gold["category"]
        and pred.line in gold["acceptable_lines"]
    )


def _same_citation(pred: ValidatedFinding, gold: dict) -> bool:
    return pred.spec_reference.strip().lower() == gold["spec_reference"].strip().lower()


def _bipartite_score(preds: list[ValidatedFinding], must_flag: list[dict], may_flag: list[dict]) -> CaseScore:
    """One-to-one Hungarian matching between predictions and must_flag golds.

    A pair can match only if file, category and line (within `acceptable_lines`)
    agree. Among valid pairings, the solver prefers predictions closest to the
    gold's primary `line`. Unmatched predictions that fall in a `may_flag` window
    are neither rewarded nor penalized.
    """
    score = CaseScore()
    matched_preds: set[int] = set()

    if must_flag and preds:
        BIG = 10_000.0
        cost = np.full((len(preds), len(must_flag)), BIG)
        for i, p in enumerate(preds):
            for j, g in enumerate(must_flag):
                if _matches(p, g):
                    cost[i, j] = abs(p.line - g["line"])

        for r, c in zip(*linear_sum_assignment(cost)):
            if cost[r, c] >= BIG:
                continue
            pred, gold = preds[r], must_flag[c]
            matched_preds.add(r)
            score.tp += 1
            score.exact_line += int(pred.line == gold["line"])
            score.severity_ok += int(pred.severity.value == gold["severity"])
            score.citation_ok += int(_same_citation(pred, gold))

    score.fn = len(must_flag) - score.tp
    score.fp = sum(
        1
        for i, p in enumerate(preds)
        if i not in matched_preds and not any(_matches(p, m) for m in may_flag)
    )
    return score


def _ratio(num: int, den: int) -> float:
    return num / den if den else 1.0


def _eval_config(dataset_dir: Path, mode: str) -> dict:
    total = CaseScore()
    t0 = time.perf_counter()

    for case_dir in sorted(dataset_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        diff_text = (case_dir / "diff.patch").read_text(encoding="utf-8")
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        report = run_review_pipeline(Path("."), diff_text, mode=mode)
        total += _bipartite_score(
            report.inline_findings, expected.get("must_flag", []), expected.get("may_flag", [])
        )

    return {
        "precision": _ratio(total.tp, total.tp + total.fp),
        "recall": _ratio(total.tp, total.tp + total.fn),
        "line_acc": _ratio(total.exact_line, total.tp),
        "severity_acc": _ratio(total.severity_ok, total.tp),
        "citation_acc": _ratio(total.citation_ok, total.tp),
        "latency_s": time.perf_counter() - t0,
    }


def _fmt(values: list[float], suffix: str = "") -> str:
    mean = float(np.mean(values))
    if len(values) == 1:
        return f"{mean:.2f}{suffix}"
    return f"{mean:.2f} ± {float(np.std(values)):.2f}{suffix}"


def execute_eval_suite(dataset_dir: Path, ablation: bool = False, runs: int = 1) -> list[dict]:
    configs = ABLATION_CONFIGS if ablation else [ABLATION_CONFIGS[-1]]

    title = "SpecGuard Evaluation & Ablation Results"
    if runs > 1:
        title += f" (mean ± std over {runs} runs)"
    table = Table(title=title)
    for column in ["Configuration", "Precision", "Recall", "Exact Line Acc", "Severity Acc", "Citation Acc", "Latency"]:
        table.add_column(column)

    per_config: dict[str, list[dict]] = {mode: [] for _, mode in configs}
    for _ in range(runs):
        # Each run is an independent sample, so forget the previous run's results.
        # Configs inside one run still share an investigation (agent vs full differ
        # only by the verifier), which keeps the ablation an apples-to-apples comparison.
        clear_session_cache()
        for _, mode in configs:
            per_config[mode].append(_eval_config(dataset_dir, mode))

    rows = []
    for label, mode in configs:
        summary = {m: [r[m] for r in per_config[mode]] for m in METRICS}
        rows.append({"configuration": label, **{m: float(np.mean(v)) for m, v in summary.items()}})
        table.add_row(
            label,
            _fmt(summary["precision"]),
            _fmt(summary["recall"]),
            _fmt(summary["line_acc"]),
            _fmt(summary["severity_acc"]),
            _fmt(summary["citation_acc"]),
            _fmt(summary["latency_s"], "s"),
        )

    console.print(table)
    return rows


if __name__ == "__main__":
    execute_eval_suite(Path("evals/dataset"), ablation=True)

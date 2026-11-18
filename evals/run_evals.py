import json
import time
from pathlib import Path
import numpy as np
from rich.console import Console
from rich.table import Table
from scipy.optimize import linear_sum_assignment
from specguard.cli import run_review_pipeline
from specguard.schemas import ValidatedFinding

console = Console()


def _bipartite_score(
    preds: list[ValidatedFinding], must_flag: list[dict], may_flag: list[dict]
) -> tuple[int, int, int, int]:
    """One-to-one Hungarian matching on line distance within acceptable_lines."""
    if not must_flag:
        unmatched_fp = [
            p for p in preds
            if not any(
                p.file_path == m["file_path"]
                and p.category.value == m["category"]
                and p.line in m["acceptable_lines"]
                for m in may_flag
            )
        ]
        return 0, len(unmatched_fp), 0, 0

    if not preds:
        return 0, 0, len(must_flag), 0

    BIG = 10_000.0
    cost = np.full((len(preds), len(must_flag)), BIG)
    for i, p in enumerate(preds):
        for j, g in enumerate(must_flag):
            if p.file_path == g["file_path"] and p.category.value == g["category"]:
                if p.line in g["acceptable_lines"]:
                    cost[i, j] = min(abs(p.line - l) for l in g["acceptable_lines"])

    row_ind, col_ind = linear_sum_assignment(cost)
    tp = 0
    exact_line = 0
    matched_pred_indices = set()
    for r, c in zip(row_ind, col_ind):
        if cost[r, c] < BIG:
            tp += 1
            matched_pred_indices.add(r)
            if cost[r, c] == 0:
                exact_line += 1

    fp = 0
    for i, p in enumerate(preds):
        if i in matched_pred_indices:
            continue
        is_may = any(
            p.file_path == m["file_path"]
            and p.category.value == m["category"]
            and p.line in m["acceptable_lines"]
            for m in may_flag
        )
        if not is_may:
            fp += 1

    fn = len(must_flag) - tp
    return tp, fp, fn, exact_line


def _eval_config(dataset_dir: Path, use_verifier: bool) -> dict:
    total_tp = total_fp = total_fn = total_exact = 0
    t0 = time.perf_counter()

    for case_dir in sorted(dataset_dir.iterdir()):
        if not case_dir.is_dir():
            continue
        diff_text = (case_dir / "diff.patch").read_text(encoding="utf-8")
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        report = run_review_pipeline(Path("."), diff_text, use_verifier=use_verifier)
        tp, fp, fn, exact = _bipartite_score(
            report.inline_findings, expected.get("must_flag", []), expected.get("may_flag", [])
        )
        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_exact += exact

    elapsed = time.perf_counter() - t0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    line_acc = total_exact / total_tp if total_tp else 1.0
    return {
        "precision": precision,
        "recall": recall,
        "line_acc": line_acc,
        "latency_s": elapsed,
    }


def execute_eval_suite(dataset_dir: Path, ablation: bool = False) -> None:
    configs = [("Tools + EvidenceGate (No Verifier)", False), ("Full Agent + Verifier", True)] if ablation else [
        ("Full Agent + Verifier", True)
    ]

    table = Table(title="SpecGuard Evaluation & Ablation Results")
    table.add_column("Configuration")
    table.add_column("Precision")
    table.add_column("Recall")
    table.add_column("Exact Line Acc")
    table.add_column("Total Latency")

    for label, use_ver in configs:
        res = _eval_config(dataset_dir, use_verifier=use_ver)
        table.add_row(
            label,
            f"{res['precision']:.2f}",
            f"{res['recall']:.2f}",
            f"{res['line_acc']:.2f}",
            f"{res['latency_s']:.2f}s",
        )

    console.print(table)


if __name__ == "__main__":
    execute_eval_suite(Path("evals/dataset"), ablation=True)

import re
from typing import Tuple
from specguard.agent.tools import RepoToolContext
from specguard.preprocessor.diff_anchor import ParsedDiff
from specguard.schemas import (
    FindingCategory,
    PRReviewReport,
    RawCandidateFinding,
    Severity,
    ValidatedFinding,
    finding_fingerprint,
)


def _normalize_ws(text: str) -> str:
    return " ".join(text.split())


def _sanitize_mentions(text: str) -> str:
    """Prevents prompt-injected @mentions or external markdown links in PR comments."""
    text = re.sub(r"@([a-zA-Z0-9_\-]+)", r"`@\1`", text)
    text = re.sub(r"\[([^\]]+)\]\((https?://[^\)]+)\)", r"\1 (`\2`)", text)
    return text


def _safe_patch(patch: str | None) -> str | None:
    """Drops a suggested patch that could break out of its ```suggestion fence.

    Inside the fence GitHub renders code verbatim (mentions and links are inert),
    so the only escape is a backtick fence of the model's own.
    """
    if patch is None or "```" in patch or "~~~" in patch:
        return None
    return patch


class EvidenceGate:
    """Deterministic post-processor replacing uncalibrated LLM confidence scores."""

    def validate_candidates(
        self,
        candidates: list[RawCandidateFinding],
        parsed_diff: ParsedDiff,
        tool_ctx: RepoToolContext,
        require_evidence: bool = True,
    ) -> Tuple[list[ValidatedFinding], list[ValidatedFinding], list[str]]:
        """Resolves anchors and, unless `require_evidence=False` (ablation baseline), demotes
        any finding whose diff or spec quote is not found verbatim."""
        inline: list[ValidatedFinding] = []
        summary: list[ValidatedFinding] = []
        audit_log: list[str] = []

        for cand in candidates:
            clean_anchor = cand.anchor.strip("[]")
            lookup_key = f"{cand.file_path}:{clean_anchor}"
            target = parsed_diff.anchor_map.get(lookup_key)

            # 1. Anchor & diff line validation
            inline_ok = True
            reasons: list[str] = []
            if target is None:
                inline_ok = False
                reasons.append(f"anchor `{cand.anchor}` not found in active diff hunk")
                resolved_line, resolved_side = 1, "RIGHT"
            else:
                resolved_line, resolved_side = target.line, target.side

            # 2. Exact diff quote verification
            file_diff_text = parsed_diff.anchored_by_file.get(cand.file_path, "")
            if require_evidence and _normalize_ws(cand.evidence_diff_quote) not in _normalize_ws(file_diff_text):
                inline_ok = False
                reasons.append("evidence_diff_quote not matched in diff")

            # 3. Spec citation & verbatim spec quote verification
            spec_body = tool_ctx.loaded_sections_text.get(cand.spec_reference, "")
            if not spec_body:
                # Fallback check across loaded sections if agent cited heading slightly differently
                for sec_name, sec_text in tool_ctx.loaded_sections_text.items():
                    if _normalize_ws(cand.evidence_spec_quote) in _normalize_ws(sec_text):
                        spec_body = sec_text
                        break

            if require_evidence and (
                not spec_body or _normalize_ws(cand.evidence_spec_quote) not in _normalize_ws(spec_body)
            ):
                inline_ok = False
                reasons.append(f"evidence_spec_quote not matched in cited spec `{cand.spec_reference}`")

            try:
                cat = FindingCategory(cand.category.upper())
            except ValueError:
                cat = FindingCategory.CODE_QUALITY

            try:
                sev = Severity(cand.severity.upper())
            except ValueError:
                sev = Severity.INFO

            fp = finding_fingerprint(cand.file_path, cat.value, cand.spec_reference, cand.evidence_diff_quote)

            finding = ValidatedFinding(
                file_path=cand.file_path,
                line=resolved_line,
                side=resolved_side,
                category=cat,
                severity=sev,
                spec_reference=_sanitize_mentions(cand.spec_reference),
                evidence_diff_quote=cand.evidence_diff_quote,
                evidence_spec_quote=cand.evidence_spec_quote,
                title=_sanitize_mentions(cand.title),
                rationale=_sanitize_mentions(cand.rationale),
                suggested_patch=_safe_patch(cand.suggested_patch),
                inline_eligible=inline_ok and sev in (Severity.CRITICAL, Severity.WARNING),
                drop_reason="; ".join(reasons) if reasons else None,
                fingerprint=fp,
            )

            if finding.inline_eligible:
                inline.append(finding)
            else:
                audit_log.append(
                    f"Demoted `{cand.title}` ({cand.file_path}:{cand.anchor}) to summary: "
                    f"{finding.drop_reason or 'INFO severity'}"
                )
                summary.append(finding)

        return inline, summary, audit_log

    @staticmethod
    def build_report(
        summary_text: str,
        inline_findings: list[ValidatedFinding],
        summary_findings: list[ValidatedFinding],
        audit_log: list[str],
    ) -> PRReviewReport:
        """Computes spec_compliance_status deterministically from validated findings."""
        all_findings = inline_findings + summary_findings
        has_critical = any(f.severity == Severity.CRITICAL for f in all_findings)
        has_warning = any(f.severity == Severity.WARNING for f in all_findings)

        if has_critical:
            status = "FAIL"
        elif has_warning:
            status = "NEEDS_REVIEW"
        else:
            status = "PASS"

        return PRReviewReport(
            summary=_sanitize_mentions(summary_text),
            spec_compliance_status=status,
            inline_findings=inline_findings,
            summary_findings=summary_findings,
            dropped_audit_log=audit_log,
        )

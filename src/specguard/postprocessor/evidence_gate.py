import re
from typing import Tuple
from specguard.agent.tools import RepoToolContext
from specguard.preprocessor.diff_anchor import AnchorTarget, ParsedDiff
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


SNAP_WINDOW = 3


def _targets_for(parsed_diff: ParsedDiff, file_path: str) -> list[AnchorTarget]:
    """All diff lines of one file, in diff order."""
    return [t for t in parsed_diff.anchor_map.values() if t.file_path == file_path]


def _parse_anchor(anchor: str) -> tuple[str, int] | None:
    """Accepts `R42`, `[R42]`, `r 42`, `L7`; returns ("RIGHT"|"LEFT", line)."""
    match = re.search(r"([RLrl])\s*(\d+)", anchor)
    if not match:
        return None
    return ("RIGHT" if match.group(1).upper() == "R" else "LEFT"), int(match.group(2))


def _label(target: AnchorTarget) -> str:
    return f"{'R' if target.side == 'RIGHT' else 'L'}{target.line}"


def _resolve_anchor(
    anchor: str, diff_quote: str, targets: list[AnchorTarget]
) -> tuple[AnchorTarget | None, str | None]:
    """Picks the diff line a finding should be posted on.

    1. If the quoted code is found on diff lines, use the one nearest the model's
       anchor. The quote is verified evidence; the anchor is the model's claim.
    2. Otherwise keep the anchor if it exists.
    3. Otherwise snap to the nearest line on the same side within ±SNAP_WINDOW.

    Returns (target or None, audit note or None).
    """
    parsed = _parse_anchor(anchor)
    exact = next((t for t in targets if parsed and (t.side, t.line) == parsed), None)

    needle = next((_normalize_ws(l) for l in diff_quote.splitlines() if l.strip()), "")
    hits = [t for t in targets if needle and needle in _normalize_ws(t.raw_code)]
    if hits:
        if exact in hits:
            return exact, None
        side, ref = parsed if parsed else (hits[0].side, hits[0].line)
        best = min(hits, key=lambda t: (abs(t.line - ref), t.side != side))
        how = f"moved from {anchor}" if exact else f"resolved missing anchor {anchor}"
        return best, f"{how} to {_label(best)} (evidence quote location)"

    if exact:
        return exact, None
    if parsed:
        side, line = parsed
        near = [t for t in targets if t.side == side and abs(t.line - line) <= SNAP_WINDOW]
        if near:
            best = min(near, key=lambda t: abs(t.line - line))
            return best, f"snapped from {anchor} to {_label(best)} (nearest diff line)"
    return None, None


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
            targets = _targets_for(parsed_diff, cand.file_path)

            # 1. Anchor resolution: the verified quote decides the line, the model's
            #    anchor only breaks ties (see _resolve_anchor).
            inline_ok = True
            reasons: list[str] = []
            target, note = _resolve_anchor(cand.anchor, cand.evidence_diff_quote, targets)
            if note:
                audit_log.append(f"`{cand.title}` ({cand.file_path}): {note}")
            if target is None:
                inline_ok = False
                reasons.append(f"anchor `{cand.anchor}` not found in active diff hunk")
                resolved_line, resolved_side = 1, "RIGHT"
            else:
                resolved_line, resolved_side = target.line, target.side

            # 2. Exact diff quote verification, against the anchored rendering or the
            #    plain code (so a multi-line quote need not repeat the [R#] prefixes)
            quote = _normalize_ws(cand.evidence_diff_quote)
            anchored_text = _normalize_ws(parsed_diff.anchored_by_file.get(cand.file_path, ""))
            plain_text = _normalize_ws("\n".join(t.raw_code for t in targets))
            if require_evidence and (not quote or (quote not in anchored_text and quote not in plain_text)):
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

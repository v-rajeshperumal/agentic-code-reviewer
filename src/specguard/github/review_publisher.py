import os
import httpx
from specguard.schemas import PRReviewReport


class GitHubReviewPublisher:
    def __init__(self, token: str | None = None, repo: str | None = None) -> None:
        self.token = token or os.environ["GITHUB_TOKEN"]
        self.repo = repo or os.environ["GITHUB_REPOSITORY"]
        self.api_base = f"https://api.github.com/repos/{self.repo}"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def publish_review(self, pr_number: int, commit_sha: str, report: PRReviewReport) -> None:
        comments = []
        for f in report.inline_findings:
            body = (
                f"<!-- specguard:fp={f.fingerprint} -->\n"
                f"**[{f.severity.value} | {f.category.value}] {f.title}**\n\n"
                f"{f.rationale}\n\n"
                f"> **Spec Reference (`{f.spec_reference}`):** \"{f.evidence_spec_quote}\"\n"
            )
            if f.suggested_patch:
                body += f"\n```suggestion\n{f.suggested_patch}\n```\n"

            comments.append(
                {
                    "path": f.file_path,
                    "line": f.line,
                    "side": f.side,
                    "body": body,
                }
            )

        summary_md = self._render_summary(report)
        event = "REQUEST_CHANGES" if report.spec_compliance_status == "FAIL" else "COMMENT"

        payload = {
            "commit_id": commit_sha,
            "body": summary_md,
            "event": event,
            "comments": comments,
        }

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{self.api_base}/pulls/{pr_number}/reviews",
                headers=self.headers,
                json=payload,
            )
            resp.raise_for_status()

    @staticmethod
    def _render_summary(report: PRReviewReport) -> str:
        badge = {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "NEEDS_REVIEW": "⚠️ NEEDS REVIEW"}[
            report.spec_compliance_status
        ]
        lines = [
            f"## SpecGuard Architectural Review — {badge}",
            "",
            report.summary,
            "",
            f"- **Inline Verified Findings:** {len(report.inline_findings)}",
            f"- **Summary / Low-Evidence Notes:** {len(report.summary_findings)}",
        ]
        if report.summary_findings:
            lines.extend(["", "<details><summary>Additional Notes & Demoted Findings</summary>", ""])
            for f in report.summary_findings:
                lines.append(f"- **[{f.severity.value}] {f.file_path}:{f.line}** — {f.title}: {f.rationale}")
            lines.extend(["", "</details>"])
        return "\n".join(lines)

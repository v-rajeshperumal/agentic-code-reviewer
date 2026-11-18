import os
import re
from dataclasses import dataclass, field

import httpx

from specguard.schemas import PRReviewReport, ValidatedFinding

FP_MARKER = re.compile(r"<!-- specguard:fp=([a-f0-9]+) -->")
RESOLVED_MARKER = re.compile(r"<!-- specguard:resolved=([a-f0-9]+) -->")
SUMMARY_MARKER = "<!-- specguard:summary -->"
REVIEW_MARKER = "<!-- specguard:review -->"


@dataclass
class ExistingComment:
    id: int
    fingerprint: str
    path: str
    outdated: bool  # GitHub sets `position` to null once the commented line changes
    resolved: bool = False


@dataclass
class PublishResult:
    posted: list[str] = field(default_factory=list)  # fingerprints of new inline comments
    skipped: list[str] = field(default_factory=list)  # already on the PR
    resolved: list[str] = field(default_factory=list)  # got a "resolved" reply
    still_open: list[str] = field(default_factory=list)  # not re-reported, but code unchanged
    summary_action: str = ""  # "created" | "updated"
    review_posted: bool = False
    dismissed_reviews: list[int] = field(default_factory=list)


class GitHubReviewPublisher:
    """Posts SpecGuard results to a PR so that re-runs on new commits stay quiet.

    - Inline comments carry `<!-- specguard:fp=... -->`; a fingerprint already on
      the PR is not posted again.
    - A previous comment is marked resolved only when the developer actually
      changed that code (GitHub marks the comment outdated) or removed the file
      from the PR. A finding the model merely failed to repeat stays open, since
      model output varies between runs.
    - The summary lives in one issue comment that is edited in place.
    - A blocking REQUEST_CHANGES review from an earlier run is dismissed once the
      PR no longer fails.
    """

    def __init__(
        self,
        token: str | None = None,
        repo: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.token = token or os.environ["GITHUB_TOKEN"]
        self.repo = repo or os.environ["GITHUB_REPOSITORY"]
        self.api_base = f"https://api.github.com/repos/{self.repo}"
        self.client = client or httpx.Client(timeout=30.0)
        self.client.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    # --- HTTP helpers -----------------------------------------------------------

    def _paginate(self, path: str) -> list[dict]:
        items: list[dict] = []
        url: str | None = f"{self.api_base}{path}"
        params: dict | None = {"per_page": 100}
        while url:
            resp = self.client.get(url, params=params)
            resp.raise_for_status()
            items.extend(resp.json())
            url = resp.links.get("next", {}).get("url")
            params = None  # the `next` URL already carries the query string
        return items

    def _post(self, path: str, payload: dict) -> dict:
        resp = self.client.post(f"{self.api_base}{path}", json=payload)
        resp.raise_for_status()
        return resp.json()

    # --- Reading prior runs -----------------------------------------------------

    def fetch_existing_specguard_comments(self, pr_number: int) -> dict[str, ExistingComment]:
        """Maps fingerprint -> the inline comment SpecGuard posted for it earlier."""
        comments = self._paginate(f"/pulls/{pr_number}/comments")
        existing: dict[str, ExistingComment] = {}
        resolved: set[str] = set()
        for c in comments:
            body = c.get("body") or ""
            if c.get("in_reply_to_id"):
                resolved.update(RESOLVED_MARKER.findall(body))
                continue
            match = FP_MARKER.search(body)
            if match:
                existing[match.group(1)] = ExistingComment(
                    id=c["id"], fingerprint=match.group(1), path=c.get("path", ""),
                    outdated=c.get("position") is None,
                )
        for fp in resolved & existing.keys():
            existing[fp].resolved = True
        return existing

    # --- Publishing -------------------------------------------------------------

    @staticmethod
    def _comment_body(f: ValidatedFinding) -> str:
        body = (
            f"<!-- specguard:fp={f.fingerprint} -->\n"
            f"**[{f.severity.value} | {f.category.value}] {f.title}**\n\n"
            f"{f.rationale}\n\n"
            f"> **Spec Reference (`{f.spec_reference}`):** \"{f.evidence_spec_quote}\"\n"
        )
        if f.suggested_patch:
            body += f"\n```suggestion\n{f.suggested_patch}\n```\n"
        return body

    def publish_review(
        self,
        pr_number: int,
        commit_sha: str,
        report: PRReviewReport,
        changed_files: list[str] | None = None,
    ) -> PublishResult:
        result = PublishResult()
        existing = self.fetch_existing_specguard_comments(pr_number)
        current = {f.fingerprint: f for f in report.inline_findings}

        # 1. Only findings not already on the PR (or re-introduced after being resolved).
        new_comments = []
        for fp, f in current.items():
            prior = existing.get(fp)
            if prior and not prior.resolved:
                result.skipped.append(fp)
                continue
            new_comments.append({"path": f.file_path, "line": f.line, "side": f.side, "body": self._comment_body(f)})
            result.posted.append(fp)

        # 2. Resolve earlier comments whose code was changed or whose file left the PR.
        files_in_pr = set(changed_files) if changed_files is not None else None
        for fp, prior in existing.items():
            if fp in current or prior.resolved:
                continue
            file_gone = files_in_pr is not None and prior.path not in files_in_pr
            if prior.outdated or file_gone:
                self._post(
                    f"/pulls/{pr_number}/comments/{prior.id}/replies",
                    {"body": f"<!-- specguard:resolved={fp} -->\n✅ Resolved in latest commit."},
                )
                result.resolved.append(fp)
            else:
                result.still_open.append(fp)

        # 3. One summary comment, edited in place.
        summary_body = f"{SUMMARY_MARKER}\n{self._render_summary(report, result)}"
        prior_summary = next(
            (c for c in self._paginate(f"/issues/{pr_number}/comments") if SUMMARY_MARKER in (c.get("body") or "")),
            None,
        )
        if prior_summary:
            resp = self.client.patch(
                f"{self.api_base}/issues/comments/{prior_summary['id']}", json={"body": summary_body}
            )
            resp.raise_for_status()
            result.summary_action = "updated"
        else:
            self._post(f"/issues/{pr_number}/comments", {"body": summary_body})
            result.summary_action = "created"

        # 4. Review: carries new inline comments, and blocks merging while the PR fails.
        reviews = [r for r in self._paginate(f"/pulls/{pr_number}/reviews") if REVIEW_MARKER in (r.get("body") or "")]
        blocking = [r for r in reviews if r.get("state") == "CHANGES_REQUESTED"]
        failing = report.spec_compliance_status == "FAIL"
        if new_comments or (failing and not blocking):
            self._post(f"/pulls/{pr_number}/reviews", {
                "commit_id": commit_sha,
                "body": f"{REVIEW_MARKER}\nSpecGuard: {len(new_comments)} new finding(s). Details in the summary comment.",
                "event": "REQUEST_CHANGES" if failing else "COMMENT",
                "comments": new_comments,
            })
            result.review_posted = True
        if not failing:
            for r in blocking:
                resp = self.client.put(
                    f"{self.api_base}/pulls/{pr_number}/reviews/{r['id']}/dismissals",
                    json={"message": "SpecGuard: all blocking findings are resolved.", "event": "DISMISS"},
                )
                # Branch protection can forbid dismissals; the summary still shows PASS.
                if resp.status_code < 400:
                    result.dismissed_reviews.append(r["id"])

        return result

    @staticmethod
    def _render_summary(report: PRReviewReport, result: PublishResult | None = None) -> str:
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
        if result is not None:
            lines.append(
                f"- **This run:** {len(result.posted)} new, {len(result.skipped)} unchanged, "
                f"{len(result.resolved)} resolved"
            )
            if result.still_open:
                lines.append(
                    f"- **Not re-reported but code unchanged (left open):** {len(result.still_open)}"
                )
        if report.summary_findings:
            lines.extend(["", "<details><summary>Additional Notes & Demoted Findings</summary>", ""])
            for f in report.summary_findings:
                lines.append(f"- **[{f.severity.value}] {f.file_path}:{f.line}** — {f.title}: {f.rationale}")
            lines.extend(["", "</details>"])
        return "\n".join(lines)

"""Idempotent PR re-runs against a fake GitHub served by httpx.MockTransport."""
import json
import re

import httpx
import pytest

from specguard.github.review_publisher import SUMMARY_MARKER, GitHubReviewPublisher
from specguard.schemas import FindingCategory, PRReviewReport, Severity, ValidatedFinding

PR = 7
BASE = "/repos/acme/payments"


class FakeGitHub:
    """Minimal in-memory GitHub REST API for the endpoints the publisher uses."""

    def __init__(self, page_size: int = 100):
        self.review_comments: list[dict] = []
        self.issue_comments: list[dict] = []
        self.reviews: list[dict] = []
        self.calls: list[tuple[str, str]] = []
        self.page_size = page_size
        self._next_id = 1000

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _page(self, request: httpx.Request, items: list[dict]) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        size = min(int(request.url.params.get("per_page", "30")), self.page_size)
        chunk = items[(page - 1) * size: page * size]
        headers = {}
        if page * size < len(items):
            nxt = request.url.copy_set_param("page", str(page + 1)).copy_set_param("per_page", str(size))
            headers["link"] = f'<{nxt}>; rel="next"'
        return httpx.Response(200, json=chunk, headers=headers)

    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, path))
        body = json.loads(request.content) if request.content else {}

        if method == "GET" and path == f"{BASE}/pulls/{PR}/comments":
            return self._page(request, self.review_comments)
        if method == "GET" and path == f"{BASE}/issues/{PR}/comments":
            return self._page(request, self.issue_comments)
        if method == "GET" and path == f"{BASE}/pulls/{PR}/reviews":
            return self._page(request, self.reviews)
        if method == "POST" and (m := re.fullmatch(rf"{BASE}/pulls/{PR}/comments/(\d+)/replies", path)):
            reply = {"id": self._id(), "in_reply_to_id": int(m.group(1)), "body": body["body"], "position": 1}
            self.review_comments.append(reply)
            return httpx.Response(201, json=reply)
        if method == "POST" and path == f"{BASE}/issues/{PR}/comments":
            comment = {"id": self._id(), "body": body["body"]}
            self.issue_comments.append(comment)
            return httpx.Response(201, json=comment)
        if method == "PATCH" and (m := re.fullmatch(rf"{BASE}/issues/comments/(\d+)", path)):
            comment = next(c for c in self.issue_comments if c["id"] == int(m.group(1)))
            comment["body"] = body["body"]
            return httpx.Response(200, json=comment)
        if method == "POST" and path == f"{BASE}/pulls/{PR}/reviews":
            state = {"REQUEST_CHANGES": "CHANGES_REQUESTED", "COMMENT": "COMMENTED"}[body["event"]]
            review = {"id": self._id(), "body": body["body"], "state": state}
            self.reviews.append(review)
            for c in body["comments"]:
                self.review_comments.append(
                    {"id": self._id(), "path": c["path"], "line": c["line"], "position": 1, "body": c["body"]}
                )
            return httpx.Response(200, json=review)
        if method == "PUT" and (m := re.fullmatch(rf"{BASE}/pulls/{PR}/reviews/(\d+)/dismissals", path)):
            review = next(r for r in self.reviews if r["id"] == int(m.group(1)))
            review["state"] = "DISMISSED"
            return httpx.Response(200, json=review)
        return httpx.Response(404, json={"message": f"unexpected {method} {path}"})

    def mark_outdated(self, fingerprint: str) -> None:
        """Simulates the developer editing the commented line."""
        for c in self.review_comments:
            if f"specguard:fp={fingerprint}" in c["body"]:
                c["position"] = None


def _finding(fp: str, line: int = 3, severity=Severity.CRITICAL, path="db/m.sql") -> ValidatedFinding:
    return ValidatedFinding(
        file_path=path, line=line, side="RIGHT", category=FindingCategory.SPEC_DRIFT, severity=severity,
        spec_reference="Money", evidence_diff_quote="amount FLOAT", evidence_spec_quote="forbidden",
        title=f"finding {fp}", rationale="r", fingerprint=fp,
    )


def _report(*findings: ValidatedFinding) -> PRReviewReport:
    crit = any(f.severity == Severity.CRITICAL for f in findings)
    warn = any(f.severity == Severity.WARNING for f in findings)
    status = "FAIL" if crit else "NEEDS_REVIEW" if warn else "PASS"
    return PRReviewReport(summary="s", spec_compliance_status=status, inline_findings=list(findings))


@pytest.fixture
def gh():
    return FakeGitHub()


def _publisher(gh: FakeGitHub) -> GitHubReviewPublisher:
    client = httpx.Client(transport=httpx.MockTransport(gh.handler))
    return GitHubReviewPublisher(token="test-token", repo="acme/payments", client=client)


def _inline_bodies(gh: FakeGitHub) -> list[str]:
    return [c["body"] for c in gh.review_comments if not c.get("in_reply_to_id")]


# (a) duplicate fingerprints are skipped ------------------------------------------

def test_rerun_with_same_findings_posts_nothing_new(gh):
    pub = _publisher(gh)
    first = pub.publish_review(PR, "sha1", _report(_finding("aaa"), _finding("bbb", line=5)))
    assert sorted(first.posted) == ["aaa", "bbb"] and first.review_posted

    second = pub.publish_review(PR, "sha2", _report(_finding("aaa"), _finding("bbb", line=6)))
    assert second.posted == [] and sorted(second.skipped) == ["aaa", "bbb"]
    assert not second.review_posted  # still blocked by the first review; no new review spam
    assert len(_inline_bodies(gh)) == 2 and len(gh.reviews) == 1


def test_only_the_new_finding_is_posted_on_rerun(gh):
    pub = _publisher(gh)
    pub.publish_review(PR, "sha1", _report(_finding("aaa")))
    second = pub.publish_review(PR, "sha2", _report(_finding("aaa"), _finding("ccc", line=9)))
    assert second.posted == ["ccc"] and second.skipped == ["aaa"]
    assert len(_inline_bodies(gh)) == 2


# (b) fixed fingerprints get a resolution reply ------------------------------------

def test_fixed_finding_gets_one_resolution_reply(gh):
    pub = _publisher(gh)
    pub.publish_review(PR, "sha1", _report(_finding("aaa"), _finding("bbb", line=5)))
    gh.mark_outdated("aaa")  # developer edited the FLOAT line

    second = pub.publish_review(PR, "sha2", _report(_finding("bbb", line=5)))
    assert second.resolved == ["aaa"]
    replies = [c for c in gh.review_comments if c.get("in_reply_to_id")]
    assert len(replies) == 1 and "Resolved in latest commit" in replies[0]["body"]

    third = pub.publish_review(PR, "sha3", _report(_finding("bbb", line=5)))
    assert third.resolved == []  # never replies twice
    assert len([c for c in gh.review_comments if c.get("in_reply_to_id")]) == 1


def test_finding_missing_but_code_unchanged_stays_open(gh):
    pub = _publisher(gh)
    pub.publish_review(PR, "sha1", _report(_finding("aaa")))
    second = pub.publish_review(PR, "sha2", _report(), changed_files=["db/m.sql"])
    assert second.resolved == [] and second.still_open == ["aaa"]


def test_finding_in_file_removed_from_pr_is_resolved(gh):
    pub = _publisher(gh)
    pub.publish_review(PR, "sha1", _report(_finding("aaa")))
    second = pub.publish_review(PR, "sha2", _report(), changed_files=["api/other.py"])
    assert second.resolved == ["aaa"]


def test_resolved_finding_that_comes_back_is_posted_again(gh):
    pub = _publisher(gh)
    pub.publish_review(PR, "sha1", _report(_finding("aaa")))
    gh.mark_outdated("aaa")
    pub.publish_review(PR, "sha2", _report())
    third = pub.publish_review(PR, "sha3", _report(_finding("aaa", line=4)))
    assert third.posted == ["aaa"]


# (c) the summary updates in place ---------------------------------------------------

def test_summary_comment_is_created_once_then_edited(gh):
    pub = _publisher(gh)
    first = pub.publish_review(PR, "sha1", _report(_finding("aaa")))
    gh.mark_outdated("aaa")
    second = pub.publish_review(PR, "sha2", _report())
    assert (first.summary_action, second.summary_action) == ("created", "updated")
    assert len(gh.issue_comments) == 1
    body = gh.issue_comments[0]["body"]
    assert SUMMARY_MARKER in body and "✅ PASS" in body and "1 resolved" in body


# blocking review lifecycle ----------------------------------------------------------

def test_blocking_review_is_dismissed_once_pr_passes(gh):
    pub = _publisher(gh)
    pub.publish_review(PR, "sha1", _report(_finding("aaa")))
    assert gh.reviews[0]["state"] == "CHANGES_REQUESTED"
    gh.mark_outdated("aaa")
    result = pub.publish_review(PR, "sha2", _report())
    assert result.dismissed_reviews == [gh.reviews[0]["id"]] and gh.reviews[0]["state"] == "DISMISSED"


def test_warning_only_rerun_comments_without_blocking(gh):
    result = _publisher(gh).publish_review(PR, "sha1", _report(_finding("aaa", severity=Severity.WARNING)))
    assert result.review_posted and gh.reviews[0]["state"] == "COMMENTED"


# pagination -------------------------------------------------------------------------

def test_existing_comments_are_found_across_pages():
    gh = FakeGitHub(page_size=2)
    pub = _publisher(gh)
    findings = [_finding(f"f{i:02d}", line=i + 1) for i in range(5)]
    pub.publish_review(PR, "sha1", _report(*findings))
    assert len(pub.fetch_existing_specguard_comments(PR)) == 5
    rerun = pub.publish_review(PR, "sha2", _report(*findings))
    assert rerun.posted == [] and len(rerun.skipped) == 5
    assert sum(1 for m, p in gh.calls if m == "GET" and p.endswith("/pulls/7/comments")) >= 6

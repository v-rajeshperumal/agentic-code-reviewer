import hashlib
from enum import Enum
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


class FindingCategory(str, Enum):
    SPEC_DRIFT = "SPEC_DRIFT"
    SECURITY = "SECURITY"
    CODE_QUALITY = "CODE_QUALITY"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


def finding_fingerprint(file_path: str, category: str, spec_reference: str, evidence: str) -> str:
    """Stable identity for a finding across PR re-runs.

    Deliberately excludes the line number (shifts when earlier lines change) and the
    model-written title (reworded between runs). `evidence` is the offending code,
    whitespace-normalized, so the same defect on a moved line keeps its fingerprint.
    """
    normalized = " ".join(evidence.split())
    key = f"{file_path}|{category}|{spec_reference.strip().lower()}|{normalized}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


class RawCandidateFinding(BaseModel):
    """Flat extraction schema used in Stage 1b so small Ollama models succeed reliably."""
    file_path: str
    anchor: str = Field(..., description="Exact line anchor from diff, e.g. R42 or L17")
    category: str
    severity: str
    spec_reference: str = Field(..., description="Exact section heading from list_spec_sections or rulebook")
    evidence_diff_quote: str = Field(..., description="Exact verbatim code snippet from the diff hunk")
    evidence_spec_quote: str = Field(..., description="Exact verbatim sentence from the spec or rulebook")
    title: str
    rationale: str
    suggested_patch: Optional[str] = None


class CandidateList(BaseModel):
    findings: list[RawCandidateFinding] = Field(default_factory=list)


class InvestigatorRecording(BaseModel):
    """Everything replay needs to reproduce a live investigation exactly.

    `loaded_sections` is the spec/rulebook text the agent actually read; the
    EvidenceGate checks spec quotes against it, so replay must restore it too.
    """
    candidates: CandidateList
    loaded_sections: dict[str, str] = Field(default_factory=dict)
    tool_trace: list[str] = Field(default_factory=list)


class VerifierVerdict(BaseModel):
    keep: bool
    reason: str


class ValidatedFinding(BaseModel):
    file_path: str
    line: int
    side: Literal["RIGHT", "LEFT"]
    start_line: Optional[int] = None
    category: FindingCategory
    severity: Severity
    spec_reference: str
    evidence_diff_quote: str
    evidence_spec_quote: str
    title: str
    rationale: str
    suggested_patch: Optional[str] = None
    inline_eligible: bool = True
    drop_reason: Optional[str] = None
    fingerprint: str = ""

    @field_validator("title")
    @classmethod
    def clamp_title(cls, v: str) -> str:
        return v[:100]


class PRReviewReport(BaseModel):
    summary: str
    spec_compliance_status: Literal["PASS", "FAIL", "NEEDS_REVIEW"]
    inline_findings: list[ValidatedFinding] = Field(default_factory=list)
    summary_findings: list[ValidatedFinding] = Field(default_factory=list)
    dropped_audit_log: list[str] = Field(default_factory=list)

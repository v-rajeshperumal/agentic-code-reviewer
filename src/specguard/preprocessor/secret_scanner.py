import hashlib
import re
from typing import Tuple
from specguard.schemas import FindingCategory, Severity, ValidatedFinding, finding_fingerprint

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("github_token", r"gh[pousr]_[0-9a-zA-Z]{36}"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("generic_secret", r"(?i)(?:api_key|secret_key|auth_token|password)\s*[:=]\s*['\"][0-9a-zA-Z_\-]{16,64}['\"]"),
]


class SecretScanner:
    def scan_and_redact_line(
        self, file_path: str, line_num: int, raw_line: str
    ) -> Tuple[str, list[ValidatedFinding]]:
        findings: list[ValidatedFinding] = []
        redacted = raw_line

        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            return redacted, findings

        for secret_type, pattern in SECRET_PATTERNS:
            match = re.search(pattern, redacted)
            if match:
                redacted = re.sub(pattern, f"<REDACTED:{secret_type}>", redacted)
                # Fingerprint on a hash of the secret value (never the value itself)
                # so it survives line shifts between PR pushes.
                secret_digest = hashlib.sha256(match.group(0).encode()).hexdigest()
                fp = finding_fingerprint(
                    file_path, FindingCategory.SECURITY.value, "Secrets Management", f"{secret_type}:{secret_digest}"
                )
                findings.append(
                    ValidatedFinding(
                        file_path=file_path,
                        line=line_num,
                        side="RIGHT",
                        category=FindingCategory.SECURITY,
                        severity=Severity.CRITICAL,
                        spec_reference="Secrets Management",
                        evidence_diff_quote=f"<REDACTED:{secret_type}>",
                        evidence_spec_quote="Hardcoded credentials, API keys, and private keys are strictly prohibited in source control.",
                        title=f"Hardcoded secret detected ({secret_type})",
                        rationale=f"Detected high-risk credential pattern `{secret_type}` in added line {line_num}. Redacted before LLM inspection.",
                        inline_eligible=True,
                        fingerprint=fp,
                    )
                )
        return redacted, findings

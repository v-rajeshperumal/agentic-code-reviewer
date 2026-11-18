import fnmatch
import re
from dataclasses import dataclass, field
from typing import Dict
from specguard.preprocessor.secret_scanner import SecretScanner
from specguard.schemas import ValidatedFinding

IGNORED_GLOBS = [
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "*.min.js",
    "*.min.css",
    "dist/**",
    "build/**",
]


@dataclass
class AnchorTarget:
    file_path: str
    line: int
    side: str  # "RIGHT" | "LEFT"
    raw_code: str


@dataclass
class ParsedDiff:
    anchored_by_file: Dict[str, str] = field(default_factory=dict)
    anchor_map: Dict[str, AnchorTarget] = field(default_factory=dict)
    deterministic_findings: list[ValidatedFinding] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)


class DiffAnchorParser:
    def __init__(self) -> None:
        self.scanner = SecretScanner()

    def _is_ignored(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pat) for pat in IGNORED_GLOBS)

    def parse(self, raw_diff: str) -> ParsedDiff:
        result = ParsedDiff()
        chunks = re.split(r"^diff --git ", raw_diff, flags=re.MULTILINE)

        for chunk in chunks:
            if not chunk.strip():
                continue

            lines = chunk.splitlines()
            header_match = re.search(r"a/(.+?)\s+b/(.+)$", lines[0])
            if not header_match:
                continue

            old_path, new_path = header_match.group(1), header_match.group(2)
            target_path = new_path if new_path != "/dev/null" else old_path

            if self._is_ignored(target_path) or "Binary files " in chunk:
                result.skipped_files.append(target_path)
                continue

            rendered_lines = [f"=== FILE: {target_path} ==="]
            old_line = 0
            new_line = 0
            in_hunk = False

            for line in lines[1:]:
                if line.startswith("@@"):
                    hunk_match = re.search(r"-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?", line)
                    if hunk_match:
                        old_line = int(hunk_match.group(1))
                        new_line = int(hunk_match.group(2))
                    in_hunk = True
                    rendered_lines.append(self.scanner.redact(line))
                    continue

                # Everything before the first hunk is a file header (index, mode,
                # similarity, rename, ---/+++). Inside a hunk, a line like
                # "--- foo" is a removed line, so headers are only matched here.
                if not in_hunk:
                    rendered_lines.append(self.scanner.redact(line))
                    continue

                # "\ No newline at end of file" annotates the previous line and
                # occupies no line number on either side.
                if line.startswith("\\"):
                    rendered_lines.append(self.scanner.redact(line))
                    continue

                if line.startswith("+"):
                    redacted_line, sec_findings = self.scanner.scan_and_redact_line(
                        target_path, new_line, line
                    )
                    result.deterministic_findings.extend(sec_findings)
                    anchor_key = f"{target_path}:R{new_line}"
                    result.anchor_map[anchor_key] = AnchorTarget(
                        file_path=target_path,
                        line=new_line,
                        side="RIGHT",
                        raw_code=redacted_line[1:],
                    )
                    rendered_lines.append(f"[R{new_line}] {redacted_line}")
                    new_line += 1
                elif line.startswith("-"):
                    # Removed and context lines are redacted too (no findings: the
                    # PR didn't add them), so an existing secret never reaches a model.
                    safe_line = self.scanner.redact(line)
                    anchor_key = f"{target_path}:L{old_line}"
                    result.anchor_map[anchor_key] = AnchorTarget(
                        file_path=target_path,
                        line=old_line,
                        side="LEFT",
                        raw_code=safe_line[1:],
                    )
                    rendered_lines.append(f"[L{old_line}] {safe_line}")
                    old_line += 1
                else:
                    safe_line = self.scanner.redact(line)
                    anchor_key = f"{target_path}:R{new_line}"
                    result.anchor_map[anchor_key] = AnchorTarget(
                        file_path=target_path,
                        line=new_line,
                        side="RIGHT",
                        raw_code=safe_line[1:] if safe_line.startswith(" ") else safe_line,
                    )
                    rendered_lines.append(f"[R{new_line}] {safe_line}")
                    old_line += 1
                    new_line += 1

            result.anchored_by_file[target_path] = "\n".join(rendered_lines)

        return result

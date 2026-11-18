import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
import yaml


@dataclass
class SpecDocument:
    name: str
    path: Path
    applies_to: List[str]
    sections: Dict[str, str]
    full_text: str


class SpecBatcher:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self.spec_dir = self.repo_root / ".spec"

    def load_specs(self) -> List[SpecDocument]:
        docs: List[SpecDocument] = []
        if not self.spec_dir.exists():
            return docs

        for md_file in sorted(self.spec_dir.glob("*.md")):
            raw = md_file.read_text(encoding="utf-8")
            applies_to = ["**/*"]
            body = raw

            if raw.startswith("---"):
                parts = raw.split("---", 2)
                if len(parts) == 3:
                    meta = yaml.safe_load(parts[1]) or {}
                    applies_to = meta.get("applies_to", ["**/*"])
                    body = parts[2].strip()

            sections = self._parse_sections(body)
            docs.append(
                SpecDocument(
                    name=md_file.name,
                    path=md_file,
                    applies_to=applies_to,
                    sections=sections,
                    full_text=body,
                )
            )
        return docs

    @staticmethod
    def _parse_sections(markdown_body: str) -> Dict[str, str]:
        sections: Dict[str, str] = {}
        current_heading = "Overview"
        buffer: List[str] = []

        for line in markdown_body.splitlines():
            if line.startswith("## "):
                if buffer:
                    sections[current_heading] = "\n".join(buffer).strip()
                current_heading = line[3:].strip()
                buffer = []
            else:
                buffer.append(line)

        if buffer:
            sections[current_heading] = "\n".join(buffer).strip()
        return sections

    def build_batches(self, changed_files: List[str]) -> List[tuple[SpecDocument, List[str]]]:
        """Groups changed files under each governing spec so cross-file changes share context."""
        batches: List[tuple[SpecDocument, List[str]]] = []
        for doc in self.load_specs():
            matched = [
                f for f in changed_files
                if any(fnmatch.fnmatch(f, pat) for pat in doc.applies_to)
            ]
            if matched:
                batches.append((doc, matched))
        return batches

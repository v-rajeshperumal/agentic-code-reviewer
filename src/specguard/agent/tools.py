from pathlib import Path
from strands import tool
from specguard.preprocessor.spec_batcher import SpecDocument


class RepoToolContext:
    """Repo-jailed read-only toolset preventing path traversal or symlink escapes."""

    def __init__(self, repo_root: Path, spec_doc: SpecDocument) -> None:
        self.repo_root = repo_root.resolve()
        self.spec_doc = spec_doc
        self.accessed_sections: set[str] = set()
        self.loaded_sections_text: dict[str, str] = {}

    def _safe_resolve(self, rel_path: str) -> Path:
        candidate = (self.repo_root / rel_path).resolve()
        if not candidate.is_relative_to(self.repo_root):
            raise PermissionError(f"Path traversal blocked: {rel_path}")
        return candidate

    def build_tools(self) -> list:
        ctx = self

        @tool
        def list_spec_sections() -> list[str]:
            """Lists all section headings available in the active system specification."""
            return list(ctx.spec_doc.sections.keys())

        @tool
        def read_spec_section(section_heading: str) -> str:
            """Reads the exact specification rules under a given section heading."""
            if section_heading not in ctx.spec_doc.sections:
                return f"Section '{section_heading}' not found. Available: {list(ctx.spec_doc.sections.keys())}"
            content = ctx.spec_doc.sections[section_heading]
            ctx.accessed_sections.add(section_heading)
            ctx.loaded_sections_text[section_heading] = content
            return content

        @tool
        def load_rulebook(language: str) -> str:
            """Loads language-specific best-practice rules (e.g. 'python', 'typescript')."""
            safe_lang = "".join(c for c in language.lower() if c.isalnum())
            rule_path = ctx._safe_resolve(f".spec/rules/{safe_lang}_best_practices.md")
            if not rule_path.exists():
                return f"No rulebook found for language '{safe_lang}'."
            text = rule_path.read_text(encoding="utf-8")
            ctx.accessed_sections.add(f"rulebook:{safe_lang}")
            ctx.loaded_sections_text[f"rulebook:{safe_lang}"] = text
            return text

        @tool
        def get_surrounding_code(file_path: str, start_line: int, end_line: int) -> str:
            """Reads up to 100 lines of surrounding repository code outside the diff hunk."""
            try:
                target = ctx._safe_resolve(file_path)
            except PermissionError as err:
                return str(err)
            if not target.exists() or not target.is_file():
                return f"File not found: {file_path}"
            lines = target.read_text(encoding="utf-8").splitlines()
            s = max(1, start_line)
            e = min(len(lines), max(s, min(end_line, s + 99)))
            numbered = [f"{i}: {lines[i - 1]}" for i in range(s, e + 1)]
            return "\n".join(numbered)

        return [list_spec_sections, read_spec_section, load_rulebook, get_surrounding_code]

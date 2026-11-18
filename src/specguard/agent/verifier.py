from pathlib import Path
from strands import Agent
from specguard.agent.hooks import LoopControlHooks
from specguard.agent.investigator import spec_context_digest
from specguard.agent.tools import RepoToolContext
from specguard.llm.cassette import CassetteStore
from specguard.llm.provider import build_strands_model, get_provider_name
from specguard.preprocessor.spec_batcher import SpecDocument
from specguard.schemas import RawCandidateFinding, VerifierVerdict


VERIFIER_PROMPT = """You are an adversarial code-review verifier.
Your job is to DISPROVE false-positive findings before they bother a developer.
Inspect the surrounding code and spec section using your tools.
Return `keep=false` if:
- The diff actually satisfies the spec via middleware, helper functions, or surrounding context.
- The finding misreads the code or spec.
Return `keep=true` ONLY if the defect is genuine and indisputable.
"""


class AdversarialVerifier:
    def __init__(
        self,
        repo_root: Path,
        cassette_store: CassetteStore | None = None,
        reuse_cassettes: bool = False,
    ) -> None:
        self.repo_root = repo_root
        self.cassettes = cassette_store or CassetteStore()
        self.reuse_cassettes = reuse_cassettes

    def verify(
        self, spec_doc: SpecDocument, finding: RawCandidateFinding, anchored_diff: str
    ) -> VerifierVerdict:
        if finding.severity.upper() not in ("CRITICAL", "WARNING"):
            return VerifierVerdict(keep=True, reason="Low severity; skipped verifier.")

        provider = get_provider_name()
        payload = (
            f"{spec_doc.name}:{spec_context_digest(self.repo_root, spec_doc)}::"
            f"{finding.model_dump_json()}::{anchored_diff}"
        )
        cached = self.cassettes.session_get("verifier", payload)
        if cached is None and (provider == "replay" or self.reuse_cassettes):
            cached = self.cassettes.load("verifier", payload)
        if cached is not None:
            return VerifierVerdict.model_validate_json(cached)
        if provider == "replay":
            return VerifierVerdict(keep=True, reason="replay:default_keep")

        tool_ctx = RepoToolContext(self.repo_root, spec_doc)
        hooks = LoopControlHooks(max_model_calls=4)
        agent = Agent(
            model=build_strands_model(),
            system_prompt=VERIFIER_PROMPT,
            tools=tool_ctx.build_tools(),
            hooks=[hooks],
        )
        prompt = (
            f"Candidate Finding:\n{finding.model_dump_json(indent=2)}\n\n"
            f"Diff Context:\n{anchored_diff}\n\n"
            "Attempt to disprove this finding, then output your verdict."
        )
        verdict: VerifierVerdict = agent.structured_output(VerifierVerdict, prompt)
        self.cassettes.save("verifier", payload, verdict.model_dump_json())
        return verdict

import hashlib
import json
from strands.hooks import HookProvider, HookRegistry, BeforeModelCallEvent, BeforeToolCallEvent


class LoopControlHooks(HookProvider):
    """Enforces hard model-call caps and tool-call deduplication via Strands hooks."""

    def __init__(self, max_model_calls: int = 6) -> None:
        self.max_model_calls = max_model_calls
        self.model_calls = 0
        self.seen_tool_calls: set[str] = set()
        self.tool_trace: list[str] = []

    def register_hooks(self, registry: HookRegistry) -> None:
        registry.add_callback(BeforeModelCallEvent, self._on_before_model_call)
        registry.add_callback(BeforeToolCallEvent, self._on_before_tool_call)

    def _on_before_model_call(self, event: BeforeModelCallEvent) -> None:
        self.model_calls += 1
        if self.model_calls > self.max_model_calls:
            raise RuntimeError(
                f"LoopControlHooks: Exceeded max_model_calls ({self.max_model_calls}). Aborting loop."
            )

    def _on_before_tool_call(self, event: BeforeToolCallEvent) -> None:
        tool_name = event.tool_use["name"]
        tool_input = json.dumps(event.tool_use.get("input", {}), sort_keys=True)
        call_hash = hashlib.sha256(f"{tool_name}:{tool_input}".encode()).hexdigest()[:12]

        if call_hash in self.seen_tool_calls:
            event.cancel_tool = (
                f"Duplicate tool call `{tool_name}` with identical arguments blocked. "
                "Use previously retrieved context and synthesize your findings now."
            )
            return

        self.seen_tool_calls.add(call_hash)
        self.tool_trace.append(f"{tool_name}({tool_input})")

import asyncio
import os
import threading
import time
from typing import Any


class TokenBucket:
    """Thread-safe token bucket that paces requests to a provider's RPM limit.

    `burst` defaults to 1 so calls are spread evenly (e.g. one every 12s at 5 RPM)
    rather than allowing a full minute's quota up front, which free tiers reject.
    Strands' own retry loop handles any 429s that still slip through.
    """

    def __init__(self, rpm: float, burst: float = 1.0) -> None:
        self.capacity = max(1.0, burst)
        self.tokens = self.capacity
        self.refill_rate = rpm / 60.0
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
                self.last_refill = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait_time = (1.0 - self.tokens) / self.refill_rate
            time.sleep(wait_time)


_BUCKETS = {
    "gemini": TokenBucket(rpm=float(os.getenv("SPECGUARD_GEMINI_RPM", "5"))),
    "ollama": TokenBucket(rpm=float(os.getenv("SPECGUARD_OLLAMA_RPM", "600")), burst=10),
}


def get_provider_name() -> str:
    return os.getenv("SPECGUARD_PROVIDER", "replay").lower()


def rate_limited(model: Any, bucket: TokenBucket) -> Any:
    """Makes every model request wait for a token, not just agent construction.

    A single ReAct investigation issues several model calls (one per tool round),
    so throttling has to sit on the model's own entry points: `stream` (agent turns)
    and `structured_output` (schema extraction).
    """
    orig_stream = model.stream
    orig_structured = model.structured_output

    async def stream(*args: Any, **kwargs: Any):
        await asyncio.to_thread(bucket.acquire)
        async for event in orig_stream(*args, **kwargs):
            yield event

    async def structured_output(*args: Any, **kwargs: Any):
        await asyncio.to_thread(bucket.acquire)
        async for event in orig_structured(*args, **kwargs):
            yield event

    model.stream = stream
    model.structured_output = structured_output
    return model


def build_strands_model() -> Any:
    """Returns a rate-limited Strands Model instance for Ollama or Gemini."""
    provider = get_provider_name()

    if provider == "ollama":
        from strands.models.ollama import OllamaModel
        model = OllamaModel(
            host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            model_id=os.getenv("SPECGUARD_OLLAMA_MODEL", "qwen2.5-coder:7b"),
            options={"num_ctx": int(os.getenv("SPECGUARD_OLLAMA_CTX", "8192")), "temperature": 0.0},
        )
    elif provider == "gemini":
        from strands.models.gemini import GeminiModel
        model = GeminiModel(
            client_args={"api_key": os.environ["GEMINI_API_KEY"]},
            model_id=os.getenv("SPECGUARD_GEMINI_MODEL", "gemini-2.5-flash"),
            params={"temperature": 0.0},
        )
    else:
        raise ValueError(f"Live model requested while SPECGUARD_PROVIDER={provider}")

    return rate_limited(model, _BUCKETS[provider])

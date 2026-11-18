import hashlib
import json
from pathlib import Path
from typing import Optional

# In-process memo shared by every CassetteStore. Live runs check it before calling a
# model, so an ablation that runs the pipeline twice (no-verifier, then full) reuses
# one investigation instead of re-sampling the model and overwriting the cassette.
_SESSION: dict[str, str] = {}


def clear_session_cache() -> None:
    _SESSION.clear()


def content_digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


class CassetteStore:
    def __init__(self, cassette_dir: Path = Path("evals/cassettes")) -> None:
        self.cassette_dir = cassette_dir
        self.cassette_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_key(namespace: str, payload: str) -> str:
        digest = hashlib.sha256(f"{namespace}:{payload}".encode("utf-8")).hexdigest()[:16]
        return f"{namespace}_{digest}.json"

    def exists(self, namespace: str, payload: str) -> bool:
        return (self.cassette_dir / self.compute_key(namespace, payload)).exists()

    def load(self, namespace: str, payload: str) -> Optional[str]:
        path = self.cassette_dir / self.compute_key(namespace, payload)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("response")

    def save(self, namespace: str, payload: str, response: str) -> None:
        path = self.cassette_dir / self.compute_key(namespace, payload)
        path.write_text(
            json.dumps({"namespace": namespace, "response": response}, indent=2),
            encoding="utf-8",
        )
        _SESSION[self.compute_key(namespace, payload)] = response

    def session_get(self, namespace: str, payload: str) -> Optional[str]:
        return _SESSION.get(self.compute_key(namespace, payload))

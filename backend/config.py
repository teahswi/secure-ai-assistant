"""Central configuration. Edit backend/config.json; any key can also be overridden by an
UPPER_CASE environment variable (e.g. CHAT_MODEL=qwen3:8b, MOCK_LLM=1).

Model swap cheat-sheet
  chat_model    qwen3:1.7b (light, default)  ->  qwen3:8b (full-size)   [also: qwen3:0.6b, llama3.2:1b]
  embed_backend hash (no model needed, default) -> ollama (uses embed_model, e.g. qwen3-embedding)
After changing embed_backend/embed_model, call POST /admin/reembed (button in Admin > Documents).
"""
import json, os

_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULTS = {
    "chat_model": "qwen3:1.7b",
    "chat_think": False,          # sent to Ollama as "think"; set null if your model rejects the flag
    "embed_backend": "hash",      # "hash" (local, dependency-free) | "ollama"
    "embed_model": "qwen3-embedding",
    "ollama_url": "http://localhost:11434",
    "mock_llm": False,            # True = simulate a fully compromised model (demo / tests)
    "top_k": 4,                   # chunks sent to the model per question
    "chunk_size": 500,            # characters per chunk at ingestion
    "history_messages": 6,
    "taint_level": 2,             # chunk level at which a session becomes "tainted"
    "llm_timeout_s": 300,
    "max_queue_per_user": 5,      # queued + running jobs allowed per user
    "max_upload_mb": 5,
}


def _coerce(default, raw):
    if isinstance(default, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(raw)
    return raw


def load():
    c = dict(DEFAULTS)
    path = os.environ.get("CONFIG_PATH", os.path.join(_DIR, "config.json"))
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            c.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    for k, d in DEFAULTS.items():
        e = os.environ.get(k.upper())
        if e is not None:
            c[k] = _coerce(d, e) if d is not None else e
    return c


cfg = load()   # modules read cfg[...] at call time, so tests/admin code can change values live

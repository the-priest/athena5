"""
providers — multi-provider LLM registry + LIVE model discovery.

Athena used to be Groq-first with a hand-written static chain.  This module
makes her provider-agnostic: any OpenAI-compatible endpoint (Groq, SiliconFlow,
OpenAI, OpenRouter, Cerebras, Together, Mistral, DeepSeek, Gemini's
OpenAI-compat endpoint, xAI, Hyperbolic, a local Ollama) can be a link in the
fallback chain, and the model list is pulled LIVE from each provider's
``GET /models`` endpoint rather than hard-coded.

Everything is stdlib (urllib) and fail-soft: a provider that is down, keyless,
or slow is simply skipped; it never raises into the app.  Discovery results are
cached briefly so a startup or a `model refresh` does not hammer the endpoints.

The public surface:

  REGISTRY                     provider -> metadata
  provider_key(p, settings)    resolve a key (env -> settings -> legacy)
  is_enabled(p, settings)      should we use this provider at all?
  list_models(p, timeout)      -> {ok, models, error, live}
  default_models(p)            curated fallback list
  build_chain(settings, ...)   -> [(model_id, display, provider), ...]
  status(settings)             -> summary rows for the UI
  set_key / pin                mutate settings helpers
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# ── registry ──────────────────────────────────────────────────────────
# base_url is the OpenAI-compatible root; models live at base_url + "/models".
REGISTRY: Dict[str, Dict[str, Any]] = {
    "groq": {
        "label": "Groq", "base_url": "https://api.groq.com/openai/v1",
        "env": "GROQ_API_KEY", "free": True, "no_key": False,
        "default_models": [
            "llama-3.1-8b-instant",
            "llama-3.3-70b-versatile",
            "meta-llama/llama-4-scout-17b-16e-instruct",
            "qwen/qwen3-32b",
            "gemma2-9b-it",
            "deepseek-r1-distill-llama-70b",
            "compound-beta",
            "compound-beta-mini",
        ],
    },
    "cerebras": {
        "label": "Cerebras (free)", "base_url": "https://api.cerebras.ai/v1",
        "env": "CEREBRAS_API_KEY", "free": True, "no_key": False,
        "default_models": ["llama-3.3-70b", "llama3.1-8b", "qwen-3-32b"],
    },
    "siliconflow": {
        "label": "SiliconFlow", "base_url": "https://api.siliconflow.com/v1",
        "env": "SILICONFLOW_API_KEY", "free": False, "no_key": False,
        "default_models": [
            "deepseek-ai/DeepSeek-V3",
            "Qwen/Qwen2.5-72B-Instruct",
            "Qwen/Qwen3-32B",
            "moonshotai/Kimi-K2-Instruct",
            "THUDM/glm-4-9b-chat",
            "deepseek-ai/DeepSeek-R1",
        ],
    },
    "openrouter": {
        "label": "OpenRouter (free tiers)", "base_url": "https://openrouter.ai/api/v1",
        "env": "OPENROUTER_API_KEY", "free": True, "no_key": False,
        "default_models": [
            "meta-llama/llama-3.3-70b-instruct:free",
            "deepseek/deepseek-r1:free",
            "qwen/qwen-2.5-72b-instruct:free",
            "google/gemini-2.0-flash-exp:free",
        ],
    },
    "together": {
        "label": "Together AI", "base_url": "https://api.together.xyz/v1",
        "env": "TOGETHER_API_KEY", "free": True, "no_key": False,
        "default_models": [
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "Qwen/Qwen2.5-72B-Instruct-Turbo",
            "mistralai/Mixtral-8x7B-Instruct-v0.1",
        ],
    },
    "mistral": {
        "label": "Mistral (free tier)", "base_url": "https://api.mistral.ai/v1",
        "env": "MISTRAL_API_KEY", "free": True, "no_key": False,
        "default_models": ["mistral-small-latest", "open-mistral-nemo",
                           "mistral-large-latest"],
    },
    "deepseek": {
        "label": "DeepSeek", "base_url": "https://api.deepseek.com/v1",
        "env": "DEEPSEEK_API_KEY", "free": False, "no_key": False,
        "default_models": ["deepseek-chat", "deepseek-reasoner"],
    },
    "google": {
        "label": "Google Gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "env": "GEMINI_API_KEY", "free": True, "no_key": False,
        "default_models": ["gemini-2.0-flash", "gemini-1.5-flash",
                           "gemini-1.5-pro"],
    },
    "xai": {
        "label": "xAI Grok", "base_url": "https://api.x.ai/v1",
        "env": "XAI_API_KEY", "free": False, "no_key": False,
        "default_models": ["grok-2-latest", "grok-beta"],
    },
    "openai": {
        "label": "OpenAI", "base_url": "https://api.openai.com/v1",
        "env": "OPENAI_API_KEY", "free": False, "no_key": False,
        "default_models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "o4-mini"],
    },
    "hyperbolic": {
        "label": "Hyperbolic", "base_url": "https://api.hyperbolic.xyz/v1",
        "env": "HYPERBOLIC_API_KEY", "free": True, "no_key": False,
        "default_models": ["meta-llama/Llama-3.3-70B-Instruct"],
    },
    "ollama": {
        "label": "Ollama (local)", "base_url": "http://localhost:11434/v1",
        "env": "", "free": True, "no_key": True,
        "default_models": ["llama3.1", "qwen2.5", "mistral"],
    },
}

# Preference order when several providers are configured.
ORDER = ["groq", "cerebras", "siliconflow", "openrouter", "together",
         "mistral", "deepseek", "google", "xai", "openai", "hyperbolic",
         "ollama"]

_UA = "Athena/7.8 provider-discovery"
_REASONING_RE = re.compile(r"^(o[1-9]|gpt-5)", re.IGNORECASE)
_TTL = 300.0
_CACHE: Dict[str, Tuple[float, List[str]]] = {}
_OLLAMA_TS: float = 0.0
_OLLAMA_UP: bool = False


# ── key / enablement ──────────────────────────────────────────────────

def provider_key(provider: str, settings: Optional[Dict[str, Any]] = None) -> str:
    meta = REGISTRY.get(provider)
    if not meta:
        return ""
    env = meta.get("env") or ""
    if env:
        v = os.environ.get(env)
        if v:
            return v.strip()
    try:
        v = ((settings or {}).get("provider_keys") or {}).get(provider)
        if v:
            return str(v).strip()
    except Exception:
        pass
    return ""


def is_enabled(provider: str, settings: Optional[Dict[str, Any]] = None) -> bool:
    meta = REGISTRY.get(provider)
    if not meta:
        return False
    try:
        explicit = (settings or {}).get("provider_enabled") or {}
        if provider in explicit:
            return bool(explicit[provider])
    except Exception:
        pass
    if provider == "ollama":
        # Only "enabled" if something is listening; caller may override.
        return bool(_ollama_up())
    return bool(provider_key(provider, settings))


def _ollama_up(timeout: float = 0.8) -> bool:
    """Reachability probe for a local Ollama, cached briefly so the several
    is_enabled() calls per boot don't each pay a socket timeout."""
    global _OLLAMA_TS, _OLLAMA_UP
    now = time.time()
    if now - _OLLAMA_TS < 60.0:
        return _OLLAMA_UP
    up = False
    try:
        req = urllib.request.Request(
            REGISTRY["ollama"]["base_url"].rstrip("/") + "/models",
            headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            up = r.status == 200
    except Exception:
        up = False
    _OLLAMA_TS, _OLLAMA_UP = now, up
    return up


# ── live discovery ────────────────────────────────────────────────────

_SKIP_TOKENS = (
    "embed", "embedding", "rerank", "bge-", "gte-", "e5-", "whisper",
    "tts", "speech", "audio", "dall-e", "dalle", "stable-diffusion",
    "sdxl", "flux", "moderation", "guard", "clip", "image", "upscale",
    "vision-encoder", "codex-mini", "realtime", "transcribe",
    "orpheus", "playai", "play-ai", "synthes", "voice", "music", "sora",
)


def chat_capable(model_id: str) -> bool:
    m = (model_id or "").lower()
    return bool(m) and not any(t in m for t in _SKIP_TOKENS)


# Preferred families, high→low.  Used to rank a LIVE list (which some
# providers return alphabetically) so the chain head is a capable chat model,
# not whatever sorts first.
_RANK_POS = (
    ("llama-3.3-70b", 100), ("llama-3.1-70b", 98), ("llama-4", 96),
    ("deepseek-r1", 92), ("deepseek-v3", 90), ("deepseek-chat", 88),
    ("qwen2.5-72b", 84), ("qwen-2.5-72b", 84), ("qwen3", 82),
    ("qwen2.5", 74), ("gpt-oss-120b", 72), ("gpt-oss", 62),
    ("gpt-4.1", 66), ("gpt-4o", 64), ("gemini-2", 66), ("gemini-1.5", 60),
    ("grok", 58), ("gemma-3", 58), ("gemma2", 55), ("mixtral", 54),
    ("mistral-large", 56), ("mistral", 50), ("kimi", 52), ("glm", 50),
    ("llama-3.1-8b", 42), ("llama3", 40), ("command-r", 48),
)
_RANK_NEG = (
    ("1b", -30), ("2b", -30), ("3b", -25), ("tiny", -35), ("allam", -22),
    ("mini", -6), ("preview", -6), ("base", -8),
)


def _rank(model_id: str) -> int:
    m = (model_id or "").lower()
    score = 0
    for token, val in _RANK_POS:
        if token in m:
            score = max(score, val)
    for token, val in _RANK_NEG:
        if token in m:
            score += val
    if ":free" in m:
        score += 6
    return score


def rank_models(models: List[str]) -> List[str]:
    return sorted(set(models), key=lambda m: (-_rank(m), m))


def list_models(provider: str, timeout: int = 6,
                use_cache: bool = True,
                settings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """LIVE model list for a provider.  Never raises.

    Returns {"ok": bool, "models": [id...], "error": str, "live": bool}.
    On any failure the curated defaults are returned with ok=False so the
    caller can still build a chain.  `settings` is consulted for the key when
    no matching environment variable is set.
    """
    meta = REGISTRY.get(provider)
    if not meta:
        return {"ok": False, "models": [], "error": f"unknown provider {provider}",
                "live": False}
    now = time.time()
    if use_cache and provider in _CACHE:
        ts, models = _CACHE[provider]
        if now - ts < _TTL:
            return {"ok": True, "models": list(models), "error": "", "live": True,
                    "cached": True}
    key = provider_key(provider, settings)
    if not key and not meta.get("no_key"):
        return {"ok": False, "models": default_models(provider),
                "error": "no API key", "live": False}
    url = meta["base_url"].rstrip("/") + "/models"
    headers = {"User-Agent": _UA, "Accept": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=max(2, int(timeout))) as r:
            raw = r.read(2_000_000).decode("utf-8", "replace")
        data = json.loads(raw)
        if isinstance(data, dict):
            rows = data.get("data") or data.get("models") or []
        else:
            rows = data or []
        ids: List[str] = []
        for m in rows:
            mid = m.get("id") if isinstance(m, dict) else m
            if mid and chat_capable(str(mid)):
                ids.append(str(mid))
        ids = rank_models(ids)
        if not ids:
            raise ValueError("no chat-capable models returned")
        _CACHE[provider] = (now, ids)
        return {"ok": True, "models": ids, "error": "", "live": True}
    except Exception as e:
        return {"ok": False, "models": default_models(provider),
                "error": f"{type(e).__name__}: {e}", "live": False}


def default_models(provider: str) -> List[str]:
    return list((REGISTRY.get(provider) or {}).get("default_models") or [])


def refresh_cache() -> None:
    global _OLLAMA_TS
    _CACHE.clear()
    _OLLAMA_TS = 0.0


# ── OpenAI-compatible client (for every non-Groq provider) ────────────
# The Groq SDK hardcodes its /openai/v1 path, so it cannot talk to a plain
# /v1 endpoint.  This tiny urllib client speaks the OpenAI chat-completions
# shape and exposes the SAME surface _call_provider expects:
#     client.chat.completions.create(model=..., messages=..., ...)
# so the host needs no special-casing.

class _Msg:
    __slots__ = ("content",)

    def __init__(self, content: str):
        self.content = content


class _Choice:
    __slots__ = ("message",)

    def __init__(self, content: str):
        self.message = _Msg(content)


class _Completion:
    __slots__ = ("choices",)

    def __init__(self, content: str):
        self.choices = [_Choice(content)]


class _ChatCompletions:
    def __init__(self, outer: "OpenAIClient"):
        self._o = outer

    def create(self, model: str, messages: list, temperature: float = 0.2,
               max_tokens: int = 1024, **_kw) -> _Completion:
        return self._o._create(model, messages, temperature, max_tokens)


class _Chat:
    def __init__(self, outer: "OpenAIClient"):
        self.completions = _ChatCompletions(outer)


class OpenAIClient:
    """Minimal OpenAI-compatible chat client.  Read-only host access via
    urllib; no third-party dependency.  Raises RuntimeError with an HTTP-coded
    message so the host's rate-limit / 404 / error heuristics keep working."""

    def __init__(self, base_url: str, api_key: str = "", timeout: int = 120):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._openai = "api.openai.com" in self.base_url
        self.chat = _Chat(self)

    def _create(self, model: str, messages: list, temperature: float,
                max_tokens: int) -> _Completion:
        url = self.base_url + "/chat/completions"
        body: Dict[str, Any] = {"model": model, "messages": messages}
        # OpenAI's reasoning models (o1/o3/o4/gpt-5) require
        # max_completion_tokens and reject a custom temperature.
        if self._openai:
            body["max_completion_tokens"] = max_tokens
            if not _REASONING_RE.match(model or ""):
                body["temperature"] = temperature
        else:
            body["max_tokens"] = max_tokens
            body["temperature"] = temperature
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": _UA}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read(8_000_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                detail = ""
            raise RuntimeError(f"HTTP {e.code} {e.reason}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"network error: {e.reason}") from e
        except Exception as e:  # noqa: BLE001 - surfaced to the fallback chain
            raise RuntimeError(f"{type(e).__name__}: {e}") from e
        try:
            data = json.loads(raw)
        except Exception as e:
            raise RuntimeError(f"bad JSON from provider: {raw[:160]}") from e
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            code = err.get("code") if isinstance(err, dict) else ""
            raise RuntimeError(f"HTTP 400 provider error {code}: {msg}")
        try:
            msg = data["choices"][0].get("message") or {}
            content = msg.get("content") or msg.get("reasoning_content") or ""
        except Exception:
            content = ""
        if not content:
            raise RuntimeError("empty completion from provider")
        return _Completion(content)


def make_client(provider: str, settings: Optional[Dict[str, Any]] = None):
    """Build the right client for a provider.

    Groq keeps the official SDK (its hardcoded /openai/v1 path matches Groq's
    own host); every other provider gets the generic OpenAI-compatible client.
    Raises on unknown provider so the caller can report it.
    """
    meta = REGISTRY.get(provider)
    if not meta:
        raise ValueError(f"unknown provider {provider}")
    key = provider_key(provider, settings)
    if provider == "groq":
        from groq import Groq  # local import: only needed for Groq
        return Groq(api_key=key or "unset")
    if not key and not meta.get("no_key"):
        raise ValueError(f"no API key for {provider}")
    return OpenAIClient(meta["base_url"], key or "local",
                        timeout=int((settings or {}).get("http_timeout", 120)))


# ── chain construction ────────────────────────────────────────────────

def _display(model_id: str) -> str:
    m = model_id
    if "/" in m:
        m = m.rsplit("/", 1)[-1]
    m = m.replace(":free", " (free)").replace("-instruct", "")
    m = m.replace("-Instruct", "").replace("-Turbo", "")
    return m[:28]


def build_chain(settings: Optional[Dict[str, Any]] = None,
                live: bool = False, per_provider: int = 3,
                max_len: int = 12) -> List[Tuple[str, str, str]]:
    """Assemble the fallback chain, ordered, de-duplicated, capped.

    `live=True` triggers (cached) model discovery per enabled provider;
    `live=False` keeps boot fast and uses the curated defaults.  A pinned
    `model_chain` in settings always comes first.
    """
    settings = settings or {}
    chain: List[Tuple[str, str, str]] = []
    seen = set()

    def _add(model: str, provider: str) -> None:
        key = (model, provider)
        if model and key not in seen and len(chain) < max_len:
            seen.add(key)
            chain.append((model, _display(model), provider))

    # 1) operator-pinned chain
    for row in (settings.get("model_chain") or []):
        try:
            _add(str(row.get("model", "")), str(row.get("provider", "")))
        except Exception:
            continue

    # 2) each enabled provider, curated-first then live extras
    for provider in ORDER:
        if len(chain) >= max_len:
            break
        if not is_enabled(provider, settings):
            continue
        defaults = default_models(provider)
        if live:
            got = list_models(provider,
                              timeout=int(settings.get("discover_timeout", 6)),
                              settings=settings)
            models = got.get("models") or defaults
            if got.get("ok"):
                ordered = [m for m in defaults if m in models] + \
                          [m for m in models if m not in defaults]
            else:
                ordered = defaults
        else:
            # Reuse a recent discovery if we have one (no network call) so a
            # chain rebuilt from `model use` never falls back to models this
            # key cannot actually reach.
            cached = _CACHE.get(provider)
            if cached:
                models = cached[1]
                ordered = [m for m in defaults if m in models] + \
                          [m for m in models if m not in defaults]
            else:
                ordered = defaults
        for m in ordered[:per_provider]:
            _add(m, provider)

    # 3) absolute last resort — first available provider's defaults
    if not chain:
        for provider in ORDER:
            if len(chain) >= max_len:
                break
            if provider_key(provider, settings) or REGISTRY[provider].get("no_key"):
                for m in default_models(provider)[:2]:
                    _add(m, provider)

    return chain


def status(settings: Optional[Dict[str, Any]] = None,
           live: bool = True) -> List[Dict[str, Any]]:
    """One row per provider for `model` / the GUI."""
    settings = settings or {}
    rows = []
    for provider in ORDER:
        meta = REGISTRY[provider]
        key = provider_key(provider, settings)
        enabled = is_enabled(provider, settings)
        models: List[str] = []
        err = ""
        if enabled:
            got = list_models(provider, timeout=4, use_cache=True,
                              settings=settings) if live \
                else {"models": default_models(provider), "error": ""}
            models = got.get("models") or []
            err = got.get("error") or ""
        rows.append({
            "provider": provider,
            "label": meta["label"],
            "free": meta.get("free", False),
            "key_set": bool(key) or bool(meta.get("no_key")),
            "enabled": enabled,
            "models": len(models),
            "error": err,
        })
    return rows


# ── mutators the CLI/GUI call ─────────────────────────────────────────

def set_key(settings: Dict[str, Any], provider: str, key: str) -> Dict[str, Any]:
    s = dict(settings or {})
    pk = dict(s.get("provider_keys") or {})
    pk[provider] = key
    s["provider_keys"] = pk
    return s


def pin(settings: Dict[str, Any], provider: str, model: str,
        name: str = "") -> Dict[str, Any]:
    s = dict(settings or {})
    s["active_model"] = f"{provider}/{model}"
    chain = list(s.get("model_chain") or [])
    row = {"provider": provider, "model": model, "name": name or _display(model)}
    chain = [c for c in chain
             if not (c.get("provider") == provider and c.get("model") == model)]
    chain.insert(0, row)
    s["model_chain"] = chain[:12]
    return s
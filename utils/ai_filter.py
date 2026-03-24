"""Multi-provider AI integration for fbsfilter.

Supports Groq (fast inference) and NVIDIA NIM (via OpenAI-compatible API).
AI filter mode is optional – the tool works in normal mode without an API key.
"""

import json
import logging
import re
from typing import List, Optional, Tuple

logger = logging.getLogger("fbsfilter.ai_filter")

# ---------------------------------------------------------------------------
# Provider state
# ---------------------------------------------------------------------------

_groq_client = None
_groq_available = False
_nvidia_client = None
_nvidia_available = False
_active_provider: str = "groq"   # "groq" or "nvidia"
_active_model: str = "llama3-70b-8192"

# Available models per provider (name → display label)
GROQ_MODELS = {
    "llama3-70b-8192": "Llama 3 70B (recommended)",
    "llama3-8b-8192": "Llama 3 8B (fast)",
    "mixtral-8x7b-32768": "Mixtral 8x7B (large context)",
    "gemma2-9b-it": "Gemma 2 9B",
}
NVIDIA_MODELS = {
    "meta/llama-3.1-70b-instruct": "Llama 3.1 70B (recommended)",
    "meta/llama-3.1-8b-instruct": "Llama 3.1 8B (fast)",
    "mistralai/mistral-7b-instruct-v0.3": "Mistral 7B",
    "microsoft/phi-3-mini-128k-instruct": "Phi-3 Mini 128K",
}

NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"

try:
    from groq import Groq
    _groq_available = True
except ImportError:
    _groq_available = False
    logger.debug("groq package not installed – Groq AI features disabled")

try:
    import openai as _openai_module
    _nvidia_available = True
except ImportError:
    _nvidia_available = False
    logger.debug("openai package not installed – NVIDIA NIM features disabled")


# ---------------------------------------------------------------------------
# Initialisation helpers
# ---------------------------------------------------------------------------

def init_groq(api_key: str, model: str = "llama3-70b-8192") -> Tuple[bool, str]:
    """Initialise the Groq client with the supplied key.

    Returns (success, message).
    """
    global _groq_client, _active_provider, _active_model
    if not _groq_available:
        return False, "groq package is not installed. Run: pip install groq"
    if not api_key or not api_key.strip():
        return False, "API key is empty."
    try:
        client = Groq(api_key=api_key.strip())
        _groq_client = client
        _active_provider = "groq"
        _active_model = model
        return True, f"Groq connected ✓  Model: {GROQ_MODELS.get(model, model)}"
    except Exception as exc:
        _groq_client = None
        return False, f"Groq API error: {exc}"


def init_nvidia(api_key: str, model: str = "meta/llama-3.1-70b-instruct") -> Tuple[bool, str]:
    """Initialise the NVIDIA NIM client (OpenAI-compatible API).

    Returns (success, message).
    """
    global _nvidia_client, _active_provider, _active_model
    if not _nvidia_available:
        return False, "openai package is not installed. Run: pip install openai"
    if not api_key or not api_key.strip():
        return False, "API key is empty."
    try:
        client = _openai_module.OpenAI(
            base_url=NVIDIA_BASE_URL,
            api_key=api_key.strip(),
        )
        _nvidia_client = client
        _active_provider = "nvidia"
        _active_model = model
        return True, f"NVIDIA NIM connected ✓  Model: {NVIDIA_MODELS.get(model, model)}"
    except Exception as exc:
        _nvidia_client = None
        return False, f"NVIDIA API error: {exc}"


def is_groq_ready() -> bool:
    """Return True if the Groq client has been successfully initialised."""
    return _groq_client is not None


def is_ai_ready() -> bool:
    """Return True if *any* AI provider is ready."""
    return _groq_client is not None or _nvidia_client is not None


def get_active_provider() -> str:
    """Return the name of the currently active AI provider ('groq' or 'nvidia')."""
    return _active_provider


def get_active_model() -> str:
    """Return the currently active model identifier."""
    return _active_model


# ---------------------------------------------------------------------------
# Internal chat helper – routes to the active provider
# ---------------------------------------------------------------------------

def _chat(system: str, user: str, model: Optional[str] = None, max_tokens: int = 512) -> str:
    """Send a chat completion request to the active AI provider.

    *model* overrides the active model when provided.
    """
    effective_model = model or _active_model

    if _active_provider == "nvidia" and _nvidia_client is not None:
        response = _nvidia_client.chat.completions.create(
            model=effective_model or "meta/llama-3.1-70b-instruct",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()

    if _groq_client is not None:
        response = _groq_client.chat.completions.create(
            model=effective_model or "llama3-70b-8192",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()

    raise RuntimeError(
        "No AI provider initialised. "
        "Enter a Groq or NVIDIA API key in the AI Assistant tab."
    )


# ---------------------------------------------------------------------------
# Credential analysis
# ---------------------------------------------------------------------------

def analyze_credentials(credentials: List[Tuple[str, str]]) -> str:
    """Ask the AI to analyse a batch of credentials and flag suspicious ones.

    Returns a plain-text report.

    NOTE: This function sends credential usernames and anonymised password
    patterns (not plain-text passwords) to the Groq cloud API.  Do not use
    this feature with real production credentials or any data you do not have
    explicit permission to share with a third-party service.
    """
    if not credentials:
        return "No credentials to analyse."
    # Send usernames and password length/pattern only – never raw passwords
    sample_lines = []
    for u, p in credentials[:50]:
        # Anonymise password: show length and character-class pattern only
        pattern = "".join(
            "L" if c.isalpha() else "D" if c.isdigit() else "S"
            for c in p
        )
        sample_lines.append(f"{u}  pwd_len={len(p)}  pattern={pattern}")
    sample = "\n".join(sample_lines)
    system = (
        "You are a security analyst assistant. "
        "You help identify patterns in leaked credential lists. "
        "Passwords are represented as length and character-class patterns only. "
        "Be concise and factual. Never encourage illegal activity."
    )
    user = (
        f"Analyse the following credential entries. "
        f"Each line contains a username, password length, and a character-class pattern "
        f"(L=letter, D=digit, S=symbol). "
        f"Identify any notable patterns (e.g. weak passwords, disposable emails, duplicates, "
        f"test accounts). Provide a short summary.\n\n{sample}"
    )
    return _chat(system, user)


def ai_classify_response(username: str, password: str, response_body: str, final_url: str) -> str:
    """Use AI to classify a login response as working/invalid/locked/2fa/error.

    Returns one of: 'working', 'invalid', 'locked', '2fa', 'error'.
    """
    snippet = response_body[:2000] if len(response_body) > 2000 else response_body
    system = (
        "You are a web security tool that classifies HTTP login responses. "
        "Reply with EXACTLY one word from: working, invalid, locked, 2fa, error. "
        "No explanation."
    )
    user = (
        f"Username: {username}\n"
        f"Final URL: {final_url}\n"
        f"Response body snippet:\n{snippet}\n\n"
        "Classify the login result."
    )
    try:
        result = _chat(system, user, max_tokens=10).lower().strip()
        for status in ("working", "invalid", "locked", "2fa", "error"):
            if status in result:
                return status
        return "invalid"
    except Exception as exc:
        logger.debug("AI classify error: %s", exc)
        return "error"


# ---------------------------------------------------------------------------
# Proxy analysis
# ---------------------------------------------------------------------------

def analyze_proxy_list(proxies: List[str]) -> str:
    """Ask the AI to analyse a proxy list and suggest filtering criteria."""
    if not proxies:
        return "No proxies to analyse."
    sample = "\n".join(proxies[:100])
    system = (
        "You are a network security assistant. "
        "Help the user understand and clean a proxy list."
    )
    user = (
        f"Here is a proxy list ({len(proxies)} entries, showing up to 100):\n\n{sample}\n\n"
        "1. What proxy types are present?\n"
        "2. Are there any obviously invalid entries?\n"
        "3. What filters would you recommend to keep only high-quality proxies?"
    )
    return _chat(system, user, max_tokens=600)


def ai_suggest_filters(raw_text: str) -> dict:
    """Parse a pasted proxy dump and return suggested filter settings as a dict."""
    system = (
        "You are a proxy list parser. "
        "Extract filter suggestions from the user's proxy dump. "
        "Reply ONLY with valid JSON, no markdown fences, with keys: "
        "'types' (list of strings: http/https/socks4/socks5), "
        "'anonymity' (list of strings: transparent/anonymous/elite), "
        "'country_codes' (list of 2-letter ISO codes, empty list if none detected)."
    )
    user = f"Proxy dump sample (first 500 chars):\n{raw_text[:500]}"
    try:
        raw = _chat(system, user, max_tokens=200)
        # Strip potential markdown fences
        raw = re.sub(r"```[a-z]*", "", raw).strip().strip("`")
        return json.loads(raw)
    except Exception as exc:
        logger.debug("ai_suggest_filters error: %s", exc)
        return {"types": [], "anonymity": [], "country_codes": []}


# ---------------------------------------------------------------------------
# AI optimisation helpers (new)
# ---------------------------------------------------------------------------

def ai_prioritize_credentials(credentials: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Return *credentials* re-ordered so likely-working ones come first.

    The AI scores each credential on likelihood of being valid (based on
    password strength, domain patterns, etc.) and returns a re-sorted list.
    Only usernames and anonymised password patterns (never raw passwords) are
    sent to the AI.

    If the AI is not available or fails, the original order is preserved.
    """
    if not credentials or not is_ai_ready():
        return credentials

    sample_lines = []
    for i, (u, p) in enumerate(credentials[:100]):
        pattern = "".join("L" if c.isalpha() else "D" if c.isdigit() else "S" for c in p)
        sample_lines.append(f"{i}\t{u}\tlen={len(p)}\tpat={pattern}")
    sample = "\n".join(sample_lines)

    system = (
        "You are a security analyst. "
        "Given a list of credential entries (index, username, password length, pattern), "
        "rank them by likelihood of being a valid, working account. "
        "Reply with ONLY a JSON array of indices in descending priority order, "
        "e.g. [3, 0, 7, 1, ...]. No explanation."
    )
    user = f"Credentials ({len(credentials)} total, showing first 100):\n{sample}\n\nRank them."

    try:
        raw = _chat(system, user, max_tokens=400)
        raw = re.sub(r"```[a-zA-Z]*", "", raw).strip().strip("`")
        indices = json.loads(raw)
        if not isinstance(indices, list):
            return credentials
        # Build re-ordered list; indices not returned by AI fall to the end
        seen: set = set()
        ordered: List[Tuple[str, str]] = []
        for idx in indices:
            if isinstance(idx, int) and 0 <= idx < len(credentials):
                ordered.append(credentials[idx])
                seen.add(idx)
        # Append any not ranked (items beyond the 100 sent or missed by AI)
        for i, cred in enumerate(credentials):
            if i not in seen:
                ordered.append(cred)
        return ordered
    except Exception as exc:
        logger.debug("ai_prioritize_credentials error: %s", exc)
        return credentials


def ai_optimize_settings(stats: dict) -> dict:
    """Return recommended checker settings based on live session statistics.

    *stats* should be a dict with keys: processed, working, invalid, locked,
    errors, elapsed_seconds, current_threads, current_delay.

    Returns a dict with optional keys: threads (int), delay (float), message (str).
    On failure returns an empty dict.
    """
    if not is_ai_ready():
        return {}

    system = (
        "You are a performance optimisation assistant for a credential checker. "
        "Analyse the session stats and recommend thread count and request delay. "
        "Reply ONLY with valid JSON (no markdown) with keys: "
        "'threads' (int, 1-50), 'delay' (float, 0.1-5.0), 'message' (short explanation)."
    )
    user = (
        f"Session stats:\n"
        f"  Processed : {stats.get('processed', 0)}\n"
        f"  Working   : {stats.get('working', 0)}\n"
        f"  Invalid   : {stats.get('invalid', 0)}\n"
        f"  Locked    : {stats.get('locked', 0)}\n"
        f"  Errors    : {stats.get('errors', 0)}\n"
        f"  Elapsed   : {stats.get('elapsed_seconds', 0):.0f}s\n"
        f"  Threads   : {stats.get('current_threads', 10)}\n"
        f"  Delay     : {stats.get('current_delay', 0.5)}s\n\n"
        "Suggest optimal threads and delay to maximise throughput while avoiding lockouts."
    )

    try:
        raw = _chat(system, user, max_tokens=150)
        raw = re.sub(r"```[a-zA-Z]*", "", raw).strip().strip("`")
        result = json.loads(raw)
        # Clamp values to safe ranges
        if "threads" in result:
            result["threads"] = max(1, min(50, int(result["threads"])))
        if "delay" in result:
            result["delay"] = round(max(0.1, min(5.0, float(result["delay"]))), 2)
        return result
    except Exception as exc:
        logger.debug("ai_optimize_settings error: %s", exc)
        return {}


def ai_analyze_failure_patterns(stats: dict) -> str:
    """Analyse high failure / lockout rates and return a diagnostic report.

    *stats* should contain: processed, working, invalid, locked, errors,
    elapsed_seconds, proxy_count, current_threads, current_delay.
    """
    if not is_ai_ready():
        return "AI not connected. Provide a Groq or NVIDIA API key in the AI Assistant tab."

    locked = stats.get("locked", 0)
    errors = stats.get("errors", 0)
    processed = max(1, stats.get("processed", 1))

    system = (
        "You are a security tools expert. "
        "Analyse the provided credential-checker session stats and diagnose why "
        "there are many locked or error results. "
        "Give 3-5 concrete, actionable recommendations. Be concise."
    )
    user = (
        f"Stats:\n"
        f"  Processed : {processed}\n"
        f"  Working   : {stats.get('working', 0)}  ({100*stats.get('working',0)//processed}%)\n"
        f"  Invalid   : {stats.get('invalid', 0)}\n"
        f"  Locked    : {locked}  ({100*locked//processed}%)\n"
        f"  Errors    : {errors}  ({100*errors//processed}%)\n"
        f"  Proxies   : {stats.get('proxy_count', 0)}\n"
        f"  Threads   : {stats.get('current_threads', 10)}\n"
        f"  Delay (s) : {stats.get('current_delay', 0.5)}\n"
        f"  Elapsed   : {stats.get('elapsed_seconds', 0):.0f}s\n\n"
        "What is causing the high failure rate and how can I fix it?"
    )

    try:
        return _chat(system, user, max_tokens=500)
    except Exception as exc:
        return f"[AI Error] {exc}"


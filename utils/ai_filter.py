"""Groq API integration for AI-assisted filtering in fbsfilter.

Provides AI-powered credential and proxy analysis using the Groq cloud API.
AI filter mode is optional – the tool works in normal mode without an API key.
"""

import json
import logging
import re
from typing import List, Optional, Tuple

logger = logging.getLogger("fbsfilter.ai_filter")

_groq_client = None
_groq_available = False

try:
    from groq import Groq
    _groq_available = True
except ImportError:
    _groq_available = False
    logger.debug("groq package not installed – AI features disabled")


def init_groq(api_key: str) -> Tuple[bool, str]:
    """Initialise the Groq client with the supplied key.

    Returns (success, message).
    """
    global _groq_client
    if not _groq_available:
        return False, "groq package is not installed. Run: pip install groq"
    if not api_key or not api_key.strip():
        return False, "API key is empty."
    try:
        client = Groq(api_key=api_key.strip())
        _groq_client = client
        return True, "Groq API key accepted."
    except Exception as exc:
        _groq_client = None
        return False, f"Groq API error: {exc}"


def is_groq_ready() -> bool:
    """Return True if the Groq client has been successfully initialised."""
    return _groq_client is not None


def _chat(system: str, user: str, model: str = "llama3-8b-8192", max_tokens: int = 512) -> str:
    """Send a chat completion request and return the response text."""
    if _groq_client is None:
        raise RuntimeError("Groq client not initialised. Provide an API key first.")
    response = _groq_client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return response.choices[0].message.content.strip()


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

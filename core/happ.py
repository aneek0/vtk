"""Happy decrypt — decrypt happ://crypt* links.

Built-in Python decryptor with all 34 crypt5 RSA keys bundled.
No external API calls needed — fully offline, no rate limits.

Usage:
    decrypt_link(url)  — decrypt a single link (passthrough + crypt*)
    decrypt_text(text) — replace all happ:// links in text
"""

from __future__ import annotations

import logging
import re
import time
import hashlib
import os
from urllib.parse import quote, urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEMO_KEY = "hd_demo_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

HAPP_RE = re.compile(r"happ://(crypt|crypt2|crypt3|crypt4|crypt5)/([^\s]+)")
HAPP_ADD_RE = re.compile(r"happ://add/(.+)")

# ---------------------------------------------------------------------------
# Demo rate limiting (in-memory, per-key)
# ---------------------------------------------------------------------------

_RATE_LIMITS: dict[str, list[float]] = {}  # key -> [timestamps]
_DEMO_LIMIT = 5  # per minute
_PERSONAL_LIMIT = 10  # per minute
_WINDOW = 60.0  # seconds


def _check_rate_limit(api_key: str) -> tuple[bool, int]:
    """Check rate limit for given key. Returns (allowed, remaining)."""
    now = time.time()
    limit = _DEMO_LIMIT if api_key == DEMO_KEY else _PERSONAL_LIMIT
    
    if api_key not in _RATE_LIMITS:
        _RATE_LIMITS[api_key] = []
    
    # Clean old timestamps
    _RATE_LIMITS[api_key] = [t for t in _RATE_LIMITS[api_key] if now - t < _WINDOW]
    
    if len(_RATE_LIMITS[api_key]) >= limit:
        # Calculate retry_after
        oldest = min(_RATE_LIMITS[api_key])
        retry_after = int(_WINDOW - (now - oldest)) + 1
        return False, retry_after
    
    _RATE_LIMITS[api_key].append(now)
    remaining = limit - len(_RATE_LIMITS[api_key])
    return True, remaining


def _get_client_ip(request) -> str:
    """Extract real client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


# ---------------------------------------------------------------------------
# Passthrough format
# ---------------------------------------------------------------------------

def _passthrough(url: str) -> str | None:
    """Handle happ://add/<url> format — strip prefix, return the inner URL."""
    m = HAPP_ADD_RE.match(url)
    if m:
        return m.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Primary path: built-in Python decryptor (all 34 crypt5 keys bundled)
# ---------------------------------------------------------------------------

def _builtin_decrypt(url: str, api_key: str = "") -> str:
    """Decrypt using the local Python implementation (no network needed).

    Raises ValueError if the format is unknown or decryption fails.
    Returns the decrypted URL.
    """
    from core.happdecrypt import decrypt_link as _decrypt
    return _decrypt(url)


def _get_key() -> str:
    """Get API key from env or settings. (Not needed for built-in decryptor.)"""
    import os

    key = os.environ.get("VTK_HAPP_KEY", DEMO_KEY)
    if key:
        return key
    try:
        from core.settings import load_settings

        s = load_settings()
        if getattr(s, "happ_key", ""):
            return s.happ_key
    except Exception:
        pass
    return DEMO_KEY


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_happ(text: str) -> bool:
    """Check if text contains happ:// links."""
    return bool(HAPP_RE.search(text))


def decrypt_link(url: str, api_key: str = "") -> str:
    """Decrypt a single happ:// link.

    Strategy:
    1. Handle passthrough format (happ://add/<url>) — strip prefix.
    2. Decrypt using built-in Python decryptor (all 34 crypt5 keys bundled, offline, no rate limit).
    """
    # 1. Passthrough
    passthrough = _passthrough(url)
    if passthrough is not None:
        return passthrough

    # 2. Built-in decrypt (no external API calls)
    try:
        return _builtin_decrypt(url)
    except ValueError as e:
        raise RuntimeError(f"Decrypt failed: {e}") from e


def decrypt_text(text: str, api_key: str = "") -> str:
    """Decrypt all happ:// links in text. Returns text with decrypted URLs."""
    # First, handle passthrough format
    text = HAPP_ADD_RE.sub(lambda m: m.group(1).strip(), text)
    
    # Then decrypt crypt* links
    def _replace(m: re.Match) -> str:
        url = m.group(0)
        try:
            return decrypt_link(url, api_key)
        except Exception as e:
            logger.warning("Failed to decrypt %s: %s", url[:40], e)
            return url  # keep original on failure

    return HAPP_RE.sub(_replace, text)


async def fetch_sub_with_decrypt(url: str, api_key: str = "", timeout: int = 15) -> str:
    """Fetch content from a URL (subscription or other).

    Fetches directly via httpx, then decrypts any happ:// links found in the text.
    No external API calls needed — uses built-in decryptor.
    """
    import httpx
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        text = resp.text
    # Decrypt any happ:// links found in the text
    return decrypt_text(text, api_key)


# ---------------------------------------------------------------------------
# Convenience for CLI / web
# ---------------------------------------------------------------------------

async def fetch_sub_with_decrypt_builtin(url: str, api_key: str = "", timeout: int = 15) -> str:
    """Fetch subscription content, decrypt embedded happ:// links.

    Uses built-in decryptor when possible, falls back to API.
    """
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        text = resp.text

    # Decrypt any happ:// links found
    return decrypt_text(text, api_key)

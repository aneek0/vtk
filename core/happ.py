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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HAPP_RE = re.compile(r"happ://(crypt|crypt2|crypt3|crypt4|crypt5)/([^\s]+)")
HAPP_ADD_RE = re.compile(r"happ://add/(.+)")

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

def _builtin_decrypt(url: str) -> str:
    """Decrypt using the local Python implementation (no network needed).

    Raises ValueError if the format is unknown or decryption fails.
    Returns the decrypted URL.
    """
    from core.happdecrypt import decrypt_link as _decrypt
    return _decrypt(url)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_happ(text: str) -> bool:
    """Check if text contains happ:// links."""
    return bool(HAPP_RE.search(text))


def decrypt_link(url: str) -> str:
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


def decrypt_text(text: str) -> str:
    """Decrypt all happ:// links in text. Returns text with decrypted URLs."""
    # First, handle passthrough format
    text = HAPP_ADD_RE.sub(lambda m: m.group(1).strip(), text)
    
    # Then decrypt crypt* links
    def _replace(m: re.Match) -> str:
        url = m.group(0)
        try:
            return decrypt_link(url)
        except Exception as e:
            logger.warning("Failed to decrypt %s: %s", url[:40], e)
            return url  # keep original on failure

    return HAPP_RE.sub(_replace, text)


async def fetch_sub_with_decrypt(url: str, timeout: int = 15) -> str:
    """Fetch content from a URL (subscription or other).

    Fetches directly via httpx, then decrypts any happ:// links found in the text.
    No external API calls needed — uses built-in decryptor.
    """
    import httpx
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        text = resp.text
    # Decrypt any happ:// links found in the text
    return decrypt_text(text)


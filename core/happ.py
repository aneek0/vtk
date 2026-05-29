"""Happy Decoder API integration — decrypt happ://crypt* links.

Uses happy-decoder.cc API. Falls back to demo key if no personal key set.
"""

import logging
import os
import re
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

DEMO_KEY = "hd_demo_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
API_BASE = "https://happy-decoder.cc"

HAPP_RE = re.compile(r"happ://(crypt|crypt2|crypt3|crypt4|crypt5)/([^\s]+)")


def _get_key() -> str:
    """Get API key from env or settings, fallback to demo."""
    key = os.environ.get("VTK_HAPP_KEY", "")
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


def is_happ(text: str) -> bool:
    """Check if text contains happ:// links."""
    return bool(HAPP_RE.search(text))


def decrypt_link(url: str, api_key: str = "") -> str:
    """Decrypt a single happ://crypt* link via Happy Decoder API.

    Returns the decrypted URL or raises RuntimeError.
    """
    if not api_key:
        api_key = _get_key()
    r = httpx.post(
        f"{API_BASE}/api/v1/decrypt",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={"url": url},
        timeout=10,
    )
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"{r.status_code}: {data['error']}")
    return data["decryptedUrl"]


def decrypt_text(text: str, api_key: str = "") -> str:
    """Decrypt all happ:// links in text. Returns text with decrypted URLs."""
    if not api_key:
        api_key = _get_key()

    def _replace(m: re.Match) -> str:
        url = m.group(0)
        try:
            return decrypt_link(url, api_key)
        except Exception as e:
            logger.warning("Failed to decrypt %s: %s", url[:40], e)
            return url  # keep original on failure

    return HAPP_RE.sub(_replace, text)


async def fetch_sub_with_decrypt(url: str, api_key: str = "", timeout: int = 15) -> str:
    """Fetch subscription URL via Happy Decoder Universal Proxy.

    Path-based proxy: https://happy-decoder.cc/p/<url>
    No API key needed. Returns Xray JSON configs or decrypted subscription text.
    """
    proxy_url = f"{API_BASE}/p/{url}"
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(proxy_url, headers={"User-Agent": "Happ/3.17.0"})
        resp.raise_for_status()
        return resp.text

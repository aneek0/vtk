"""URL-safe base64 helpers shared by the parser and the share-link codec."""

import base64


def b64decode(s: str) -> str:
    """Decode URL-safe base64, tolerating missing padding."""
    s = s.strip()
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")


def b64encode(s: str) -> str:
    """Encode to URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

"""Random device fingerprint endpoint — single source for web + bot."""

from fastapi import APIRouter

from core.fingerprint import random_device

router = APIRouter()


@router.get("/api/device/random")
async def api_device_random():
    """Return a random device fingerprint params dict."""
    return random_device()

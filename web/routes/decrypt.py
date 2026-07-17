import os
import time
import random

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

router = APIRouter()


# ── Happ API endpoints ──

@router.post("/api/happ/decrypt")
async def api_happ_decrypt(body: dict):
    from core.happ import decrypt_link
    url = body.get("url", "")
    if not url:
        return JSONResponse({"ok": False, "error": "Missing 'url' field"}, status_code=400)
    try:
        result = decrypt_link(url)
        return {"ok": True, "decryptedUrl": result}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.post("/api/happ/decrypt-text")
async def api_happ_decrypt_text(body: dict):
    from core.happ import decrypt_text
    text = body.get("text", "")
    if not text:
        return JSONResponse({"ok": False, "error": "Missing 'text' field"}, status_code=400)
    try:
        result = decrypt_text(text)
        return {"ok": True, "text": result, "decrypted": result != text}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.get("/api/happ/check")
async def api_happ_check(url: str = ""):
    from core.happ import is_happ, decrypt_link
    try:
        if is_happ(url):
            decrypted = decrypt_link(url)
            return {"ok": True, "is_happ": True, "decrypted": decrypted}
        return {"ok": True, "is_happ": False, "original": url}
    except Exception as e:
        return {"ok": True, "is_happ": True, "error": str(e)}


@router.get("/api/happ/supported")
async def api_happ_supported():
    from core.happdecrypt import _load_crypt5_keys, _PKCS1_KEYS_B64
    keys = _load_crypt5_keys()
    return {
        "ok": True,
        "versions": ["crypt", "crypt2", "crypt3", "crypt4", "crypt5"],
        "crypt1_4_keys": len(_PKCS1_KEYS_B64),
        "crypt5_keys": len(keys),
    }


# ── v1 API (happy-decoder.cc compatible) ──

_HAPP_DEMO_KEY = "hd_demo_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
_API_KEYS: dict[str, dict] = {}
_KEY_CREATION_TIMES: dict[str, float] = {}
_API_KEYS_LOCK = __import__("threading").Lock()


def _generate_key() -> str:
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))


def _get_happ_key() -> str:
    return os.environ.get("VTK_HAPP_KEY", _HAPP_DEMO_KEY)


class HappDecryptRequest(BaseModel):
    url: str = Field(..., description="happ://crypt* or happ://add/ link to decrypt")


@router.post("/api/v1/decrypt")
async def api_v1_decrypt(request: Request, req: HappDecryptRequest):
    from core.happ import _passthrough, _check_rate_limit, _get_client_ip, decrypt_link

    api_key = (
        request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        or request.query_params.get("apikey", "")
        or _get_happ_key()
    )
    if not api_key:
        return JSONResponse({"error": "missing or invalid api key"}, status_code=401)

    with _API_KEYS_LOCK:
        if api_key != _HAPP_DEMO_KEY and api_key not in _API_KEYS:
            return JSONResponse({"error": "missing or invalid api key"}, status_code=401)

    allowed, retry_after = _check_rate_limit(api_key)
    if not allowed:
        return JSONResponse(
            {"error": "rate limit exceeded"},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    url = req.url or ""
    if not url:
        return JSONResponse({"error": "invalid request body"}, status_code=400)

    passthrough = _passthrough(url)
    if passthrough is not None:
        return {"decryptedUrl": passthrough}

    try:
        result = decrypt_link(url)
        return {"decryptedUrl": result}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@router.options("/api/v1/decrypt")
async def api_v1_decrypt_options():
    return JSONResponse({}, status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
    })


@router.get("/api/v1/keys")
async def api_v1_keys():
    return {
        "ok": True,
        "note": "Built-in decryptor does not require keys. All 34 crypt5 RSA keys bundled.",
        "crypt1_4_keys": 4,
        "crypt5_keys": 34,
    }


@router.post("/api/v1/key")
async def api_v1_generate_key(request: Request):
    from core.happ import _get_client_ip

    client_ip = _get_client_ip(request)
    now = time.time()

    with _API_KEYS_LOCK:
        last_created = _KEY_CREATION_TIMES.get(client_ip, 0)
        if now - last_created < 60:
            retry_after = int(60 - (now - last_created)) + 1
            return JSONResponse(
                {"error": f"rate limited, try again in {retry_after}s"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        key = _generate_key()
        _API_KEYS[key] = {"created": now, "ip": client_ip, "personal": True}
        _KEY_CREATION_TIMES[client_ip] = now

    return {"ok": True, "key": key, "limit": "10 req/min", "note": "Store this key safely."}

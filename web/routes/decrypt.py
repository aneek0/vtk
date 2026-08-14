from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

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


"""Decryptor API — one route set per registered scheme (happ, incy, …).

Generated from :data:`core.decryptors.DECRYPTORS` so a new scheme needs no
copy of these four handlers. Paths and response shapes are unchanged:
``/api/<scheme>/{decrypt,decrypt-text,check,supported}``.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from core.decryptors import DECRYPTORS, Decryptor

router = APIRouter()


def _register(decryptor: Decryptor) -> None:
    scheme = decryptor.scheme
    check_key = decryptor.check_key

    async def decrypt(body: dict):
        url = body.get("url", "")
        if not url:
            return JSONResponse({"ok": False, "error": "Missing 'url' field"}, status_code=400)
        try:
            return {"ok": True, "decryptedUrl": decryptor.decrypt_link(url)}
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    async def decrypt_text(body: dict):
        text = body.get("text", "")
        if not text:
            return JSONResponse({"ok": False, "error": "Missing 'text' field"}, status_code=400)
        try:
            result = decryptor.decrypt_text(text)
            return {"ok": True, "text": result, "decrypted": result != text}
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

    async def check(url: str = ""):
        try:
            if decryptor.is_(url):
                return {"ok": True, check_key: True,
                        "decrypted": decryptor.decrypt_link(url)}
            return {"ok": True, check_key: False, "original": url}
        except Exception as e:
            return {"ok": True, check_key: True, "error": str(e)}

    async def supported():
        return {"ok": True, **decryptor.supported()}

    router.add_api_route(f"/api/{scheme}/decrypt", decrypt, methods=["POST"],
                         name=f"api_{scheme}_decrypt")
    router.add_api_route(f"/api/{scheme}/decrypt-text", decrypt_text,
                         methods=["POST"], name=f"api_{scheme}_decrypt_text")
    router.add_api_route(f"/api/{scheme}/check", check, methods=["GET"],
                         name=f"api_{scheme}_check")
    router.add_api_route(f"/api/{scheme}/supported", supported, methods=["GET"],
                         name=f"api_{scheme}_supported")


for _decryptor in DECRYPTORS:
    _register(_decryptor)

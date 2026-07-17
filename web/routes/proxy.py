import hashlib
import random
import re
from urllib.parse import unquote

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter()


def _parse_device_params(param_str: str) -> dict:
    params = {}
    for part in param_str.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip().lower()] = v.strip()
        else:
            params["os"] = part.lower()
    return params


def _generate_device_fingerprint(ua: str, hwid: str, os_name: str, ver: str, model: str, locale: str) -> dict:
    headers = {}
    if ua:
        headers["User-Agent"] = ua
    else:
        headers["User-Agent"] = "Happ/3.17.0"
    if hwid:
        hw_hash = hashlib.md5(hwid.encode()).hexdigest()[:12]
        headers["X-Hwid"] = f"hd-{hw_hash}"
    if os_name.lower() == "ios":
        major = ver.split(".")[0] if ver else str(random.choice(["17", "18", "16", "15"]))
        headers["X-Device-Os"] = "iOS"
        headers["X-Ver-Os"] = major
        headers["X-Device-Model"] = model or random.choice(
            ["iPhone 16", "iPhone 16 Pro", "iPhone 15", "iPhone 15 Pro", "iPhone 14"]
        )
    elif os_name.lower() == "android":
        major = ver.split(".")[0] if ver else str(random.choice(["14", "13", "12", "11"]))
        headers["X-Device-Os"] = "Android"
        headers["X-Ver-Os"] = major
        headers["X-Device-Model"] = model or random.choice(
            ["Pixel 8", "Pixel 7", "Samsung S24", "Samsung S23", "OnePlus 12"]
        )
    else:
        headers["X-Device-Os"] = os_name or "iOS"
        headers["X-Ver-Os"] = ver or "18"
        headers["X-Device-Model"] = model or "iPhone 16"
    headers["Accept-Language"] = locale.replace("_", "-") if locale else "en-US,en;q=0.9"
    return headers


@router.get("/p/{url:path}")
async def api_proxy(
    url: str,
    request: Request,
    format: str = Query("as_is", help="Output format: as_is, json, txt, base64, mihomo"),
    hwid_off: str = Query("", help="Set to '1' to disable HWID"),
    seed_random: str = Query("", help="Set to '1' for random seed"),
):
    import base64 as _base64
    import httpx

    from core.happ import decrypt_text
    from core.logic import parse_subscription_text, ParseError
    from core.converters import convert, Format

    raw_path = unquote(url)
    match = re.search(r"(https?://)", raw_path)
    if not match:
        return JSONResponse(
            {"error": f"Invalid URL format: {raw_path}. Expected /p/<params>/<http-url>"},
            status_code=400,
        )
    split_pos = match.start()
    device_part = raw_path[:split_pos].rstrip("/")
    target_url = raw_path[split_pos:]

    device_params = _parse_device_params(device_part) if device_part else {}
    ua = device_params.get("ua", "")
    hwid = device_params.get("hwid", "")
    os_name = device_params.get("os", "")
    ver = device_params.get("ver", "")
    model = device_params.get("model", "")
    locale = device_params.get("locale", "")

    if not target_url.startswith(("http://", "https://")):
        return JSONResponse({"error": f"Invalid subscription URL: {target_url}"}, status_code=400)

    if seed_random == "1":
        ua = ua or f"Happ/{random.randint(3, 4)}.{random.randint(0, 30)}.{random.randint(0, 10)}"
        hwid = hwid or hashlib.md5(str(random.random()).encode()).hexdigest()[:12]
        os_name = os_name or random.choice(["ios", "android"])
        ver = ver or str(random.randint(15, 18))
        model = model or ""
        locale = locale or random.choice(["en_US", "ru_RU", "de_DE", "fr_FR"])

    fingerprint = _generate_device_fingerprint(ua, hwid, os_name, ver, model, locale)
    headers = {"User-Agent": fingerprint["User-Agent"]}
    if hwid_off != "1" and "X-Hwid" in fingerprint:
        headers["X-Hwid"] = fingerprint["X-Hwid"]
    headers["X-Device-Os"] = fingerprint["X-Device-Os"]
    headers["X-Ver-Os"] = fingerprint["X-Ver-Os"]
    headers["X-Device-Model"] = fingerprint["X-Device-Model"]
    headers["Accept-Language"] = fingerprint["Accept-Language"]

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            output_format = format.lower().replace("-", "_")
            resp = await client.get(target_url, headers=headers)
            resp.raise_for_status()
            content = resp.text
    except Exception as e:
        return JSONResponse({"error": f"Failed to fetch {target_url}: {e}"}, status_code=502)

    content = decrypt_text(content)

    stripped = content.strip()
    if stripped and not stripped.startswith(("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "socks://", "http://", "https://", "{", "- name:", "#")):
        try:
            decoded = _base64.b64decode(stripped).decode("utf-8", errors="ignore")
            if decoded and len(decoded) > 10:
                content = decoded
        except Exception:
            pass

    if output_format == "as_is":
        return PlainTextResponse(content)

    format_map = {
        "json": Format.SINGBOX, "txt": Format.TXT, "base64": Format.TXT,
        "mihomo": Format.MIHOMO, "clash": Format.MIHOMO,
        "singbox": Format.SINGBOX, "flclash": Format.FLCLASH, "xray": Format.XRAY,
    }
    fmt = format_map.get(output_format, Format.TXT)
    try:
        nodes = parse_subscription_text(content)
        nodes = [n for n in nodes if n.protocol != "error"]
        if nodes:
            result = convert(nodes, fmt)
            if output_format == "base64":
                result = _base64.b64encode(result.encode()).decode()
            return PlainTextResponse(result)
        elif output_format == "base64":
            return PlainTextResponse(_base64.b64encode(content.encode()).decode())
        else:
            return JSONResponse({"error": "No valid proxy links found in subscription"}, status_code=400)
    except ParseError as e:
        return JSONResponse({"error": f"Parse error: {e}"}, status_code=400)

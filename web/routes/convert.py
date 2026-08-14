from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from core.logic import process_input, ParseError
from core.converters import Format, to_txt
from core.reverse import from_config
from core.fingerprint import generate_device_fingerprint

router = APIRouter()


def _device_headers(device: dict, on: bool) -> dict | None:

    """Build device headers from a dict of device params if `on` is True."""
    if not on:
        return None
    return generate_device_fingerprint(
        ua=device.get("ua", ""),
        hwid=device.get("hwid", ""),
        os_name=device.get("os", ""),
        ver=device.get("ver", ""),
        model=device.get("model", ""),
        locale=device.get("locale", ""),
    )



@router.get("/api/extract")
async def api_extract(input: str = Query(..., help="sing-box JSON or mihomo YAML config")):
    try:
        nodes = from_config(input.strip())
        result = to_txt(nodes)
        return {"ok": True, "nodes": len(nodes), "result": result}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.post("/api/convert")
async def api_convert(body: dict):
    """JSON API — convert links to specified format.

    POST body: {"input": "...", "format": "singbox", "tag_prefix": "",
                "device_on": false,
                "device": {"os": "android", "ua": "...", "ver": "...",
                           "model": "...", "locale": "...", "hwid": "..."}}
    """
    from core.settings import load_settings

    text = (body.get("input") or "").strip()
    if not text:
        return JSONResponse({"ok": False, "error": "Missing 'input' field"}, status_code=400)

    fmt_str = body.get("format", "singbox")
    tag_prefix = body.get("tag_prefix", "")
    device = body.get("device") or {}
    device_on = bool(body.get("device_on", False))
    headers = _device_headers(device, device_on)
    s = load_settings()

    # Resolve + validate the requested output format (None -> per-type default)
    try:
        fmt = Format(fmt_str)
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": f"Unknown format: {fmt_str}. Valid: singbox, mihomo, txt, flclash, xray"},
            status_code=400,
        )

    res = await process_input(text, fmt=fmt, device_headers=headers, tag_prefix=tag_prefix)

    if not res.get("ok"):
        return JSONResponse({"ok": False, "error": res.get("error", "Processing failed")}, status_code=400)

    sub_headers = res["sub_headers"]
    servers = res["servers"]
    result = res["result"]
    return {"ok": True, "format": res["format"], "nodes": res["nodes"], "result": result, "sub_headers": sub_headers, "servers": servers}


@router.get("/api/convert")
async def api_convert_get(
    input: str = Query(..., help="Proxy link, URL, or raw content"),
    format: str = Query("singbox", help="Output format: singbox, mihomo, txt"),
    tag_prefix: str = Query("", help="Tag prefix"),
    device_on: bool = Query(False, help="Send device headers"),
    os: str = Query("", help="Device OS (android/ios)"),
    ua: str = Query("", help="User-Agent"),
    ver: str = Query("", help="App version"),
    model: str = Query("", help="Device model"),
    locale: str = Query("", help="Locale e.g. ru_RU"),
    hwid: str = Query("", help="HWID"),
):
    """GET variant — for small inputs only (URL length limit ~2K)."""
    from core.settings import load_settings

    s = load_settings()
    text = input.strip()

    device = {"os": os, "ua": ua, "ver": ver, "model": model, "locale": locale, "hwid": hwid}
    headers = _device_headers(device, device_on)

    try:
        fmt = Format(format)
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": f"Unknown format: {format}. Valid: singbox, mihomo, txt, flclash, xray"},
            status_code=400,
        )

    res = await process_input(text, fmt=fmt, device_headers=headers, tag_prefix=tag_prefix)

    if not res.get("ok"):
        return JSONResponse({"ok": False, "error": res.get("error", "Processing failed")}, status_code=400)

    sub_headers = res["sub_headers"]
    servers = res["servers"]
    result = res["result"]
    return {"ok": True, "format": res["format"], "nodes": res["nodes"], "result": result, "sub_headers": sub_headers, "servers": servers}


@router.get("/api/check")
async def api_check(link: str = Query(...)):
    from core.logic import parse_link
    try:
        node = parse_link(link)
        return {"ok": True, "protocol": node.protocol, "name": node.display_name,
                "address": f"{node.address}:{node.port}"}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

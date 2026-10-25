from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from core.converters import Format, to_txt
from core.fingerprint import generate_device_fingerprint
from core.formats import names
from core.logic import ParseError, process_input
from core.reverse import from_config

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


async def _convert_request(
    text: str,
    fmt_str: str,
    *,
    tag_prefix: str = "",
    device: dict | None = None,
    device_on: bool = False,
    protocol: str = "",
    group_by_country: bool = False,
) -> dict:
    """Run one conversion and build the JSON response both routes return.

    GET and POST differ only in how they read their parameters; the work — and
    the response contract — lives here so the two can never drift again.
    """
    try:
        fmt = Format(fmt_str)
    except ValueError:
        return JSONResponse(
            {"ok": False,
             "error": f"Unknown format: {fmt_str}. Valid: {', '.join(names())}"},
            status_code=400,
        )

    res = await process_input(
        text,
        fmt=fmt,
        device_headers=_device_headers(device or {}, device_on),
        tag_prefix=tag_prefix,
        group_by_country=group_by_country,
        protocol=protocol or None,
    )
    if not res.get("ok"):
        return JSONResponse(
            {"ok": False, "error": res.get("error", "Processing failed")},
            status_code=400,
        )
    return {
        "ok": True,
        "format": res["format"],
        "nodes": res["nodes"],
        "total_nodes": res.get("total_nodes", res["nodes"]),
        "protocols": res.get("protocols", {}),
        "result": res["result"],
        "sub_headers": res["sub_headers"],
        "servers": res["servers"],
    }


@router.get("/api/extract")
async def api_extract(input: str = Query(..., description="sing-box JSON or mihomo YAML config")):
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
    text = (body.get("input") or "").strip()
    if not text:
        return JSONResponse({"ok": False, "error": "Missing 'input' field"}, status_code=400)
    return await _convert_request(
        text,
        body.get("format", "singbox"),
        tag_prefix=body.get("tag_prefix", ""),
        device=body.get("device") or {},
        device_on=bool(body.get("device_on", False)),
        protocol=body.get("protocol", ""),
        group_by_country=bool(body.get("group_by_country", False)),
    )


@router.get("/api/convert")
async def api_convert_get(
    input: str = Query(..., description="Proxy link, URL, or raw content"),
    format: str = Query("singbox", description="Output format: singbox, mihomo, txt"),
    tag_prefix: str = Query("", description="Tag prefix"),
    device_on: bool = Query(False, description="Send device headers"),
    protocol: str = Query("", description="Filter by protocol (vless, hysteria2, …)"),
    group_by_country: bool = Query(False, description="Sort/group by country"),
    os: str = Query("", description="Device OS (android/ios)"),
    ua: str = Query("", description="User-Agent"),
    ver: str = Query("", description="App version"),
    model: str = Query("", description="Device model"),
    locale: str = Query("", description="Locale e.g. ru_RU"),
    hwid: str = Query("", description="HWID"),
):
    """GET variant — for small inputs only (URL length limit ~2K)."""
    text = input.strip()
    if not text:
        return JSONResponse({"ok": False, "error": "Missing 'input' field"}, status_code=400)
    return await _convert_request(
        text,
        format,
        tag_prefix=tag_prefix,
        device={"os": os, "ua": ua, "ver": ver, "model": model,
                "locale": locale, "hwid": hwid},
        device_on=device_on,
        protocol=protocol,
        group_by_country=group_by_country,
    )


@router.get("/api/check")
async def api_check(link: str = Query(...)):
    from core.logic import parse_link

    try:
        node = parse_link(link)
        return {"ok": True, "protocol": node.protocol, "name": node.display_name,
                "address": f"{node.address}:{node.port}"}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

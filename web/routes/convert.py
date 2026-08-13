from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from core.logic import Node, parse_text_input, parse_subscription_text, fetch_subscription, ParseError
from core.converters import Format, convert, to_txt
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


def _node_to_dict(node: Node) -> dict:
    proto = node.protocol
    d = {"protocol": proto, "name": node.display_name, "address": node.address, "port": node.port, "net": node.net or "raw"}
    d["type"] = node.net or "raw"
    try:
        d["link"] = node.to_link()
    except Exception:
        d["link"] = ""
    if node.reality_pbk:
        d["reality"] = True
        d["security"] = "reality"
    elif node.tls:
        d["tls"] = True
        d["security"] = "tls"
    else:
        d["security"] = "none"
    if proto == "vless":
        d["encryption"] = node.extra.get("encryption", "none")
    elif proto in ("ss", "ssr"):
        d["encryption"] = node.ss_method or ""
    if node.sni:
        d["sni"] = node.sni
    if node.alpn:
        d["alpn"] = node.alpn
    if node.fp:
        d["fp"] = node.fp
    if node.reality_pbk:
        d["pbk"] = node.reality_pbk
    if node.reality_sid:
        d["sid"] = node.reality_sid
    if node.uuid:
        d["uuid"] = node.uuid
    if node.path:
        d["path"] = node.path
    if node.host:
        d["host"] = node.host
    if node.flow:
        d["flow"] = node.flow
    if node.trojan_password:
        d["password"] = node.trojan_password
    if node.hysteria2_password:
        d["password"] = node.hysteria2_password
    if node.hysteria2_obfs:
        d["obfs"] = node.hysteria2_obfs
    elif node.obfs:
        d["obfs"] = node.obfs
    if proto == "ss":
        if node.ss_method:
            d["method"] = node.ss_method
        if node.ss_password:
            d["password"] = node.ss_password
    if proto == "ssr":
        if node.ss_method:
            d["method"] = node.ss_method
        if node.ss_password:
            d["password"] = node.ss_password
        if node.ssr_protocol:
            d["ssr_protocol"] = node.ssr_protocol
        if node.ssr_obfs:
            d["ssr_obfs"] = node.ssr_obfs
        if node.ssr_protocol_param:
            d["ssr_protocol_param"] = node.ssr_protocol_param
        if node.ssr_obfs_param:
            d["ssr_obfs_param"] = node.ssr_obfs_param
    if proto == "vmess":
        d["aid"] = node.vmess_aid
        d["scy"] = node.vmess_scy
    if proto == "socks":
        if node.socks_username:
            d["socks_user"] = node.socks_username
        if node.socks_password:
            d["socks_pass"] = node.socks_password
    return d


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
    sub_headers = []

    if text.startswith(("http://", "https://")) and "\n" not in text:
        try:
            resp = await fetch_subscription(text, timeout=s.timeout, return_headers=True, headers=headers)
            sub_headers = resp.get("headers", [])
            content = resp.get("content", "")
            nodes = parse_subscription_text(content)
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    else:
        nodes = parse_text_input(text)
        nodes = [n for n in nodes if n.protocol != "error"]

    if not nodes:
        return JSONResponse({"ok": False, "error": "No valid proxy links"}, status_code=400)

    try:
        fmt = Format(fmt_str)
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": f"Unknown format: {fmt_str}. Valid: singbox, mihomo, txt, flclash, xray"},
            status_code=400,
        )

    try:
        result = convert(nodes, fmt, tag_prefix=tag_prefix)
        servers = [_node_to_dict(n) for n in nodes]
        return {"ok": True, "format": fmt_str, "nodes": len(nodes), "result": result, "sub_headers": sub_headers, "servers": servers}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


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
    sub_headers = []
    device = {"os": os, "ua": ua, "ver": ver, "model": model, "locale": locale, "hwid": hwid}
    headers = _device_headers(device, device_on)

    if text.startswith(("http://", "https://")) and "\n" not in text:
        try:
            resp = await fetch_subscription(text, timeout=s.timeout, return_headers=True, headers=headers)
            sub_headers = resp.get("headers", [])
            content = resp.get("content", "")
            nodes = parse_subscription_text(content)
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    else:
        nodes = parse_text_input(text)
        nodes = [n for n in nodes if n.protocol != "error"]

    if not nodes:
        return JSONResponse({"ok": False, "error": "No valid proxy links"}, status_code=400)

    try:
        fmt = Format(format)
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": f"Unknown format: {format}. Valid: singbox, mihomo, txt"},
            status_code=400,
        )

    try:
        result = convert(nodes, fmt, tag_prefix=tag_prefix)
        servers = [_node_to_dict(n) for n in nodes]
        return {"ok": True, "format": format, "nodes": len(nodes), "result": result, "sub_headers": sub_headers, "servers": servers}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@router.get("/api/check")
async def api_check(link: str = Query(...)):
    from core.logic import parse_link
    try:
        node = parse_link(link)
        return {"ok": True, "protocol": node.protocol, "name": node.display_name,
                "address": f"{node.address}:{node.port}"}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

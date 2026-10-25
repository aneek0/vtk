"""Share-link codec: the single owner of share-link rendering.

Parsing lives in :mod:`core.logic` (one parser per scheme). Rendering lives
here so that every output path — ``to_txt``, the front-end server list copied
from the UI, file exports — produces the same link for the same
:class:`~core.logic.Node`. Renderers here must stay inverse to the parsers:
``parse_link(render_link(node))`` reproduces the node's transport-relevant
fields for every supported protocol.

``render_link`` returns ``""`` for protocols it cannot render (unknown or
``error`` nodes); callers that emit lists skip those.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import quote, urlencode

from core._b64 import b64encode

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from core.logic import Node


def _fragment(node: Node) -> str:
    return "#" + quote(node.name, safe="") if node.name else ""


def render_vless(node: Node) -> str:
    params = {"encryption": "none", "type": node.net or "raw"}
    if node.tls:
        params["security"] = "reality" if node.reality_pbk else "tls"
        if node.sni:
            params["sni"] = node.sni
        if node.alpn:
            params["alpn"] = node.alpn
        if node.fp:
            params["fp"] = node.fp
        if node.reality_pbk:
            params["pbk"] = node.reality_pbk
        if node.reality_sid:
            params["sid"] = node.reality_sid
    if node.flow:
        params["flow"] = node.flow
    if node.net in ("ws", "h2", "xhttp") and node.path:
        params["path"] = node.path
    elif node.net == "grpc" and node.path:
        params["serviceName"] = node.path
    if node.host:
        params["host"] = node.host
    base = f"vless://{node.uuid}@{node.address}:{node.port}"
    return base + "?" + urlencode(params) + _fragment(node)


def render_vmess(node: Node) -> str:
    payload = {
        "v": "2",
        "ps": node.name,
        "add": node.address,
        "port": node.port,
        "id": node.uuid,
        "aid": node.vmess_aid,
        "scy": node.vmess_scy,
        "net": node.net,
        "tls": "tls" if node.tls else "",
    }
    if node.sni:
        payload["sni"] = node.sni
    if node.alpn:
        payload["alpn"] = node.alpn
    if node.path:
        payload["path"] = node.path
    if node.host:
        payload["host"] = node.host
    return "vmess://" + b64encode(json.dumps(payload, ensure_ascii=False))


def render_trojan(node: Node) -> str:
    params = {}
    if node.sni:
        params["sni"] = node.sni
    if node.alpn:
        params["alpn"] = node.alpn
    if node.net and node.net != "tcp":
        params["type"] = node.net
    if node.path:
        params["path"] = node.path
    if node.host:
        params["host"] = node.host
    if node.fp:
        params["fp"] = node.fp
    base = f"trojan://{quote(node.trojan_password, safe='')}@{node.address}:{node.port}"
    if params:
        base += "?" + urlencode(params)
    return base + _fragment(node)


def render_ss(node: Node) -> str:
    userinfo = b64encode(f"{node.ss_method}:{node.ss_password}")
    return f"ss://{userinfo}@{node.address}:{node.port}" + _fragment(node)


def render_ssr(node: Node) -> str:
    main = ":".join([
        node.address,
        str(node.port),
        node.ssr_protocol or "origin",
        node.ss_method,
        node.ssr_obfs or "plain",
        b64encode(node.ss_password),
    ])
    params = {
        "remarks": b64encode(node.name),
        "protoparam": b64encode(node.ssr_protocol_param),
        "obfsparam": b64encode(node.ssr_obfs_param),
    }
    return "ssr://" + b64encode(main + "/?" + urlencode(params))


def render_hysteria2(node: Node) -> str:
    params = {}
    if node.sni:
        params["sni"] = node.sni
    if node.alpn:
        params["alpn"] = node.alpn
    if node.obfs:
        params["obfs"] = node.obfs
    base = (
        f"hysteria2://{quote(node.hysteria2_password, safe='')}"
        f"@{node.address}:{node.port}"
    )
    if params:
        base += "?" + urlencode(params)
    return base + _fragment(node)


def render_socks(node: Node) -> str:
    userinfo = (
        b64encode(f"{node.socks_username}:{node.socks_password}") + "@"
        if node.socks_username else ""
    )
    return f"socks://{userinfo}{node.address}:{node.port}" + _fragment(node)


RENDERERS = {
    "vless": render_vless,
    "vmess": render_vmess,
    "trojan": render_trojan,
    "ss": render_ss,
    "ssr": render_ssr,
    "hysteria2": render_hysteria2,
    "socks": render_socks,
}


def render_link(node: Node) -> str:
    """Render one Node back to a share link ("" when no renderer applies)."""
    renderer = RENDERERS.get(node.protocol)
    if renderer is None:
        return ""
    return renderer(node)

"""Converters: sing-box JSON, mihomo YAML, FlClash YAML, plain txt."""

import base64
from collections import defaultdict
from enum import Enum
from typing import Optional
from urllib.parse import urlencode, quote

from .logic import Node, ParseError, extract_country

try:
    import orjson
    _HAS_ORJSON = True
except ImportError:
    import json as _json_fallback
    _HAS_ORJSON = False


def _json_dumps(obj, **kwargs) -> str:
    if _HAS_ORJSON:
        return orjson.dumps(obj, option=orjson.OPT_INDENT_2 | orjson.OPT_APPEND_NEWLINE).decode()
    return _json_fallback.dumps(obj, indent=2, ensure_ascii=False)


def _json_loads(s: str):
    if _HAS_ORJSON:
        return orjson.loads(s)
    return _json_fallback.loads(s)


class Format(str, Enum):
    SINGBOX = "singbox"
    MIHOMO = "mihomo"
    FLCLASH = "flclash"
    TXT = "txt"


def _yaml_escape(s: str) -> str:
    if not s:
        return '""'
    if any(c in s for c in ":{}[]&*?|-><!%@`#,\"'\\\n"):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


# ---------------------------------------------------------------------------
# sing-box
# ---------------------------------------------------------------------------

def _node_to_singbox(node: Node, tag: Optional[str] = None) -> Optional[dict]:
    if tag is None:
        tag = node.display_name

    base = {"type": node.protocol, "tag": tag}

    if node.protocol == "vless":
        base["server"] = node.address
        base["server_port"] = node.port
        base["uuid"] = node.uuid
        if node.flow:
            base["flow"] = node.flow
        _fill_transport(base, node)
        _fill_tls(base, node)

    elif node.protocol == "vmess":
        base["server"] = node.address
        base["server_port"] = node.port
        base["uuid"] = node.uuid
        base["alter_id"] = node.vmess_aid
        base["security"] = node.vmess_scy
        _fill_transport(base, node)
        if node.tls:
            tls = {"enabled": True}
            if node.sni:
                tls["server_name"] = node.sni
            if node.alpn:
                tls["alpn"] = node.alpn.split(",") if "," in node.alpn else [node.alpn]
            base["tls"] = tls

    elif node.protocol == "trojan":
        base["server"] = node.address
        base["server_port"] = node.port
        base["password"] = node.trojan_password
        _fill_transport(base, node)
        if node.sni:
            tls = {"enabled": True, "server_name": node.sni}
            if node.alpn:
                tls["alpn"] = node.alpn.split(",") if "," in node.alpn else [node.alpn]
            base["tls"] = tls
        elif node.tls:
            base["tls"] = {"enabled": True}

    elif node.protocol == "ss":
        base["type"] = "shadowsocks"
        base["server"] = node.address
        base["server_port"] = node.port
        base["method"] = node.ss_method
        base["password"] = node.ss_password

    elif node.protocol == "hysteria2":
        base["server"] = node.address
        base["server_port"] = node.port
        base["password"] = node.hysteria2_password
        if node.sni:
            tls = {"enabled": True, "server_name": node.sni}
            if node.alpn:
                tls["alpn"] = node.alpn.split(",") if "," in node.alpn else [node.alpn]
            base["tls"] = tls
        if node.obfs:
            base["obfs"] = {"type": node.obfs}

    elif node.protocol == "socks":
        base["server"] = node.address
        base["server_port"] = node.port
        if node.socks_username:
            base["username"] = node.socks_username
        if node.socks_password:
            base["password"] = node.socks_password

    elif node.protocol == "ssr":
        return None

    return base


def _fill_transport(base: dict, node: Node):
    if node.net and node.net != "tcp":
        transport = {"type": node.net}
        if node.net == "ws":
            transport["path"] = node.path
            if node.host:
                transport["headers"] = {"Host": node.host}
        elif node.net == "grpc":
            transport["service_name"] = node.path
        elif node.net == "h2":
            transport["path"] = node.path
            if node.host:
                transport["host"] = [node.host]
        base["transport"] = transport


def _fill_tls(base: dict, node: Node):
    if node.tls:
        tls = {"enabled": True}
        if node.sni:
            tls["server_name"] = node.sni
        if node.fp:
            tls["utls"] = {"enabled": True, "fingerprint": node.fp}
        if node.alpn:
            tls["alpn"] = node.alpn.split(",") if "," in node.alpn else [node.alpn]
        if node.reality_pbk:
            tls["utls"] = tls.get("utls", {"enabled": True})
            tls["utls"]["enabled"] = True
            tls["reality"] = {"enabled": True, "public_key": node.reality_pbk}
            if node.reality_sid:
                tls["reality"]["short_id"] = node.reality_sid
        base["tls"] = tls


def to_singbox(nodes: list[Node], tag_prefix: str = "") -> str:
    outbounds = []
    for i, node in enumerate(nodes):
        tag = node.display_name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        entry = _node_to_singbox(node, tag=tag)
        if entry is not None:
            outbounds.append(entry)
    if not outbounds:
        raise ParseError("No convertible nodes")
    result = _json_dumps({"outbounds": outbounds})
    # Validate
    _json_loads(result)
    return result


# ---------------------------------------------------------------------------
# mihomo (Clash Meta) YAML
# ---------------------------------------------------------------------------

def to_mihomo(nodes: list[Node], tag_prefix: str = "") -> str:
    lines = ["proxies:"]
    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        name = node.name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        lines.append(f"- name: {_yaml_escape(name)}")
        lines.append(f"  type: {node.protocol}")
        lines.append(f"  server: {node.address}")
        lines.append(f"  port: {node.port}")

        if node.protocol == "vless":
            lines.append(f"  uuid: {node.uuid}")
            if node.flow:
                lines.append(f"  flow: {node.flow}")
            _mihomo_transport(lines, node)
            if node.tls:
                lines.append(f"  tls: true")
                if node.sni:
                    lines.append(f"  servername: {node.sni}")
                if node.fp:
                    lines.append(f"  client-fingerprint: {node.fp}")
                if node.reality_pbk:
                    lines.append(f"  reality-opts:")
                    lines.append(f"    public-key: {_yaml_escape(node.reality_pbk)}")
                    if node.reality_sid:
                        lines.append(f"    short-id: {_yaml_escape(node.reality_sid)}")

        elif node.protocol == "vmess":
            lines.append(f"  uuid: {node.uuid}")
            lines.append(f"  alterId: {node.vmess_aid}")
            lines.append(f"  cipher: {node.vmess_scy}")
            _mihomo_transport(lines, node)
            if node.tls:
                lines.append(f"  tls: true")
                if node.sni:
                    lines.append(f"  servername: {node.sni}")

        elif node.protocol == "trojan":
            lines.append(f"  password: {_yaml_escape(node.trojan_password)}")
            if node.sni:
                lines.append(f"  sni: {node.sni}")
            if node.net and node.net != "tcp":
                lines.append(f"  network: {node.net}")
            if node.fp:
                lines.append(f"  client-fingerprint: {node.fp}")

        elif node.protocol == "ss":
            lines.append(f"  cipher: {node.ss_method}")
            lines.append(f"  password: {_yaml_escape(node.ss_password)}")

        elif node.protocol == "hysteria2":
            lines.append(f"  password: {_yaml_escape(node.hysteria2_password)}")
            if node.sni:
                lines.append(f"  sni: {node.sni}")
            if node.alpn:
                lines.append(f"  alpn:")
                for a in node.alpn.split(","):
                    lines.append(f"    - {_yaml_escape(a.strip())}")
            if node.obfs:
                lines.append(f"  obfs: {node.obfs}")

        elif node.protocol == "socks":
            if node.socks_username:
                lines.append(f"  username: {_yaml_escape(node.socks_username)}")
            if node.socks_password:
                lines.append(f"  password: {_yaml_escape(node.socks_password)}")

        lines.append("")
    return "\n".join(lines)


def _mihomo_transport(lines: list, node: Node):
    if node.net and node.net != "tcp":
        lines.append(f"  network: {node.net}")
        if node.net == "ws":
            if node.path:
                lines.append(f"  ws-opts:\n    path: {_yaml_escape(node.path)}")
            if node.host:
                lines.append(f"    headers:\n      Host: {_yaml_escape(node.host)}")
        elif node.net == "grpc":
            lines.append(f"  grpc-opts:\n    grpc-service-name: {_yaml_escape(node.path)}")


# ---------------------------------------------------------------------------
# FlClash YAML — full mihomo config with proxy-groups and rules
# ---------------------------------------------------------------------------

def to_flclash(nodes: list[Node], tag_prefix: str = "", group_by_country: bool = False) -> str:
    """Generate a complete FlClash/mihomo config file."""
    lines = [
        "mixed-port: 7890",
        "socks-port: 7891",
        "redir-port: 7892",
        "allow-lan: true",
        "mode: global",
        "log-level: info",
        "external-controller: 127.0.0.1:9090",
        "dns:",
        "  enable: true",
        "  use-hosts: true",
        "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16",
        "  default-nameserver:",
        "    - https://8.8.8.8/dns-query",
        "    - https://1.1.1.1/dns-query",
        "  nameserver:",
        "    - https://8.8.8.8/dns-query",
        "    - https://1.1.1.1/dns-query",
        "  fake-ip-filter:",
        '    - "*.lan"',
        "proxies:",
    ]

    names = []
    country_groups: dict[str, list[str]] = defaultdict(list)

    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        name = node.name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        names.append(name)
        country_groups[extract_country(name)].append(name)

        lines.append(f"  - name: {_yaml_escape(name)}")
        lines.append(f"    type: {node.protocol}")
        lines.append(f"    server: {node.address}")
        lines.append(f"    port: {node.port}")
        lines.append(f"    network: {node.net}")
        lines.append(f"    udp: true")

        if node.protocol == "vless":
            lines.append(f"    packet-encoding: xudp")
            lines.append(f"    uuid: {node.uuid}")
            if node.flow:
                lines.append(f"    flow: {node.flow}")
            _flclash_transport(lines, node)
            _flclash_tls(lines, node)

        elif node.protocol == "vmess":
            lines.append(f"    uuid: {node.uuid}")
            lines.append(f"    alterId: {node.vmess_aid}")
            lines.append(f"    cipher: {node.vmess_scy}")
            _flclash_transport(lines, node)
            if node.tls:
                lines.append(f"    tls: true")
                if node.sni:
                    lines.append(f"    servername: {node.sni}")

        elif node.protocol == "trojan":
            lines.append(f"    password: {_yaml_escape(node.trojan_password)}")
            if node.sni:
                lines.append(f"    servername: {node.sni}")
            if node.alpn:
                lines.append(f"    alpn:")
                for a in node.alpn.split(","):
                    lines.append(f"      - {_yaml_escape(a.strip())}")
            if node.net and node.net != "tcp":
                lines.append(f"    network: {node.net}")
            if node.fp:
                lines.append(f"    client-fingerprint: {node.fp}")

        elif node.protocol == "ss":
            lines.append(f"    cipher: {node.ss_method}")
            lines.append(f"    password: {_yaml_escape(node.ss_password)}")

        elif node.protocol == "hysteria2":
            lines.append(f"    password: {_yaml_escape(node.hysteria2_password)}")
            if node.sni:
                lines.append(f"    servername: {node.sni}")
            if node.obfs:
                lines.append(f"    obfs: {node.obfs}")

        elif node.protocol == "socks":
            if node.socks_username:
                lines.append(f"    username: {_yaml_escape(node.socks_username)}")
            if node.socks_password:
                lines.append(f"    password: {_yaml_escape(node.socks_password)}")

    # Proxy groups
    lines.append("proxy-groups:")
    lines.append("  - name: Quattro VPN")
    lines.append("    type: select")
    lines.append("    proxies:")

    if group_by_country and len(country_groups) > 1:
        # Add "All" group first, then per-country groups
        for name in names:
            lines.append(f"      - {_yaml_escape(name)}")
        for country, cnames in sorted(country_groups.items()):
            lines.append(f"      - {_yaml_escape(country)}")
        # Add country-specific select groups
        for country, cnames in sorted(country_groups.items()):
            lines.append(f"  - name: {_yaml_escape(country)}")
            lines.append("    type: select")
            lines.append("    proxies:")
            for cn in cnames:
                lines.append(f"      - {_yaml_escape(cn)}")
    else:
        for name in names:
            lines.append(f"      - {_yaml_escape(name)}")

    lines.append("  - name: Auto")
    lines.append("    type: url-test")
    lines.append("    url: http://www.gstatic.com/generate_204")
    lines.append("    interval: 300")
    lines.append("    tolerance: 50")
    lines.append("    proxies:")
    for name in names:
        lines.append(f"      - {_yaml_escape(name)}")

    lines.append("rules:")
    lines.append("  - MATCH, Quattro VPN")

    return "\n".join(lines)


def _flclash_transport(lines: list, node: Node):
    if node.net == "ws":
        if node.path:
            lines.append(f"    ws-opts:\n      path: {_yaml_escape(node.path)}")
        if node.host:
            lines.append(f"      headers:\n        Host: {_yaml_escape(node.host)}")
    elif node.net == "grpc":
        lines.append(f"    grpc-opts:\n      grpc-service-name: {_yaml_escape(node.path)}")


def _flclash_tls(lines: list, node: Node):
    if node.tls:
        lines.append(f"    tls: true")
        if node.sni:
            lines.append(f"    servername: {node.sni}")
        if node.fp:
            lines.append(f"    client-fingerprint: {node.fp}")
        if node.alpn:
            lines.append(f"    alpn:")
            for a in node.alpn.split(","):
                lines.append(f"      - {_yaml_escape(a.strip())}")
        if node.reality_pbk:
            lines.append(f"    reality-opts:")
            lines.append(f"      public-key: {_yaml_escape(node.reality_pbk)}")
            if node.reality_sid:
                lines.append(f"      short-id: {_yaml_escape(node.reality_sid)}")


# ---------------------------------------------------------------------------
# plain txt
# ---------------------------------------------------------------------------

def to_txt(nodes: list[Node]) -> str:
    lines = []
    for node in nodes:
        if node.protocol == "vless":
            lines.append(node.to_vless_link())
        elif node.protocol == "vmess":
            payload = _json_dumps({
                "v": "2", "ps": node.name, "add": node.address,
                "port": str(node.port), "id": node.uuid,
                "aid": str(node.vmess_aid), "scy": node.vmess_scy,
                "net": node.net, "type": "", "host": node.host,
                "path": node.path,
                "tls": "tls" if node.tls else "",
                "sni": node.sni, "alpn": node.alpn,
            })
            lines.append("vmess://" + base64.urlsafe_b64encode(payload.encode()).decode().rstrip("="))
        elif node.protocol == "trojan":
            lines.append(node.to_trojan_link())
        elif node.protocol == "ss":
            lines.append(node.to_ss_link())
        elif node.protocol == "ssr":
            main = f"{node.address}:{node.port}:{node.ssr_protocol}:{node.ss_method}:{node.ssr_obfs}:{base64.urlsafe_b64encode(node.ss_password.encode()).rstrip(b'=').decode()}"
            params = ""
            if node.ssr_protocol_param:
                params += f"&protoparam={node.ssr_protocol_param}"
            if node.ssr_obfs_param:
                params += f"&obfsparam={node.ssr_obfs_param}"
            if node.name:
                params += f"&remarks={node.name}"
            if params:
                main += "/?" + params.lstrip("&")
            lines.append("ssr://" + base64.urlsafe_b64encode(main.encode()).rstrip(b'=').decode())
        elif node.protocol == "hysteria2":
            lines.append(node.to_hysteria2_link())
        elif node.protocol == "socks":
            auth = ""
            if node.socks_username:
                auth = f"{quote(node.socks_username, safe='')}"
                if node.socks_password:
                    auth += f":{quote(node.socks_password, safe='')}"
                auth += "@"
            name = "#" + quote(node.name, safe="") if node.name else ""
            lines.append(f"socks://{auth}{node.address}:{node.port}{name}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_CONVERTERS = {
    Format.SINGBOX: to_singbox,
    Format.MIHOMO: to_mihomo,
    Format.FLCLASH: to_flclash,
    Format.TXT: to_txt,
}


def convert(nodes: list[Node], fmt: Format, tag_prefix: str = "", group_by_country: bool = False) -> str:
    converter = _CONVERTERS.get(fmt)
    if converter is None:
        raise ParseError(f"Unsupported format: {fmt}")
    if fmt == Format.FLCLASH:
        return converter(nodes, tag_prefix=tag_prefix, group_by_country=group_by_country)
    if fmt == Format.TXT:
        return converter(nodes)
    return converter(nodes, tag_prefix=tag_prefix)

"""Converters: sing-box JSON, mihomo YAML, FlClash YAML, plain txt."""

import json
import base64
from enum import Enum
from typing import Optional
from urllib.parse import urlencode, quote

from .logic import Node, ParseError


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

    elif node.protocol == "vmess":
        base["server"] = node.address
        base["server_port"] = node.port
        base["uuid"] = node.uuid
        base["alter_id"] = node.vmess_aid
        base["security"] = node.vmess_scy
        if node.net and node.net != "tcp":
            transport = {"type": node.net}
            if node.net == "ws":
                transport["path"] = node.path
                if node.host:
                    transport["headers"] = {"Host": node.host}
            elif node.net == "grpc":
                transport["service_name"] = node.path
            base["transport"] = transport
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
        if node.net and node.net != "tcp":
            transport = {"type": node.net}
            if node.net == "ws":
                transport["path"] = node.path
                if node.host:
                    transport["headers"] = {"Host": node.host}
            elif node.net == "grpc":
                transport["service_name"] = node.path
            base["transport"] = transport
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

    elif node.protocol == "ssr":
        return None

    return base


def to_singbox(nodes: list[Node], tag_prefix: str = "") -> str:
    outbounds = []
    for i, node in enumerate(nodes):
        tag = node.display_name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        entry = _node_to_singbox(node, tag=tag)
        if entry is not None:
            outbounds.append(entry)
    if not outbounds:
        raise ParseError("No convertible nodes")
    return json.dumps({"outbounds": outbounds}, indent=2, ensure_ascii=False)


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
            if node.net and node.net != "tcp":
                lines.append(f"  network: {node.net}")
                if node.net == "ws":
                    if node.path:
                        lines.append(f"  ws-opts:\n    path: {_yaml_escape(node.path)}")
                    if node.host:
                        lines.append(f"    headers:\n      Host: {_yaml_escape(node.host)}")
                elif node.net == "grpc":
                    lines.append(f"  grpc-opts:\n    grpc-service-name: {_yaml_escape(node.path)}")
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
            if node.net and node.net != "tcp":
                lines.append(f"  network: {node.net}")
                if node.net == "ws":
                    if node.path:
                        lines.append(f"  ws-opts:\n    path: {_yaml_escape(node.path)}")
                    if node.host:
                        lines.append(f"    headers:\n      Host: {_yaml_escape(node.host)}")
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

        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# FlClash YAML — full mihomo config with proxy-groups and rules
# ---------------------------------------------------------------------------

def to_flclash(nodes: list[Node], tag_prefix: str = "") -> str:
    """Generate a complete FlClash/mihomo config file.

    Includes: base settings, proxies, proxy-groups, rule-providers, rules.
    """
    names = []
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

    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        name = node.name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        names.append(name)
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
            if node.net == "ws":
                if node.path:
                    lines.append(f"    ws-opts:\n      path: {_yaml_escape(node.path)}")
                if node.host:
                    lines.append(f"      headers:\n        Host: {_yaml_escape(node.host)}")
            elif node.net == "grpc":
                lines.append(f"    grpc-opts:\n      grpc-service-name: {_yaml_escape(node.path)}")
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

        elif node.protocol == "vmess":
            lines.append(f"    uuid: {node.uuid}")
            lines.append(f"    alterId: {node.vmess_aid}")
            lines.append(f"    cipher: {node.vmess_scy}")
            if node.net == "ws":
                if node.path:
                    lines.append(f"    ws-opts:\n      path: {_yaml_escape(node.path)}")
                if node.host:
                    lines.append(f"      headers:\n        Host: {_yaml_escape(node.host)}")
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

    # Proxy groups
    lines.append("proxy-groups:")
    lines.append("  - name: Quattro VPN")
    lines.append("    type: select")
    lines.append("    proxies:")
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

    # Rules
    lines.append("rules:")
    lines.append("  - MATCH, Quattro VPN")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# plain txt
# ---------------------------------------------------------------------------

def to_txt(nodes: list[Node]) -> str:
    lines = []
    for node in nodes:
        if node.protocol == "vless":
            lines.append(node.to_vless_link())
        elif node.protocol == "vmess":
            payload = json.dumps({
                "v": "2", "ps": node.name, "add": node.address,
                "port": str(node.port), "id": node.uuid,
                "aid": str(node.vmess_aid), "scy": node.vmess_scy,
                "net": node.net, "type": "", "host": node.host,
                "path": node.path,
                "tls": "tls" if node.tls else "",
                "sni": node.sni, "alpn": node.alpn,
            }, ensure_ascii=False)
            lines.append("vmess://" + base64.urlsafe_b64encode(payload.encode()).decode().rstrip("="))
        elif node.protocol == "trojan":
            params = {}
            if node.sni:
                params["sni"] = node.sni
            if node.alpn:
                params["alpn"] = node.alpn
            base = f"trojan://{node.trojan_password}@{node.address}:{node.port}"
            if params:
                base += "?" + urlencode(params)
            if node.name:
                base += "#" + quote(node.name, safe="")
            lines.append(base)
        elif node.protocol == "ss":
            userinfo = base64.urlsafe_b64encode(
                f"{node.ss_method}:{node.ss_password}".encode()
            ).decode().rstrip("=")
            name = "#" + quote(node.name, safe="") if node.name else ""
            lines.append(f"ss://{userinfo}@{node.address}:{node.port}{name}")
        elif node.protocol == "ssr":
            main = f"{node.address}:{node.port}:{node.ssr_protocol}:{node.ss_method}:{node.ssr_obfs}:{base64.urlsafe_b64encode(node.ss_password.encode()).decode().rstrip('=')}"
            params = ""
            if node.ssr_protocol_param:
                params += f"&protoparam={node.ssr_protocol_param}"
            if node.ssr_obfs_param:
                params += f"&obfsparam={node.ssr_obfs_param}"
            if node.name:
                params += f"&remarks={node.name}"
            if params:
                main += "/?" + params.lstrip("&")
            lines.append("ssr://" + base64.urlsafe_b64encode(main.encode()).decode().rstrip("="))
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


def convert(nodes: list[Node], fmt: Format, tag_prefix: str = "") -> str:
    converter = _CONVERTERS.get(fmt)
    if converter is None:
        raise ParseError(f"Unsupported format: {fmt}")
    if fmt == Format.TXT:
        return converter(nodes)
    return converter(nodes, tag_prefix=tag_prefix)

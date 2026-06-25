"""Converters: sing-box JSON, mihomo YAML, FlClash YAML, plain txt.

Architecture (inspired by sunway910/clashconverter):
- ProtocolAdapter pattern: each protocol has an adapter class with
  to_clash_dict() / to_mihomo_dict() / to_singbox_dict() / to_link()
- Universal _node_to_dict() → format-specific adapters add extra fields
- Pydantic-style validation via dataclass models (lightweight, no dependency)
- YAML serialization via PyYAML (no manual indentation)
"""

import base64
from abc import ABC, abstractmethod
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

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


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
    XRAY = "xray"


def _yaml_escape(s: str) -> str:
    if not s:
        return '""'
    _YAML_SPECIAL = ':{}[]&*?|-><!%@`#,\'"\\\n'
    if any(c in s for c in _YAML_SPECIAL):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


# ---------------------------------------------------------------------------
# Protocol Adapters (TS project pattern)
# ---------------------------------------------------------------------------

class ProtocolAdapter(ABC):
    """Base adapter — each protocol implements format-specific generation."""

    protocol: str = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not cls.protocol:
            name = cls.__name__.lower()
            if name.endswith("adapter"):
                name = name[:-len("adapter")]
            cls.protocol = name

    def to_clash_dict(self, node: Node) -> dict:
        """Convert node to Clash/mihomo dict format."""
        return _base_clash_dict(node)

    def to_mihomo_dict(self, node: Node) -> dict:
        """Convert node to mihomo-specific dict format."""
        return self.to_clash_dict(node)

    def to_singbox_dict(self, node: Node) -> dict:
        """Convert node to sing-box dict format."""
        return _base_singbox_dict(node)

    def to_link(self, node: Node) -> str:
        """Convert node back to share link."""
        return ""


class VLESSAdapter(ProtocolAdapter):
    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        obj["uuid"] = node.uuid
        obj["network"] = node.net
        obj["packet-encoding"] = "xudp"
        if node.flow:
            obj["flow"] = node.flow
        _fill_clash_transport(obj, node)
        _fill_clash_tls(obj, node)
        return obj

    def to_mihomo_dict(self, node: Node) -> dict:
        obj = self.to_clash_dict(node)
        # mihomo-specific: no packet-encoding field
        obj.pop("packet-encoding", None)
        return obj

    def to_singbox_dict(self, node: Node) -> dict:
        obj = _base_singbox_dict(node)
        obj["uuid"] = node.uuid
        if node.flow:
            obj["flow"] = node.flow
        _fill_singbox_transport(obj, node)
        _fill_singbox_tls(obj, node)
        return obj

    def to_link(self, node: Node) -> str:
        return node.to_vless_link()


class VMessAdapter(ProtocolAdapter):
    @property
    def protocol(self) -> str:
        return "vmess"

    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        obj["uuid"] = node.uuid
        obj["alterId"] = node.vmess_aid
        obj["cipher"] = node.vmess_scy
        obj["network"] = node.net
        _fill_clash_transport(obj, node)
        if node.tls:
            obj["tls"] = True
            if node.sni:
                obj["servername"] = node.sni
        return obj

    def to_singbox_dict(self, node: Node) -> dict:
        obj = _base_singbox_dict(node)
        obj["uuid"] = node.uuid
        obj["security"] = node.vmess_scy
        obj["alter_id"] = node.vmess_aid
        _fill_singbox_transport(obj, node)
        if node.tls or node.sni:
            obj["tls"] = {"enabled": True}
            if node.sni:
                obj["tls"]["server_name"] = node.sni
        return obj

    def to_link(self, node: Node) -> str:
        # VMess uses base64-encoded JSON
        ps = node.name
        addr = node.address
        port = node.port
        uuid = node.uuid
        aid = node.vmess_aid
        scy = node.vmess_scy
        net = node.net
        tls = "tls" if node.tls else ""
        json_str = f'{{"v":"2","ps":"{ps}","add":"{addr}","port":{port},"id":"{uuid}","aid":{aid},"scy":"{scy}","net":"{net}","tls":"{tls}"}}'
        encoded = base64.b64encode(json_str.encode()).decode()
        return f"vmess://{encoded}"


class TrojanAdapter(ProtocolAdapter):
    @property
    def protocol(self) -> str:
        return "trojan"

    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        obj["password"] = node.trojan_password
        if node.sni:
            obj["sni"] = node.sni
        if node.alpn:
            obj["alpn"] = [a.strip() for a in node.alpn.split(",")]
        if node.net and node.net != "tcp":
            obj["network"] = node.net
        if node.fp:
            obj["client-fingerprint"] = node.fp
        # Trojan WS support (like TS project)
        _fill_clash_transport(obj, node)
        return obj

    def to_singbox_dict(self, node: Node) -> dict:
        obj = _base_singbox_dict(node)
        obj["password"] = node.trojan_password
        if node.sni or node.net == "ws":
            obj["tls"] = {"enabled": True}
            if node.sni:
                obj["tls"]["server_name"] = node.sni
        _fill_singbox_transport(obj, node)
        return obj

    def to_link(self, node: Node) -> str:
        return node.to_trojan_link()


class SSAdapter(ProtocolAdapter):
    @property
    def protocol(self) -> str:
        return "ss"

    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        obj["cipher"] = node.ss_method
        obj["password"] = node.ss_password
        return obj

    def to_singbox_dict(self, node: Node) -> dict:
        return {
            "type": "shadowsocks",
            "tag": node.display_name,
            "server": node.address,
            "server_port": node.port,
            "method": node.ss_method,
            "password": node.ss_password,
        }

    def to_link(self, node: Node) -> str:
        return node.to_ss_link()


class Hysteria2Adapter(ProtocolAdapter):
    @property
    def protocol(self) -> str:
        return "hysteria2"

    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        obj["password"] = node.hysteria2_password
        if node.sni:
            obj["servername"] = node.sni
        if node.obfs:
            obj["obfs"] = node.obfs
        return obj

    def to_singbox_dict(self, node: Node) -> dict:
        obj = _base_singbox_dict(node)
        obj["password"] = node.hysteria2_password
        obj["tls"] = {"enabled": True}
        if node.sni:
            obj["tls"]["server_name"] = node.sni
        return obj

    def to_link(self, node: Node) -> str:
        return node.to_hysteria2_link()


class SOCKSAdapter(ProtocolAdapter):
    @property
    def protocol(self) -> str:
        return "socks"

    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        if node.socks_username:
            obj["username"] = node.socks_username
        if node.socks_password:
            obj["password"] = node.socks_password
        return obj

    def to_singbox_dict(self, node: Node) -> dict:
        return {
            "type": "socks",
            "tag": node.display_name,
            "server": node.address,
            "server_port": node.port,
            **({"username": node.socks_username} if node.socks_username else {}),
            **({"password": node.socks_password} if node.socks_password else {}),
        }


class SSRAdapter(ProtocolAdapter):
    @property
    def protocol(self) -> str:
        return "ssr"

    def to_clash_dict(self, node: Node) -> dict:
        obj = _base_clash_dict(node)
        obj["cipher"] = node.ss_method
        obj["password"] = node.ss_password
        obj["protocol"] = node.ssr_protocol
        obj["obfs"] = node.ssr_obfs
        if node.ssr_protocol_param:
            obj["protocolparam"] = node.ssr_protocol_param
        if node.ssr_obfs_param:
            obj["obfsparam"] = node.ssr_obfs_param
        return obj


# ---------------------------------------------------------------------------
# Adapter Registry
# ---------------------------------------------------------------------------

_ADAPTERS: dict[str, ProtocolAdapter] = {}


def _register_adapters():
    """Register all protocol adapters."""
    if _ADAPTERS:
        return
    for adapter_cls in [
        VLESSAdapter, VMessAdapter, TrojanAdapter,
        SSAdapter, Hysteria2Adapter, SOCKSAdapter, SSRAdapter,
    ]:
        a = adapter_cls()
        _ADAPTERS[a.protocol] = a


def get_adapter(protocol: str) -> Optional[ProtocolAdapter]:
    """Get adapter for a protocol type."""
    _register_adapters()
    return _ADAPTERS.get(protocol)


# ---------------------------------------------------------------------------
# Shared helpers for building dicts
# ---------------------------------------------------------------------------

def _base_clash_dict(node: Node) -> dict:
    """Base dict with common Clash fields."""
    return {
        "name": node.name if node.name else f"{node.protocol}-{node.port}",
        "type": node.protocol,
        "server": node.address,
        "port": node.port,
        "udp": True,
    }


def _base_singbox_dict(node: Node) -> dict:
    """Base dict with common sing-box fields."""
    return {
        "type": node.protocol,
        "tag": node.display_name,
        "server": node.address,
        "server_port": node.port,
    }


def _fill_clash_transport(obj: dict, node: Node):
    """Add transport options to a Clash proxy dict."""
    if node.net == "ws":
        ws_opts: dict = {}
        if node.path:
            ws_opts["path"] = node.path
        if node.host:
            ws_opts["headers"] = {"Host": node.host}
        if ws_opts:
            obj["ws-opts"] = ws_opts
    elif node.net == "grpc":
        grpc_opts: dict = {}
        if node.path:
            grpc_opts["grpc-service-name"] = node.path
        if grpc_opts:
            obj["grpc-opts"] = grpc_opts


def _fill_clash_tls(obj: dict, node: Node):
    """Add TLS/reality options to a Clash proxy dict."""
    if node.tls:
        obj["tls"] = True
        if node.sni:
            obj["servername"] = node.sni
        if node.fp:
            obj["client-fingerprint"] = node.fp
        if node.reality_pbk:
            obj["reality-opts"] = {"public-key": node.reality_pbk}
            if node.reality_sid:
                obj["reality-opts"]["short-id"] = node.reality_sid


def _fill_singbox_transport(obj: dict, node: Node):
    """Add transport options to a sing-box proxy dict."""
    if node.net == "ws":
        transport: dict = {"type": "ws"}
        if node.path:
            transport["path"] = node.path
        if node.host:
            transport["headers"] = {"Host": [node.host]}
        obj["transport"] = transport
    elif node.net == "grpc":
        transport = {"type": "grpc"}
        if node.path:
            transport["service_name"] = node.path
        obj["transport"] = transport


def _fill_singbox_tls(obj: dict, node: Node):
    """Add TLS/reality options to a sing-box proxy dict."""
    if node.tls or node.sni:
        tls = {"enabled": True}
        if node.sni:
            tls["server_name"] = node.sni
        if node.fp:
            tls["utls"] = {"enabled": True, "fingerprint": node.fp}
        if node.reality_pbk:
            tls["reality"] = {
                "enabled": True,
                "public_key": node.reality_pbk,
                "short_id": node.reality_sid or "",
            }
        obj["tls"] = tls


# ---------------------------------------------------------------------------
# Universal _node_to_dict
# ---------------------------------------------------------------------------

def _node_to_dict(node: Node, fmt: str) -> dict:
    """Universal node-to-dispenser: calls the right adapter for the format.

    Args:
        node: Parsed Node
        fmt: One of 'clash', 'mihomo', 'singbox'

    Returns:
        Dict ready for YAML/JSON serialization
    """
    adapter = get_adapter(node.protocol)
    if adapter is None:
        return {}

    if fmt == "clash":
        return adapter.to_clash_dict(node)
    elif fmt == "mihomo":
        return adapter.to_mihomo_dict(node)
    elif fmt == "singbox":
        return adapter.to_singbox_dict(node)
    return {}


# ---------------------------------------------------------------------------
# sing-box
# ---------------------------------------------------------------------------

def to_singbox(nodes: list[Node], tag_prefix: str = "") -> str:
    outbounds = []
    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        tag = node.display_name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        entry = _node_to_dict(node, "singbox")
        if entry:
            entry["tag"] = tag  # Override tag with proper name
            outbounds.append(entry)
    if not outbounds:
        raise ParseError("No convertible nodes")
    result = _json_dumps({"outbounds": outbounds})
    _json_loads(result)  # Validate
    return result


# ---------------------------------------------------------------------------
# mihomo (Clash Meta) YAML
# ---------------------------------------------------------------------------

def to_mihomo(nodes: list[Node], tag_prefix: str = "") -> str:
    if not _HAS_YAML:
        raise ImportError("PyYAML is required for mihomo format")

    proxy_dicts = []
    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        obj = _node_to_dict(node, "mihomo")
        if obj:
            proxy_dicts.append(obj)

    if not proxy_dicts:
        raise ParseError("No convertible nodes")

    config = {"proxies": proxy_dicts}
    return _yaml.dump(config, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# FlClash YAML — full mihomo config with proxy-groups and rules
# ---------------------------------------------------------------------------

def to_flclash(nodes: list[Node], tag_prefix: str = "", group_by_country: bool = False) -> str:
    """Generate a complete FlClash/mihomo config file.

    Uses dict-based approach (like sunway910/clashconverter) to avoid
    YAML indentation/escaping issues with special characters.
    """
    if not _HAS_YAML:
        raise ImportError("PyYAML is required for flclash format")

    # DNS configuration
    dns_config = {
        "enable": True,
        "use-hosts": True,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "default-nameserver": [
            "https://8.8.8.8/dns-query",
            "https://1.1.1.1/dns-query",
        ],
        "nameserver": [
            "https://8.8.8.8/dns-query",
            "https://1.1.1.1/dns-query",
        ],
        "fake-ip-filter": ["*.lan"],
    }

    # Build proxy dicts
    proxy_dicts = []
    names = []
    country_groups: dict[str, list[str]] = defaultdict(list)

    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        obj = _node_to_dict(node, "clash")
        if not obj:
            continue
        name = obj["name"]
        names.append(name)
        country_groups[extract_country(name)].append(name)
        proxy_dicts.append(obj)

    if not proxy_dicts:
        raise ParseError("No convertible nodes")

    # Build proxy groups
    proxy_groups = []

    # Main select group
    main_group = {
        "name": "Quattro VPN",
        "type": "select",
        "proxies": [],
    }

    if group_by_country and len(country_groups) > 1:
        main_group["proxies"] = [_yaml_escape(n) for n in names]
        for country in sorted(country_groups.keys()):
            main_group["proxies"].append(_yaml_escape(country))
        proxy_groups.append(main_group)

        for country, cnames in sorted(country_groups.items()):
            proxy_groups.append({
                "name": country,
                "type": "select",
                "proxies": [_yaml_escape(cn) for cn in cnames],
            })
    else:
        main_group["proxies"] = [_yaml_escape(n) for n in names]
        proxy_groups.append(main_group)

    # Auto url-test group
    proxy_groups.append({
        "name": "Auto",
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "proxies": [_yaml_escape(n) for n in names],
    })

    # Assemble full config
    config = {
        "mixed-port": 7890,
        "socks-port": 7891,
        "redir-port": 7892,
        "allow-lan": True,
        "mode": "global",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": dns_config,
        "proxies": proxy_dicts,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH, Quattro VPN"],
    }

    return _yaml.dump(config, default_flow_style=False, allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# Xray JSON — full client config with routing, dns, inbounds, observatory
# ---------------------------------------------------------------------------

def to_xray(nodes: list[Node], tag_prefix: str = "") -> str:
    """Generate a complete Xray JSON client config (array of configs, one per group).

    Each proxy gets a 'proxy' tag, with direct/block fallbacks.
    Includes: inbounds (socks+http), dns, routing, observatory, burstObservatory.
    """
    outbounds = []
    for i, node in enumerate(nodes):
        if node.protocol == "ssr":
            continue
        tag = node.name if node.name else f"{tag_prefix}{node.protocol}-{i}"
        o = _node_to_xray_outbound(node, tag)
        if o:
            outbounds.append(o)

    if not outbounds:
        raise ParseError("No convertible nodes")

    # Add direct and block
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    # Extract country from first node name for remarks
    remarks = ""
    for n in nodes:
        if n.name:
            country = extract_country(n.name)
            if country:
                remarks = country
                break

    config = {
        "dns": {
            "servers": ["1.1.1.1", "1.0.0.1"],
            "queryStrategy": "UseIPv4",
        },
        "routing": {
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "Super_Balancer",
                },
            ],
            "balancers": [
                {
                    "tag": "Super_Balancer",
                    "selector": ["proxy"],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "maxRTT": "1s",
                            "expected": 2,
                            "baselines": ["1s"],
                            "tolerance": 0.01,
                        },
                    },
                    "fallbackTag": "direct",
                }
            ],
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {"allowTransparent": False},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": False,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
        ],
        "outbounds": outbounds,
        "observatory": {
            "subjectSelector": ["proxy"],
            "probeUrl": "https://www.google.com/generate_204?gl=us",
            "probeInterval": "10s",
        },
        "burstObservatory": {
            "subjectSelector": ["proxy"],
            "probeUrl": "https://www.google.com/generate_204?gl=us",
            "probeInterval": "10s",
        },
    }

    if remarks:
        config["remarks"] = remarks

    return _json_dumps(config)


def _node_to_xray_outbound(node: Node, tag: str) -> Optional[dict]:
    """Convert a single Node to an Xray outbound config."""
    if node.protocol == "vless":
        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": node.uuid,
                            "encryption": "none",
                            "flow": node.flow or "",
                        }
                    ],
                }
            ]
        }
    elif node.protocol == "vmess":
        settings = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": node.uuid,
                            "alterId": node.vmess_aid,
                            "security": node.vmess_scy,
                        }
                    ],
                }
            ]
        }
    elif node.protocol == "trojan":
        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "password": node.trojan_password,
                }
            ]
        }
    elif node.protocol == "ss":
        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "method": node.ss_method,
                            "password": node.ss_password,
                        }
                    ],
                }
            ]
        }
    elif node.protocol == "hysteria2":
        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                }
            ]
        }
    elif node.protocol == "socks":
        settings = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    **({"users": [{"user": node.socks_username, "pass": node.socks_password}]}
                        if node.socks_username else {}),
                }
            ]
        }
    else:
        return None

    stream = _build_xray_stream(node)
    return {
        "tag": tag,
        "protocol": node.protocol,
        "settings": settings,
        "streamSettings": stream,
    }


def _build_xray_stream(node: Node) -> dict:
    """Build Xray streamSettings for a node."""
    stream: dict = {"network": node.net if node.net != "tcp" else "tcp"}

    if node.tls:
        stream["security"] = "tls"
        tls_settings: dict = {}
        if node.sni:
            tls_settings["serverName"] = node.sni
        if node.fp:
            tls_settings["fingerprint"] = node.fp
        if node.alpn:
            tls_settings["alpn"] = node.alpn.split(",")
        stream["tlsSettings"] = tls_settings

    if node.net == "ws":
        ws_settings: dict = {}
        if node.path:
            ws_settings["path"] = node.path
        if node.host:
            ws_settings["headers"] = {"Host": node.host}
        stream["wsSettings"] = ws_settings
    elif node.net == "grpc":
        stream["grpcSettings"] = {}
        if node.path:
            stream["grpcSettings"]["serviceName"] = node.path

    return stream


# ---------------------------------------------------------------------------
# TXT — share links
# ---------------------------------------------------------------------------

def to_txt(nodes: list[Node], tag_prefix: str = "") -> str:
    """Generate a list of share links (one per node)."""
    links = []
    for node in nodes:
        if node.protocol == "error":
            continue
        adapter = get_adapter(node.protocol)
        if adapter:
            link = adapter.to_link(node)
            if link:
                links.append(link)
    return "\n".join(links)


# ---------------------------------------------------------------------------
# Main convert() dispatcher
# ---------------------------------------------------------------------------

def convert(
    nodes: list[Node],
    fmt: Format,
    tag_prefix: str = "",
    group_by_country: bool = False,
) -> str:
    """Convert nodes to the specified format.

    Args:
        nodes: List of parsed Node objects
        fmt: Target format
        tag_prefix: Prefix for auto-generated names
        group_by_country: Whether to group proxies by country (flclash only)

    Returns:
        Formatted string ready for use
    """
    if fmt == Format.SINGBOX:
        return to_singbox(nodes, tag_prefix)
    elif fmt == Format.MIHOMO:
        return to_mihomo(nodes, tag_prefix)
    elif fmt == Format.FLCLASH:
        return to_flclash(nodes, tag_prefix, group_by_country)
    elif fmt == Format.TXT:
        return to_txt(nodes, tag_prefix)
    elif fmt == Format.XRAY:
        return to_xray(nodes, tag_prefix)
    else:
        raise ParseError(f"Unsupported format: {fmt}")

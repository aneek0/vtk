"""Core parsing: vless/vmess/ss/ssr/trojan/hysteria2/socks/happ links + subscriptions."""

import base64
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

import httpx


class ParseError(Exception):
    pass


@dataclass
class Node:
    protocol: str
    uuid: str = ""
    address: str = ""
    port: int = 0
    name: str = ""
    # transport
    net: str = "tcp"       # tcp, ws, grpc, h2, quic, xhttp
    path: str = ""
    host: str = ""
    # security
    tls: bool = False
    sni: str = ""
    alpn: str = ""
    fp: str = ""
    # reality
    reality_pbk: str = ""
    reality_sid: str = ""
    reality_spx: str = ""
    # vmess
    vmess_aid: int = 0
    vmess_scy: str = "auto"
    # ss
    ss_method: str = ""
    ss_password: str = ""
    # ssr
    ssr_protocol: str = ""
    ssr_obfs: str = ""
    ssr_protocol_param: str = ""
    ssr_obfs_param: str = ""
    # trojan
    trojan_password: str = ""
    # flow (XTLS)
    flow: str = ""
    # hysteria2
    hysteria2_password: str = ""
    hysteria2_obfs: str = ""
    obfs: str = ""  # generic obfs field
    # socks
    socks_username: str = ""
    socks_password: str = ""
    # extra
    extra: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return self.name or f"{self.protocol}://{self.address}:{self.port}"

    def to_vless_link(self) -> str:
        if self.protocol != "vless":
            raise ParseError(f"Cannot convert {self.protocol} to vless link")
        from urllib.parse import urlencode, quote
        params = {"encryption": "none", "type": self.net or "tcp"}
        if self.tls:
            params["security"] = "tls"
            if self.sni:
                params["sni"] = self.sni
            if self.fp:
                params["fp"] = self.fp
        if self.reality_pbk:
            params["security"] = "reality"
            params["pbk"] = self.reality_pbk
            if self.reality_sid:
                params["sid"] = self.reality_sid
        if self.path:
            params["path"] = self.path
        if self.host:
            params["host"] = self.host
        if self.flow:
            params["flow"] = self.flow
        if self.alpn:
            params["alpn"] = self.alpn
        base = f"vless://{self.uuid}@{self.address}:{self.port}"
        link = base + "?" + urlencode(params)
        if self.name:
            link += "#" + quote(self.name, safe="")
        return link

    def to_trojan_link(self) -> str:
        if self.protocol != "trojan":
            raise ParseError(f"Cannot convert {self.protocol} to trojan link")
        from urllib.parse import urlencode, quote
        params: dict = {}
        if self.sni:
            params["sni"] = self.sni
        if self.alpn:
            params["alpn"] = self.alpn
        if self.net and self.net != "tcp":
            params["type"] = self.net
        if self.fp:
            params["fp"] = self.fp
        base = f"trojan://{self.trojan_password}@{self.address}:{self.port}"
        link = base
        if params:
            link += "?" + urlencode(params)
        if self.name:
            link += "#" + quote(self.name, safe="")
        return link

    def to_ss_link(self) -> str:
        if self.protocol != "ss":
            raise ParseError(f"Cannot convert {self.protocol} to ss link")
        from urllib.parse import quote
        userinfo = _b64encode(f"{self.ss_method}:{self.ss_password}")
        link = f"ss://{userinfo}@{self.address}:{self.port}"
        if self.name:
            link += "#" + quote(self.name, safe="")
        return link

    def to_hysteria2_link(self) -> str:
        if self.protocol != "hysteria2":
            raise ParseError(f"Cannot convert {self.protocol} to hysteria2 link")
        from urllib.parse import urlencode, quote
        params: dict = {}
        if self.sni:
            params["sni"] = self.sni
        if self.obfs:
            params["obfs"] = self.obfs
        base = f"hysteria2://{self.hysteria2_password}@{self.address}:{self.port}"
        link = base
        if params:
            link += "?" + urlencode(params)
        if self.name:
            link += "#" + quote(self.name, safe="")
        return link


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(qs: dict, key: str, default: str = "") -> str:
    return qs.get(key, [default])[0]


def _b64decode(s: str) -> str:
    s = s.strip()
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")


def _b64encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def fix_link(link: str) -> str:
    """Normalize a proxy link to standard format.

    Fixes:
    - vless/trojan: adds ? before first & if no ? present
    - vless: adds type=tcp if missing (required by some clients like podkop)
    - vless: normalizes packet-encoding -> packetEncoding
    """
    link = link.strip()
    if not link:
        return link

    for prefix in ("vless://", "trojan://"):
        if link.startswith(prefix):
            rest = link[len(prefix):]
            # authority ends at first ?, &, or #
            end = len(rest)
            for c in ("?", "&", "#"):
                idx = rest.find(c)
                if idx != -1 and idx < end:
                    end = idx

            authority = rest[:end]
            remainder = rest[end:]

            # & -> ? at start of query
            if remainder.startswith("&"):
                remainder = "?" + remainder[1:]

            # vless: ensure type is present (check decoded full link)
            if prefix == "vless://" and "type=" not in unquote(link[len(prefix):]):
                hash_idx = remainder.find("#")
                if hash_idx != -1:
                    remainder = remainder[:hash_idx] + "&type=tcp" + remainder[hash_idx:]
                elif remainder.startswith("?"):
                    remainder = remainder + "&type=tcp"
                else:
                    remainder = remainder + "?type=tcp"

            # Normalize packet-encoding -> packetEncoding
            remainder = remainder.replace("packet-encoding=", "packetEncoding=")

            return prefix + authority + remainder

    return link


def extract_country(name: str) -> str:
    """Extract country from node name using emoji flags or text patterns.

    Returns country name or "Other" if not found.
    """
    if not name:
        return "Other"

    # Common country emoji patterns at start of name
    FLAG_MAP = {
        "🇷🇺": "RU", "🇺🇸": "US", "🇩🇪": "DE", "🇳🇱": "NL",
        "🇬🇧": "GB", "🇫🇷": "FR", "🇯🇵": "JP", "🇰🇷": "KR",
        "🇸🇪": "SE", "🇫🇮": "FI", "🇵🇱": "PL", "🇪🇪": "EE",
        "🇱🇻": "LV", "🇱🇹": "LT", "🇨🇭": "CH", "🇦🇿": "AZ",
        "🇹🇷": "TR", "🇮🇱": "IL", "🇰🇿": "KZ", "🇲🇩": "MD",
        "🇧🇬": "BG", "🇭🇺": "HU", "🇪🇸": "ES", "🇮🇪": "IE",
        "🇩🇰": "DK", "🇭🇰": "HK", "🇮🇳": "IN", "🇨🇳": "CN",
        "🇧🇷": "BR", "🇨🇦": "CA", "🇦🇺": "AU", "🇮🇹": "IT",
    }

    for flag, code in FLAG_MAP.items():
        if name.startswith(flag):
            return code

    # Try text patterns: "US |", "Germany", "Netherlands" etc.
    text_patterns = {
        r"^RU\b|(?<!\w)Russia(?!\w)": "RU",
        r"^US\b|(?<!\w)United States(?!\w)": "US",
        r"^DE\b|(?<!\w)Germany(?!\w)": "DE",
        r"^NL\b|(?<!\w)Netherlands(?!\w)": "NL",
        r"^GB\b|(?<!\w)United Kingdom(?!\w)|(?<!\w)UK(?!\w)": "GB",
        r"^FR\b|(?<!\w)France(?!\w)": "FR",
        r"^JP\b|(?<!\w)Japan(?!\w)": "JP",
        r"^FI\b|(?<!\w)Finland(?!\w)": "FI",
        r"^PL\b|(?<!\w)Poland(?!\w)": "PL",
        r"^SE\b|(?<!\w)Sweden(?!\w)": "SE",
    }
    for pattern, code in text_patterns.items():
        if re.search(pattern, name, re.I):
            return code

    return "Other"


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def parse_vless(link: str) -> Node:
    link = link.strip()
    if not link.startswith("vless://"):
        raise ParseError("Not a vLESS link")
    link = fix_link(link)
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    uuid = parsed.username or ""
    if not uuid:
        raise ParseError("Missing UUID")
    qs = parse_qs(parsed.query)
    node = Node(
        protocol="vless",
        uuid=uuid,
        address=parsed.hostname,
        port=parsed.port,
        net=_get(qs, "type", "tcp"),
        path=unquote(_get(qs, "path")),
        host=_get(qs, "host"),
        tls=_get(qs, "security") in ("tls", "reality"),
        sni=_get(qs, "sni"),
        alpn=_get(qs, "alpn"),
        fp=_get(qs, "fp"),
        reality_pbk=_get(qs, "pbk"),
        reality_sid=_get(qs, "sid"),
        reality_spx=_get(qs, "spx"),
        flow=_get(qs, "flow"),
    )
    if parsed.fragment:
        node.name = unquote(parsed.fragment)
    return node


def parse_vmess(link: str) -> Node:
    link = link.strip()
    if not link.startswith("vmess://"):
        raise ParseError("Not a VMess link")
    payload = link[8:]
    try:
        data = json.loads(_b64decode(payload))
    except Exception as e:
        raise ParseError(f"Invalid VMess JSON: {e}")
    try:
        return Node(
            protocol="vmess",
            uuid=data["id"],
            address=data["add"],
            port=int(data["port"]),
            name=unquote(data.get("ps", "")),
            net=data.get("net", "tcp"),
            path=unquote(data.get("path", "")),
            host=data.get("host", ""),
            tls=data.get("tls", "") == "tls",
            sni=data.get("sni", ""),
            alpn=data.get("alpn", ""),
            vmess_aid=int(data.get("aid", 0)),
            vmess_scy=data.get("scy", "auto"),
        )
    except (KeyError, ValueError) as e:
        raise ParseError(f"Missing VMess field: {e}")


def parse_trojan(link: str) -> Node:
    link = link.strip()
    if not link.startswith("trojan://"):
        raise ParseError("Not a Trojan link")
    link = fix_link(link)
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    qs = parse_qs(parsed.query)
    node = Node(
        protocol="trojan",
        trojan_password=unquote(parsed.username or ""),
        address=parsed.hostname,
        port=parsed.port,
        sni=_get(qs, "sni"),
        alpn=_get(qs, "alpn"),
        net=_get(qs, "type", "tcp"),
        path=unquote(_get(qs, "path")),
        host=_get(qs, "host"),
        fp=_get(qs, "fp"),
    )
    if parsed.fragment:
        node.name = unquote(parsed.fragment)
    return node


def parse_ss(link: str) -> Node:
    """Parse ss:// link (SIP002 or legacy)."""
    link = link.strip()
    if not link.startswith("ss://"):
        raise ParseError("Not an SS link")
    parsed = urlparse(link)
    if parsed.hostname and parsed.port is not None:
        try:
            decoded = _b64decode(parsed.username or "")
        except Exception:
            decoded = unquote(parsed.username or "")
        if ":" not in decoded:
            raise ParseError("Invalid SS userinfo (expected method:password)")
        method, password = decoded.split(":", 1)
        name = unquote(parsed.fragment) if parsed.fragment else ""
        return Node(
            protocol="ss",
            address=parsed.hostname,
            port=parsed.port,
            name=name,
            ss_method=method,
            ss_password=password,
        )
    else:
        payload = link[5:]
        try:
            decoded = _b64decode(payload)
        except Exception as e:
            raise ParseError(f"Invalid SS base64: {e}")
        m = re.match(r"^(.+?):(.+?)@(.+?):(\d+)", decoded)
        if not m:
            raise ParseError(f"Cannot parse legacy SS: {decoded}")
        return Node(
            protocol="ss",
            address=m.group(3),
            port=int(m.group(4)),
            ss_method=m.group(1),
            ss_password=m.group(2),
        )


def parse_ssr(link: str) -> Node:
    """Parse ssr:// link."""
    link = link.strip()
    if not link.startswith("ssr://"):
        raise ParseError("Not an SSR link")
    payload = link[6:]
    try:
        decoded = _b64decode(payload)
    except Exception as e:
        raise ParseError(f"Invalid SSR base64: {e}")
    main, _, param_str = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        raise ParseError(f"Invalid SSR format: {decoded}")
    params = {}
    if param_str:
        for kv in param_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = unquote(v)
    return Node(
        protocol="ssr",
        address=parts[0],
        port=int(parts[1]),
        name=unquote(params.get("remarks", "")),
        ssr_protocol=parts[2],
        ss_method=parts[3],
        ssr_obfs=parts[4],
        ss_password=_b64decode(parts[5]),
        ssr_protocol_param=unquote(params.get("protoparam", "")),
        ssr_obfs_param=unquote(params.get("obfsparam", "")),
    )


def parse_hysteria2(link: str) -> Node:
    """Parse hysteria2:// link."""
    link = link.strip()
    if not link.startswith("hysteria2://"):
        raise ParseError("Not a Hysteria2 link")
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    qs = parse_qs(parsed.query)
    node = Node(
        protocol="hysteria2",
        address=parsed.hostname,
        port=parsed.port,
        hysteria2_password=unquote(parsed.username or ""),
        sni=_get(qs, "sni"),
        alpn=_get(qs, "alpn"),
        obfs=_get(qs, "obfs"),
    )
    if parsed.fragment:
        node.name = unquote(parsed.fragment)
    return node


def parse_socks(link: str) -> Node:
    """Parse socks:// link."""
    link = link.strip()
    if not link.startswith("socks://"):
        raise ParseError("Not a SOCKS link")
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    node = Node(
        protocol="socks",
        address=parsed.hostname,
        port=parsed.port,
        socks_username=unquote(parsed.username or ""),
        socks_password=unquote(parsed.password or ""),
    )
    if parsed.fragment:
        node.name = unquote(parsed.fragment)
    return node


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_PROTOCOL_PREFIXES = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "ssr://": parse_ssr,
    "hysteria2://": parse_hysteria2,
    "socks://": parse_socks,
}


def parse_link(link: str) -> Node:
    """Auto-detect protocol and parse a single link."""
    link = link.strip()
    for prefix, parser in _PROTOCOL_PREFIXES.items():
        if link.startswith(prefix):
            return parser(link)
    raise ParseError(f"Unknown protocol prefix in: {link[:30]}...")


def parse_text_input(text: str) -> list[Node]:
    """Parse text containing one or more links (one per line).

    Optimized: fix_link is called inside each parser, not redundantly here.
    For large inputs, processes line-by-line to minimize memory.
    """
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Additional safety: fix_link handles & -> ? normalization
        # This catches cases where urlparse would fail on malformed ports
        line = fix_link(line)
        try:
            nodes.append(parse_link(line))
        except ParseError as e:
            nodes.append(Node(protocol="error", name=str(e), extra={"raw": line}))
    return nodes


def iter_parse_text(text: str):
    """Streaming parser — yields nodes one at a time (generator).

    Use for very large inputs to avoid loading all nodes into memory.
    """
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield parse_link(line)
        except ParseError as e:
            yield Node(protocol="error", name=str(e), extra={"raw": line})


# ---------------------------------------------------------------------------
# Subscription fetching
# ---------------------------------------------------------------------------

_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Happ/3.21.1",
    "v2rayNG/1.8.29",
    "ClashMetaForAndroid/2.12.0",
    "sing-box/1.9.0",
    "V2Ray/5.0.0",
]


async def fetch_subscription(url: str, timeout: int = 15, user_agent: str = "", hwid: str = "") -> str:
    """Fetch subscription content from URL.

    If user_agent is empty, tries a list of known UA strings.
    If hwid is provided, sends it as X-HWID header.
    """
    uas = [user_agent] if user_agent else _UA_LIST
    last_err = ""
    for ua in uas:
        headers = {"User-Agent": ua}
        if hwid:
            headers["X-HWID"] = hwid
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
            try:
                resp = await client.get(url)
                if resp.status_code >= 500:
                    last_err = f"HTTP {resp.status_code} with UA: {ua[:30]}..."
                    continue
                resp.raise_for_status()
                content = resp.text.strip()
                if "\n" not in content and "\r" not in content:
                    try:
                        content = _b64decode(content)
                    except Exception:
                        pass
                return content
            except Exception as e:
                last_err = str(e)
                continue
    raise Exception(last_err or "All UA attempts failed")


def extract_subscription_name(url: str, content: str, resp_headers: dict | None = None) -> str:
    """Extract a human-readable name for a subscription.

    Tries in order:
    1. Content-Disposition header (filename)
    2. #profile-title: comment in content (Clash/V2Ray format)
    3. URL path last segment
    4. hostname from URL
    """
    # 1. Content-Disposition header
    if resp_headers:
        cd = resp_headers.get("content-disposition", "")
        if "filename*" in cd:
            # RFC 5987: filename*=UTF-8''encoded_name
            import re
            m = re.search(r"filename\*\s*=\s*UTF-8''(.+?)(?:;|$)", cd, re.I)
            if m:
                return unquote(m.group(1))
        if "filename=" in cd:
            import re
            m = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', cd, re.I)
            if m:
                name = m.group(1).strip()
                if name and name not in ("1.bin", "download", "sub", "config"):
                    return name

    # 2. #profile-title: in content
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#profile-title:"):
            title = line.split(":", 1)[1].strip()
            if title:
                return title[:100]  # limit length

    # 3. URL path segments (skip file-like names)
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]
    # File-like patterns: digits.txt, 1.bin, config.yaml, etc.
    import re
    _FILE_RE = re.compile(r'^(\d+\.(txt|bin|yaml|yml|json|conf|dat)|\w+\.(txt|bin|yaml|yml|json|conf|dat))$', re.I)
    # Try last segment first, then walk backwards
    for part in reversed(path_parts):
        if part in ("sub", "config", "download", "api", "get"):
            continue
        if _FILE_RE.match(part):
            continue
        return part[:100]

    # 4. hostname
    return parsed.hostname or "subscription"


async def parse_subscription(url: str, timeout: int = 15) -> list[Node]:
    """Fetch and parse a subscription URL."""
    content = await fetch_subscription(url, timeout)
    nodes = parse_text_input(content)
    return [n for n in nodes if n.protocol != "error"]


def parse_subscription_text(text: str) -> list[Node]:
    """Parse already-fetched subscription text (may be base64).

    Falls back to config parsing (reverse.from_config) if no share-links found.
    """
    text = text.strip()
    if "\n" not in text and "\r" not in text:
        try:
            text = _b64decode(text)
        except Exception:
            pass
    nodes = parse_text_input(text)
    # Filter out error nodes — they indicate unparseable content
    real_nodes = [n for n in nodes if n.protocol != "error"]
    if not real_nodes:
        # Try direct JSON/YAML config parsing (Xray array, sing-box, mihomo)
        try:
            from core.reverse import from_config
            real_nodes = from_config(text)
        except Exception:
            pass
    return real_nodes

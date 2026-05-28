"""Core parsing: vless/vmess/ss/ssr/trojan links + subscription fetching."""

import base64
import json
import re
import binascii
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

import httpx


class ParseError(Exception):
    pass


@dataclass
class Node:
    protocol: str          # vless, vmess, ss, ssr, trojan
    uuid: str = ""         # vless/vmess/trojan
    address: str = ""
    port: int = 0
    name: str = ""         # human-readable tag
    # transport
    net: str = "tcp"       # tcp, ws, grpc, h2, quic
    path: str = ""
    host: str = ""         # Host header (ws/h2)
    # security
    tls: bool = False
    sni: str = ""
    alpn: str = ""
    fp: str = ""           # fingerprint (client-fingerprint)
    # reality
    reality_pbk: str = ""
    reality_sid: str = ""
    reality_spx: str = ""
    # vmess specific
    vmess_aid: int = 0
    vmess_scy: str = "auto"  # security: auto/aes-128-gcm/chacha20-poly1305/none
    # ss specific
    ss_method: str = ""
    ss_password: str = ""
    # ssr specific
    ssr_protocol: str = ""
    ssr_obfs: str = ""
    ssr_protocol_param: str = ""
    ssr_obfs_param: str = ""
    # trojan specific
    trojan_password: str = ""
    # flow (XTLS)
    flow: str = ""
    # extra raw params
    extra: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        return f"{self.protocol}://{self.address}:{self.port}"

    def to_vless_link(self) -> str:
        """Reconstruct as vless:// share link (only works for vless nodes)."""
        if self.protocol != "vless":
            raise ParseError(f"Cannot convert {self.protocol} to vless link")
        from urllib.parse import urlencode, quote
        params = {"encryption": "none"}
        if self.net and self.net != "tcp":
            params["type"] = self.net
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


# ---------------------------------------------------------------------------
# Individual link parsers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def _get(qs: dict, key: str, default: str = "") -> str:
    return qs.get(key, [default])[0]


def fix_link(link: str) -> str:
    """Normalize a proxy link to standard format.

    Fixes:
    - vless/vmess/trojan: adds ? before first & if no ? present
    - vless: adds type=tcp if missing (required by some clients like podkop)
    - vless: normalizes packet-encoding → packetEncoding
    """
    link = link.strip()
    if not link:
        return link

    for prefix in ("vless://", "trojan://"):
        if link.startswith(prefix):
            # Find the end of authority (host:port)
            rest = link[len(prefix):]
            # authority ends at first ?, &, or #
            end = len(rest)
            for c in ("?", "&", "#"):
                idx = rest.find(c)
                if idx != -1 and idx < end:
                    end = idx

            authority = rest[:end]
            remainder = rest[end:]

            # If remainder starts with & → replace with ?
            if remainder.startswith("&"):
                remainder = "?" + remainder[1:]

            # For vless: ensure type=tcp is in query (check decoded link)
            if prefix == "vless://" and "type=" not in unquote(link[len(prefix):]):
                # Insert type=tcp before fragment (#) if present
                hash_idx = remainder.find("#")
                if hash_idx != -1:
                    remainder = remainder[:hash_idx] + "&type=tcp" + remainder[hash_idx:]
                elif remainder.startswith("?"):
                    remainder = remainder + "&type=tcp"
                else:
                    remainder = remainder + "?type=tcp"

            # Normalize packet-encoding → packetEncoding
            remainder = remainder.replace("packet-encoding=", "packetEncoding=")

            return prefix + authority + remainder

    return link


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
    # name from fragment
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
        # SIP002: ss://base64(method:password)@host:port#name
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
        # legacy: ss://base64(method:password@host:port)
        payload = link[5:]
        try:
            decoded = _b64decode(payload)
        except Exception as e:
            raise ParseError(f"Invalid SS base64: {e}")
        # method:password@host:port
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
    # host:port:protocol:method:obfs:base64pass/?params
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


def _b64decode(s: str) -> str:
    """Decode base64 with padding fix."""
    s = s.strip()
    missing = len(s) % 4
    if missing:
        s += "=" * (4 - missing)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_PROTOCOL_PREFIXES = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "ssr://": parse_ssr,
}


def parse_link(link: str) -> Node:
    """Auto-detect protocol and parse a single link."""
    link = link.strip()
    for prefix, parser in _PROTOCOL_PREFIXES.items():
        if link.startswith(prefix):
            return parser(link)
    raise ParseError(f"Unknown protocol prefix in: {link[:30]}...")


def parse_text_input(text: str) -> list[Node]:
    """Parse text containing one or more links (one per line)."""
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nodes.append(parse_link(line))
        except ParseError as e:
            nodes.append(Node(protocol="error", name=str(e), extra={"raw": line}))
    return nodes


# ---------------------------------------------------------------------------
# Subscription fetching
# ---------------------------------------------------------------------------

async def fetch_subscription(url: str, timeout: int = 15) -> str:
    """Fetch subscription content from URL."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        content = resp.text.strip()
        # Many subs are base64-encoded
        if "\n" not in content and "\r" not in content:
            try:
                content = _b64decode(content)
            except Exception:
                pass  # not base64, use raw
        return content


async def parse_subscription(url: str, timeout: int = 15) -> list[Node]:
    """Fetch and parse a subscription URL."""
    content = await fetch_subscription(url, timeout)
    nodes = parse_text_input(content)
    # Filter out error nodes
    return [n for n in nodes if n.protocol != "error"]


def parse_subscription_text(text: str) -> list[Node]:
    """Parse already-fetched subscription text (may be base64)."""
    text = text.strip()
    # Try decode as single base64 blob
    if "\n" not in text and "\r" not in text:
        try:
            text = _b64decode(text)
        except Exception:
            pass
    return parse_text_input(text)

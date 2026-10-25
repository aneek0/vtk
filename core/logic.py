"""Core parsing: vless/vmess/ss/ssr/trojan/hysteria2/socks/happ links + subscriptions."""

import contextlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlparse

from core._b64 import b64decode as _b64decode
from core.decryptors import decrypt_input
from core.input import InputKind, classify, default_format
from core.share import render_link


class ParseError(Exception):
    pass


# Known VLESS query parameter keys (whitelist)
_VLESS_KNOWN_PARAMS = {
    "encryption", "type", "security", "sni", "fp", "alpn",
    "pbk", "sid", "spx", "flow", "host", "path", "packetEncoding",
    "serviceName", "mode", "headerType",
}

# Known Trojan query parameter keys
_TROJAN_KNOWN_PARAMS = {
    "sni", "alpn", "type", "path", "host", "fp", "security",
}

# Known Hysteria2 query parameter keys
_HYSTERIA2_KNOWN_PARAMS = {
    "sni", "alpn", "obfs", "obfs-password", "insecure",
}


def _sanitize_value(val: str) -> str:
    """Clean a single query param value from junk characters."""
    # Remove Latin Extended spam chars (U+00C0-U+01FF) used as obfuscation
    val = re.sub(r"[\u00C0-\u01FF]", "", val)
    return val


def _sanitize_params(qs: dict, known: set) -> dict:
    """Remove unknown/malicious query params and clean known ones.

    Input: parse_qs output {key: [val1, val2, ...]}
    Output: same format {key: [val]} for compatibility with _get().
    """
    clean = {}
    for k, v in qs.items():
        if k not in known:
            continue
        val = v[0] if isinstance(v, list) else v
        # Clean junk characters from value
        val = _sanitize_value(val)
        # Drop params with repeated/spam values (e.g. host=/?BIA_TELEGRAM@FOO_FOO_FOO)
        if len(val) > 200:
            continue
        # Drop params with suspicious repeated patterns
        if re.search(r"(.{5,})\1{3,}", val):
            continue
        # Drop params containing known spam tokens
        lowered = val.lower()
        if any(tok in lowered for tok in ("bia_telegram", "marambashi", "networld_vpn",
                                          "vpnserverrr", "you_are_beautiful")):
            continue
        clean[k] = [val]
    return clean


def _clean_name(name: str) -> str:
    """Clean node name from mojibake and garbage."""
    if not name:
        return name
    # Fix double-encoded UTF-8 (mojibake like ÃƒÂ)
    try:
        raw = name.encode("latin-1")
        fixed = raw.decode("utf-8")
        if any(ord(c) > 127 for c in fixed):
            name = fixed
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    # Remove Latin Extended spam chars (U+00C0-U+01FF) used as obfuscation
    # e.g. ÃƒÂƒÃ (C3 192 C2 192 C3) — junk inserted by some VPN providers
    name = re.sub(r"[\u00C0-\u01FF]", "", name)
    # Remove non-printable chars except emoji/flags
    name = re.sub(r"[^\x20-\x7E\u00A0-\uFFFF\u2600-\u27BF\U0001F000-\U0001FFFF]", "", name)
    return name.strip()


@dataclass
class Node:
    protocol: str
    uuid: str = ""
    address: str = ""
    port: int = 0
    name: str = ""
    # transport
    net: str = "raw"       # raw, ws, grpc, h2, quic, xhttp
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

    def validate(self) -> bool:
        """Validate node structure (lightweight, no external deps).

        Raises ParseError if critical fields are missing or invalid.
        """
        if self.protocol not in ("vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "socks"):
            return True  # Skip validation for error/unknown nodes

        if not self.address:
            raise ParseError(f"Missing address for {self.protocol} node")
        if not self.port or self.port < 1 or self.port > 65535:
            raise ParseError(f"Invalid port {self.port} for {self.protocol} node")

        # Protocol-specific required fields
        if self.protocol == "vless" and not self.uuid:
            raise ParseError("Missing UUID for VLESS node")
        if self.protocol == "vmess" and not self.uuid:
            raise ParseError("Missing UUID for VMess node")
        if self.protocol == "trojan" and not self.trojan_password:
            raise ParseError("Missing password for Trojan node")
        if self.protocol == "ss" and (not self.ss_method or not self.ss_password):
            raise ParseError("Missing method/password for SS node")
        if self.protocol == "hysteria2" and not self.hysteria2_password:
            raise ParseError("Missing password for Hysteria2 node")

        # Validate network type
        valid_nets = ("tcp", "raw", "ws", "grpc", "h2", "quic", "xhttp")
        if self.net not in valid_nets:
            self.net = "raw"  # Auto-fix invalid transport

        return True

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(qs: dict, key: str, default: str = "") -> str:
    return qs.get(key, [default])[0]


# Query parameters that known spam generators inject into vless/trojan links.
_SPAM_QUERY_KEYS = {"seq", "scid", "sId"}
_SPAM_QUERY_TOKENS = (
    "bia_telegram", "marambashi", "networld_vpn",
    "vpnserverrr", "you_are_beautiful",
)
_REPEATED_VALUE_RE = re.compile(r"(.{5,})\1{3,}")
_VALID_TRANSPORTS = ("tcp", "raw", "ws", "grpc", "h2", "quic", "xhttp")


def _split_link(rest: str) -> tuple[str, str, str]:
    """Split ``authority[?query][#fragment]``.

    Some providers emit ``authority&param=value`` with no ``?``; a leading
    ``&`` therefore starts the query just like ``?``.  The fragment is cut
    first so a ``#`` inside it can never be mistaken for a query boundary.
    """
    head, has_fragment, fragment = rest.partition("#")
    cut = min((i for i in (head.find("?"), head.find("&")) if i != -1), default=-1)
    if cut == -1:
        return head, "", fragment if has_fragment else ""
    return head[:cut], head[cut + 1:], fragment if has_fragment else ""


def _clean_query_param(key: str, raw_value: str) -> str | None:
    """Return the normalized ``key=value`` pair, or ``None`` to drop it."""
    value = _sanitize_value(unquote(raw_value))
    if key in _SPAM_QUERY_KEYS:
        return None
    if _REPEATED_VALUE_RE.search(value):
        return None
    if any(token in value.lower() for token in _SPAM_QUERY_TOKENS):
        return None
    if len(value) > 200:
        return None
    if key == "packet-encoding":
        key = "packetEncoding"
    if key == "type" and value not in _VALID_TRANSPORTS:
        return "type=raw"
    return f"{key}={raw_value}"


def fix_link(link: str) -> str:
    """Normalize a vless/trojan link before parsing.

    Repairs third-party output that podkop and Happ reject:

    - ``&`` instead of ``?`` before the first query parameter;
    - missing ``type=raw`` (vless default transport);
    - invalid transport types (``type=foo`` → ``type=raw``);
    - known spam/malware query parameters;
    - ``packet-encoding`` → ``packetEncoding``.

    Works on the authority/query/fragment split rather than on raw string
    offsets, so a link with a fragment and no query (``...#name``) stays valid.
    Other schemes pass through unchanged.
    """
    link = link.strip()
    if not link:
        return link

    for prefix in ("vless://", "trojan://"):
        if not link.startswith(prefix):
            continue
        authority, query, fragment = _split_link(link[len(prefix):])
        params = []
        for part in query.split("&"):
            if "=" not in part:
                continue
            key, raw_value = part.split("=", 1)
            cleaned = _clean_query_param(key, raw_value)
            if cleaned:
                params.append(cleaned)

        if prefix == "vless://" and not any(
            p.split("=", 1)[0] == "type" for p in params
        ):
            params.append("type=raw")

        fixed = prefix + authority
        if params:
            fixed += "?" + "&".join(params)
        if fragment:
            fixed += "#" + fragment
        return fixed
    return link

# Country detection tables (module-level: built once, not per call).
_FLAG_MAP = {
    "🇷🇺": "RU", "🇺🇸": "US", "🇩🇪": "DE", "🇳🇱": "NL",
    "🇬🇧": "GB", "🇫🇷": "FR", "🇯🇵": "JP", "🇰🇷": "KR",
    "🇸🇪": "SE", "🇫🇮": "FI", "🇵🇱": "PL", "🇪🇪": "EE",
    "🇱🇻": "LV", "🇱🇹": "LT", "🇨🇭": "CH", "🇦🇿": "AZ",
    "🇹🇷": "TR", "🇮🇱": "IL", "🇰🇿": "KZ", "🇲🇩": "MD",
    "🇧🇬": "BG", "🇭🇺": "HU", "🇪🇸": "ES", "🇮🇪": "IE",
    "🇩🇰": "DK", "🇭🇰": "HK", "🇮🇳": "IN", "🇨🇳": "CN",
    "🇧🇷": "BR", "🇨🇦": "CA", "🇦🇺": "AU", "🇮🇹": "IT",
}

# Precompiled text patterns: "US |", "Germany", "Netherlands" etc.
# Search flags (re.I) preserved from the original inline dict.
_COUNTRY_TEXT_PATTERNS = [
    (re.compile(r"^RU\b|(?<!\w)Russia(?!\w)", re.I), "RU"),
    (re.compile(r"^US\b|(?<!\w)United States(?!\w)", re.I), "US"),
    (re.compile(r"^DE\b|(?<!\w)Germany(?!\w)", re.I), "DE"),
    (re.compile(r"^NL\b|(?<!\w)Netherlands(?!\w)", re.I), "NL"),
    (re.compile(r"^GB\b|(?<!\w)United Kingdom(?!\w)|(?<!\w)UK(?!\w)", re.I), "GB"),
    (re.compile(r"^FR\b|(?<!\w)France(?!\w)", re.I), "FR"),
    (re.compile(r"^JP\b|(?<!\w)Japan(?!\w)", re.I), "JP"),
    (re.compile(r"^FI\b|(?<!\w)Finland(?!\w)", re.I), "FI"),
    (re.compile(r"^PL\b|(?<!\w)Poland(?!\w)", re.I), "PL"),
    (re.compile(r"^SE\b|(?<!\w)Sweden(?!\w)", re.I), "SE"),
]

def extract_country(name: str) -> str:
    """Extract country from node name using emoji flags or text patterns.

    Returns country name or "Other" if not found.
    """
    if not name:
        return "Other"

    for flag, code in _FLAG_MAP.items():
        if flag in name:
            return code

    for pattern, code in _COUNTRY_TEXT_PATTERNS:
        if pattern.search(name):
            return code
    return "Other"


def sort_nodes_by_country(nodes: list) -> list:
    """Sort nodes by country of node name: alphabetical country codes
    first, no-country ("Other") last. Stable within a country."""
    return sorted(nodes, key=lambda n: (extract_country(n.name or "") == "Other",
                                        extract_country(n.name or "")))


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def parse_vless(link: str) -> Node:
    link = link.strip()
    if not link.startswith("vless://"):
        raise ParseError("Not a VLESS link")
    link = fix_link(link)
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    uuid = parsed.username or ""
    if not uuid:
        raise ParseError("Missing UUID")
    qs = _sanitize_params(parse_qs(parsed.query), _VLESS_KNOWN_PARAMS)
    net = _get(qs, "type", "raw")
    # Reject invalid transport types — fallback to raw
    if net not in ("tcp", "raw", "ws", "grpc", "h2", "quic", "xhttp"):
        net = "raw"
    node = Node(
        protocol="vless",
        uuid=uuid,
        address=parsed.hostname,
        port=parsed.port,
        net=net,
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
        node.name = _clean_name(unquote(parsed.fragment))
    return node


def parse_vmess(link: str) -> Node:
    link = link.strip()
    if not link.startswith("vmess://"):
        raise ParseError("Not a VMess link")
    payload = link[8:]
    try:
        data = json.loads(_b64decode(payload))
    except Exception as e:
        raise ParseError(f"Invalid VMess JSON: {e}") from e
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
        raise ParseError(f"Missing VMess field: {e}") from e


def parse_trojan(link: str) -> Node:
    link = link.strip()
    if not link.startswith("trojan://"):
        raise ParseError("Not a Trojan link")
    link = fix_link(link)
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    qs = _sanitize_params(parse_qs(parsed.query), _TROJAN_KNOWN_PARAMS)
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
        node.name = _clean_name(unquote(parsed.fragment))
    return node


def _fix_ss_2022_key(method: str, password: str) -> str:
    """Fix 2022-blake3 key length by truncating or zero-padding.

    Some subscription providers generate wrong-length keys (e.g. 32 bytes
    for 2022-blake3-aes-128-gcm which needs 16). This auto-corrects them
    so the client doesn't crash with "bad key length".
    """
    import base64
    expected = {
        "2022-blake3-aes-128-gcm": 16,
        "2022-blake3-aes-256-gcm": 32,
        "2022-blake3-chacha20-poly1305": 32,
    }
    exp = expected.get(method)
    if not exp:
        return password

    # Try to decode password as base64
    try:
        # Add padding if needed
        padded = password + "=" * (-len(password) % 4)
        key_bytes = base64.b64decode(padded)
    except Exception:
        # Not valid base64, return as-is
        return password

    if len(key_bytes) == exp:
        return password  # Already correct

    # Fix length: truncate or zero-pad
    key_bytes = key_bytes[:exp] if len(key_bytes) > exp else key_bytes + b"\x00" * (exp - len(key_bytes))

    # Re-encode to base64 (standard, with padding)
    return base64.b64encode(key_bytes).decode()


def parse_ss(link: str) -> Node:
    """Parse ss:// link (SIP002 or legacy)."""
    link = link.strip()
    if not link.startswith("ss://"):
        raise ParseError("Not an SS link")

    # Strip fragment early — emoji/non-ASCII in #fragment breaks urlparse
    # and also gets included in link[5:] for base64 decode
    fragment = ""
    if "#" in link:
        link, fragment = link.split("#", 1)

    parsed = urlparse(link)
    if parsed.hostname and parsed.port is not None:
        try:
            decoded = _b64decode(parsed.username or "")
        except Exception:
            decoded = unquote(parsed.username or "")
        if ":" not in decoded:
            raise ParseError("Invalid SS userinfo (expected method:password)")
        method, password = decoded.split(":", 1)
        password = _fix_ss_2022_key(method, password)
        name = unquote(fragment) if fragment else ""
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
            raise ParseError(f"Invalid SS base64: {e}") from e
        m = re.match(r"^(.+?):(.+?)@(.+?):(\d+)", decoded)
        if not m:
            raise ParseError(f"Cannot parse legacy SS: {decoded}")
        method = m.group(1)
        password = _fix_ss_2022_key(method, m.group(2))
        return Node(
            protocol="ss",
            address=m.group(3),
            port=int(m.group(4)),
            ss_method=method,
            ss_password=password,
            name=unquote(fragment) if fragment else "",
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
        raise ParseError(f"Invalid SSR base64: {e}") from e
    main, _, param_str = decoded.partition("/?")
    parts = main.split(":")
    if len(parts) < 6:
        raise ParseError(f"Invalid SSR format: {decoded}")
    params = {}
    if param_str:
        for kv in param_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = _ssr_param(v)
    return Node(
        protocol="ssr",
        address=parts[0],
        port=int(parts[1]),
        name=params.get("remarks", ""),
        ssr_protocol=parts[2],
        ss_method=parts[3],
        ssr_obfs=parts[4],
        ss_password=_b64decode(parts[5]),
        ssr_protocol_param=params.get("protoparam", ""),
        ssr_obfs_param=params.get("obfsparam", ""),
    )


def _ssr_param(value: str) -> str:
    """Decode an SSR query value: base64url per spec, plain text when lenient."""
    value = unquote(value)
    if not value:
        return ""
    try:
        decoded = _b64decode(value)
    except Exception:
        return value
    return decoded if decoded.isprintable() else value


def parse_hysteria2(link: str) -> Node:
    link = link.strip()
    if not link.startswith("hysteria2://"):
        raise ParseError("Not a Hysteria2 link")
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    qs = _sanitize_params(parse_qs(parsed.query), _HYSTERIA2_KNOWN_PARAMS)
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
        node.name = _clean_name(unquote(parsed.fragment))
    return node


def parse_socks(link: str) -> Node:
    """Parse socks:// link."""
    link = link.strip()
    if not link.startswith("socks://"):
        raise ParseError("Not a SOCKS link")
    parsed = urlparse(link)
    if not parsed.hostname or not parsed.port:
        raise ParseError("Missing host/port")
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if username and not password:
        # v2rayN-style socks links carry base64("user:pass") as the userinfo.
        try:
            decoded = _b64decode(username)
        except Exception:
            decoded = ""
        if ":" in decoded:
            username, password = decoded.split(":", 1)
    node = Node(
        protocol="socks",
        address=parsed.hostname,
        port=parsed.port,
        socks_username=username,
        socks_password=password,
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
    """Auto-detect protocol and parse a single link.

    Malformed values that ``urllib.parse`` rejects (for example a port it
    cannot cast to int) surface as :class:`ParseError`, so a single bad line
    never escapes the batch parsers.
    """
    link = link.strip()
    for prefix, parser in _PROTOCOL_PREFIXES.items():
        if link.startswith(prefix):
            try:
                return parser(link)
            except ValueError as e:
                raise ParseError(f"Invalid link: {e}") from e
    raise ParseError(f"Unknown protocol prefix in: {link[:30]}...")


def parse_text_input(text: str) -> list[Node]:
    """Parse text containing one or more links (one per line).

    Optimized: fix_link is called inside each parser, not redundantly here.
    For large inputs, processes line-by-line to minimize memory.

    A protective ``decrypt_input`` runs first so any ``happ://`` / ``incy://``
    links embedded in the text are decrypted inline (idempotent — plain text
    passes through unchanged). This keeps direct callers safe from the class
    of bug where encrypted inputs skipped the protocol parser.
    """
    text = decrypt_input(text)
    nodes = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # fix_link normalization runs inside parse_vless/parse_trojan;
        # other protocols need none.
        try:
            node = parse_link(line)
            node.validate()  # Lightweight validation (raises ParseError on critical issues)
            nodes.append(node)
        except ParseError as e:
            nodes.append(Node(protocol="error", name=str(e), extra={"raw": line}))
    return nodes


def iter_parse_text(text: str):
    """Streaming parser — yields nodes one at a time (generator).

    Use for very large inputs to avoid loading all nodes into memory.
    Runs the same protective ``decrypt_input`` pass as ``parse_text_input``
    so encrypted ``happ://`` / ``incy://`` links are handled identically.
    """
    text = decrypt_input(text)
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            node = parse_link(line)
            node.validate()
            yield node
        except ParseError as e:
            yield Node(protocol="error", name=str(e), extra={"raw": line})


# ---------------------------------------------------------------------------
# Subscription fetching
# ---------------------------------------------------------------------------



async def fetch_subscription(url: str, timeout: int = 15, return_headers: bool = False, headers: dict | None = None):
    """Fetch subscription content from URL directly (no external API).

    If return_headers=True, returns {"content": str, "headers": [(key,val),...]}

    `headers` (optional) are merged into the request (e.g. device fingerprint
    headers for proxied subscriptions).
    """
    from core import net

    resp = await net.fetch(url, timeout=timeout, headers=headers)
    if return_headers:
        # Parse profile-title/profile-web-page-url from content (Clash/v2ray comments)
        profile_title = ""
        profile_url = ""
        for line in resp.text.splitlines():
            ls = line.strip()
            if ls.lower().startswith("profile-title:"):
                profile_title = ls.split(":", 1)[1].strip()
            elif ls.lower().startswith("profile-web-page-url:"):
                profile_url = ls.split(":", 1)[1].strip()

        def _decode_val(v: str) -> str:
            if v.startswith("base64:"):
                try:
                    return _b64decode(v[7:])
                except Exception:
                    return v
            return v

        def _format_bytes(b: int) -> str:
            gb = b / (1024 ** 3)
            return f"{gb:.1f}"

        def _format_userinfo(val: str) -> str:
            parts = {}
            for m in re.finditer(r'(\w+)=([^;]+)', val):
                parts[m.group(1)] = m.group(2)
            items = []
            up = parts.get("upload", "0")
            if up == "0" or up.lower() == "unlimited":
                items.append("upload: unlimited")
            else:
                items.append(f"upload: {_format_bytes(int(up))} GB")
            dl = parts.get("download", "0")
            items.append(f"download: {_format_bytes(int(dl))} GB")
            total = parts.get("total", "0")
            items.append(f"total: {_format_bytes(int(total))} GB")
            expire = parts.get("expire", "")
            if expire:
                try:
                    dt = datetime.fromtimestamp(int(expire))
                    items.append(f"expire: {dt.strftime('%d.%m.%Y')}")
                except (ValueError, OSError):
                    items.append(f"expire: {expire}")
            return " | ".join(items)

        def _format_interval(val: str) -> str:
            try:
                n = int(val)
                if n == 1:
                    return "1h"
                return f"{n}h"
            except ValueError:
                return val

        h = resp.headers
        resp_headers_list = []

        # Profile-Title (from content comment or header)
        if not profile_title:
            pt = h.get("profile-title", "")
            if pt:
                profile_title = _decode_val(pt)
        if profile_title:
            resp_headers_list.append(("Profile-Title", profile_title))

        # Account (from content-disposition filename)
        cd = h.get("content-disposition", "")
        if "filename=" in cd:
            m = re.search(r'filename=([^;\s]+)', cd)
            if m:
                acc = m.group(1).strip().strip('"')
                if acc:
                    resp_headers_list.append(("Account", acc))

        # Subscription-Userinfo
        si = h.get("subscription-userinfo", "")
        if si:
            resp_headers_list.append(("Subscription-Userinfo", _format_userinfo(si)))

        # Update-Interval
        ui = h.get("profile-update-interval", "")
        if ui:
            resp_headers_list.append(("Update-Interval", _format_interval(ui)))

        # Content-Type
        ct = h.get("content-type", "")
        if ct:
            resp_headers_list.append(("Content-Type", ct))

        # Support-Url
        su = h.get("support-url", "")
        if su:
            resp_headers_list.append(("Support-Url", su))

        # Announce (base64 decoded)
        an = h.get("announce", "")
        if an:
            resp_headers_list.append(("Announce", _decode_val(an)))

        # Announce-Url
        au = h.get("announce-url", "")
        if au:
            resp_headers_list.append(("Announce-Url", au))

        # Profile-Web-Page-Url (from content comment or header)
        if not profile_url:
            pw = h.get("profile-web-page-url", "")
            if pw:
                profile_url = pw
        if profile_url:
            resp_headers_list.append(("Profile-Web-Page-Url", profile_url))

        return {"content": resp.text, "headers": resp_headers_list}
    return resp.text


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

            m = re.search(r"filename\*\s*=\s*UTF-8''(.+?)(?:;|$)", cd, re.I)
            if m:
                return unquote(m.group(1))
        if "filename=" in cd:

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
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]
    # File-like patterns: digits.txt, 1.bin, config.yaml, etc.
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

    A protective ``decrypt_input`` runs first so an ``incy://`` / ``happ://``
    wrapper embedded in the fetched body is stripped before parsing
    (idempotent for plain content).
    """
    text = decrypt_input(text)
    text = text.strip()
    if "\n" not in text and "\r" not in text:
        with contextlib.suppress(Exception):
            text = _b64decode(text)
    nodes = parse_text_input(text)
    # Filter out error nodes — they indicate unparseable content
    real_nodes = [n for n in nodes if n.protocol != "error"]
    if not real_nodes:
        # Try direct JSON/YAML config parsing (Xray array, sing-box, mihomo)
        with contextlib.suppress(Exception):
            from core.reverse import from_config

            real_nodes = from_config(text)
    return real_nodes


# ---------------------------------------------------------------------------
# Unified input processing
# ---------------------------------------------------------------------------


def protocol_counts(nodes: list[Node]) -> dict[str, int]:
    """Count nodes per protocol, most frequent first."""
    counts: dict[str, int] = {}
    for n in nodes:
        counts[n.protocol] = counts.get(n.protocol, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _node_to_dict(node: Node) -> dict:
    """Build the rich per-node dict used by the bot/web front-end.

    Mirrors the previous web ``_node_to_dict`` so the front-end contract is
    unchanged. Lives in core now so every platform reuses one definition.
    """
    proto = node.protocol
    d = {"protocol": proto, "name": node.display_name, "address": node.address,
         "port": node.port, "net": node.net or "raw"}
    d["type"] = node.net or "raw"
    d["link"] = render_link(node)
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


async def process_input(raw: str, fmt=None, device_headers: dict | None = None,
                        timeout: int | None = None, tag_prefix: str = "",
                        protocol: str | None = None, group_by_country: bool | None = None) -> dict:
    """Single unified entry point used by bot, web and CLI.

    Pipeline (all decryption centralized here):

        raw -> decrypt_input -> detect (link/sub/config)
            -> fetch/parse -> convert -> result dict

    Args:
        raw: Raw user input (links, subscription URL, config, or an
            ``happ://`` / ``incy://`` encrypted wrapper).
        fmt: Optional target ``Format``. When ``None`` resolved per input
            type via ``load_settings()``.
        device_headers: Optional request headers sent when fetching a
            subscription (device fingerprint).
        timeout: Optional subscription fetch timeout (seconds).

    Returns:
        dict: ``{"ok": True, "input_type": ..., "format": ..., "nodes": n,
        "result": ..., "servers": [...], "sub_headers": [...],
        "content": ..., "sub_name": ...}`` on success, or
        ``{"ok": False, "error": ...}`` on failure.
    """
    from core.settings import load_settings

    s = load_settings()
    if timeout is None:
        timeout = s.timeout

    try:
        raw = decrypt_input(raw)
    except Exception as e:
        return {"ok": False, "error": f"Decrypt failed: {e}"}

    kind = classify(raw)
    sub_name = ""
    sub_headers = []
    content = ""
    sub_url = ""

    if kind is InputKind.SUB:
        try:
            sub_url = raw.strip()
            resp = await fetch_subscription(
                sub_url, timeout=timeout, return_headers=True,
                headers=device_headers,
            )
            content = resp.get("content", "")
            sub_headers = resp.get("headers", [])
            sub_name = extract_subscription_name(raw.strip(), content,
                                                 dict(sub_headers))
            nodes = parse_subscription_text(content)
        except Exception as e:
            return {"ok": False, "error": f"Subscription fetch failed: {e}"}
    elif kind is InputKind.CONFIG:
        try:
            from core.reverse import from_config
            nodes = from_config(raw)
        except ParseError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"Config parse failed: {e}"}
    else:
        nodes = [n for n in parse_text_input(raw) if n.protocol != "error"]

    return render_nodes(
        nodes, fmt, kind=kind, protocol=protocol,
        group_by_country=group_by_country, tag_prefix=tag_prefix,
        sub_name=sub_name, sub_headers=sub_headers, content=content,
        sub_url=sub_url,
    )


def render_nodes(nodes: list[Node], fmt=None, *, kind: InputKind = InputKind.LINK,
                 protocol: str | None = None,
                 group_by_country: bool | None = None, tag_prefix: str = "",
                 sub_name: str = "", sub_headers: list | None = None,
                 content: str = "", sub_url: str = "") -> dict:
    """Filter, sort, convert and shape already-parsed nodes for front-ends.

    Split out of :func:`process_input` so a caller that already holds parsed
    nodes (the bot's protocol picker) re-renders them without refetching the
    subscription or re-parsing the input. Returns the same dict contract as
    ``process_input``.
    """
    from core.converters import Format, convert
    from core.settings import load_settings

    s = load_settings()
    protocols = protocol_counts(nodes)
    total_nodes = len(nodes)
    parsed = list(nodes)  # pre-filter: a picker re-renders from this
    if protocol and protocol != "all":
        nodes = [n for n in nodes if n.protocol == protocol]
        if not nodes:
            return {"ok": False,
                    "error": f"No {protocol} nodes (have: {', '.join(protocols)})"}

    if not nodes:
        return {"ok": False, "error": "No valid proxy links found."}

    if fmt is None:
        fmt = default_format(kind, s, total_nodes)
    if group_by_country is None:
        group_by_country = s.group_by_country
    if group_by_country:
        nodes = sort_nodes_by_country(nodes)
    try:
        result = convert(nodes, fmt, tag_prefix=tag_prefix,
                         group_by_country=group_by_country)
    except ParseError as e:
        return {"ok": False, "error": str(e)}

    return {
        "ok": True,
        "input_type": kind.value,
        "format": fmt.value if isinstance(fmt, Format) else str(fmt),
        "nodes": len(nodes),
        "total_nodes": total_nodes,
        "protocols": protocols,
        "result": result,
        "parsed": parsed,
        "servers": [_node_to_dict(n) for n in nodes],
        "sub_headers": sub_headers or [],
        "content": content,
        "sub_name": sub_name,
        "sub_url": sub_url,
    }

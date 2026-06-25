"""Reverse converters: sing-box JSON / mihomo YAML → share links."""

import json
import re
from typing import Optional

from .logic import Node, ParseError


def _parse_yaml_simple(text: str) -> dict:
    """Minimal YAML parser for mihomo proxy lists (no PyYAML dependency)."""
    # Very simple line-based parser for flat YAML structures
    result = {}
    current_list = None
    current_item = None
    indent_stack = [(0, result)]

    for raw_line in text.splitlines():
        stripped = raw_line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())

        # Pop stack to find parent
        while len(indent_stack) > 1 and indent_stack[-1][0] >= indent:
            indent_stack.pop()

        parent = indent_stack[-1][1]

        if stripped.startswith("- "):
            # List item
            if current_list is None:
                current_list = []
                parent["_list"] = current_list
            item = {"_value": stripped[2:].strip()}
            current_list.append(item)
            current_item = item
            indent_stack.append((indent, item))
        elif ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if val == "":
                # Could be a nested dict or list start
                new_dict = {}
                parent[key] = new_dict
                if current_item is not None and "_value" in current_item:
                    current_item[key] = new_dict
                indent_stack.append((indent, new_dict))
            else:
                # Try type coercion
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                elif val.isdigit():
                    val = int(val)
                elif val.lstrip("-").isdigit():
                    val = int(val)
                parent[key] = val

    return result


def _extract_yaml_proxies(text: str) -> list[dict]:
    """Extract proxy entries from mihomo YAML text."""
    proxies = []
    current = None
    current_ws_opts = None
    current_grpc_opts = None
    current_h2_opts = None
    current_reality_opts = None
    current_headers = None
    current_alpn_list = None
    current_host_list = None

    def flush():
        nonlocal current, current_ws_opts, current_grpc_opts, current_h2_opts
        nonlocal current_reality_opts, current_headers, current_alpn_list, current_host_list
        if current is not None:
            if current_ws_opts is not None:
                current["ws-opts"] = current_ws_opts
            if current_grpc_opts is not None:
                current["grpc-opts"] = current_grpc_opts
            if current_h2_opts is not None:
                current["h2-opts"] = current_h2_opts
            if current_reality_opts is not None:
                current["reality-opts"] = current_reality_opts
            proxies.append(current)
        current = None
        current_ws_opts = None
        current_grpc_opts = None
        current_h2_opts = None
        current_reality_opts = None
        current_headers = None
        current_alpn_list = None
        current_host_list = None

    lines = text.splitlines()
    in_proxies = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped == "proxies:":
            in_proxies = True
            i += 1
            continue

        if not in_proxies:
            i += 1
            continue

        # Check if we've left the proxies section (non-indented key)
        if stripped and not stripped.startswith("-") and not stripped.startswith("#") and ":" in stripped:
            indent = len(line) - len(line.lstrip())
            if indent == 0:
                break

        if stripped.startswith("- name:"):
            flush()
            current = {}
            current["name"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
        elif current is not None:
            if stripped.startswith("type:"):
                current["type"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("server:"):
                current["server"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("port:"):
                current["port"] = int(stripped.split(":", 1)[1].strip())
            elif stripped.startswith("uuid:"):
                current["uuid"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("password:"):
                current["password"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("cipher:"):
                current["cipher"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("network:"):
                current["network"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("sni:") or stripped.startswith("servername:"):
                current["sni"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("client-fingerprint:"):
                current["fp"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("flow:"):
                current["flow"] = stripped.split(":", 1)[1].strip().strip('"')
            elif stripped.startswith("tls:"):
                val = stripped.split(":", 1)[1].strip()
                current["tls"] = val == "true"
            elif stripped.startswith("alterId:"):
                current["alterId"] = int(stripped.split(":", 1)[1].strip())
            elif stripped.startswith("ws-opts:"):
                current_ws_opts = {}
            elif stripped.startswith("grpc-opts:"):
                current_grpc_opts = {}
            elif stripped.startswith("h2-opts:"):
                current_h2_opts = {}
            elif stripped.startswith("reality-opts:"):
                current_reality_opts = {}
            elif stripped.startswith("alpn:"):
                current_alpn_list = []
                current["alpn_list"] = current_alpn_list
            elif stripped.startswith("host:"):
                current_host_list = []
                current["host_list"] = current_host_list

            # Nested opts
            if current_ws_opts is not None and "path:" in stripped:
                current_ws_opts["path"] = stripped.split(":", 1)[1].strip().strip('"')
            if current_ws_opts is not None and "Host:" in stripped:
                current_ws_opts["Host"] = stripped.split(":", 1)[1].strip().strip('"')
            if current_grpc_opts is not None and "grpc-service-name:" in stripped:
                current_grpc_opts["grpc-service-name"] = stripped.split(":", 1)[1].strip().strip('"')
            if current_h2_opts is not None and "path:" in stripped:
                current_h2_opts["path"] = stripped.split(":", 1)[1].strip().strip('"')
            if current_h2_opts is not None and stripped.startswith("- "):
                val = stripped[2:].strip().strip('"')
                if "host_list" in current:
                    current["host_list"].append(val)
            if current_reality_opts is not None and "public-key:" in stripped:
                current_reality_opts["public-key"] = stripped.split(":", 1)[1].strip().strip('"')
            if current_reality_opts is not None and "short-id:" in stripped:
                current_reality_opts["short-id"] = stripped.split(":", 1)[1].strip().strip('"')
            if current_alpn_list is not None and stripped.startswith("- "):
                current_alpn_list.append(stripped[2:].strip().strip('"'))
            if current_host_list is not None and stripped.startswith("- "):
                current_host_list.append(stripped[2:].strip().strip('"'))

        i += 1

    flush()
    return proxies


def _yaml_proxy_to_node(p: dict) -> Optional[Node]:
    """Convert a parsed mihomo proxy dict to Node."""
    proto = p.get("type", "")
    if not proto or proto == "ssr":
        return None

    node = Node(
        protocol=proto,
        address=p.get("server", ""),
        port=p.get("port", 0),
        name=p.get("name", ""),
        net=p.get("network", "tcp"),
        sni=p.get("sni", ""),
        fp=p.get("fp", ""),
        tls=p.get("tls", False),
    )

    if proto == "vless":
        node.uuid = p.get("uuid", "")
        node.flow = p.get("flow", "")
        ws = p.get("ws-opts", {})
        if ws:
            node.path = ws.get("path", "")
            node.host = ws.get("Host", "")
        h2 = p.get("h2-opts", {})
        if h2:
            node.path = h2.get("path", "")
            hl = p.get("host_list", [])
            if hl:
                node.host = hl[0]
        grpc = p.get("grpc-opts", {})
        if grpc:
            node.path = grpc.get("grpc-service-name", "")
        rel = p.get("reality-opts", {})
        if rel:
            node.reality_pbk = rel.get("public-key", "")
            node.reality_sid = rel.get("short-id", "")
        alpn_list = p.get("alpn_list", [])
        if alpn_list:
            node.alpn = ",".join(alpn_list)

    elif proto == "vmess":
        node.uuid = p.get("uuid", "")
        node.vmess_aid = p.get("alterId", 0)
        ws = p.get("ws-opts", {})
        if ws:
            node.path = ws.get("path", "")
            node.host = ws.get("Host", "")
        grpc = p.get("grpc-opts", {})
        if grpc:
            node.path = grpc.get("grpc-service-name", "")

    elif proto == "trojan":
        node.trojan_password = p.get("password", "")
        node.flow = p.get("flow", "")
        ws = p.get("ws-opts", {})
        if ws:
            node.path = ws.get("path", "")
            node.host = ws.get("Host", "")
        grpc = p.get("grpc-opts", {})
        if grpc:
            node.path = grpc.get("grpc-service-name", "")
        alpn_list = p.get("alpn_list", [])
        if alpn_list:
            node.alpn = ",".join(alpn_list)

    elif proto == "ss":
        node.ss_method = p.get("cipher", "")
        node.ss_password = p.get("password", "")

    return node


def _singbox_outbound_to_node(o: dict) -> Optional[Node]:
    """Convert a sing-box or Xray outbound entry to Node."""
    proto = o.get("type", "") or o.get("protocol", "")
    if not proto or proto in ("ssr", "selector", "urltest", "direct", "block", "dns", "freedom", "blackhole"):
        return None

    # Detect format: sing-box uses "server"/"server_port", Xray uses "settings.vnext"
    is_xray = "settings" in o and "streamSettings" in o

    if is_xray:
        return _xray_outbound_to_node(o, proto)

    node = Node(
        protocol=proto if proto != "shadowsocks" else "ss",
        address=o.get("server", ""),
        port=o.get("server_port", 0),
        name=o.get("tag", ""),
    )

    transport = o.get("transport", {})
    if transport:
        node.net = transport.get("type", "tcp")
        node.path = transport.get("path", "")
        headers = transport.get("headers", {})
        if headers:
            node.host = headers.get("Host", "")
        if not node.path:
            node.path = transport.get("service_name", "")

    tls = o.get("tls", {})
    if tls and tls.get("enabled"):
        node.tls = True
        node.sni = tls.get("server_name", "")
        node.alpn = ",".join(tls.get("alpn", [])) if isinstance(tls.get("alpn"), list) else tls.get("alpn", "")
        utls = tls.get("utls", {})
        if utls:
            node.fp = utls.get("fingerprint", "")
        reality = tls.get("reality", {})
        if reality:
            node.reality_pbk = reality.get("public_key", "")
            node.reality_sid = reality.get("short_id", "")

    if proto == "vless":
        node.uuid = o.get("uuid", "")
        node.flow = o.get("flow", "")
    elif proto == "vmess":
        node.uuid = o.get("uuid", "")
        node.vmess_aid = o.get("alter_id", 0)
        node.vmess_scy = o.get("security", "auto")
    elif proto == "trojan":
        node.trojan_password = o.get("password", "")
    elif proto in ("ss", "shadowsocks"):
        node.ss_method = o.get("method", "")
        node.ss_password = o.get("password", "")

    return node


def _xray_outbound_to_node(o: dict, proto: str) -> Optional[Node]:
    """Convert Xray-format outbound to Node."""
    if proto in ("freedom", "blackhole", "direct", "block", "dns"):
        return None
    settings = o.get("settings", {})
    stream = o.get("streamSettings", {})
    tag = o.get("tag", "")

    # Extract address/port from vnext (vless/vmess) or servers (trojan/ss)
    address = ""
    port = 0
    uuid = ""
    password = ""
    flow = ""
    method = ""

    vnext = settings.get("vnext", [])
    if vnext:
        address = vnext[0].get("address", "")
        port = vnext[0].get("port", 0)
        users = vnext[0].get("users", [])
        if users:
            uuid = users[0].get("id", "")
            flow = users[0].get("flow", "")
            encryption = users[0].get("encryption", "")

    servers = settings.get("servers", [])
    if servers:
        address = servers[0].get("address", "")
        port = servers[0].get("port", 0)
        users = servers[0].get("users", [])
        if users:
            uuid = users[0].get("id", "")
            password = users[0].get("password", "")
        method = servers[0].get("method", "")
        password = servers[0].get("password", "") or password

    # Shadowsocks in Xray
    if proto == "shadowsocks" or proto == "ss":
        ss_settings = settings.get("servers", [{}])[0] if servers else {}
        address = ss_settings.get("address", address)
        port = ss_settings.get("port", port)
        method = ss_settings.get("method", "")
        password = ss_settings.get("password", "")

    if not address:
        return None

    net = stream.get("network", "tcp")
    security = stream.get("security", "")

    node = Node(
        protocol="ss" if proto in ("shadowsocks", "ss") else proto,
        address=address,
        port=port,
        name=tag,
        uuid=uuid,
        net=net,
        flow=flow,
        trojan_password=password,
        ss_method=method,
        ss_password=password,
    )

    # TLS / Reality
    if security == "tls":
        node.tls = True
        tls_settings = stream.get("tlsSettings", {})
        node.sni = tls_settings.get("serverName", "")
        node.fp = tls_settings.get("fingerprint", "")
        alpn = tls_settings.get("alpn", [])
        if isinstance(alpn, list):
            node.alpn = ",".join(alpn)
    elif security == "reality":
        node.tls = True
        reality_settings = stream.get("realitySettings", {})
        node.sni = reality_settings.get("serverName", "")
        node.reality_pbk = reality_settings.get("publicKey", "")
        node.reality_sid = reality_settings.get("shortId", "")
        node.fp = reality_settings.get("fingerprint", "")

    # Transport path/host
    if net == "ws":
        ws_settings = stream.get("wsSettings", {})
        node.path = ws_settings.get("path", "")
        headers = ws_settings.get("headers", {})
        if headers:
            node.host = headers.get("Host", "")
    elif net == "grpc":
        grpc_settings = stream.get("grpcSettings", {})
        node.path = grpc_settings.get("serviceName", "")
    elif net == "h2":
        h2_settings = stream.get("httpSettings", {})
        node.path = h2_settings.get("path", "")
        host = h2_settings.get("host", [])
        if isinstance(host, list) and host:
            node.host = host[0]
    elif net == "xhttp":
        xhttp_settings = stream.get("xhttpSettings", {})
        node.path = xhttp_settings.get("path", "")

    return node


def from_singbox(json_text: str) -> list[Node]:
    """Parse sing-box JSON config → list of Nodes."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as e:
        raise ParseError(f"Invalid JSON: {e}")

    outbounds = data.get("outbounds", [])
    if not outbounds:
        raise ParseError("No outbounds found in sing-box config")

    nodes = []
    for o in outbounds:
        node = _singbox_outbound_to_node(o)
        if node:
            nodes.append(node)
    return nodes


def from_mihomo(yaml_text: str) -> list[Node]:
    """Parse mihomo YAML proxy list → list of Nodes."""
    proxies = _extract_yaml_proxies(yaml_text)
    if not proxies:
        raise ParseError("No proxies found in mihomo config")

    nodes = []
    for p in proxies:
        node = _yaml_proxy_to_node(p)
        if node:
            nodes.append(node)
    return nodes


def from_config(text: str) -> list[Node]:
    """Auto-detect config format (sing-box JSON / mihomo YAML / Xray JSON array) and parse."""
    text = text.strip()
    if not text:
        raise ParseError("Empty input")

    # Try JSON first
    if text.startswith("{"):
        return from_singbox(text)

    # Try JSON array (Xray config array from Happy Decoder proxy)
    if text.startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                nodes = []
                for item in arr:
                    if isinstance(item, dict):
                        # Wrap single config in array for from_singbox
                        nodes.extend(from_singbox(json.dumps(item)))
                return nodes
        except (json.JSONDecodeError, ParseError):
            pass

    # Try YAML
    if "proxies:" in text or text.startswith("- name:"):
        return from_mihomo(text)

    raise ParseError("Unknown config format — expected sing-box JSON or mihomo YAML")

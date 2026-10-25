"""Tests for core logic — parsers, converters, edge cases."""

import json

import pytest

from core.converters import Format, convert
from core.logic import (
    Node,
    ParseError,
    extract_country,
    fix_link,
    iter_parse_text,
    parse_hysteria2,
    parse_link,
    parse_socks,
    parse_ss,
    parse_text_input,
    parse_trojan,
    parse_vless,
    parse_vmess,
    sort_nodes_by_country,
)
from core.share import render_link

# ---------------------------------------------------------------------------
# fix_link
# ---------------------------------------------------------------------------

class TestFixLink:
    def test_vless_adds_type_raw(self):
        link = "vless://uuid@host:443?encryption=none#Name"
        fixed = fix_link(link)
        assert "type=raw" in fixed

    def test_vless_preserves_existing_type(self):
        link = "vless://uuid@host:443?encryption=none&type=ws#Name"
        fixed = fix_link(link)
        assert "type=ws" in fixed
        assert fixed.count("type=") == 1

    def test_vless_preserves_type_raw(self):
        link = "vless://uuid@host:443?encryption=none&type=raw#Name"
        fixed = fix_link(link)
        assert "type=raw" in fixed
        assert fixed.count("type=") == 1

    def test_vless_type_before_fragment(self):
        link = "vless://uuid@host:443?encryption=none#Name"
        fixed = fix_link(link)
        q, frag = fixed.split("#", 1)
        assert "type=raw" in q
        assert "Name" in frag

    def test_vless_ampersand_to_question(self):
        link = "vless://uuid@host:443&encryption=none#Name"
        fixed = fix_link(link)
        assert fixed.startswith("vless://uuid@host:443?")
        q = fixed.split("#")[0].split("?", 1)[1]
        assert "encryption=none" in q
        assert "type=raw" in q

    def test_vless_packet_encoding_normalize(self):
        link = "vless://uuid@host:443?packet-encoding=xudp#Name"
        fixed = fix_link(link)
        assert "packetEncoding=xudp" in fixed

    def test_trojan_ampersand_to_question(self):
        link = "trojan://pass@host:443&sni=example.com#Name"
        fixed = fix_link(link)
        assert fixed.startswith("trojan://pass@host:443?")

    def test_non_proxy_link_unchanged(self):
        assert fix_link("https://example.com") == "https://example.com"

    def test_empty_link(self):
        assert fix_link("") == ""

    def test_vless_fragment_without_query(self):
        fixed = fix_link("vless://uuid@host:443#Name")
        assert fixed == "vless://uuid@host:443?type=raw#Name"

    def test_vless_fragment_without_query_parses(self):
        node = parse_vless(fix_link("vless://uuid@host:443#Name"))
        assert node.port == 443
        assert node.name == "Name"


# ---------------------------------------------------------------------------
# parse_vless
# ---------------------------------------------------------------------------

VLESS_LINK = (
    "vless://555363ce-f418-0016-90da-c611c0b91af7@cloud.quattro-tech.ru:8443"
    "?encryption=none&type=tcp&security=reality"
    "&sni=cloud.quattro-tech.ru&fp=safari"
    "&pbk=10rVZPoOUP1TlQviIAsQ_jAROX0fRQxH0C92nq_zGQc"
    "&sid=43dcff53849b81e6&flow=xtls-rprx-vision"
    "#%F0%9F%87%A6%F0%9F%87%BF%20%D0%90%D0%B7%D0%B5%D1%80%D0%B1%D0%B0%D0%B9%D0%B4%D0%B6%D0%B0%D0%BD"
)


class TestParseVless:
    def test_basic(self):
        node = parse_vless(VLESS_LINK)
        assert node.protocol == "vless"
        assert node.uuid == "555363ce-f418-0016-90da-c611c0b91af7"
        assert node.address == "cloud.quattro-tech.ru"
        assert node.port == 8443
        assert node.net == "tcp"
        assert node.tls is True
        assert node.sni == "cloud.quattro-tech.ru"
        assert node.fp == "safari"
        assert node.reality_pbk == "10rVZPoOUP1TlQviIAsQ_jAROX0fRQxH0C92nq_zGQc"
        assert node.reality_sid == "43dcff53849b81e6"
        assert node.flow == "xtls-rprx-vision"
        assert "Азербайджан" in node.name

    def test_without_type(self):
        link = "vless://uuid@host:443?encryption=none#Test"
        node = parse_vless(link)
        assert node.net == "raw"

    def test_ws_transport(self):
        link = "vless://uuid@host:443?encryption=none&type=ws&path=%2Fws&host=example.com#WS"
        node = parse_vless(link)
        assert node.net == "ws"
        assert node.path == "/ws"
        assert node.host == "example.com"

    def test_grpc_transport(self):
        link = "vless://uuid@host:443?encryption=none&type=grpc&path=grpc#GRPC"
        node = parse_vless(link)
        assert node.net == "grpc"
        assert node.path == "grpc"

    def test_missing_host(self):
        with pytest.raises(ParseError):
            parse_vless("vless://uuid@:443?encryption=none")

    def test_missing_uuid(self):
        with pytest.raises(ParseError):
            parse_vless("vless://@host:443?encryption=none")


# ---------------------------------------------------------------------------
# parse_trojan
# ---------------------------------------------------------------------------

class TestParseTrojan:
    def test_basic(self):
        link = "trojan://password@host:443?sni=example.com#Trojan"
        node = parse_trojan(link)
        assert node.protocol == "trojan"
        assert node.trojan_password == "password"
        assert node.address == "host"
        assert node.port == 443
        assert node.sni == "example.com"
        assert node.name == "Trojan"

    def test_with_ampersand(self):
        link = "trojan://pass@host:443&sni=example.com#Name"
        node = parse_trojan(link)
        assert node.sni == "example.com"


# ---------------------------------------------------------------------------
# parse_vmess
# ---------------------------------------------------------------------------

class TestParseVmess:
    def test_basic(self):
        import base64
        import json
        payload = json.dumps({
            "v": "2", "ps": "Test", "add": "host", "port": "443",
            "id": "uuid-uuid-uuid-uuid-uuid-uuid-uuid-uuid",
            "aid": "0", "scy": "auto", "net": "tcp",
            "type": "", "host": "", "path": "", "tls": "", "sni": "", "alpn": "",
        })
        link = "vmess://" + base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        node = parse_vmess(link)
        assert node.protocol == "vmess"
        assert node.uuid == "uuid-uuid-uuid-uuid-uuid-uuid-uuid-uuid"
        assert node.address == "host"
        assert node.port == 443
        assert node.name == "Test"


# ---------------------------------------------------------------------------
# parse_ss
# ---------------------------------------------------------------------------

class TestParseSS:
    def test_sip002(self):
        import base64
        userinfo = base64.urlsafe_b64encode(b"chacha20:password").decode().rstrip("=")
        link = f"ss://{userinfo}@host:8388#SS"
        node = parse_ss(link)
        assert node.protocol == "ss"
        assert node.ss_method == "chacha20"
        assert node.ss_password == "password"
        assert node.address == "host"
        assert node.port == 8388
        assert node.name == "SS"


# ---------------------------------------------------------------------------
# parse_hysteria2
# ---------------------------------------------------------------------------

class TestParseHysteria2:
    def test_basic(self):
        link = "hysteria2://password@host:443?sni=example.com#H2"
        node = parse_hysteria2(link)
        assert node.protocol == "hysteria2"
        assert node.hysteria2_password == "password"
        assert node.address == "host"
        assert node.port == 443
        assert node.sni == "example.com"
        assert node.name == "H2"


# ---------------------------------------------------------------------------
# parse_socks
# ---------------------------------------------------------------------------

class TestParseSocks:
    def test_basic(self):
        link = "socks://user:pass@host:1080#SOCKS"
        node = parse_socks(link)
        assert node.protocol == "socks"
        assert node.address == "host"
        assert node.port == 1080
        assert node.socks_username == "user"
        assert node.socks_password == "pass"
        assert node.name == "SOCKS"

    def test_no_auth(self):
        link = "socks://host:1080"
        node = parse_socks(link)
        assert node.socks_username == ""
        assert node.socks_password == ""


# ---------------------------------------------------------------------------
# parse_text_input
# ---------------------------------------------------------------------------

class TestParseTextInput:
    def test_multiple_links(self):
        text = f"{VLESS_LINK}\n{VLESS_LINK}"
        nodes = parse_text_input(text)
        assert len(nodes) == 2
        assert all(n.protocol == "vless" for n in nodes)

    def test_skips_empty_and_comments(self):
        text = f"\n# comment\n{VLESS_LINK}\n\n"
        nodes = parse_text_input(text)
        assert len(nodes) == 1

    def test_mixed_errors(self):
        text = f"{VLESS_LINK}\nbad-link\n{VLESS_LINK}"
        nodes = parse_text_input(text)
        assert len(nodes) == 3
        assert nodes[0].protocol == "vless"
        assert nodes[1].protocol == "error"
        assert nodes[2].protocol == "vless"

    def test_out_of_range_port_does_not_kill_batch(self):
        text = f"{VLESS_LINK}\nvless://uuid@host:99999#Bad\n{VLESS_LINK}"
        nodes = parse_text_input(text)
        assert [n.protocol for n in nodes] == ["vless", "error", "vless"]

    def test_iter_parse_text(self):
        text = f"{VLESS_LINK}\n{VLESS_LINK}"
        nodes = list(iter_parse_text(text))
        assert len(nodes) == 2


# ---------------------------------------------------------------------------
# extract_country
# ---------------------------------------------------------------------------

class TestExtractCountry:
    def test_flag_emoji(self):
        assert extract_country("🇷🇺 Russia") == "RU"
        assert extract_country("🇺🇸 US Server") == "US"
        assert extract_country("🇩🇪 Germany") == "DE"
        assert extract_country("🇦🇿 Азербайджан") == "AZ"

    def test_no_flag(self):
        assert extract_country("Some Server") == "Other"
        assert extract_country("") == "Other"


    def test_flag_anywhere(self):
        assert extract_country("Frankfurt 🇩🇪") == "DE"

    def test_sort_nodes_by_country(self):
        nodes = [
            Node(protocol="vless", uuid="u1", address="1.1.1.1", port=443, name="🇺🇸 NY"),
            Node(protocol="vless", uuid="u2", address="2.2.2.2", port=443, name="Home"),
            Node(protocol="vless", uuid="u3", address="3.3.3.3", port=443, name="Frankfurt 🇩🇪"),
            Node(protocol="vless", uuid="u4", address="4.4.4.4", port=443, name="🇩🇪 Berlin"),
        ]
        assert [n.name for n in sort_nodes_by_country(nodes)] == [
            "Frankfurt 🇩🇪", "🇩🇪 Berlin", "🇺🇸 NY", "Home",
        ]

    def test_convert_sorts_all_formats(self):
        nodes = [
            Node(protocol="vless", uuid="u1", address="1.1.1.1", port=443, name="🇺🇸 NY"),
            Node(protocol="vless", uuid="u2", address="2.2.2.2", port=443, name="Home"),
            Node(protocol="vless", uuid="u3", address="3.3.3.3", port=443, name="🇩🇪 Berlin"),
        ]
        txt = convert(nodes, Format.TXT, group_by_country=True)
        assert txt.splitlines()[0].endswith("#%F0%9F%87%A9%F0%9F%87%AA%20Berlin")

# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------

class TestConverters:
    def test_singbox(self):
        nodes = [parse_vless(VLESS_LINK)]
        result = convert(nodes, Format.SINGBOX)
        assert '"outbounds"' in result
        assert '"vless"' in result

    def test_mihomo(self):
        nodes = [parse_vless(VLESS_LINK)]
        result = convert(nodes, Format.MIHOMO)
        assert "proxies:" in result
        assert "vless" in result

    def test_flclash(self):
        nodes = [parse_vless(VLESS_LINK)]
        result = convert(nodes, Format.FLCLASH)
        assert "proxies:" in result
        assert "mixed-port: 7890" in result
        assert "dns:" in result
        # Full FlClash config includes a select proxy-group
        assert "proxy-groups" in result
        assert "rules" in result
        assert "🔰 PROXY" in result

    def test_flclash_dedup_names(self):
        link1 = "vless://uuid@host:443?encryption=none#Same"
        link2 = "vless://uuid2@host2:443?encryption=none#Same"
        nodes = parse_text_input(link1 + "\n" + link2)
        result = convert(nodes, Format.FLCLASH)
        assert "proxies:" in result
        assert "-1" in result or "-2" in result  # dedup suffix

    def test_txt(self):
        nodes = [parse_vless(VLESS_LINK)]
        result = convert(nodes, Format.TXT)
        assert result.startswith("vless://")
        assert "type=tcp" in result

    def test_xray(self):
        nodes = [parse_vless(VLESS_LINK)]
        result = convert(nodes, Format.XRAY)
        data = json.loads(result)
        assert "outbounds" in data
        assert "routing" in data
        assert "dns" in data
        assert "inbounds" in data
        assert "burstObservatory" in data
        # Check proxy outbound (tag = node display_name)
        proxy = next(o for o in data["outbounds"] if o["protocol"] == "vless")
        assert "vnext" in proxy["settings"]
        # Check direct/block
        tags = [o["tag"] for o in data["outbounds"]]
        assert "direct" in tags
        assert "block" in tags

    def test_xray_with_reality(self):
        link = VLESS_LINK  # has reality
        nodes = [parse_vless(link)]
        result = convert(nodes, Format.XRAY)
        data = json.loads(result)
        proxy = next(o for o in data["outbounds"] if o["protocol"] == "vless")
        assert proxy["streamSettings"]["security"] == "reality"
        assert "realitySettings" in proxy["streamSettings"]

    def test_xray_shadowsocks_protocol_and_settings(self):
        """Xray names the protocol "shadowsocks"; servers carry method/password."""
        nodes = [parse_ss("ss://YWVzLTI1Ni1nY206cGFzcw==@s.com:8388#S1")]
        proxy = next(
            o for o in json.loads(convert(nodes, Format.XRAY))["outbounds"] if o["tag"] == "S1"
        )
        assert proxy["protocol"] == "shadowsocks"
        server = proxy["settings"]["servers"][0]
        assert server["method"] == "aes-256-gcm"
        assert server["password"] == "pass"
        assert "users" not in server

    def test_xray_hysteria2_maps_to_hysteria(self):
        """Xray names it "hysteria" (v2), flat settings, auth in streamSettings."""
        nodes = [parse_hysteria2("hysteria2://pass@h.com:443/?sni=h.com#H1")]
        proxy = next(
            o for o in json.loads(convert(nodes, Format.XRAY))["outbounds"] if o["tag"] == "H1"
        )
        assert proxy["protocol"] == "hysteria"
        assert proxy["settings"] == {"version": 2, "address": "h.com", "port": 443}
        stream = proxy["streamSettings"]
        assert stream["network"] == "hysteria"
        assert stream["hysteriaSettings"]["auth"] == "pass"
        assert stream["security"] == "tls"

    def test_xray_vmess_has_no_alter_id(self):
        """alterId is not part of Xray's VMessAccount schema."""
        import base64

        payload = base64.b64encode(
            json.dumps(
                {
                    "v": "2", "ps": "M", "add": "v.com", "port": "443",
                    "id": "00000000-0000-0000-0000-000000000000",
                    "aid": 0, "scy": "auto", "net": "tcp",
                }
            ).encode()
        ).decode()
        proxy = next(
            o for o in json.loads(convert([parse_vmess(f"vmess://{payload}")], Format.XRAY))["outbounds"]
            if o["protocol"] == "vmess"
        )
        user = proxy["settings"]["vnext"][0]["users"][0]
        assert "alterId" not in user
        assert user["security"] == "auto"

    def test_xray_burst_observatory_has_ping_config(self):
        """Xray refuses burstObservatory without pingConfig."""
        data = json.loads(convert([parse_vless(VLESS_LINK)], Format.XRAY))
        assert "pingConfig" in data["burstObservatory"]

    def test_empty_nodes(self):
        with pytest.raises(ParseError):
            convert([], Format.SINGBOX)

# render_link round-trip

class TestRoundTrip:
    def test_vless_round_trip(self):
        node = parse_vless(VLESS_LINK)
        link = render_link(node)
        node2 = parse_vless(link)
        assert node.uuid == node2.uuid
        assert node.address == node2.address
        assert node.port == node2.port
        assert node.name == node2.name

    def test_vmess_round_trip(self):
        node = Node(protocol="vmess", uuid="11111111-2222-3333-4444-555555555555",
                    address="vm.example.com", port=443, name="VM 🇩🇪",
                    net="ws", tls=True, sni="vm.example.com", path="/ws",
                    vmess_aid=0, vmess_scy="auto")
        node2 = parse_link(render_link(node))
        assert (node2.protocol, node2.address, node2.port, node2.name) == (
            "vmess", "vm.example.com", 443, "VM 🇩🇪")
        assert node2.uuid == node.uuid
        assert node2.net == "ws"
        assert node2.tls is True
        assert node2.path == "/ws"

    def test_ssr_round_trip(self):
        node = Node(protocol="ssr", address="ssr.example.com", port=8388,
                    name="SSR node", ss_method="aes-256-cfb",
                    ss_password="secret", ssr_protocol="origin",
                    ssr_obfs="plain", ssr_protocol_param="",
                    ssr_obfs_param="")
        node2 = parse_link(render_link(node))
        assert (node2.address, node2.port, node2.name) == (
            "ssr.example.com", 8388, "SSR node")
        assert node2.ss_method == "aes-256-cfb"
        assert node2.ss_password == "secret"

    def test_socks_with_auth_round_trip(self):
        node = Node(protocol="socks", address="s.example.com", port=1080,
                    name="Socks", socks_username="user",
                    socks_password="p@ss:word")
        node2 = parse_link(render_link(node))
        assert (node2.socks_username, node2.socks_password) == (
            "user", "p@ss:word")

    def test_txt_includes_every_supported_protocol(self):
        nodes = [
            Node(protocol="vmess", uuid="u", address="a", port=443),
            Node(protocol="ssr", address="b", port=8388, ss_method="rc4-md5",
                 ss_password="x"),
            Node(protocol="socks", address="c", port=1080),
            Node(protocol="error", name="bad"),
        ]
        txt = convert(nodes, Format.TXT)
        assert [line.split("://")[0] for line in txt.splitlines()] == [
            "vmess", "ssr", "socks"]

    def test_txt_links_reparse(self):
        nodes = [parse_vless(VLESS_LINK), parse_trojan("trojan://p@t.example:443#T"),
                 parse_ss("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388#S")]
        reparsed = [parse_link(line) for line in convert(nodes, Format.TXT).splitlines()]
        assert [n.protocol for n in reparsed] == ["vless", "trojan", "ss"]
        assert [n.name for n in reparsed] == [n.name for n in nodes]

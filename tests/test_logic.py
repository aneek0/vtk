"""Tests for core logic — parsers, converters, edge cases."""

import json
import pytest
from core.logic import (
    Node, ParseError, fix_link, parse_vless, parse_vmess, parse_trojan,
    parse_ss, parse_ssr, parse_hysteria2, parse_socks,
    parse_text_input, parse_link, extract_country, iter_parse_text,
)
from core.converters import convert, Format


# ---------------------------------------------------------------------------
# fix_link
# ---------------------------------------------------------------------------

class TestFixLink:
    def test_vless_adds_type_tcp(self):
        link = "vless://uuid@host:443?encryption=none#Name"
        fixed = fix_link(link)
        assert "type=tcp" in fixed

    def test_vless_preserves_existing_type(self):
        link = "vless://uuid@host:443?encryption=none&type=ws#Name"
        fixed = fix_link(link)
        assert "type=ws" in fixed
        assert fixed.count("type=") == 1

    def test_vless_type_before_fragment(self):
        link = "vless://uuid@host:443?encryption=none#Name"
        fixed = fix_link(link)
        q, frag = fixed.split("#", 1)
        assert "type=tcp" in q
        assert "Name" in frag

    def test_vless_ampersand_to_question(self):
        link = "vless://uuid@host:443&encryption=none#Name"
        fixed = fix_link(link)
        assert fixed.startswith("vless://uuid@host:443?")
        q = fixed.split("#")[0].split("?", 1)[1]
        assert "encryption=none" in q
        assert "type=tcp" in q

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
        assert node.net == "tcp"

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
        import base64, json
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
        assert "mixed-port: 7890" in result
        assert "proxy-groups:" in result

    def test_flclash_group_by_country(self):
        link_ru = "vless://uuid@host:443?encryption=none#%F0%9F%87%B7%F0%9F%87%BA%20Russia"
        link_us = "vless://uuid@host:443?encryption=none#%F0%9F%87%BA%F0%9F%87%B8%20USA"
        nodes = [parse_vless(link_ru), parse_vless(link_us)]
        result = convert(nodes, Format.FLCLASH, group_by_country=True)
        assert "RU" in result
        assert "US" in result

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
        proxy = [o for o in data["outbounds"] if o["protocol"] == "vless"][0]
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
        proxy = [o for o in data["outbounds"] if o["protocol"] == "vless"][0]
        assert proxy["streamSettings"]["security"] == "reality"
        assert "realitySettings" in proxy["streamSettings"]

    def test_empty_nodes(self):
        with pytest.raises(ParseError):
            convert([], Format.SINGBOX)


# ---------------------------------------------------------------------------
# Node.to_vless_link round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    def test_vless_round_trip(self):
        node = parse_vless(VLESS_LINK)
        link = node.to_vless_link()
        node2 = parse_vless(link)
        assert node.uuid == node2.uuid
        assert node.address == node2.address
        assert node.port == node2.port
        assert node.name == node2.name

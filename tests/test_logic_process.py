"""Tests for the centralized core entry point.

Covers ``core.logic.decrypt_input`` and ``core.logic.process_input`` — the
single unified path that bot / web / CLI now route through. Verifies that
``incy://`` / ``happ://`` wrappers are decrypted *before* input-type
detection so the embedded protocol payloads reach the parser (the bug that
motivated the refactor).
"""

import asyncio
import base64
import json

import pytest

from core.logic import decrypt_input, process_input


@pytest.fixture
def incy_vectors():
    return json.load(open("data/incy_vectors.json"))


def test_decrypt_input_incy(incy_vectors):
    """A real incy://crypt1 link decrypts to its original URL (offline)."""
    link = incy_vectors["links"][0]["link"]
    out = decrypt_input(link)
    assert out == incy_vectors["links"][0]["url"]


def test_decrypt_input_happ_passthrough():
    """happ://add/<url> resolves to the inner URL; plain text is untouched."""
    url = "https://sub.example.com/abc"
    assert decrypt_input(f"happ://add/{url}") == url
    # Already-plain input passes through unchanged (idempotent).
    assert decrypt_input("vless://abc@example.com:443#n") == "vless://abc@example.com:443#n"


def test_decrypt_input_swallows_per_link_errors():
    """An undecodable encrypted token does not raise — it is left as-is."""
    bad = "incy://crypt1/!!!!not-valid!!!!"
    assert decrypt_input(bad) == bad


def test_process_input_incy_share(incy_vectors):
    """An incy link wrapping plain share links converts without any network."""
    link = incy_vectors["links"][0]["link"]
    # The wrapped payload in the fixture is a subscription URL, so use a
    # hand-built plain-share incy payload path via decrypt_text instead:
    from core.incy import decrypt_text
    share = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls#Test"
    enc = None
    try:
        from incy_link_encoder import encryptLink
        enc = encryptLink(share, {"name": "t"})
    except Exception:
        pytest.skip("official incy package not installed")
    assert decrypt_text(enc) == share
    res = asyncio.run(process_input(enc, fmt="txt"))
    assert res["ok"] is True
    assert "vless://" in res["result"]
    assert res["nodes"] == 1
    assert res["servers"][0]["protocol"] == "vless"


def test_process_input_incy_sub(monkeypatch, incy_vectors):
    """An incy link wrapping a subscription URL: decrypt -> fetch (mocked)
    -> parse -> converts to the requested format."""
    payload = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&type=ws#FakeSub"
    b64 = base64.b64encode(payload.encode()).decode()

    async def _fake(url, timeout=15, return_headers=False, headers=None):
        if return_headers:
            return {"content": b64, "headers": []}
        return b64

    monkeypatch.setattr("core.logic.fetch_subscription", _fake)

    link = incy_vectors["links"][0]["link"]
    res = asyncio.run(process_input(link, fmt="txt"))
    assert res["ok"] is True
    assert "vless://" in res["result"]
    assert res["nodes"] == 1
    assert res["input_type"] == "sub"
    # The mock returned the *decrypted* URL; sub_name is derived from the URL path.
    assert res["sub_name"] == "abc123token"


def test_process_input_config_from_json():
    """An Xray/sing-box JSON config is detected and reverse-converted to txt."""
    cfg = json.dumps({
        "outbounds": [{
            "type": "vless", "tag": "t",
            "server": "example.com", "server_port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555",
            "tls": {"enabled": True},
        }],
    })
    res = asyncio.run(process_input(cfg, fmt="txt"))
    assert res["ok"] is True
    assert res["input_type"] == "config"
    assert "vless://" in res["result"]


def test_process_input_no_nodes_errors():
    """Unparseable input yields ok=False (front-end contract: no 500)."""
    res = asyncio.run(process_input("this is not a proxy link at all"))
    assert res["ok"] is False
    assert "error" in res

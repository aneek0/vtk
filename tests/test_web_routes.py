"""Tests for web routes — device header injection, /p/ passthrough, /api/device/random.

Uses FastAPI TestClient with httpx.AsyncClient mocked to avoid real network.
"""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    captured = {}

    class _Resp:
        def __init__(self, text):
            self.text = text
            self.headers = {}

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None, **k):
            captured["url"] = url
            captured["headers"] = headers
            return _Resp("vless://uuid@host:443?encryption=none#Node1\n")

    monkeypatch.setattr("httpx.AsyncClient", _Client)
    import web.main as main
    return TestClient(main.app), captured


def test_device_random(client):
    c, _ = client
    r = c.get("/api/device/random")
    assert r.status_code == 200
    d = r.json()
    assert set(d.keys()) == {"os", "ua", "ver", "model", "locale", "hwid"}


def test_convert_injects_device_headers(client):
    c, cap = client
    r = c.post("/api/convert", json={
        "input": "https://sub.example.com/x",
        "format": "txt",
        "device_on": True,
        "device": {"os": "android", "ua": "Happ/3.26.0", "hwid": "abc123", "ver": "3.8.13", "model": "Pixel 8", "locale": "ru_RU"},
    })
    assert r.status_code == 200
    assert cap["headers"]["User-Agent"] == "Happ/3.26.0"
    assert cap["headers"]["X-Hwid"] == "hd-" + __import__("hashlib").md5(b"abc123").hexdigest()[:12]
    assert cap["headers"]["X-Device-Os"] == "Android"
    assert cap["headers"]["X-Device-Model"] == "Pixel 8"
    assert cap["headers"]["Accept-Language"] == "ru-RU"


def test_convert_no_headers_when_off(client):
    c, cap = client
    r = c.post("/api/convert", json={
        "input": "https://sub.example.com/x",
        "format": "txt",
        "device_on": False,
        "device": {"ua": "Happ/3.26.0", "hwid": "abc"},
    })
    assert r.status_code == 200
    assert cap["headers"] is None


def test_proxy_passthrough_regression(client):
    c, cap = client
    r = c.get("/p/android,ua=Happ/3.24.1/https://sub.example.com/x")
    assert r.status_code == 200
    assert cap["url"] == "https://sub.example.com/x"
    assert cap["headers"]["User-Agent"] == "Happ/3.24.1"
    assert cap["headers"]["X-Device-Os"] == "Android"


def test_convert_incy_link_end_to_end(client):
    """An incy://crypt1 deep link should auto-decrypt, fetch the embedded
    subscription (mocked), and convert to the requested format."""
    import json
    vectors = json.load(open("data/incy_vectors.json"))
    link = vectors["links"][0]["link"]
    c, cap = client
    r = c.post("/api/convert", json={"input": link, "format": "txt"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["ok"] is True
    # The mock httpx client returns a vless link for any fetched URL.
    assert "vless://" in d["result"]
    assert cap.get("url") == vectors["links"][0]["url"]


def test_convert_incy_plain_share_links(client):
    """When the incy link embeds plain share links (not a URL), they convert
    directly without a network fetch."""
    try:
        from incy_link_encoder import encryptLink
    except Exception:
        pytest.skip("official incy package not installed in test env")
    share = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls#Test"
    link = encryptLink(share, {"name": "t"})
    r = client[0].post("/api/convert", json={"input": link, "format": "txt"})
    assert r.status_code == 200, r.text
    assert "vless://" in r.json()["result"]

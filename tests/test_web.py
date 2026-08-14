"""Tests for web frontend — template rendering, API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from web.main import app

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


VLESS = "vless://info@104.26.14.71:2053?encryption=none&security=tls&type=ws&host=x.com&path=/"


# ── Template rendering ──

class TestTemplates:
    async def _check_page(self, client, path, tab_name):
        r = await client.get(path)
        assert r.status_code == 200
        assert "VTK" in r.text
        assert f'id="tab-{tab_name}"' in r.text
        return r

    async def test_home(self, client):
        await self._check_page(client, "/", "convert")

    async def test_convert_page(self, client):
        r = await self._check_page(client, "/convert", "convert")
        assert "convertInput" in r.text
        assert "convertFormat" in r.text
        assert "tagPrefix" in r.text

    async def test_proxy_page(self, client):
        r = await self._check_page(client, "/proxy", "proxy")
        assert "proxyUrl" in r.text
        assert "proxyUa" in r.text
        assert "proxyFormat" in r.text
        assert "as-is (raw)" in r.text

    async def test_decrypt_page(self, client):
        r = await self._check_page(client, "/decrypt", "decrypt")
        assert "decryptInput" in r.text
        assert "DECRYPT URL" in r.text or "DECRYPT" in r.text

    async def test_api_page(self, client):
        r = await self._check_page(client, "/api", "api")
        assert "Rate Limiting" in r.text or "10 req/min" in r.text

    async def test_health(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "uptime" in data

    async def test_favicon(self, client):
        r = await client.get("/convert")
        assert 'rel="icon"' in r.text
        assert "svg" in r.text

    async def test_theme_toggle(self, client):
        r = await client.get("/convert")
        assert 'id="themeToggle"' in r.text

    async def test_custom_select_markup(self, client):
        # The custom select JS creates cs-wrap etc. dynamically in the browser,
        # but the native <select> tags must be present in the template.
        r = await client.get("/convert")
        assert "<select" in r.text
        assert 'id="convertFormat"' in r.text

    async def test_spinner_css(self, client):
        r = await client.get("/static/style.css")
        assert r.status_code == 200
        assert ".spinner" in r.text

    async def test_app_js(self, client):
        r = await client.get("/static/app.js")
        assert r.status_code == 200
        assert "proxyQR" in r.text
        assert "apiPost" in r.text
        assert "apiGet" in r.text
        assert "initSelects" in r.text
        assert "initTheme" in r.text
        assert "initDragDrop" in r.text


# ── API endpoints ──

class TestAPI:
    async def test_convert_post(self, client):
        r = await client.post("/api/convert", json={"input": VLESS, "format": "singbox"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["nodes"] == 1
        assert "outbounds" in data["result"]

    async def test_convert_get(self, client):
        r = await client.get(f"/api/convert?input={VLESS}&format=singbox")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["nodes"] == 1

    async def test_convert_bad_format(self, client):
        r = await client.post("/api/convert", json={"input": VLESS, "format": "invalid"})
        assert r.status_code == 400
        data = r.json()
        assert data["ok"] is False

    async def test_convert_empty(self, client):
        r = await client.post("/api/convert", json={"input": "", "format": "singbox"})
        assert r.status_code == 400

    async def test_convert_mihomo(self, client):
        r = await client.post("/api/convert", json={"input": VLESS, "format": "mihomo"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "proxies:" in data["result"]

    async def test_convert_txt(self, client):
        r = await client.post("/api/convert", json={"input": VLESS, "format": "txt"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["result"].startswith("vless://")

    async def test_check(self, client):
        r = await client.get(f"/api/check?link={VLESS}")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["protocol"] == "vless"

    async def test_check_bad(self, client):
        r = await client.get("/api/check?link=invalid://xx")
        assert r.status_code == 400
        data = r.json()
        assert data["ok"] is False

    async def test_extract(self, client):
        body = '{"outbounds": [{"type": "vless", "tag": "t1", "server": "1.2.3.4", "server_port": 443, "uuid": "abc"}]}'
        r = await client.get(f"/api/extract?input={body}")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["nodes"] >= 1

    async def test_happ_supported(self, client):
        r = await client.get("/api/happ/supported")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "crypt5_keys" in data


# ── Proxy endpoint ──

class TestProxy:
    async def test_proxy_bad_url(self, client):
        """Should fail with 502 / 400, not a streaming error."""
        r = await client.get("/p/android/https://nonexistent.example.com/sub")
        assert r.status_code in (400, 502)
        assert "streamed" not in r.text

    async def test_proxy_no_url(self, client):
        r = await client.get("/p/android/")
        assert r.status_code == 400

    async def test_proxy_rate_limit(self, client):
        """Second immediate request from the same IP should be rate limited."""
        target = "https://nonexistent.example.com/sub"
        r1 = await client.get(f"/p/android/{target}")
        assert r1.status_code in (400, 502)  # first request passes the limiter
        r2 = await client.get(f"/p/android/{target}")
        assert r2.status_code == 429
        assert r2.headers.get("Retry-After") == "1"

"""End-to-end tests for the Telegram bot message pipeline.

These drive ``bot.main._process_input`` directly with a faked ``Message`` and
a mocked ``core.logic.process_input``. They cover the regression where
``decrypt_input`` was referenced but never imported (so every message raised
``NameError`` and the bot reacted to nothing), plus the main workflows, edge
cases, and failure modes of the link handler.
"""

import asyncio
from collections import defaultdict
from unittest.mock import AsyncMock

import pytest

import bot.main as botmod
from core.settings import Settings, save_settings


class FakeMessage:
    """Minimal stand-in for ``aiogram.types.Message``.

    ``reply`` returns a status object exposing ``edit_text`` so the bot's
    "Fetching subscription..." -> "✅ N nodes" flow is exercised.
    """

    def __init__(self):
        self.replies = []
        self.documents = []
        self.status = None

    async def reply(self, text=None, **kwargs):
        msg = FakeStatus(text)
        self.replies.append(msg)
        # The first reply for a detected subscription becomes the live status
        # message that is later edited in place.
        if self.status is None and "⏳" in (text or ""):
            self.status = msg
        return msg

    async def reply_document(self, document, **kwargs):
        self.documents.append((document, kwargs))
        return FakeStatus("doc")


class FakeStatus:
    def __init__(self, text):
        self.text = text
        self.edited = None

    async def edit_text(self, text, **kwargs):
        self.edited = text
        self.text = text
        return self


def _make_process_input_result(ok=True, **over):
    base = {
        "ok": ok,
        "nodes": 1,
        "result": "output-content",
        "sub_name": "",
        "content": "{}",
        "format": "singbox",
        "input_type": "link",
        "error": "",
    }
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _fresh_settings(tmp_path, monkeypatch):
    """Isolate settings so the app-link import / passthrough don't leak."""
    cfg = tmp_path / "settings.json"
    monkeypatch.setattr(botmod, "load_settings", lambda: Settings())
    monkeypatch.setattr(botmod, "save_settings", lambda s: None)
    monkeypatch.setattr(botmod, "_user_timestamps", defaultdict(list))
    return cfg


@pytest.fixture
def fake_msg():
    return FakeMessage()


# ---------------------------------------------------------------------------
# Regression: decrypt_input must not raise NameError on any input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none#n",
    "https://sub.example.com/abc",
    "happ://add/https://sub.example.com",
    "# random yaml-ish\nproxies:\n  - name: x",
])
def test_process_input_does_not_raise_on_any_input(monkeypatch, fake_msg, text):
    """The refactoring regression: decrypt_input was unimported -> NameError."""
    captured = {}

    async def fake_process(raw, **kwargs):
        captured["raw"] = raw
        return _make_process_input_result()

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, text))
    assert fake_msg.replies  # bot produced some output


# ---------------------------------------------------------------------------
# Main workflows
# ---------------------------------------------------------------------------

def test_workflow_single_link(monkeypatch, fake_msg):
    async def fake_process(raw, **kwargs):
        return _make_process_input_result(
            nodes=1, result="vless://...", format="singbox", input_type="link"
        )

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, "vless://a@b:443#n"))
    # Short result -> inline <pre> reply, no file.
    assert any("<pre>" in (r.text or "") for r in fake_msg.replies)
    assert not fake_msg.documents


def test_workflow_subscription_shows_status_then_ok(monkeypatch, fake_msg):
    async def fake_process(raw, **kwargs):
        return _make_process_input_result(
            nodes=3, sub_name="MySub", format="mihomo", input_type="sub"
        )

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, "https://sub.example.com/feed"))
    # Status message posted (⏳) and later edited to ✅ ... converting.
    assert fake_msg.status is not None
    assert "✅" in (fake_msg.status.edited or "")


def test_workflow_config_to_file(monkeypatch, fake_msg):
    big = "-" * 5000  # exceeds 3000-char inline threshold

    async def fake_process(raw, **kwargs):
        return _make_process_input_result(
            nodes=2, result=big, format="flclash", input_type="config"
        )

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, "proxies:\n  - name: x"))
    assert fake_msg.documents  # large YAML always sent as file


def test_workflow_empty_result_reports_error(monkeypatch, fake_msg):
    async def fake_process(raw, **kwargs):
        return _make_process_input_result(nodes=0, result="   ")

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, "vless://a@b:443#n"))
    assert any("Empty result" in (r.text or "") for r in fake_msg.replies)


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

def test_failure_process_input_not_ok(monkeypatch, fake_msg):
    async def fake_process(raw, **kwargs):
        return _make_process_input_result(ok=False, error="boom")

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, "https://sub.example.com/x"))
    assert any("❌ boom" in (r.text or "") for r in fake_msg.replies)


def test_failure_sub_error_edits_status(monkeypatch, fake_msg):
    async def fake_process(raw, **kwargs):
        return _make_process_input_result(ok=False, error="fetch failed", input_type="sub")

    monkeypatch.setattr(botmod, "process_input", fake_process)
    asyncio.run(botmod._process_input(fake_msg, "https://sub.example.com/x"))
    assert fake_msg.status is not None
    assert "❌ fetch failed" == (fake_msg.status.edited or "").strip()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_edge_incy_link_decrypted_before_detection(monkeypatch, fake_msg):
    """An encrypted wrapper that decrypts to a subscription URL must be
    detected as a sub (and show the fetching status message)."""
    captured = {}

    async def fake_process(raw, **kwargs):
        captured["raw"] = raw
        return _make_process_input_result(input_type="sub", sub_name="Dec")

    monkeypatch.setattr(botmod, "process_input", fake_process)
    # happ://add/<url> is a real decryptable wrapper resolving to a sub URL.
    asyncio.run(botmod._process_input(fake_msg, "happ://add/https://sub.example.com/feed"))
    # decrypt_input ran on the wrapper -> detected as sub -> status shown.
    assert fake_msg.status is not None


def test_edge_app_link_import_sets_headers(monkeypatch, fake_msg):
    """A pasted /p/<params>/<url> app-link imports device params + unwraps."""
    captured = {}
    params = "android,ver=3.8.13,model=OnePlus%20Open,ua=Happ/3.26.0,locale=ja_JP,hwid=8ddcfe6b"
    target = "https://sub.example.com/feed"

    async def fake_process(raw, **kwargs):
        captured["raw"] = raw
        captured["device_headers"] = kwargs.get("device_headers")
        return _make_process_input_result(input_type="sub")

    monkeypatch.setattr(botmod, "process_input", fake_process)
    link = f"https://anything.host/p/{params}/{target}"
    asyncio.run(botmod._process_input(fake_msg, link))

    assert captured["raw"] == target  # unwrapped to the inner URL
    assert any("Imported device params" in (r.text or "") for r in fake_msg.replies)
    assert captured["device_headers"]  # headers now populated


def test_edge_rate_limit_blocks_after_threshold(monkeypatch, fake_msg):
    async def fake_process(raw, **kwargs):
        return _make_process_input_result()

    monkeypatch.setattr(botmod, "process_input", fake_process)
    uid = 42
    # 3 messages allowed, 4th blocked within the window.
    assert botmod._check_rate_limit(uid) is True
    assert botmod._check_rate_limit(uid) is True
    assert botmod._check_rate_limit(uid) is True
    assert botmod._check_rate_limit(uid) is False


def test_edge_passthrough_sends_proxy_url(monkeypatch, fake_msg):
    """sub_passthrough ON: still fetches but also returns proxy link + raw file."""
    captured = {}

    async def fake_process(raw, **kwargs):
        captured["raw"] = raw
        return _make_process_input_result(
            input_type="sub", sub_name="MySub",
            sub_url="https://sub.example.com/feed",
        )

    monkeypatch.setattr(botmod, "process_input", fake_process)
    settings = Settings()
    settings.sub_passthrough = True
    monkeypatch.setattr(botmod, "load_settings", lambda: settings)
    asyncio.run(botmod._process_input(fake_msg, "https://sub.example.com/feed"))
    assert any("Proxy link" in (r.text or "") for r in fake_msg.replies)
    # Raw proxy JSON also attached as a document.
    assert any("Raw proxy JSON" in kw.get("caption", "") for _, kw in fake_msg.documents)

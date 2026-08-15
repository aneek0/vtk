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
        msg.reply_markup = kwargs.get("reply_markup")
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
        self.reply_markup = None

    async def edit_text(self, text, **kwargs):
        self.edited = text
        self.text = text
        self.reply_markup = kwargs.get("reply_markup")
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


# ---------------------------------------------------------------------------
# Real integration: drive the actual core.logic.process_input (only HTTP mocked)
# ---------------------------------------------------------------------------

import base64 as _b64

_LINK = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=tls&type=ws&path=%2Fwss#US-Node"


def test_real_integration_single_link_through_core(monkeypatch, fake_msg):
    """The full pipeline: decrypt -> detect -> parse -> convert to singbox,
    with the *real* core.logic.process_input. HTTP is not involved here."""
    # Use default settings (link_format=SINGBOX) so the result is deterministic
    # regardless of any on-disk settings.json.
    monkeypatch.setattr("core.settings.load_settings", lambda: Settings())
    asyncio.run(botmod._process_input(fake_msg, _LINK))
    # Result should be real sing-box JSON produced by the core converter.
    pre = next(r for r in fake_msg.replies if (r.text or "").startswith("<pre>"))
    body = pre.text.replace("<pre>", "").replace("</pre>", "")
    assert '"outbounds"' in body
    assert "US-Node" in body
    assert not fake_msg.documents


def test_real_integration_subscription_fetch_mocked(monkeypatch, fake_msg):
    """Subscription path through the real core: fetch mocked at the HTTP layer
    so we still exercise parsing/conversion/format selection end-to-end."""
    # Default settings -> sub_format=MIHOMO (YAML), deterministic output.
    monkeypatch.setattr("core.settings.load_settings", lambda: Settings())
    payload = _b64.b64encode(f"vless://aaaa@9.9.9.9:443?encryption=none#SubNode".encode()).decode()

    async def _fake_fetch(url, timeout=15, return_headers=False, headers=None):
        if return_headers:
            return {"content": payload, "headers": {}}
        return payload

    monkeypatch.setattr("core.logic.fetch_subscription", _fake_fetch)

    asyncio.run(botmod._process_input(fake_msg, "https://sub.example.com/feed"))
    # Status message must be shown (detected as sub) and later marked done.
    assert fake_msg.status is not None
    assert "✅" in (fake_msg.status.edited or "")
    # Output (mihomo YAML) exceeds the inline threshold, so it is sent as a
    # file; the parsed node must appear in that document.
    file_contents = " ".join(
        (d.data.decode() if hasattr(d, "data") else str(d)) for d, _ in fake_msg.documents
    )
    assert "SubNode" in file_contents


def test_real_integration_unparseable_input_reports_error(monkeypatch, fake_msg):
    """Garbage that core cannot parse must surface as a user-facing error, not
    crash the handler."""
    monkeypatch.setattr("core.settings.load_settings", lambda: Settings())
    asyncio.run(botmod._process_input(fake_msg, "this is not a proxy at all !!!"))
    assert any("❌" in (r.text or "") for r in fake_msg.replies)


# ---------------------------------------------------------------------------
# Real dispatch surface: handle_text / handle_document (the handlers the
# regression actually broke) + router wiring
# ---------------------------------------------------------------------------

class FakeUser:
    def __init__(self, uid=7):
        self.id = uid


class FakeBot:
    def __init__(self, file_bytes=b""):
        self._file_bytes = file_bytes
        self.calls = []

    async def get_file(self, file_id):
        self.calls.append(("get_file", file_id))
        return type("F", (), {"file_path": f"/dl/{file_id}"})()

    async def download_file(self, path):
        self.calls.append(("download_file", path))
        data = self._file_bytes
        return type("C", (), {"read": lambda self=None: data})()


def _msg_with(text, uid=7):
    m = FakeMessage()
    m.text = text
    m.from_user = FakeUser(uid)
    m.bot = FakeBot()
    return m


def test_dispatch_handle_text_invokes_pipeline(monkeypatch):
    """The real text handler must call _process_input (the regression path)."""
    seen = {}

    async def spy(message, text):
        seen["text"] = text

    monkeypatch.setattr(botmod, "_process_input", spy)
    msg = _msg_with("vless://a@b:443#n")
    asyncio.run(botmod.handle_text(msg))
    assert seen.get("text") == "vless://a@b:443#n"


def test_dispatch_handle_text_rate_limited(monkeypatch):
    """After exceeding the rate limit, the handler replies with a throttle
    message and does NOT reach _process_input."""
    reached = {"process": False}
    monkeypatch.setattr(botmod, "_user_timestamps", defaultdict(list))

    async def spy(message, text):
        reached["process"] = True

    monkeypatch.setattr(botmod, "_process_input", spy)
    uid = 99
    # 3 allowed, 4th blocked.
    for _ in range(3):
        asyncio.run(botmod.handle_text(_msg_with("x", uid=uid)))
    assert reached["process"] is True
    reached["process"] = False
    asyncio.run(botmod.handle_text(_msg_with("x", uid=uid)))
    assert reached["process"] is False


def test_dispatch_handle_document_decodes_and_routes(monkeypatch):
    """Uploaded file content is read and handed to _process_input."""
    seen = {}
    content = "vless://feed@host:443#FromFile\n"

    async def spy(message, text):
        seen["text"] = text

    monkeypatch.setattr(botmod, "_process_input", spy)
    msg = FakeMessage()
    msg.document = type("D", (), {"file_id": "FID123"})()
    msg.bot = FakeBot(file_bytes=content.encode())
    msg.from_user = FakeUser(5)
    asyncio.run(botmod.handle_document(msg))
    assert seen.get("text") == content


def test_dispatch_handle_document_read_error_is_reported(monkeypatch):
    """A file the bot cannot download yields a user-facing error, no crash."""

    async def boom(message, text):
        raise AssertionError("should not be called")

    monkeypatch.setattr(botmod, "_process_input", boom)
    msg = FakeMessage()
    msg.document = type("D", (), {"file_id": "BAD"})()
    msg.bot = FakeBot()
    # Force download to fail.
    async def _fail(path):
        raise RuntimeError("download failed")

    msg.bot.download_file = _fail
    msg.from_user = FakeUser(5)
    asyncio.run(botmod.handle_document(msg))
    assert any("Error reading file" in (r.text or "") for r in msg.replies)


def test_router_is_registered_and_callbacks_present():
    """The bot router wires the message + callback handlers; importing the
    module and inspecting the router confirms no wiring regressed."""
    # The handler functions exist and are registered on the router.
    assert botmod.handle_text in {h.callback for h in botmod.router.message.handlers}
    assert botmod.handle_document in {h.callback for h in botmod.router.message.handlers}
    # Callback handlers for settings sections are registered.
    cb_callbacks = {h.callback for h in botmod.router.callback_query.handlers}
    assert botmod.cb_section in cb_callbacks
    assert botmod.cb_set_format in cb_callbacks


def test_settings_commands_registered():
    """/start /help /settings /proxy commands are wired on the router."""
    cmd_callbacks = {h.callback for h in botmod.router.message.handlers}
    for fn in (botmod.cmd_start, botmod.cmd_help, botmod.cmd_settings, botmod.cmd_proxy):
        assert fn in cmd_callbacks


# ---------------------------------------------------------------------------
# Command + callback handlers (settings UI) and real Dispatcher dispatch
# ---------------------------------------------------------------------------

class FakeCallback:
    def __init__(self, data):
        self.data = data
        self.answered = None
        self.answer_calls = []
        self.message = FakeStatus("")

    async def answer(self, text=None, **kwargs):
        self.answered = text
        self.answer_calls.append(text)


@pytest.fixture
def _isolated_settings(tmp_path, monkeypatch):
    """Point the real settings persistence at a temp file so handlers that
    load/save actually persist and we can assert on it. Bind the bot's
    load/save to the *real* core functions (not the autouse mock) so
    persistence is exercised end-to-end."""
    import core.settings as cs
    p = tmp_path / "settings.json"
    monkeypatch.setattr(cs, "DEFAULT_SETTINGS_PATH", str(p))
    monkeypatch.setattr(botmod, "load_settings", cs.load_settings)
    monkeypatch.setattr(botmod, "save_settings", cs.save_settings)
    return p


def test_cmd_start_and_help_reply(monkeypatch):
    msg = FakeMessage()
    asyncio.run(botmod.cmd_start(msg))
    assert "VLESS Toolkit" in (msg.replies[0].text or "")
    msg2 = FakeMessage()
    asyncio.run(botmod.cmd_help(msg2))
    assert "Usage" in (msg2.replies[0].text or "")


def test_cmd_settings_shows_menu(monkeypatch):
    msg = FakeMessage()
    asyncio.run(botmod.cmd_settings(msg))
    # Main settings keyboard rendered; reply_markup passed through.
    assert msg.replies[0].reply_markup is not None


def test_cb_section_shows_format_keyboard(_isolated_settings):
    cb = FakeCallback(botmod.CB_LINK_FMT)
    asyncio.run(botmod.cb_section(cb))
    assert "Links" in (cb.message.text or "")
    assert cb.message.reply_markup is not None
    assert cb.answer_calls  # callback.answer() called


def test_cb_set_format_persists(_isolated_settings):
    """Selecting a format for a section persists to settings."""
    from core.settings import load_settings
    cb = FakeCallback(f"{botmod.CB_SUB_FMT}:flclash")
    asyncio.run(botmod.cb_set_format(cb))
    s = load_settings()
    assert s.sub_format.value == "flclash"
    assert "✅" in (cb.answered or "")


def test_cb_set_format_invalid_format_propagates(_isolated_settings):
    """An unknown format string raises inside Format() (handler has no
    guard) — documented behavior, not a silent no-op. The malformed
    (missing-colon) case answers and returns early instead."""
    cb = FakeCallback(f"{botmod.CB_LINK_FMT}:notaformat")
    with pytest.raises(ValueError):
        asyncio.run(botmod.cb_set_format(cb))


def test_cb_set_format_malformed_answers_and_returns(_isolated_settings):
    cb = FakeCallback(f"{botmod.CB_LINK_FMT}")  # missing colon
    asyncio.run(botmod.cb_set_format(cb))
    assert cb.answer_calls


def test_cb_toggle_passthrough_persists(_isolated_settings):
    from core.settings import load_settings
    before = load_settings().sub_passthrough
    cb = FakeCallback("sub_passthrough")
    asyncio.run(botmod.cb_toggle_passthrough(cb))
    assert load_settings().sub_passthrough is not before


def test_cb_proxy_toggles_and_back(_isolated_settings):
    from core.settings import load_settings
    cb = FakeCallback(botmod.CB_PROXY)
    asyncio.run(botmod.cb_proxy_menu(cb))
    assert "Proxy device" in (cb.message.text or "")
    # Toggle headers on/off persists.
    before = load_settings().proxy_headers_on
    cb2 = FakeCallback("proxy_headers_on")
    asyncio.run(botmod.cb_proxy_headers(cb2))
    assert load_settings().proxy_headers_on is not before
    # 'back' returns to main settings menu.
    cb3 = FakeCallback("back")
    asyncio.run(botmod.cb_back(cb3))
    assert "Settings" in (cb3.message.text or "")


def test_cb_proxy_random_persists_device(_isolated_settings):
    from core.settings import load_settings
    cb = FakeCallback("proxy_random")
    asyncio.run(botmod.cb_proxy_random(cb))
    s = load_settings()
    assert s.proxy_os and s.proxy_ua  # randomized fields populated
    assert cb.answer_calls and "🎲 Randomized" in cb.answer_calls


def test_cmd_proxy_set_manual(_isolated_settings):
    from core.settings import load_settings
    msg = FakeMessage()
    msg.text = "/proxy set android,ver=3.8.13,ua=Happ/3.26.0,hwid=abc"
    asyncio.run(botmod.cmd_proxy(msg))
    assert "saved" in (msg.replies[0].text or "")
    s = load_settings()
    assert s.proxy_os == "android"
    assert s.proxy_ver == "3.8.13"
    assert s.proxy_ua == "Happ/3.26.0"
    assert s.proxy_hwid == "abc"


def test_real_dispatcher_routes_text_to_handler(monkeypatch):
    """Feed a real Update through aiogram's Dispatcher and confirm the text
    handler runs (end-to-end wiring beyond unit mocks)."""
    from aiogram import Bot, Dispatcher
    from aiogram.types import Update

    seen = {}

    async def spy(message, text):
        seen["text"] = text

    monkeypatch.setattr(botmod, "_process_input", spy)

    dp = Dispatcher()
    dp.include_router(botmod.router)
    # Build a minimal text-message Update.
    update = Update(
        update_id=1,
        message={
            "message_id": 1,
            "from": {"id": 1, "is_bot": False, "first_name": "u"},
            "chat": {"id": 1, "type": "private"},
            "date": 0,
            "text": "vless://a@b:443#n",
        },
    )
    bot = Bot(token="123:fake")
    asyncio.run(dp.feed_update(bot, update))
    assert seen.get("text") == "vless://a@b:443#n"



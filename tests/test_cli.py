"""Tests for CLI auto-decryption of happ:// and incy:// links in convert."""

import json

import pytest

import cli.main as cli_main


@pytest.fixture
def fake_sub(monkeypatch):
    """Make do_convert's subscription fetch return a base64 subscription
    payload (string), as real fetch_subscription does."""
    import base64
    payload = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&type=ws#FakeSub"
    b64 = base64.b64encode(payload.encode()).decode()

    async def _fake(url, timeout=15):
        return b64
    monkeypatch.setattr("core.logic.fetch_subscription", _fake)


def test_cli_decrypt_incy_subscription_link(fake_sub, capsys):
    """An incy://crypt1 deep link wrapping a subscription URL should
    decrypt, fetch (mocked), and convert."""
    vectors = json.load(open("data/incy_vectors.json"))
    link = vectors["links"][0]["link"]
    cli_main.do_convert(link, "txt")
    out = capsys.readouterr().out
    assert "vless://" in out


def test_cli_decrypt_incy_plain_share_link(capsys):
    """An incy link wrapping plain share links converts without a fetch."""
    try:
        from incy_link_encoder import encryptLink
    except Exception:
        pytest.skip("official incy package not installed")
    share = "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls#Test"
    link = encryptLink(share, {"name": "t"})
    cli_main.do_convert(link, "txt")
    out = capsys.readouterr().out
    assert "vless://" in out


def test_cli_decrypt_failure_warns(capsys):
    """A malformed encrypted link can't be decrypted; decrypt_text returns
    it unchanged, so do_convert later fails as no valid proxy links."""
    bad = "incy://crypt1/!!!!not-valid!!!!"
    with pytest.raises(Exception):
        cli_main.do_convert(bad, "txt")

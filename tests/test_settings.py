"""Tests for settings durability: per-key validation, atomic save, permissions."""

import contextlib
import json
import os
import stat

from core.converters import Format
from core.settings import Settings, load_settings, save_settings


def test_invalid_key_does_not_discard_other_settings(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "sub_format": "not-a-format",
        "txt_format": "mihomo",
        "tag_prefix": "prod",
        "timeout": 7,
    }))
    s = load_settings(str(path))
    assert s.txt_format is Format.MIHOMO
    assert s.tag_prefix == "prod"
    assert s.timeout == 7
    assert s.sub_format is Format.MIHOMO  # default for the broken key only


def test_unknown_keys_are_ignored(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"nope": 1, "tag_prefix": "x"}))
    assert load_settings(str(path)).tag_prefix == "x"


def test_save_load_round_trip_all_fields(tmp_path):
    path = tmp_path / "nested" / "settings.json"
    s = Settings(
        sub_format=Format.FLCLASH,
        link_format=Format.TXT,
        config_format=Format.SINGBOX,
        txt_format=Format.MIHOMO,
        web_default_format=Format.SINGBOX,
        tag_prefix="eu",
        timeout=5,
        insecure_tls=True,
        group_by_country=True,
        sub_passthrough=True,
        proxy_headers_on=True,
        proxy_os="ios",
        proxy_ua="Happ/9",
        proxy_ver="18.1",
        proxy_model="iPhone 16",
        proxy_locale="en_US",
        proxy_hwid="abc",
        proxy_hwid_on=False,
    )
    save_settings(s, str(path))
    assert load_settings(str(path)) == s


def test_save_is_atomic_and_private(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"tag_prefix": "old"}))
    save_settings(Settings(tag_prefix="new"), str(path))
    assert load_settings(str(path)).tag_prefix == "new"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # No temp files left behind.
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]


def test_save_failure_keeps_previous_file(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    save_settings(Settings(tag_prefix="before"), str(path))

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("core.settings.json.dump", boom)
    with contextlib.suppress(OSError):
        save_settings(Settings(tag_prefix="after"), str(path))
    assert load_settings(str(path)).tag_prefix == "before"
    assert [p.name for p in tmp_path.iterdir()] == ["settings.json"]

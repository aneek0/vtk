"""TDD tests for core.fingerprint — device fingerprinting for proxy subscriptions.

Single source of truth shared by web (proxy + convert tabs) and the bot.
"""

import os

import pytest

from core.fingerprint import (
    RANDOM_AGENTS,
    ANDROID_MODELS,
    IOS_MODELS,
    LOCALES,
    generate_device_fingerprint,
    get_proxy_base,
    parse_app_proxy_url,
    parse_device_params,
    random_device,
    to_params_string,
)


# ---------------------------------------------------------------------------
# parse_device_params
# ---------------------------------------------------------------------------

class TestParseDeviceParams:
    def test_comma_eq_form(self):
        params = parse_device_params("android,ver=3.8.13,model=OnePlus Open,ua=Happ/3.26.0,locale=ja_JP,hwid=8ddcfe6b6b55")
        assert params == {
            "os": "android",
            "ver": "3.8.13",
            "model": "OnePlus Open",
            "ua": "Happ/3.26.0",
            "locale": "ja_JP",
            "hwid": "8ddcfe6b6b55",
        }

    def test_first_token_without_eq_is_os(self):
        params = parse_device_params("ios")
        assert params["os"] == "ios"

    def test_empty(self):
        assert parse_device_params("") == {}

    def test_ignores_whitespace(self):
        params = parse_device_params(" android , ver = 3.8.13 ")
        assert params["os"] == "android"
        assert params["ver"] == "3.8.13"


# ---------------------------------------------------------------------------
# generate_device_fingerprint
# ---------------------------------------------------------------------------

class TestGenerateDeviceFingerprint:
    def test_android_keys(self):
        fp = generate_device_fingerprint(
            ua="Happ/3.26.0", hwid="8ddcfe6b6b55", os_name="android",
            ver="3.8.13", model="OnePlus Open", locale="ja_JP",
        )
        assert fp["User-Agent"] == "Happ/3.26.0"
        assert fp["X-Hwid"].startswith("hd-")
        assert fp["X-Device-Os"] == "Android"
        assert fp["X-Ver-Os"] == "3"
        assert fp["X-Device-Model"] == "OnePlus Open"
        assert fp["Accept-Language"] == "ja-JP"

    def test_ios_keys(self):
        fp = generate_device_fingerprint(
            ua="Happ/3.26.0", hwid="abc", os_name="ios",
            ver="17.0", model="iPhone 16", locale="en_US",
        )
        assert fp["X-Device-Os"] == "iOS"
        assert fp["X-Ver-Os"] == "17"
        assert fp["X-Device-Model"] == "iPhone 16"
        assert fp["Accept-Language"] == "en-US"

    def test_default_ua(self):
        fp = generate_device_fingerprint(ua="", hwid="", os_name="", ver="", model="", locale="")
        assert fp["User-Agent"] == "Happ/3.17.0"

    def test_no_hwid_header_when_empty(self):
        fp = generate_device_fingerprint(ua="Happ/3.26.0", hwid="", os_name="android", ver="", model="", locale="")
        assert "X-Hwid" not in fp

    def test_locale_underscore_to_dash(self):
        fp = generate_device_fingerprint(ua="x", hwid="", os_name="android", ver="", model="", locale="ru_RU")
        assert fp["Accept-Language"] == "ru-RU"

    def test_locale_default(self):
        fp = generate_device_fingerprint(ua="x", hwid="", os_name="android", ver="", model="", locale="")
        assert fp["Accept-Language"] == "en-US,en;q=0.9"


# ---------------------------------------------------------------------------
# to_params_string
# ---------------------------------------------------------------------------

class TestToParamsString:
    def test_round_trip(self):
        s = "android,ver=3.8.13,model=OnePlus Open,ua=Happ/3.26.0,locale=ja_JP,hwid=8ddcfe6b6b55"
        params = parse_device_params(s)
        out = to_params_string(params)
        # order is normalized; re-parse to compare as dict
        assert parse_device_params(out) == params

    def test_empty(self):
        assert to_params_string({}) == "android"


# ---------------------------------------------------------------------------
# parse_app_proxy_url  (host-agnostic)
# ---------------------------------------------------------------------------

class TestParseAppProxyUrl:
    EXAMPLE = "https://vtk.aneeko.qzz.io/p/android,ver=3.8.13,model=OnePlus%20Open,ua=Happ/3.26.0,locale=ja_JP,hwid=8ddcfe6b6b55/https://sub.meow.ac/honDa-jBX0tCGxT6?format=txt"

    def test_target_url(self):
        res = parse_app_proxy_url(self.EXAMPLE)
        assert res["target_url"] == "https://sub.meow.ac/honDa-jBX0tCGxT6?format=txt"

    def test_device_params(self):
        res = parse_app_proxy_url(self.EXAMPLE)
        p = res["params"]
        assert p["os"] == "android"
        assert p["ver"] == "3.8.13"
        assert p["model"] == "OnePlus Open"
        assert p["ua"] == "Happ/3.26.0"
        assert p["locale"] == "ja_JP"
        assert p["hwid"] == "8ddcfe6b6b55"

    def test_host_agnostic(self):
        url = "https://happy-decoder.cc/p/ios,ua=Happ/3.0/https://x.com/s"
        res = parse_app_proxy_url(url)
        assert res["target_url"] == "https://x.com/s"
        assert res["params"]["os"] == "ios"

    def test_not_app_link_returns_none(self):
        assert parse_app_proxy_url("https://sub.meow.ac/plain") is None

    def test_no_device_part(self):
        res = parse_app_proxy_url("https://h/p/https://sub.meow.ac/s")
        assert res["target_url"] == "https://sub.meow.ac/s"
        assert res["params"] == {}


# ---------------------------------------------------------------------------
# get_proxy_base  (env-config)
# ---------------------------------------------------------------------------

class TestGetProxyBase:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("VTK_PROXY_BASE", raising=False)
        assert get_proxy_base() == "https://vtk.aneeko.qzz.io"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("VTK_PROXY_BASE", "https://proxy.example.com/")
        assert get_proxy_base() == "https://proxy.example.com"

    def test_env_no_scheme(self, monkeypatch):
        monkeypatch.setenv("VTK_PROXY_BASE", "proxy.example.com")
        assert get_proxy_base() == "https://proxy.example.com"


# ---------------------------------------------------------------------------
# random_device
# ---------------------------------------------------------------------------

class TestRandomDevice:
    def test_keys(self):
        d = random_device()
        assert set(d.keys()) == {"os", "ua", "ver", "model", "locale", "hwid"}

    def test_os_valid(self):
        assert random_device()["os"] in ("android", "ios")

    def test_pools_nonempty(self):
        assert RANDOM_AGENTS and ANDROID_MODELS and IOS_MODELS and LOCALES


# ---------------------------------------------------------------------------
# settings round-trip (proxy fields)
# ---------------------------------------------------------------------------

class TestSettingsProxyRoundTrip:
    def test_save_load_proxy_fields(self, tmp_path, monkeypatch):
        from core import settings as s_mod

        path = tmp_path / "settings.json"
        monkeypatch.setattr(s_mod, "DEFAULT_SETTINGS_PATH", str(path))
        s = s_mod.load_settings()
        s.proxy_headers_on = True
        s.proxy_os = "ios"
        s.proxy_ua = "Happ/3.26.0"
        s.proxy_ver = "3.8.13"
        s.proxy_model = "iPhone 16"
        s.proxy_locale = "ja_JP"
        s.proxy_hwid = "8ddcfe6b6b55"
        s.proxy_hwid_on = False
        s_mod.save_settings(s)

        loaded = s_mod.load_settings()
        assert loaded.proxy_headers_on is True
        assert loaded.proxy_os == "ios"
        assert loaded.proxy_ua == "Happ/3.26.0"
        assert loaded.proxy_ver == "3.8.13"
        assert loaded.proxy_model == "iPhone 16"
        assert loaded.proxy_locale == "ja_JP"
        assert loaded.proxy_hwid == "8ddcfe6b6b55"
        assert loaded.proxy_hwid_on is False

    def test_defaults(self):
        from core import settings as s_mod

        s = s_mod.Settings()
        assert s.proxy_headers_on is False
        assert s.proxy_hwid_on is True
        assert s.proxy_os == "android"

"""Tests for the shared fetch policy: SSRF guard, redirect limit, TLS switch."""

import asyncio
from typing import ClassVar

import httpx
import pytest

from core import net
from core.net import UnsafeURLError


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/sub",
        "http://[::1]/",
        "ftp://example.com/x",
        "file:///etc/passwd",
    ],
)
def test_rejects_non_public_targets(monkeypatch, url):
    monkeypatch.delenv(net.ALLOW_PRIVATE_ENV, raising=False)
    with pytest.raises(UnsafeURLError):
        _run(net.assert_url_allowed(url))


def test_allows_public_ip_literal(monkeypatch):
    monkeypatch.delenv(net.ALLOW_PRIVATE_ENV, raising=False)
    _run(net.assert_url_allowed("http://1.1.1.1/"))


def test_env_opt_out_allows_loopback(monkeypatch):
    monkeypatch.setenv(net.ALLOW_PRIVATE_ENV, "1")
    _run(net.assert_url_allowed("http://127.0.0.1:8080/sub"))


def test_redirect_hop_is_guarded(monkeypatch):
    """A public URL redirecting to loopback must be rejected before it is fetched."""
    monkeypatch.delenv(net.ALLOW_PRIVATE_ENV, raising=False)
    fetched = []

    class _Resp:
        is_redirect = True
        headers: ClassVar[dict] = {"location": "http://127.0.0.1:9000/secret"}
        text = ""

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
            fetched.append(url)
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    # The first hop is allowed by stub, so the guard is only exercised on hop 2.
    calls = []

    async def _allow_public(url):
        calls.append(url)
        if "127.0.0.1" in url:
            raise UnsafeURLError("loopback")

    monkeypatch.setattr(net, "assert_url_allowed", _allow_public)

    with pytest.raises(UnsafeURLError):
        _run(net.fetch("https://public.example/x", timeout=1))
    assert calls == ["https://public.example/x", "http://127.0.0.1:9000/secret"]


def test_redirect_limit(monkeypatch):
    monkeypatch.delenv(net.ALLOW_PRIVATE_ENV, raising=False)

    class _Resp:
        is_redirect = True
        headers: ClassVar[dict] = {"location": "/again"}
        text = ""

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
            return _Resp()

    async def _allow(url):
        return None

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    monkeypatch.setattr(net, "assert_url_allowed", _allow)

    with pytest.raises(httpx.HTTPError):
        _run(net.fetch("https://public.example/x", timeout=1))


def test_fakeip_range_is_allowed(monkeypatch):
    """sing-box/mihomo fakeip addresses must pass: they map back to a domain."""
    monkeypatch.delenv(net.ALLOW_PRIVATE_ENV, raising=False)
    _run(net.assert_url_allowed("http://198.18.0.114/"))

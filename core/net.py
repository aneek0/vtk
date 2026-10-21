"""HTTP fetch policy for subscription / direct-URL fetches.

Every network fetch in the toolkit goes through :func:`fetch` so the trust
boundary is decided once:

* TLS verification is **on** unless the operator opted out with
  ``insecure_tls`` in the settings file (some subscription hosts ship broken
  certificates).
* Redirects are followed manually, at most :data:`MAX_REDIRECTS` hops, and the
  private-network guard runs on **every** hop — a public URL redirecting to
  ``127.0.0.1`` is rejected exactly like a direct one.
* :func:`assert_url_allowed` rejects non-http(s) schemes and any host that
  resolves to a non-global address (loopback, LAN, link-local metadata
  endpoints), which would otherwise turn the ``/p/`` passthrough into an SSRF
  pivot. Set ``VTK_ALLOW_PRIVATE_URLS=1`` to deliberately fetch LAN
  subscriptions.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from urllib.parse import urljoin, urlsplit

import httpx

from core.settings import load_settings

MAX_REDIRECTS = 3
ALLOW_PRIVATE_ENV = "VTK_ALLOW_PRIVATE_URLS"

_FAKEIP_NET = ipaddress.ip_network("198.18.0.0/15")


def _is_blocked(ip: ipaddress._BaseAddress) -> bool:
    # sing-box / mihomo fakeip: the resolver hands out addresses from RFC 2544
    # space and maps them back to the real upstream. Treating them as private
    # would break every subscription fetch on such networks.
    if ip.version == 4 and ip in _FAKEIP_NET:
        return False
    return not ip.is_global


class UnsafeURLError(ValueError):
    """URL rejected by the private-network guard."""


class ResolveError(RuntimeError):
    """The target host could not be resolved (upstream problem, not bad input)."""


def allow_private_urls() -> bool:
    """Operator opt-out: permit fetches to private / loopback addresses."""
    return os.environ.get(ALLOW_PRIVATE_ENV, "").strip().lower() in {"1", "true", "yes"}


async def assert_url_allowed(url: str) -> None:
    """Raise :class:`UnsafeURLError` unless *url* is http(s) to a public host.

    The hostname is resolved here; the caller then connects to it, so a
    DNS-rebinding host could still swap the address between check and connect.
    Mitigating that needs a custom transport pinned to the checked IPs — out of
    scope for a single-user toolkit, noted in docs/adr/0001.
    """
    if allow_private_urls():
        return
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeURLError(f"unsupported scheme {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("URL has no host")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
    except (OSError, ValueError) as exc:
        raise ResolveError(f"cannot resolve {host}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_blocked(ip):
            raise UnsafeURLError(f"{host} resolves to non-public address {ip}")


async def fetch(url: str, timeout: float, headers: dict | None = None) -> httpx.Response:
    """GET *url* with TLS verification, bounded redirects and the SSRF guard."""
    verify = not load_settings().insecure_tls
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=verify) as client:
        for _ in range(MAX_REDIRECTS + 1):
            await assert_url_allowed(url)
            resp = await client.get(url, headers=headers or None)
            location = resp.headers.get("location", "") if resp.is_redirect else ""
            if not location:
                resp.raise_for_status()
                return resp
            url = urljoin(url, location)
    raise httpx.HTTPError(f"too many redirects (>{MAX_REDIRECTS})")

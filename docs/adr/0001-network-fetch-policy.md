# 1. One network fetch policy

Date: 2026-10-21
Status: accepted

## Context

Subscription fetches were implemented three times (`core/logic.py`,
`core/happ.py`, `core/incy.py`, plus `web/routes/proxy.py`) and all of them used
`httpx.AsyncClient(verify=False)` with unlimited redirects. The web passthrough
`/p/<params>/<url>` fetches a URL supplied by the caller, so the same code was an
open SSRF pivot: `http://127.0.0.1:...`, `169.254.169.254`, LAN hosts and
redirect chains were all reachable.

## Decision

All fetches go through `core.net.fetch`:

- TLS verification **on** by default; `Settings.insecure_tls` is the explicit
  opt-out for broken subscription hosts.
- `follow_redirects=False`, at most `MAX_REDIRECTS = 3` hops followed manually.
- `assert_url_allowed` runs on **every** hop: scheme must be http(s) and every
  resolved address must be globally routable (`ipaddress.is_global`).
- `VTK_ALLOW_PRIVATE_URLS=1` disables the private-address guard for operators
  who deliberately pull a subscription from their own LAN.

## Consequences

- The guard rejects only addresses that are not globally routable, **except**
  `198.18.0.0/15`. That range is what sing-box/mihomo fakeip hands out for every
  remote domain, so blocking it would break subscription fetches on such
  networks while adding no protection: the router maps the fake address back to
  the domain it resolved.
- A public host that redirects to a private address is rejected like a direct
  one.
- DNS rebinding between check and connect is not mitigated; pinning connections
  to checked addresses would need a custom transport and is out of scope for a
  single-user toolkit.
- Operators must flip `insecure_tls` if a subscription host has a broken chain;
  the silent default no longer hides MITM.

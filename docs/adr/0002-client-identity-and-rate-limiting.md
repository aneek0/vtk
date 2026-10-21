# 2. Client identity for the `/p/` rate limit

Date: 2026-10-21
Status: accepted

## Context

`web/routes/proxy.py` rate-limited by the first `X-Forwarded-For` entry,
trusting the header verbatim. Any client could rotate the header and bypass the
limit. When the in-memory table exceeded 4096 entries it was cleared wholesale,
unblocking every client at once.

## Decision

- `X-Forwarded-For` is honored only when the direct peer is a loopback address
  (a local reverse proxy / tunnel). Otherwise the peer address is the key, so a
  direct client cannot spoof it.
- On overflow, entries older than the rate window are pruned; no global reset.
- The limiter stays in-memory: the toolkit is a single-user deployment, and a
  persistent store buys nothing.

## Consequences

- Multi-worker deployments have per-worker limits (N requests/s, N = workers).
  Acceptable for this service; document it instead of adding a shared store.
- Deployments behind a non-loopback proxy need a trusted-proxy allowlist; that
  is not implemented until such a deployment exists.

# 5. Decryption failures are typed and per-link

Date: 2026-10-21
Status: accepted

## Context

`decrypt_input` wrapped both decryptors in `contextlib.suppress(Exception)`.
That hid real bugs (import errors, typos in the decryptor) behind "input
unchanged", and made the failure contract unreadable.

## Decision

- `core.errors.DecryptError` (subclass of `RuntimeError`) is the only expected
  decode failure. `core.happ` and `core.incy` raise it; their `decrypt_text`
  catches only it, per link, and keeps the original link.
- `decrypt_input` suppresses only `DecryptError`; anything else propagates to
  `process_input`, which reports it as an error instead of silently passing the
  input through.

## Consequences

- A corrupt link still leaves the rest of the batch convertible.
- A decryptor bug now surfaces instead of being masked.
- `RuntimeError` subclassing keeps older callers/tests working.

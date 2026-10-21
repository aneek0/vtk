# 3. Settings durability and per-key validation

Date: 2026-10-21
Status: accepted

## Context

`core/settings.py` parsed the file with one `try` around everything: a single
invalid enum value (`Format("yaml")`) raised `ValueError` and the loader
returned fresh defaults, silently discarding unrelated settings such as
`tag_prefix` and `proxy_hwid`. Saving used `Path.write_text`, which truncates in
place; a crash mid-write left an empty file. The key list was hand-copied
between load and save, so adding a field meant editing two places.

## Decision

- Load coerces each field independently (`_coerce`) and skips only the invalid
  key with a warning.
- Save serializes every dataclass field (`dataclasses.fields`) — one list, no
  drift.
- Save writes to a temp file in the same directory, `fsync`s, sets mode `0600`
  (the file holds the proxy HWID), then `os.replace`s it into place.
- `insecure_tls` lives in settings, so the fetch policy is operator-tunable
  without code changes.

## Consequences

- Torn writes are impossible; a crash leaves the previous file valid.
- Unknown keys written by newer versions are preserved? No — they are dropped
  on save. Acceptable: the file is owned by this tool.

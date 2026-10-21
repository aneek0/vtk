# 4. One input pipeline for every frontend

Date: 2026-10-21
Status: accepted

## Context

`process_input` was introduced to centralize decrypt → detect → fetch/parse →
convert, but the CLI's interactive mode and `cmd_sub` kept their own copies of
the pipeline. They skipped `happ://`/`incy://` decryption and device headers,
so the same input produced different results depending on the frontend.

## Decision

- `cmd_interactive` and `do_convert` call `core.logic.process_input`; the local
  `_convert_link` / `_convert_links` / `_convert_config` helpers are deleted.
- Input type is detected once, inside the core, after decryption.
- Frontends only render the returned dict (`ok`, `nodes`, `result`, `servers`,
  `sub_headers`) and map `ok: False` to their own error surface.

## Consequences

- CLI gains decryption and equal parsing behavior for free; a pipeline fix lands
  in one place.
- `cmd_sub` keeps a direct `fetch_subscription` call because it needs the raw
  body and the subscription name for the output filename; it is the only
  remaining frontend-specific fetch.

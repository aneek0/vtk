"""Web interface for VLESS toolkit — FastAPI."""

from fastapi import FastAPI, Form, Request, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

from core.logic import parse_link, parse_text_input, parse_subscription_text, ParseError
from core.converters import convert, Format, to_txt
from core.reverse import from_config
from core.settings import load_settings

app = FastAPI(title="VLESS Toolkit")

_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VLESS Toolkit</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}
textarea{width:100%;min-height:100px;box-sizing:border-box;padding:8px;font-family:monospace;font-size:14px}
select,button{margin:4px 4px 4px 0;padding:8px 16px;font-size:14px;cursor:pointer}
pre{background:#f5f5f5;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;font-size:13px}
.ok{color:#2e7d32}.err{color:#c62828}
label{font-weight:600}
.form-row{margin:12px 0}
</style>
</head>
<body>
<h1>🔧 VLESS Toolkit</h1>
<form method="post" action="/convert">
<div class="form-row">
<label>Paste links, subscription URL, or raw subscription content:</label><br>
<textarea name="input" placeholder="vless://... or https://sub-url"></textarea>
</div>
<div class="form-row">
<label>Output format:</label><br>
<select name="format">
<option value="singbox" {{sel_singbox}}>sing-box JSON</option>
<option value="mihomo" {{sel_mihomo}}>mihomo YAML</option>
<option value="flclash" {{sel_flclash}}>FlClash YAML</option>
<option value="txt" {{sel_txt}}>Plain text (share links)</option>
</select>
<label>Tag prefix:</label>
<input type="text" name="tag_prefix" value="{{tag_prefix}}" placeholder="optional" style="padding:8px">
<button type="submit">Convert</button>
</div>
</form>
{{result_section}}
<hr>
<p><small>API: <code>GET /api/convert?input=...&format=singbox</code></small></p>
</body>
</html>"""


def _render_result(result: str, ok: bool) -> str:
    css = "ok" if ok else "err"
    icon = "✅" if ok else "❌"
    return f'<div class="form-row"><pre class="{css}">{icon} {result}</pre></div>'


@app.get("/", response_class=HTMLResponse)
async def index():
    s = load_settings()
    html = _HTML
    html = html.replace("{{sel_singbox}}", "selected" if s.web_default_format == Format.SINGBOX else "")
    html = html.replace("{{sel_mihomo}}", "selected" if s.web_default_format == Format.MIHOMO else "")
    html = html.replace("{{sel_flclash}}", "selected" if s.web_default_format == Format.FLCLASH else "")
    html = html.replace("{{sel_txt}}", "selected" if s.web_default_format == Format.TXT else "")
    html = html.replace("{{tag_prefix}}", s.tag_prefix)
    html = html.replace("{{result_section}}", "")
    return html


@app.post("/convert", response_class=HTMLResponse)
async def convert_form(
    request: Request,
    input: str = Form(...),
    format: str = Form("singbox"),
    tag_prefix: str = Form(""),
):
    s = load_settings()
    html = _HTML
    html = html.replace("{{sel_singbox}}", "selected" if format == "singbox" else "")
    html = html.replace("{{sel_mihomo}}", "selected" if format == "mihomo" else "")
    html = html.replace("{{sel_txt}}", "selected" if format == "txt" else "")
    html = html.replace("{{tag_prefix}}", tag_prefix)

    # Determine input type
    text = input.strip()

    from core.happ import is_happ, decrypt_text
    happ_decrypted = False
    if is_happ(text):
        try:
            text = decrypt_text(text)
            happ_decrypted = True
        except Exception as e:
            html = html.replace("{{result_section}}", _render_result(f"Happ decrypt failed: {e}", False))
            return html

    # Try as config (JSON / YAML) → reverse convert to share links
    if text.startswith("{") or "proxies:" in text or text.startswith("- name:"):
        try:
            nodes = from_config(text)
        except ParseError:
            nodes = []
        if nodes:
            result = to_txt(nodes)
            html = html.replace("{{result_section}}", _render_result(
                f"✅ Extracted {len(nodes)} share links:\n{result}", True))
            return html

    if text.startswith(("http://", "https://")):
        try:
            import asyncio
            from core.logic import fetch_subscription
            content = asyncio.run(fetch_subscription(text, timeout=s.timeout))
            nodes = parse_subscription_text(content)
        except Exception as e:
            html = html.replace("{{result_section}}", _render_result(str(e), False))
            return html
    else:
        nodes = parse_text_input(text)
        nodes = [n for n in nodes if n.protocol != "error"]

    if not nodes:
        html = html.replace("{{result_section}}", _render_result("No valid proxy links found", False))
        return html

    try:
        result = convert(nodes, Format(format), tag_prefix=tag_prefix)
        html = html.replace("{{result_section}}", _render_result(result, True))
    except ParseError as e:
        html = html.replace("{{result_section}}", _render_result(str(e), False))

    return html


@app.get("/api/extract")
async def api_extract(input: str = Query(..., help="sing-box JSON or mihomo YAML config")):
    """Extract share links from a config."""
    try:
        nodes = from_config(input.strip())
        result = to_txt(nodes)
        return {"ok": True, "nodes": len(nodes), "result": result}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.get("/api/convert")
async def api_convert(
    input: str = Query(..., help="Proxy link, URL, or raw content"),
    format: str = Query("singbox", help="Output format: singbox, mihomo, txt"),
    tag_prefix: str = Query("", help="Tag prefix"),
):
    """JSON API — convert links to specified format."""
    s = load_settings()
    text = input.strip()

    if text.startswith(("http://", "https://")):
        try:
            import asyncio
            from core.logic import fetch_subscription
            content = asyncio.run(fetch_subscription(text, timeout=s.timeout))
            nodes = parse_subscription_text(content)
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    else:
        nodes = parse_text_input(text)
        nodes = [n for n in nodes if n.protocol != "error"]

    if not nodes:
        return JSONResponse({"ok": False, "error": "No valid proxy links"}, status_code=400)

    try:
        result = convert(nodes, Format(format), tag_prefix=tag_prefix)
        return {"ok": True, "format": format, "nodes": len(nodes), "result": result}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.get("/api/check")
async def api_check(link: str = Query(...)):
    """Validate a single proxy link."""
    try:
        node = parse_link(link)
        return {"ok": True, "protocol": node.protocol, "name": node.display_name,
                "address": f"{node.address}:{node.port}"}
    except ParseError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)

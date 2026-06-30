"""Web interface for VLESS toolkit — FastAPI."""

import time

from fastapi import FastAPI, Form, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

from core.logic import parse_link, parse_text_input, parse_subscription_text, ParseError
from core.converters import convert, Format, to_txt
from core.reverse import from_config
from core.settings import load_settings

app = FastAPI(title="VLESS Toolkit")

# CORS — allow cross-origin API calls (mimics happy-decoder.cc CORS: *)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VTK — Proxy Toolkit</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#050308;--bg-2:#08040e;
  --panel:rgba(8,5,15,0.85);--panel-strong:rgba(4,3,8,0.95);
  --border:rgba(90,200,180,0.18);
  --text:#c8dce4;--muted:#6a8490;
  --cyan:#4db8a4;--pink:#c75a8a;--lime:#8db852;
  --radius:8px;
}
html,body{margin:0}
body{
  font-family:"JetBrains Mono","Fira Code",Consolas,monospace;
  font-size:13px;line-height:1.5;
  background:var(--bg);color:var(--text);
  min-height:100vh;
  display:flex;flex-direction:column;align-items:center;
}
main{width:100%;max-width:780px}
header{
  padding:1rem 1.5rem 0.8rem;
  border-bottom:1px solid var(--border);
  text-align:center;
}
.tab-bar{display:flex;gap:0;margin:0.8rem auto;justify-content:center;max-width:780px}.tab-btn{padding:0.4rem 0.9rem;color:var(--muted);text-decoration:none;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.08em;border-bottom:2px solid transparent;transition:all 0.15s}.tab-btn:hover{color:var(--text)}.tab-btn.active{color:var(--cyan);border-bottom-color:var(--cyan)}
  font-size:1.3rem;font-weight:700;margin:0;
  color:var(--cyan);letter-spacing:-0.02em;
}
header .sub{font-size:0.75rem;color:var(--muted);margin-top:0.2rem}
nav{display:flex;gap:0;margin:0.8rem 1.5rem;}
nav button{
  background:none;border:none;color:var(--muted);
  padding:0.4rem 0.9rem;font:inherit;font-size:0.78rem;
  text-transform:uppercase;letter-spacing:0.08em;cursor:pointer;
  border-bottom:2px solid transparent;transition:all 0.15s;
}
nav button:hover{color:var(--text)}
nav button.active{color:var(--cyan);border-bottom-color:var(--cyan)}
main{padding:1rem 1.5rem;max-width:820px}
input[name="tab"]{display:none}.tab-content{display:none}#rb-convert:checked ~ #main #content-convert,#rb-proxy:checked ~ #main #content-proxy,#rb-decrypt:checked ~ #main #content-decrypt,#rb-api:checked ~ #main #content-api{display:block}
label{
  display:block;font-size:0.7rem;color:var(--cyan);
  text-transform:uppercase;letter-spacing:0.1em;
  margin:0.7rem 0 0.3rem;
}
textarea{
  width:100%;min-height:80px;resize:vertical;
  background:var(--bg-2);color:var(--text);
  border:1px solid var(--border);border-radius:var(--radius);
  padding:0.5rem 0.7rem;font:inherit;font-size:0.78rem;
  line-height:1.5;
}
textarea:focus{outline:none;border-color:var(--cyan)}
textarea::placeholder{color:var(--muted)}
select,input[type="text"]{
  width:100%;padding:0.4rem 0.6rem;
  background:var(--bg-2);color:var(--text);
  border:1px solid var(--border);border-radius:var(--radius);
  font:inherit;font-size:0.78rem;
}
select:focus,input:focus{outline:none;border-color:var(--cyan)}
button.btn{
  background:linear-gradient(180deg,rgba(77,184,164,0.15),rgba(77,184,164,0.08));
  color:var(--cyan);border:1px solid var(--border);
  padding:0.45rem 1rem;border-radius:var(--radius);
  font:inherit;font-size:0.78rem;cursor:pointer;
  transition:all 0.15s;
}
button.btn:hover{background:rgba(77,184,164,0.2)}
button.btn:active{transform:translateY(1px)}
button.btn-rnd{
  background:rgba(139,184,82,0.12);color:var(--lime);
}
button.btn-rnd:hover{background:rgba(139,184,82,0.22)}
.row{display:flex;gap:0.5rem;align-items:flex-end}
.row>*{flex:1}
.result-box{
  display:none;margin-top:0.8rem;
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:0.8rem;
}
.result-box.visible{display:block}
.result-content.success{border-left:3px solid var(--lime)}
.result-content.error{border-left:3px solid var(--pink)}
.result-shell{display:flex;gap:0.5rem;align-items:flex-start}
.result-content{flex:1;word-break:break-word;font-size:0.78rem;color:var(--text)}
.copy-btn{
  background:none;border:1px solid var(--border);color:var(--muted);
  padding:0.3rem 0.6rem;border-radius:var(--radius);cursor:pointer;
  font-size:0.72rem;
}
.copy-btn:hover{color:var(--text);border-color:var(--cyan)}
.url-box{
  background:var(--bg-2);border:1px solid var(--border);
  padding:0.6rem;border-radius:var(--radius);
  word-break:break-all;margin-bottom:0.5rem;font-size:0.75rem;
}
.url-box a{color:var(--cyan);text-decoration:none}
.url-box a:hover{text-decoration:underline}
.preview{
  margin-top:0.5rem;padding:0.5rem 0.7rem;
  background:var(--bg-2);border-radius:var(--radius);
  font-size:0.7rem;color:var(--muted);
  max-height:120px;overflow-y:auto;white-space:pre-wrap;
}
.preview strong{color:var(--text)}
.footer{
  margin-top:2rem;padding-top:0.8rem;
  border-top:1px solid var(--border);
  font-size:0.7rem;color:var(--muted);text-align:center;
}
</style>
</head>
<body>
<header>
  <h1>◆ VTK</h1>
  <div class="sub">Proxy converter · Happ decoder · Subscription proxy</div>
</header>

<input type="radio" name="tab" id="rb-convert" checked><input type="radio" name="tab" id="rb-proxy"><input type="radio" name="tab" id="rb-decrypt"><input type="radio" name="tab" id="rb-api">
<div class="tab-bar">
  <label for="rb-convert" class="tab-btn">CONVERT</label>
  <label for="rb-proxy" class="tab-btn">PROXY</label>
  <label for="rb-decrypt" class="tab-btn">DECRYPT</label>
  <label for="rb-api" class="tab-btn">API</label>
</div>

<main id="main">
<!-- CONVERT TAB -->
<div class="tab-content" id="content-convert">
  <label>Links / subscription / config</label>
  <textarea id="convertInput" placeholder="vless://... vmess://... happ://... https://sub.url"></textarea>
  <div class="row">
    <div>
      <label>Format</label>
      <select id="convertFormat">
        <option value="singbox">sing-box JSON</option>
        <option value="mihomo">mihomo YAML</option>
        <option value="flclash">FlClash YAML</option>
        <option value="xray">XRAY JSON</option>
        <option value="txt">Plain text</option>
      </select>
    </div>
    <div>
      <label>Tag prefix</label>
      <input type="text" id="tagPrefix" placeholder="optional">
    </div>
  </div>
  <button class="btn" onclick="convertLinks()">[ CONVERT ]</button>
  <div id="convertResult" class="result-box">
    <div class="result-shell">
      <div id="convertResultContent" class="result-content success"></div>
      <button class="copy-btn" onclick="copyResult('convertResultContent')">COPY</button>
    </div>
  </div>
</div>

<!-- PROXY TAB -->
<div class="tab-content" id="content-proxy">
  <label>Subscription URL</label>
  <input type="text" id="proxyUrl" placeholder="https://panel.haizvpn.pw/api/sub/...">
  <div class="row">
    <div><label>User-Agent</label><input type="text" id="proxyUa" placeholder="Happ/3.24.1"></div>
    <div><label>HWID</label><input type="text" id="proxyHwid" placeholder="device-id"></div>
  </div>
  <div class="row">
    <div><label>OS</label>
      <select id="proxyOs"><option>android</option><option>ios</option></select>
    </div>
    <div><label>Version</label><input type="text" id="proxyVer" placeholder="3.24.1"></div>
  </div>
  <div class="row">
    <div><label>Model</label><input type="text" id="proxyModel" placeholder="Pixel 8"></div>
    <div><label>Locale</label><input type="text" id="proxyLocale" placeholder="ru_RU"></div>
  </div>
  <label>Output format</label>
  <select id="proxyFormat">
    <option value="singbox">sing-box JSON</option>
    <option value="mihomo">mihomo YAML</option>
    <option value="flclash">flClash YAML</option>
    <option value="xray">xray JSON</option>
    <option value="txt">txt (share links)</option>
    <option value="base64">base64</option>
  </select>
  <div class="row">
    <button class="btn" onclick="proxyFetch()">[ PROXY GET ]</button>
    <button class="btn btn-rnd" onclick="randomizeProxy()">[ RANDOM ]</button>
  </div>
  <div id="proxyResult" class="result-box">
    <div id="proxyResultContent" class="result-content success"></div>
  </div>
</div>

<!-- DECRYPT TAB -->
<div class="tab-content" id="content-decrypt">
  <label>happ:// link or text with links</label>
  <textarea id="decryptInput" placeholder="happ://crypt5/..." rows="3"></textarea>
  <div class="row">
    <button class="btn" onclick="decryptLink()">[ DECRYPT URL ]</button>
    <button class="btn" onclick="decryptText()">[ DECRYPT TEXT ]</button>
  </div>
  <button class="copy-btn" onclick="clearDecrypt()" style="margin-top:0.5rem">[ CLEAR ]</button>
  <div id="decryptResult" class="result-box">
    <div class="result-shell">
      <div id="decryptResultContent" class="result-content success"></div>
      <button class="copy-btn" onclick="copyResult('decryptResultContent')">COPY</button>
    </div>
  </div>
</div>

<!-- API TAB -->
<div class="tab-content" id="content-api">
  <label>API v1</label>
  <div style="font-size:0.72rem;color:var(--muted);line-height:1.8">
    Free API for decrypting encrypted Happ VPN subscriptions. CORS: *
  </div>

  <label style="margin-top:1rem">Quick Start</label>
  <div class="url-box" style="font-size:0.72rem">
    curl -X POST http://127.0.0.1:9000/api/v1/decrypt <br>
    &nbsp;&nbsp;-H "Authorization: Bearer hd_demo_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" <br>
    &nbsp;&nbsp;-H "Content-Type: application/json" <br>
    &nbsp;&nbsp;-d '{"url":"happ://crypt5/..."}'
  </div>
  <button class="copy-btn" style="margin:0.3rem 0 0.8rem" onclick="navigator.clipboard.writeText('curl -X POST http://127.0.0.1:9000/api/v1/decrypt -H &quot;Authorization: Bearer hd_demo_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6&quot; -H &quot;Content-Type: application/json&quot; -d &quot;{\&quot;url\&quot;:\&quot;happ://crypt5/...\&quot;}&quot;')">COPY</button>

  <label>Endpoints</label>
  <div style="font-size:0.72rem;color:var(--muted);line-height:2">
    <code>POST /api/v1/decrypt</code> — Decrypt a happ://crypt* or happ://add link.<br>
    &nbsp;&nbsp;Body:{"url":"happ://..."} → {"decryptedUrl":"https://..."}<br>
    &nbsp;&nbsp;Auth: Bearer &lt;key&gt; (header) or ?apikey=&lt;key&gt; (query)<br>
    <code>POST /api/v1/key</code> — Generate a personal API key (1 per minute per IP)<br>
    &nbsp;&nbsp;Response: {"key":"abc123...","limit":"10 req/min"}<br>
    <code>GET /api/v1/keys</code> — Supported versions and key counts<br>
    <code>POST /api/v1/decrypt-text</code> — Decrypt all happ links in arbitrary text<br>
    &nbsp;&nbsp;Body:{"text":"Check happ://crypt5/..."} → {"text":"Check https://..."}
  </div>

  <label style="margin-top:1rem">Rate Limiting</label>
  <div style="font-size:0.72rem;color:var(--muted);line-height:2">
    Demo key: <strong>5 req/min</strong> (shared, counted per key, not per IP)<br>
    Personal key: <strong>10 req/min</strong><br>
    Overlimit → HTTP 429 with {"error":"rate limit exceeded"} and Retry-After header
  </div>

  <label style="margin-top:1rem">Passthrough Format</label>
  <div style="font-size:0.72rem;color:var(--muted);line-height:2">
    <code>happ://add/https://sub.example.com/abc</code><br>
    Simply strips the prefix, returns the URL as-is (no decryption needed).
  </div>

  <label style="margin-top:1rem">Error Codes</label>
  <div style="font-size:0.72rem;color:var(--muted);line-height:2">
    <code>200</code> — {"decryptedUrl":"..."}<br>
    <code>400</code> — {"error":"invalid request body"} or crypt-specific error<br>
    <code>401</code> — {"error":"missing or invalid api key"}<br>
    <code>429</code> — {"error":"rate limit exceeded"}
  </div>
</div>
</main>

<footer>
  VTK · <a href="#" onclick="testApi()" style="color:var(--cyan);text-decoration:none">test api</a>
</footer>
ipt>



<script>
function showResult(id, content, success, isHtml) {
  var box = document.getElementById(id);
  var el = document.getElementById(id + 'Content');
  if (!el) return;
  if (isHtml) el.innerHTML = content;
  else el.textContent = content;
  el.className = 'result-content ' + (success ? 'success' : 'error');
  box.classList.add('visible');
}

function copyResult(id) {
  var text = document.getElementById(id).textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text);
  }
  var btn = document.querySelector('#' + id + ' .copy-btn');
  if (btn) { btn.textContent = '\u2713'; setTimeout(function(){ btn.textContent = 'COPY'; }, 1200); }
}

async function convertLinks() {
  var input = document.getElementById('convertInput').value.trim();
  if (!input) { showResult('convertResult', 'Enter links', false); return; }
  var format = document.getElementById('convertFormat').value;
  var prefix = document.getElementById('tagPrefix').value;
  try {
    var url = '/api/convert?input=' + encodeURIComponent(input) + '&format=' + format;
    if (prefix) url += '&tag_prefix=' + encodeURIComponent(prefix);
    var r = await fetch(url);
    var d = await r.json();
    if (d.ok) showResult('convertResult', d.result, true);
    else showResult('convertResult', 'Error: ' + (d.error || 'unknown'), false);
  } catch (e) { showResult('convertResult', 'Error: ' + e.message, false); }
}

async function decryptLink() {
  var input = document.getElementById('decryptInput').value.trim();
  if (!input) { showResult('decryptResult', 'Enter link', false); return; }
  try {
    var r = await fetch('/api/happ/decrypt', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: input})
    });
    var d = await r.json();
    if (d.ok) showResult('decryptResult', d.decryptedUrl, true);
    else showResult('decryptResult', 'Error: ' + (d.error || 'unknown'), false);
  } catch (e) { showResult('decryptResult', 'Error: ' + e.message, false); }
}

async function decryptText() {
  var input = document.getElementById('decryptInput').value.trim();
  if (!input) { showResult('decryptResult', 'Enter text', false); return; }
  try {
    var r = await fetch('/api/happ/decrypt-text', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text: input})
    });
    var d = await r.json();
    if (d.ok) showResult('decryptResult', d.text, d.decrypted);
    else showResult('decryptResult', 'Error: ' + (d.error || 'unknown'), false);
  } catch (e) { showResult('decryptResult', 'Error: ' + e.message, false); }
}

function clearDecrypt() {
  document.getElementById('decryptInput').value = '';
  document.getElementById('decryptResult').classList.remove('visible');
}

async function proxyFetch() {
  var url = document.getElementById('proxyUrl').value.trim();
  if (!url) { showResult('proxyResult', 'Enter subscription URL', false); return; }
  var parts = [];
  var fields = ['proxyVer', 'proxyModel', 'proxyUa', 'proxyLocale', 'proxyHwid'];
  var vals = ['ver=', 'model=', 'ua=', 'locale=', 'hwid='];
  for (var i = 0; i < fields.length; i++) {
    var v = document.getElementById(fields[i]).value.trim();
    if (v) parts.push(vals[i] + v);
  }
  var os_val = document.getElementById('proxyOs').value.trim();
  if (parts.length === 0) parts.push(os_val || 'android');
  else parts.unshift(os_val || 'android');
  var format = document.getElementById('proxyFormat').value;
  var host = window.location.origin;
  var paramsStr = parts.join(',');
  var fullUrl = host + '/p/' + paramsStr + '/' + url;
  if (format !== 'as_is') fullUrl += '?format=' + format;
  var urlHtml = '<label>URL for app<\/label><div class="url-box"><a href="' + fullUrl + '" target="_blank">' + fullUrl + '<\/a><\/div>';
  urlHtml += `<button class=\"copy-btn\" onclick=\"navigator.clipboard.writeText('${fullUrl}')\">COPY</button>`;
  urlHtml += '<a href="' + fullUrl + '" target="_blank"><button class="copy-btn">OPEN<\/button><\/a>';
  showResult('proxyResult', urlHtml, true, true);
  try {
    var r = await fetch('/p/' + paramsStr + '/' + url + (format !== 'as_is' ? '?format=' + format : ''));
    var text = await r.text();
    if (text.length > 0) {
      var preview = '<div class="preview"><strong>Preview:<\/strong><br>' +
        text.substring(0, 800) + (text.length > 800 ? '... (' + text.length + ' bytes)' : '') + '<\/div>';
      document.getElementById('proxyResultContent').innerHTML += preview;
    }
  } catch (e) { /* ignore */ }
}

function randomizeProxy() {
  var agents = ['Happ/3.24.1','Happ/3.23.0','Happ/3.20.2','Happ/3.18.2','Happ/3.17.0'];
  var iosModels = ['iPhone 16','iPhone 15','iPhone 14'];
  var androidModels = ['Pixel 8','Samsung S24','OnePlus 12'];
  var locales = ['en_US','ru_RU','de_DE','fr_FR'];
  var r = function(a) { return a[Math.floor(Math.random() * a.length)]; };
  var os = r(['ios','android']);
  document.getElementById('proxyUa').value = r(agents);
  document.getElementById('proxyHwid').value = Array.from({length:12}, function(){ return Math.floor(Math.random()*16).toString(16); }).join('');
  document.getElementById('proxyOs').value = os;
  document.getElementById('proxyVer').value = (3 + Math.floor(Math.random()*2)) + '.' + Math.floor(Math.random()*24) + '.' + Math.floor(Math.random()*10);
  document.getElementById('proxyModel').value = r(os==='ios'?iosModels:androidModels);
  document.getElementById('proxyLocale').value = r(locales);
}

async function testApi() {
  try {
    var r = await fetch('/api/happ/supported');
    var d = await r.json();
    alert('API OK: ' + d.crypt5_keys + ' crypt5 keys');
  } catch(e) { alert('Error: ' + e.message); }
}
</script>

</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return _HTML


@app.post("/convert", response_class=HTMLResponse)
async def convert_form(
    request: Request,
    input: str = Form(...),
    format: str = Form("singbox"),
    tag_prefix: str = Form(""),
):
    """Legacy form POST — redirect to home (new UI uses JS)."""
    return HTMLResponse(
        '<html><head><meta http-equiv="refresh" content="0;url=/"></head>'
        '<body>Redirecting to <a href="/">home</a>...</body></html>'
    )

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
            from core.logic import fetch_subscription
            content = await fetch_subscription(text, timeout=s.timeout)
            nodes = parse_subscription_text(content)
        except Exception as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    else:
        nodes = parse_text_input(text)
        nodes = [n for n in nodes if n.protocol != "error"]

    if not nodes:
        return JSONResponse({"ok": False, "error": "No valid proxy links"}, status_code=400)

    try:
        fmt = Format(format)
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": f"Unknown format: {format}. Valid: singbox, mihomo, txt"},
            status_code=400,
        )

    try:
        result = convert(nodes, fmt, tag_prefix=tag_prefix)
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


# ---------------------------------------------------------------------------
# Happ decrypt API endpoints
# ---------------------------------------------------------------------------

@app.post("/api/happ/decrypt")
async def api_happ_decrypt(body: dict):
    """Decrypt a happ://crypt* link.

    Body: {"url": "happ://crypt5/..."}
    Returns: {"url": "https://..."}
    """
    url = body.get("url", "")
    if not url:
        return JSONResponse({"ok": False, "error": "Missing 'url' field"}, status_code=400)

    try:
        from core.happ import decrypt_link
        result = decrypt_link(url)
        return {"ok": True, "decryptedUrl": result}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/api/happ/decrypt-text")
async def api_happ_decrypt_text(body: dict):
    """Decrypt all happ:// links in arbitrary text.

    Body: {"text": "Check out happ://crypt5/..."}
    Returns: {"text": "Check out https://..."}
    """
    text = body.get("text", "")
    if not text:
        return JSONResponse({"ok": False, "error": "Missing 'text' field"}, status_code=400)

    try:
        from core.happ import decrypt_text
        result = decrypt_text(text)
        return {"ok": True, "text": result, "decrypted": result != text}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.get("/api/happ/check")
async def api_happ_check(url: str = Query(..., help="happ:// link")):
    """Check if a URL is a happ:// link."""
    try:
        from core.happ import is_happ, decrypt_link
        if is_happ(url):
            decrypted = decrypt_link(url)
            return {"ok": True, "is_happ": True, "decrypted": decrypted}
        return {"ok": True, "is_happ": False, "original": url}
    except Exception as e:
        return {"ok": True, "is_happ": True, "error": str(e)}


@app.get("/api/happ/supported")
async def api_happ_supported():
    """Return supported happ versions and available crypt5 keys count."""
    from core.happdecrypt import _load_crypt5_keys, _PKCS1_KEYS_B64
    keys = _load_crypt5_keys()
    return {
        "ok": True,
        "versions": ["crypt", "crypt2", "crypt3", "crypt4", "crypt5"],
        "crypt1_4_keys": len(_PKCS1_KEYS_B64),
        "crypt5_keys": len(keys),
    }


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# happy-decoder.cc compatible API (v1)
# ---------------------------------------------------------------------------

from pydantic import BaseModel, Field

class HappDecryptRequest(BaseModel):
    url: str = Field(..., description="happ://crypt* or happ://add/ link to decrypt")

_HAPP_DEMO_KEY = "hd_demo_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
_API_KEYS: dict[str, dict] = {}
_KEY_CREATION_TIMES: dict[str, float] = {}


def _generate_key() -> str:
    import random
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))


def _get_happ_key() -> str:
    return os.environ.get("VTK_HAPP_KEY", _HAPP_DEMO_KEY)


from core.happ import _passthrough, _check_rate_limit, _get_client_ip


@app.post("/api/v1/decrypt")
async def api_v1_decrypt(request: Request, req: HappDecryptRequest):
    """Decrypt a happ:// link — compatible with happy-decoder.cc API."""
    api_key = (
        request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        or request.query_params.get("apikey", "")
        or _get_happ_key()
    )
    
    if not api_key:
        return JSONResponse({"error": "missing or invalid api key"}, status_code=401)
    
    if api_key != _HAPP_DEMO_KEY and api_key not in _API_KEYS:
        return JSONResponse({"error": "missing or invalid api key"}, status_code=401)
    
    allowed, retry_after = _check_rate_limit(api_key)
    if not allowed:
        return JSONResponse(
            {"error": "rate limit exceeded"},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )
    
    url = req.url or ""
    if not url:
        return JSONResponse({"error": "invalid request body"}, status_code=400)
    
    passthrough = _passthrough(url)
    if passthrough is not None:
        return {"decryptedUrl": passthrough}
    
    try:
        from core.happ import decrypt_link
        result = decrypt_link(url)
        return {"decryptedUrl": result}
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


@app.options("/api/v1/decrypt")
async def api_v1_decrypt_options():
    """CORS preflight handler."""
    return JSONResponse({}, status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
    })


@app.get("/api/v1/keys")
async def api_v1_keys():
    """Key-info endpoint."""
    return {
        "ok": True,
        "note": "Built-in decryptor does not require keys. All 34 crypt5 RSA keys bundled.",
        "crypt1_4_keys": 4,
        "crypt5_keys": 34,
    }


@app.post("/api/v1/key")
async def api_v1_generate_key(request: Request):
    """Generate a personal API key (max 1 per minute per IP)."""
    client_ip = _get_client_ip(request)
    now = time.time()
    
    last_created = _KEY_CREATION_TIMES.get(client_ip, 0)
    if now - last_created < 60:
        retry_after = int(60 - (now - last_created)) + 1
        return JSONResponse(
            {"error": f"rate limited, try again in {retry_after}s"},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )
    
    key = _generate_key()
    _API_KEYS[key] = {"created": now, "ip": client_ip, "personal": True}
    _KEY_CREATION_TIMES[client_ip] = now
    
    return {"ok": True, "key": key, "limit": "10 req/min", "note": "Store this key safely."}


# ---------------------------------------------------------------------------
# Universal Proxy endpoint /p/ (happy-decoder.cc compatible)
# ---------------------------------------------------------------------------

from urllib.parse import unquote
import random
import hashlib
import re

def _parse_device_params(param_str: str) -> dict:
    """Parse device params from path segment like 'android,ver=14.88,model=67,ua=Happ/3.24.1'"""
    params = {}
    for part in param_str.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip().lower()] = v.strip()
        else:
            # bare value = os
            params["os"] = part.lower()
    return params

def _generate_device_fingerprint(ua: str, hwid: str, os_name: str, ver: str, model: str, locale: str) -> dict:
    """Generate realistic device fingerprint headers for proxy request."""
    headers = {}

    # User-Agent
    if ua:
        headers["User-Agent"] = ua
    else:
        headers["User-Agent"] = "Happ/3.17.0"

    # X-Hwid: hd-xxxxxxxxxxxx format
    if hwid:
        hw_hash = hashlib.md5(hwid.encode()).hexdigest()[:12]
        headers["X-Hwid"] = f"hd-{hw_hash}"

    # X-Device-Os + X-Ver-Os
    if os_name.lower() == "ios":
        ios_versions = ["17", "18", "16", "15"]
        major = ver.split(".")[0] if ver else random.choice(ios_versions)
        headers["X-Device-Os"] = "iOS"
        headers["X-Ver-Os"] = major
        if not model:
            iphone_models = ["iPhone 16", "iPhone 16 Pro", "iPhone 15", "iPhone 15 Pro", "iPhone 14"]
            headers["X-Device-Model"] = random.choice(iphone_models)
        else:
            headers["X-Device-Model"] = model
    elif os_name.lower() == "android":
        android_versions = ["14", "13", "12", "11"]
        major = ver.split(".")[0] if ver else random.choice(android_versions)
        headers["X-Device-Os"] = "Android"
        headers["X-Ver-Os"] = major
        if not model:
            android_models = ["Pixel 8", "Pixel 7", "Samsung S24", "Samsung S23", "OnePlus 12"]
            headers["X-Device-Model"] = random.choice(android_models)
        else:
            headers["X-Device-Model"] = model
    else:
        headers["X-Device-Os"] = os_name or "iOS"
        headers["X-Ver-Os"] = ver or "18"
        headers["X-Device-Model"] = model or "iPhone 16"

    # Accept-Language from locale
    if locale:
        headers["Accept-Language"] = locale.replace("_", "-")
    else:
        headers["Accept-Language"] = "en-US,en;q=0.9"

    return headers

@app.get("/p/{url:path}")
async def api_proxy(
    url: str,
    request: Request,
    format: str = Query("as_is", help="Output format: as_is, json, txt, base64, mihomo"),
    hwid_off: str = Query("", help="Set to '1' to disable HWID"),
    seed_random: str = Query("", help="Set to '1' for random seed"),
):
    """Universal proxy endpoint — fetch subscription with device fingerprint, decrypt happ:// links, convert.

    Compatible with happy-decoder.cc /p/ endpoint.
    URL format: /p/<device-params>/<subscription-url>
    Device params: os=android/ios,ver=X.Y,model=XX,ua=X,locale=X,hwid=X (comma-separated)

    Examples:
      /p/android,ver=14.88,model=67/https://panel.haizvpn.pw/api/sub/abc
      /p/ios,ver=18,model=16/https://sub.example.com/all
      /p/android,ver=14,model=Pixel8,ua=Happ/3.24.1,locale=ru_RU,seed_random=1/https://sub.url
    """
    # Decode the full path
    raw_path = unquote(url)

    # Split device params from subscription URL
    # Format: <device-params>/<subscription-url>
    # Find where http:// or https:// starts
    match = re.search(r"(https?://)", raw_path)
    if not match:
        return JSONResponse(
            {"error": f"Invalid URL format: {raw_path}. Expected /p/<params>/<http-url>"},
            status_code=400,
        )

    split_pos = match.start()
    device_part = raw_path[:split_pos].rstrip("/")
    target_url = raw_path[split_pos:]

    # Parse device params
    device_params = _parse_device_params(device_part) if device_part else {}

    ua = device_params.get("ua", "")
    hwid = device_params.get("hwid", "")
    os_name = device_params.get("os", "")
    ver = device_params.get("ver", "")
    model = device_params.get("model", "")
    locale = device_params.get("locale", "")

    # Validate URL
    if not target_url.startswith(("http://", "https://")):
        return JSONResponse(
            {"error": f"Invalid subscription URL: {target_url}"},
            status_code=400,
        )

    # Generate device fingerprint headers
    if seed_random == "1":
        ua = ua or f"Happ/{random.randint(3, 4)}.{random.randint(0, 30)}.{random.randint(0, 10)}"
        hwid = hwid or hashlib.md5(str(random.random()).encode()).hexdigest()[:12]
        os_name = os_name or random.choice(["ios", "android"])
        ver = ver or str(random.randint(15, 18))
        model = model or ""
        locale = locale or random.choice(["en_US", "ru_RU", "de_DE", "fr_FR"])

    fingerprint = _generate_device_fingerprint(ua, hwid, os_name, ver, model, locale)
    headers = {"User-Agent": fingerprint["User-Agent"]}
    if hwid_off != "1" and "X-Hwid" in fingerprint:
        headers["X-Hwid"] = fingerprint["X-Hwid"]
    headers["X-Device-Os"] = fingerprint["X-Device-Os"]
    headers["X-Ver-Os"] = fingerprint["X-Ver-Os"]
    headers["X-Device-Model"] = fingerprint["X-Device-Model"]
    headers["Accept-Language"] = fingerprint["Accept-Language"]

    try:
        import httpx
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(target_url, headers=headers)
            resp.raise_for_status()
            content = resp.text
    except Exception as e:
        return JSONResponse(
            {"error": f"Failed to fetch {target_url}: {e}"},
            status_code=502,
        )

    # Decrypt any happ:// links in the content
    from core.happ import decrypt_text, is_happ

    output_format = format.lower().replace("-", "_")

    if is_happ(content):
        content = decrypt_text(content)

    # Auto-detect and decode base64 content
    import base64 as _base64
    stripped = content.strip()
    if stripped and not stripped.startswith(("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "socks://", "http://", "https://", "{", "- name:", "#")):
        try:
            decoded = _base64.b64decode(stripped).decode("utf-8", errors="ignore")
            if decoded and len(decoded) > 10:
                content = decoded
        except Exception:
            pass

    # If format is not as_is, parse and convert
    if output_format != "as_is":
        from core.logic import parse_subscription_text, ParseError
        from core.converters import convert, Format

        format_map = {
            "json": Format.SINGBOX,
            "txt": Format.TXT,
            "base64": Format.TXT,  # will encode after
            "mihomo": Format.MIHOMO,
            "clash": Format.MIHOMO,
            "singbox": Format.SINGBOX,
            "flclash": Format.FLCLASH,
            "xray": Format.XRAY,
        }
        fmt = format_map.get(output_format, Format.TXT)

        try:
            nodes = parse_subscription_text(content)
            nodes = [n for n in nodes if n.protocol != "error"]

            if nodes:
                bare = output_format in ("mihomo", "clash") or request.query_params.get("bare", "") == "1"
                result = convert(nodes, fmt, bare=bare)
                if output_format == "base64":
                    import base64
                    result = base64.b64encode(result.encode()).decode()
                return PlainTextResponse(result)
            elif output_format == "base64":
                import base64
                return PlainTextResponse(base64.b64encode(content.encode()).decode())
            else:
                return JSONResponse(
                    {"error": "No valid proxy links found in subscription"},
                    status_code=400,
                )
        except ParseError as e:
            return JSONResponse(
                {"error": f"Parse error: {e}"},
                status_code=400,
            )

    return PlainTextResponse(content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
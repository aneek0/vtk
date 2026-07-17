from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os

router = APIRouter()

_templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
templates = Jinja2Templates(directory=_templates_dir)


def _page(request: Request, tab: str = "convert") -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", {"tab": tab})


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return _page(request)


@router.get("/convert", response_class=HTMLResponse)
async def convert_page(request: Request):
    return _page(request, "convert")


@router.get("/proxy", response_class=HTMLResponse)
async def proxy_page(request: Request):
    return _page(request, "proxy")


@router.get("/decrypt", response_class=HTMLResponse)
async def decrypt_page(request: Request):
    return _page(request, "decrypt")


@router.get("/api", response_class=HTMLResponse)
async def api_page(request: Request):
    return _page(request, "api")


@router.post("/convert", response_class=HTMLResponse)
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

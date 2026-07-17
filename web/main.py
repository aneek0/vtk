"""Web interface for VLESS toolkit — FastAPI."""

import os
import time
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from web.routes.convert import router as convert_router
from web.routes.proxy import router as proxy_router
from web.routes.decrypt import router as decrypt_router
from web.routes.frontend import router as frontend_router

logger = logging.getLogger("vtk.web")

app = FastAPI(title="VLESS Toolkit")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

# Routers
app.include_router(frontend_router)
app.include_router(convert_router)
app.include_router(proxy_router)
app.include_router(decrypt_router)


# ── Health ──

@app.get("/health")
async def health():
    return {"status": "ok", "uptime": time.time() - _start_time}


_start_time = time.time()


# ── Exception handlers ──

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s: %s", request.url.path, exc, exc_info=True)
    return JSONResponse({"error": "internal server error"}, status_code=500)


# ── Startup / shutdown ──

@app.on_event("startup")
async def startup():
    logger.info("VTK web started")


@app.on_event("shutdown")
async def shutdown():
    logger.info("VTK web shutting down")
    import asyncio
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for t in tasks:
        t.cancel()


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=9000)

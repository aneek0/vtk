# vtk web image — FastAPI interface only.
FROM python:3.13-slim AS base

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Dependencies first (cached layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev --extra web

# Project + bundled data (keymat ships in the wheel)
COPY . .
RUN uv sync --frozen --no-dev --extra web

RUN useradd --create-home vtk && chown -R vtk:vtk /app
USER vtk

EXPOSE 9000
CMD ["uv", "run", "--no-dev", "uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "9000"]

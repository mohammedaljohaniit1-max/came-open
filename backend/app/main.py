"""
CAMRADAR - Attack Surface Intelligence Platform
FastAPI application entry point.
"""
from __future__ import annotations

import warnings
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .core.config import settings
from .core.database import init_db
from .routes.api import router as api_router

# Silence noisy urllib3/httpx TLS warnings when probing self-signed camera hosts.
warnings.filterwarnings("ignore")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="CAMRADAR - Attack Surface Intelligence Platform",
    description="Real-time OSINT camera aggregator & availability validator "
                "(Cybersecurity graduation project).",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

# --- Static frontend ---
FRONTEND = settings.FRONTEND_DIR
app.mount("/css", StaticFiles(directory=FRONTEND / "css"), name="css")
app.mount("/js", StaticFiles(directory=FRONTEND / "js"), name="js")
app.mount("/assets", StaticFiles(directory=FRONTEND / "assets"), name="assets")


@app.get("/")
async def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/favicon.ico")
async def favicon():
    return FileResponse(FRONTEND / "assets" / "favicon.svg")

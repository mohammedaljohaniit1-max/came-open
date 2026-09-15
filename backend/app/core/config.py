"""
Central configuration for CAMRADAR.

Loads settings from environment variables (.env supported). Keeps all tunables
and the (scope-limited) Shodan credential in one place.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import List

from dotenv import load_dotenv

# Load .env from project root if present.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(_PROJECT_ROOT / ".env")


class Settings:
    """Runtime configuration resolved from the environment."""

    def __init__(self) -> None:
        # --- Shodan ---
        # NOTE: OSS-plan key. Only /shodan/host/{ip} and /shodan/host/count are
        # available; the bulk /shodan/host/search endpoint returns 403 and is
        # therefore never called by CAMRADAR.
        self.SHODAN_API_KEY: str = os.getenv(
            "SHODAN_API_KEY", "BuHu9XqFRSmbubbZlnNRTqJVZCHDMfY4"
        )
        self.SHODAN_BASE_URL: str = "https://api.shodan.io"

        # --- Server ---
        self.HOST: str = os.getenv("HOST", "0.0.0.0")
        self.PORT: int = int(os.getenv("PORT", "5000"))

        # --- Pre-Flight Validator ---
        self.PROBE_TIMEOUT_MS: int = int(os.getenv("PROBE_TIMEOUT_MS", "1500"))
        self.PROBE_CONCURRENCY: int = int(os.getenv("PROBE_CONCURRENCY", "100"))

        # --- Paths ---
        self.PROJECT_ROOT: Path = _PROJECT_ROOT
        self.DATA_DIR: Path = _PROJECT_ROOT / "backend" / "data"
        self.DB_PATH: Path = self.DATA_DIR / "camradar.db"
        self.FRONTEND_DIR: Path = _PROJECT_ROOT / "frontend"
        self.SEED_PATH: Path = self.DATA_DIR / "seed_catalogue.json"

        # --- Legal / scope control ---
        raw_cidrs = os.getenv("AUTHORIZED_SCAN_CIDRS", "").strip()
        self.AUTHORIZED_SCAN_CIDRS: List[str] = (
            [c.strip() for c in raw_cidrs.split(",") if c.strip()] if raw_cidrs else []
        )

        # Ensure data dir exists.
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)

    @property
    def probe_timeout_s(self) -> float:
        return self.PROBE_TIMEOUT_MS / 1000.0


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

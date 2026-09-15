#!/usr/bin/env python3
"""
CAMRADAR launcher.

Run with:  python app.py
Opens the Attack Surface Intelligence dashboard on http://localhost:5000
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

import uvicorn  # noqa: E402

from app.core.config import settings  # noqa: E402


def main() -> None:
    print("=" * 68)
    print("  CAMRADAR - Attack Surface Intelligence Platform")
    print("  OSINT Camera Aggregator & Real-Time Availability Validator")
    print("=" * 68)
    print(f"  Dashboard : http://localhost:{settings.PORT}")
    print(f"  API docs  : http://localhost:{settings.PORT}/docs")
    print("=" * 68)
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
    )


if __name__ == "__main__":
    main()

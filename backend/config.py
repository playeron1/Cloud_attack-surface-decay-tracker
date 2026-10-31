import os
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    DEBUG = _env_bool("CAST_DEBUG", False)
    CORS_ORIGINS = [
        value.strip()
        for value in os.getenv(
            "CAST_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        ).split(",")
        if value.strip()
    ]
    AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
    AWS_PROFILE_NAME = os.getenv("AWS_PROFILE") or None
    MAX_SCAN_HOSTS = int(os.getenv("CAST_MAX_SCAN_HOSTS", "10"))
    MAX_HISTORY_ITEMS = int(os.getenv("CAST_MAX_HISTORY_ITEMS", "20"))
    HISTORY_DB_PATH = os.getenv(
        "CAST_HISTORY_DB",
        str(Path(__file__).resolve().parent / "reports" / "cast_history.sqlite3"),
    )

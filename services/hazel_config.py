import json
import os
import platform
import sys
from pathlib import Path


def _resource_root() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parents[1]


def user_config_dir() -> Path:
    if os.name == "nt":
        base = Path(os.getenv("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.getenv("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "HazelCoolTrader"


# Backward-compatible private alias used by older callers.
_user_config_dir = user_config_dir


def _read_json(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def app_config() -> dict:
    config = {}
    for path in (
        _resource_root() / "assets" / "kendra_pay_config.json",
        user_config_dir() / "kendra_pay_config.json",
        _resource_root() / "assets" / "hazel_build_profile.json",
    ):
        config.update(_read_json(path))
    return config


def get_config(key: str, default: str = "") -> str:
    value = os.getenv(key)
    if value is not None and str(value).strip() != "":
        return str(value).strip()
    value = app_config().get(key, default)
    return str(value).strip() if value is not None else default

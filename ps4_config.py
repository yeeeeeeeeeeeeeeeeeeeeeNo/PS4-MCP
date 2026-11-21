import json
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = ROOT_DIR / "config.json"


def load_config() -> dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    # Ensure workspace subdirectories exist cleanly
    for key, rel in cfg.get("paths", {}).items():
        (ROOT_DIR / rel).mkdir(parents=True, exist_ok=True)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    tmp.replace(CONFIG_PATH)


def get_dir(cfg: dict[str, Any], key: str) -> Path:
    rel = cfg.get("paths", {}).get(key, key)
    p = ROOT_DIR / rel
    p.mkdir(parents=True, exist_ok=True)
    return p


def update_nested_config(dot_path: str, value: Any) -> dict[str, Any]:
    cfg = load_config()
    parts = dot_path.split(".")
    cur = cfg
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value
    save_config(cfg)
    return cfg

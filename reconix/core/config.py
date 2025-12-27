from pathlib import Path
import yaml

CONFIG_PATH = Path.home() / ".reconix.yml"

DEFAULT_CONFIG = {
    "mode": "quick",
    "dirsearch": {
        "enabled": False,
        "wordlist": "/usr/share/wordlists/dirb/common.txt",
        "extensions": ["php", "html", "js"],
        "threads": 20,
        "recursive": False,
        "recursion_depth": 2,
    },
    "nmap": {
        "top_ports": 100,
        "timing": "T3",
    },
}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        user_cfg = yaml.safe_load(CONFIG_PATH.read_text()) or {}
        return {**DEFAULT_CONFIG, **user_cfg}
    return DEFAULT_CONFIG


def save_config(cfg: dict):
    CONFIG_PATH.write_text(yaml.safe_dump(cfg))

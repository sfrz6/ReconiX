from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import yaml

CONFIG_PATH = Path.home() / ".reconix.yml"


DEFAULT_CONFIG: Dict[str, Any] = {
    # Default mode if user doesn't pass --mode
    "mode": "quick",

    # OSINT keys/settings (keys are stored here but should NEVER be printed)
    "osint": {
        "githubkey": "",  # empty by default
    },

    # Subfinder provider keys -> used to generate provider-config.yaml
    "subfinder": {
        "providers": {
            # examples (empty by default):
            # "virustotal": [],
            # "securitytrails": [],
            # "shodan": [],
        }
    },

    # QUICK settings (passive)
    "quick": {
        "wayback_top": 50,        # top N wayback URLs
        "osint_lite": True,       # RDAP + DNS (and similar lightweight enrichment)
        "github_osint": False,    # optional GitHub OSINT (can be enabled via CLI)
        "delta": True,            # quick_snapshot.json delta detection
    },

    # NORMAL settings (active-ish)
    "normal": {
        # httpx stage
        "httpx": {
            "enabled": True,
            "threads": 80,
            "timeout": 8,
            "follow_redirects": True,
            "tech_detect": True,
        },

        # katana stage
        "katana": {
            "enabled": True,
            "depth": 2,
            "concurrency": 20,
            "timeout": 10,
            "js_crawl": False,
        },

        # wafw00f stage (you wanted config-first; enable default here if you want it ON)
        "wafw00f": {
            "enabled": True,
            "timeout": 5,
            "max_urls": 200,
            "noredirect": True,
            "findall": False,
        },

        # Port scan stage selection (used when user passes --port/--port-scan)
        # tool: "nmap" | "naabu" | "both"
        "portscan": {
            "tool": "both",
        },

        # naabu defaults (fast port discovery)
        "naabu": {
            "top_ports": 100,
            "rate": 300,
            "timeout": 5,
        },

        # ffuf defaults (only runs when user passes --dir/--dir-search)
        "ffuf": {
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "extensions": ["php", "html", "js"],
            "threads": 20,
            "recursive": False,
            "recursion_depth": 2,
        },

        # nmap defaults (only runs when user passes --port/--port-scan and tool includes nmap)
        "nmap": {
            "top_ports": 100,
            "timing": "T3",              # can be overridden by --nmap-fast or --nmap-timing
            "service_detection": False,  # optional noisy feature
        },
    },

    # ---------------------------------------------------------------------
    # Legacy keys (kept for backward compatibility with your current code/UI)
    # You can gradually migrate orchestrator to prefer normal.ffuf / normal.nmap.
    # ---------------------------------------------------------------------
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


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge override into base (without modifying original dicts).
    override wins for conflicts, but nested dict defaults are preserved.
    """
    result: Dict[str, Any] = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)  # type: ignore[arg-type]
        else:
            result[k] = v
    return result


def load_config() -> Dict[str, Any]:
    """
    Load ~/.reconix.yml and deep-merge into DEFAULT_CONFIG.
    If config file doesn't exist, return defaults.
    """
    if CONFIG_PATH.exists():
        raw = CONFIG_PATH.read_text(encoding="utf-8")
        user_cfg = yaml.safe_load(raw) or {}
        if not isinstance(user_cfg, dict):
            # If file is corrupted/non-dict, ignore it safely
            user_cfg = {}
        return _deep_merge(DEFAULT_CONFIG, user_cfg)
    return dict(DEFAULT_CONFIG)


def save_config(cfg: Dict[str, Any]) -> None:
    """
    Save full config to ~/.reconix.yml.
    """
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )

# reconix/modules/katana.py
from __future__ import annotations

import shutil
import subprocess
from typing import Dict, List, Optional
from urllib.parse import urlparse


def _require(bin_name: str):
    if shutil.which(bin_name) is None:
        raise FileNotFoundError(f"Missing binary: {bin_name}")


def _norm_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    # keep only real URLs
    if not (u.startswith("http://") or u.startswith("https://")):
        return ""
    # strip fragments
    try:
        p = urlparse(u)
        return p._replace(fragment="").geturl()
    except Exception:
        return u


def _cfg_get(cfg: dict, key: str, default=None):
    cur = cfg
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def run_katana(
    base_urls: List[str],
    *,
    cfg: Optional[dict] = None,
    depth: Optional[int] = None,
    js_crawl: Optional[bool] = None,
    rate_limit: Optional[int] = None,
    timeout: int = 90,
) -> Dict[str, List[str]]:
    """
    Katana URL discovery.

    IMPORTANT:
      - Your katana build doesn't support -json, so we parse plain stdout URLs.
      - Returns: { base_url: [discovered_urls] }
    """
    _require("katana")
    if not base_urls:
        return {}

    # defaults from config (NORMAL)
    if cfg:
        depth = int(depth if depth is not None else _cfg_get(cfg, "normal.katana.depth", 2))
        js_crawl = bool(js_crawl if js_crawl is not None else _cfg_get(cfg, "normal.katana.js_crawl", True))
        rate_limit = int(rate_limit if rate_limit is not None else _cfg_get(cfg, "normal.katana.rate_limit", 50))
    else:
        depth = int(depth if depth is not None else 2)
        js_crawl = bool(js_crawl if js_crawl is not None else True)
        rate_limit = int(rate_limit if rate_limit is not None else 50)

    # safety caps
    if depth < 1:
        depth = 1
    if depth > 5:
        depth = 5

    results: Dict[str, List[str]] = {}

    for base in base_urls:
        base = (base or "").strip()
        if not base:
            continue

        cmd = [
            "katana",
            "-u", base,
            "-silent",
            "-depth", str(depth),
        ]

        # JS crawling (supported in your build: -jc)
        if js_crawl:
            cmd += ["-jc"]

        # rate limit (commonly supported as -rl)
        if rate_limit and rate_limit > 0:
            cmd += ["-rl", str(rate_limit)]

        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # if katana fails, skip gracefully
        if p.returncode != 0:
            continue

        urls: List[str] = []
        seen = set()

        for line in (p.stdout or "").splitlines():
            u = _norm_url(line)
            if not u:
                continue
            if u in seen:
                continue
            seen.add(u)
            urls.append(u)

        if urls:
            results[base] = urls

    return results

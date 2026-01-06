# reconix/modules/wayback.py
from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".map", ".woff", ".woff2",
    ".ico", ".pdf", ".zip", ".tar", ".gz", ".7z", ".mp4", ".mp3"
)

_CDX_API = "https://web.archive.org/cdx/search/cdx"


def _norm_domain(domain: str) -> str:
    d = (domain or "").strip().lower()

    # If user passed a URL, extract hostname
    if "://" in d:
        try:
            d = urlparse(d).hostname or d
        except Exception:
            pass

    # Remove any path fragments accidentally included
    d = d.split("/")[0].strip().rstrip(".")
    # basic sanity
    d = re.sub(r"\s+", "", d)
    return d


def fetch_wayback_urls(domain: str, timeout: int = 20, limit: int = 2000) -> list[str]:
    """
    Fetch archived URLs from Wayback CDX API.
    Returns up to `limit` non-static URLs.
    """
    d = _norm_domain(domain)
    if not d:
        return []

    params = {
        # more stable than "*.domain/*" in practice
        "url": d,
        "matchType": "domain",        # include subdomains
        "output": "json",
        "fl": "original,statuscode",  # we filter by statuscode + still return original
        "collapse": "urlkey",
        "filter": "statuscode:200",   # reduce noise
    }

    r = requests.get(_CDX_API, params=params, timeout=timeout, headers={"User-Agent": "ReconiX"})
    r.raise_for_status()

    rows = r.json()
    if not isinstance(rows, list) or len(rows) <= 1:
        # header only or unexpected format
        return []

    out: list[str] = []
    for row in rows[1:]:  # skip header
        # expected: [original, statuscode] in some order depending on header
        # but we used fl=original,statuscode, so:
        u = (row[0] or "").strip() if isinstance(row, list) and len(row) > 0 else ""
        if not u:
            continue

        lu = u.lower()
        if lu.endswith(STATIC_EXT):
            continue

        out.append(u)
        if len(out) >= limit:
            break

    return out

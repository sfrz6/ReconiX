# reconix/modules/cve_candidates.py
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _extract_cves(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(text or "")})


def _run_searchsploit_json(query: str, timeout: int = 10) -> dict[str, Any] | None:
    """
    Uses local Exploit-DB index via searchsploit.
    Requires: searchsploit installed.
    """
    q = (query or "").strip()
    if not q:
        return None
    if shutil.which("searchsploit") is None:
        return None

    cmd = ["searchsploit", "-j", q]
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return None

    out = (p.stdout or "").strip()
    if not out:
        return None

    try:
        return json.loads(out)
    except Exception:
        return None


def _get_searchsploit_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Tolerant extraction of exploit rows across searchsploit versions.
    """
    if not isinstance(data, dict):
        return []
    # common: {"RESULTS_EXPLOIT":{"rows":[...]}}
    for k in ("RESULTS_EXPLOIT", "RESULTS", "results_exploit", "results"):
        node = data.get(k)
        if isinstance(node, dict):
            rows = node.get("rows")
            if isinstance(rows, list):
                return [r for r in rows if isinstance(r, dict)]
    return []


# Keep NORMAL from spamming noisy generic libs/CDNs/framework mentions
_DEFAULT_IGNORE = {
    "cloudflare",
    "jquery",
    "bootstrap",
    "font awesome",
    "google analytics",
    "google tag manager",
    "recaptcha",
    "hsts",
    "http/2",
    "open graph",
    "html5",
}


def _clean_query(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    # normalize separators
    s = s.replace("/", " ").replace(":", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def build_queries_from_tech(
    tech_list: list[Any],
    *,
    ignore: set[str] | None = None,
    require_version: bool = False,
) -> list[str]:
    """
    Accepts either:
      - list[str]  (legacy)
      - list[{"name":..., "version":..., "raw":...}] (preferred from http.py)

    If require_version=True -> only include queries that have version.
    """
    ignore = {x.lower() for x in (ignore or _DEFAULT_IGNORE)}

    queries: list[str] = []
    seen: set[str] = set()

    for t in tech_list or []:
        name = ""
        ver = ""

        if isinstance(t, dict):
            name = str(t.get("name") or "").strip()
            ver = str(t.get("version") or "").strip()
            raw = str(t.get("raw") or "").strip()
            if not name and raw:
                name = raw
        else:
            raw = str(t).strip()
            if raw:
                # best-effort parsing for legacy strings
                raw2 = raw.replace("/", " ").replace(":", " ")
                raw2 = re.sub(r"\s+", " ", raw2).strip()
                # split last token as version if it looks versiony
                parts = raw2.split()
                if len(parts) >= 2 and re.match(r"^[0-9][0-9A-Za-z.\-_+~]+$", parts[-1]):
                    ver = parts[-1]
                    name = " ".join(parts[:-1]).strip()
                else:
                    name = raw2

        name_l = name.lower().strip()
        if not name_l:
            continue
        if name_l in ignore:
            continue
        if require_version and not ver:
            continue

        q = f"{name} {ver}".strip() if ver else name
        q = _clean_query(q)
        if not q:
            continue
        if q.lower() in seen:
            continue
        seen.add(q.lower())
        queries.append(q)

    return queries


def build_queries_from_services(services: list[dict[str, Any]]) -> list[str]:
    """
    services expected like:
    { "port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.2p1", "extrainfo": "...", "cpe": "cpe:/a:..." }
    """
    queries: list[str] = []
    seen: set[str] = set()

    for svc in services or []:
        if not isinstance(svc, dict):
            continue

        product = str(svc.get("product") or "").strip()
        version = str(svc.get("version") or "").strip()
        name = str(svc.get("name") or "").strip()

        base = product or name
        if not base:
            continue

        q = f"{base} {version}".strip() if version else base
        q = _clean_query(q)
        if not q:
            continue

        key = q.lower()
        if key in seen:
            continue
        seen.add(key)
        queries.append(q)

    return queries


def cve_candidates_from_queries(
    queries: list[str],
    *,
    max_queries: int = 25,
    timeout: int = 10,
    max_results_per_query: int = 10,
) -> list[dict[str, Any]]:
    """
    Returns CVE candidates as inferred results from local searchsploit titles.
    Not a validated vulnerability finding.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    for q in (queries or [])[: max(0, int(max_queries))]:
        q = (q or "").strip()
        if not q:
            continue

        data = _run_searchsploit_json(q, timeout=timeout)
        if not data:
            continue

        rows = _get_searchsploit_rows(data)

        for row in rows[: max(0, int(max_results_per_query))]:
            title = str(row.get("Title") or "").strip()
            edb = str(row.get("EDB-ID") or "").strip()
            path = str(row.get("Path") or "").strip()
            cves = _extract_cves(title)

            key = f"{q}|{edb}|{path}|{title}"
            if key in seen:
                continue
            seen.add(key)

            out.append(
                {
                    "source": "searchsploit",
                    "query": q,
                    "title": title,
                    "edb_id": edb,
                    "path": path,
                    "cves": cves,
                    "note": "inferred (not validated)",
                }
            )

    return out

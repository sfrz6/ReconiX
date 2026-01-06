# reconix/modules/wafw00f.py
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _dedup_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        x = (x or "").strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _cfg_get(cfg: dict, key: str, default=None):
    cur: Any = cfg
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


_WAF_LINE_RE = re.compile(r"behind\s+(.+?)\s+WAF", re.IGNORECASE)


def _parse_waf_text(stdout: str) -> List[str]:
    """
    Best-effort parsing for typical wafw00f text output.
    """
    vendors: List[str] = []
    if not stdout:
        return vendors

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue

        m = _WAF_LINE_RE.search(line)
        if m:
            v = m.group(1).strip()
            if v and v not in vendors:
                vendors.append(v)

    return vendors


def run_wafw00f(
    urls: Iterable[str],
    *,
    cfg: Optional[dict] = None,
    out_ndjson: Optional[Path] = None,
    timeout: Optional[int] = None,
    max_urls: Optional[int] = None,
    noredirect: Optional[bool] = None,
    findall: Optional[bool] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Run wafw00f against alive base URLs (authorized only).

    Returns:
      dict[url] -> {
        "detected": bool,
        "wafs": [vendors],
        "tool": "wafw00f",
        "timestamp": "...",
        "raw_hint": "..." (optional)
      }

    Writes NDJSON to out_ndjson if provided.
    """

    waf = shutil.which("wafw00f")
    if not waf:
        raise RuntimeError("wafw00f not found in PATH. Install it to enable WAF detection.")

    # Resolve config-first defaults
    if cfg:
        timeout = timeout if timeout is not None else int(_cfg_get(cfg, "normal.wafw00f.timeout", 8))
        max_urls = max_urls if max_urls is not None else int(_cfg_get(cfg, "normal.wafw00f.max_urls", 200))
        noredirect = noredirect if noredirect is not None else bool(_cfg_get(cfg, "normal.wafw00f.noredirect", True))
        findall = findall if findall is not None else bool(_cfg_get(cfg, "normal.wafw00f.findall", False))
    else:
        timeout = 8 if timeout is None else int(timeout)
        max_urls = 200 if max_urls is None else int(max_urls)
        noredirect = True if noredirect is None else bool(noredirect)
        findall = False if findall is None else bool(findall)

    url_list = _dedup_keep_order(urls)[: max(0, int(max_urls))]
    results: Dict[str, Dict[str, Any]] = {}

    if out_ndjson is not None:
        out_ndjson.parent.mkdir(parents=True, exist_ok=True)

    if not url_list:
        if out_ndjson is not None:
            out_ndjson.write_text("", encoding="utf-8")
        return results

    # Flags (common safe ones)
    base_flags: List[str] = []
    if findall:
        base_flags.append("-a")
    if noredirect:
        base_flags.append("-r")

    # Use a temp file for -i (never leave files behind)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=True) as tmp:
        tmp.write("\n".join(url_list) + "\n")
        tmp.flush()
        inp_path = tmp.name

        # --- Best effort bulk JSON attempt ---
        # Different wafw00f builds expose different flags; try safe variants.
        bulk_cmds: List[List[str]] = []
        for tflag in ("-T", "-t"):
            bulk_cmds.append([waf] + base_flags + [tflag, str(timeout), "-i", inp_path, "-f", "json"])
            bulk_cmds.append([waf] + base_flags + [tflag, str(timeout), "-i", inp_path, "-f", "json", "-o", "-"])

        bulk_data: Optional[Any] = None
        for cmd in bulk_cmds:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                out = (proc.stdout or "").strip()
                if proc.returncode == 0 and out:
                    try:
                        bulk_data = json.loads(out)
                        break
                    except Exception:
                        bulk_data = None
            except Exception:
                continue

        # If bulk JSON worked, normalize it
        if bulk_data is not None:
            items: List[dict] = []
            if isinstance(bulk_data, list):
                items = [x for x in bulk_data if isinstance(x, dict)]
            elif isinstance(bulk_data, dict):
                if isinstance(bulk_data.get("results"), list):
                    items = [x for x in bulk_data["results"] if isinstance(x, dict)]
                else:
                    items = [bulk_data]

            for it in items:
                url = (it.get("url") or it.get("target") or it.get("input") or "").strip()
                if not url:
                    continue

                wafs = it.get("waf") or it.get("wafs") or it.get("vendors") or it.get("detected") or []
                if isinstance(wafs, str):
                    waf_list = [wafs] if wafs else []
                elif isinstance(wafs, list):
                    waf_list = [str(x).strip() for x in wafs if str(x).strip()]
                else:
                    waf_list = []

                ts = _utc_now()
                results[url] = {
                    "detected": bool(waf_list),
                    "wafs": waf_list,
                    "tool": "wafw00f",
                    "timestamp": ts,
                }

            if out_ndjson is not None:
                with out_ndjson.open("w", encoding="utf-8") as f:
                    for url in url_list:
                        r = results.get(url) or {
                            "detected": False,
                            "wafs": [],
                            "tool": "wafw00f",
                            "timestamp": _utc_now(),
                        }
                        f.write(
                            json.dumps(
                                {
                                    "type": "waf_fingerprint",
                                    "tool": "wafw00f",
                                    "url": url,
                                    "detected": r["detected"],
                                    "wafs": r["wafs"],
                                    "timestamp": r["timestamp"],
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )

            return results

    # --- Fallback: per-URL text parsing ---
    w = out_ndjson.open("w", encoding="utf-8") if out_ndjson is not None else None
    try:
        for url in url_list:
            detected = False
            vendors: List[str] = []
            raw_hint = ""

            per_url_cmds: List[List[str]] = []
            for tflag in ("-T", "-t"):
                per_url_cmds.append([waf] + base_flags + [tflag, str(timeout), url])

            ran_ok = False
            for cmd in per_url_cmds:
                proc = subprocess.run(cmd, capture_output=True, text=True)
                out = (proc.stdout or "").strip()
                if proc.returncode == 0:
                    ran_ok = True
                    vendors = _parse_waf_text(out)
                    detected = bool(vendors)
                    raw_hint = out[:200]
                    break

            ts = _utc_now()
            rec_obj = {
                "detected": detected if ran_ok else False,
                "wafs": vendors if ran_ok else [],
                "tool": "wafw00f",
                "timestamp": ts,
            }
            if raw_hint:
                rec_obj["raw_hint"] = raw_hint

            results[url] = rec_obj

            if w is not None:
                w.write(
                    json.dumps(
                        {
                            "type": "waf_fingerprint",
                            "tool": "wafw00f",
                            "url": url,
                            "detected": rec_obj["detected"],
                            "wafs": rec_obj["wafs"],
                            "timestamp": rec_obj["timestamp"],
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
    finally:
        if w is not None:
            w.close()

    return results

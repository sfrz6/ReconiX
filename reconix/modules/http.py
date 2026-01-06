# reconix/modules/http.py
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any


def _require(bin_name: str) -> None:
    if shutil.which(bin_name) is None:
        raise FileNotFoundError(f"Missing binary: {bin_name}")


def _parse_httpx_lines(stdout: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            # ignore malformed lines
            continue
    return out


def _extract_tech_field(row: dict[str, Any]) -> list[str]:
    """
    httpx tech output can differ by version. Normalize into list[str].
    """
    tech = row.get("tech") or row.get("technologies") or row.get("technology") or []
    if isinstance(tech, str):
        tech = [tech] if tech.strip() else []
    if not isinstance(tech, list):
        return []

    cleaned: list[str] = []
    for x in tech:
        s = str(x).strip()
        if s and s not in cleaned:
            cleaned.append(s)
    return cleaned


_VERSION_PATTERNS = [
    # Name/1.2.3 or Name/1.2p1
    re.compile(r"^(?P<name>[^/]+?)[/](?P<ver>[0-9][0-9A-Za-z.\-_+~]+)$"),
    # Name:1.2.3
    re.compile(r"^(?P<name>[^:]+?)[:](?P<ver>[0-9][0-9A-Za-z.\-_+~]+)$"),
    # Name 1.2.3
    re.compile(r"^(?P<name>.+?)\s+(?P<ver>[0-9][0-9A-Za-z.\-_+~]+)$"),
]


def _parse_tech_item(s: str) -> dict[str, Any]:
    """
    Convert a tech string into structured form:
      {"name": "...", "version": "...|None", "raw": "..."}
    """
    raw = (s or "").strip()
    if not raw:
        return {"name": "", "version": None, "raw": ""}

    name = raw
    ver: str | None = None

    # Strip obvious wrappers, keep raw as-is
    candidate = raw.strip()

    # Common patterns
    for rx in _VERSION_PATTERNS:
        m = rx.match(candidate)
        if m:
            name = (m.group("name") or "").strip()
            ver = (m.group("ver") or "").strip()
            break

    # Cleanup name (avoid empty)
    name = re.sub(r"\s+", " ", name).strip()
    if not name:
        name = raw

    return {"name": name, "version": ver, "raw": raw}


def _normalize_tech_struct(row: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Ensure row["tech"] is list[{"name","version","raw"}]
    """
    items = _extract_tech_field(row)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()

    for item in items:
        obj = _parse_tech_item(item)
        n = str(obj.get("name") or "").strip()
        v = obj.get("version")
        key = (n.lower(), v.lower() if isinstance(v, str) else None)
        if not n or key in seen:
            continue
        seen.add(key)
        out.append(obj)

    return out


def _is_unknown_flag(stderr: str) -> bool:
    s = (stderr or "").lower()
    return (
        "unknown flag" in s
        or "flag provided but not defined" in s
        or "unknown shorthand flag" in s
        or "invalid flag" in s
        or "unknown argument" in s
    )


def run_httpx(
    hosts: list[str],
    *,
    tech_detect: bool = True,
    timeout: int = 8,
    retries: int = 1,
    threads: int = 50,
    follow_redirects: bool = True,
) -> list[dict[str, Any]]:
    """
    Run httpx against hosts and return parsed JSON rows.

    Output normalization:
      - row["tech"] becomes list[{"name","version","raw"}]
      - keeps other httpx fields untouched
    """
    _require("httpx")
    if not hosts:
        return []

    base_cmd = [
        "httpx",
        "-silent",
        "-json",
        "-title",
        "-status-code",
        "-threads",
        str(max(1, int(threads))),
        "-timeout",
        str(max(1, int(timeout))),
        "-retries",
        str(max(0, int(retries))),
    ]
    if follow_redirects:
        # httpx uses -follow-redirects (alias -fr in some builds)
        base_cmd += ["-follow-redirects"]

    stdin = "\n".join(h.strip() for h in hosts if str(h).strip())

    def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )

    if tech_detect:
        # 1) try -tech-detect
        p = _run(base_cmd + ["-tech-detect"])
        # 2) fallback to -td only if it's actually a flag error
        if p.returncode != 0 and _is_unknown_flag(p.stderr):
            p = _run(base_cmd + ["-td"])
    else:
        p = _run(base_cmd)

    if p.returncode != 0:
        raise RuntimeError((p.stderr or "").strip() or "httpx failed")

    rows = _parse_httpx_lines(p.stdout)

    for r in rows:
        r["tech"] = _normalize_tech_struct(r)

    return rows

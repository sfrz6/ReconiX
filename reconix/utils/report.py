# reconix/utils/report.py

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse


def _now_local_iso() -> str:
    try:
        return datetime.now().astimezone().isoformat(timespec="seconds")
    except Exception:
        return datetime.now().isoformat(timespec="seconds")


def _safe_load_json(path: Optional[Path]) -> Optional[dict]:
    try:
        if not path or not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def _iter_ndjson(path: Path) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = (line or "").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                continue


def _host_from_url(u: str) -> str:
    try:
        h = urlparse(u).hostname or ""
        return h.strip().lower().rstrip(".")
    except Exception:
        return ""


def _normalize_ports(items: Any) -> List[int]:
    ports: Set[int] = set()
    if not items:
        return []
    if isinstance(items, int):
        return [items]
    if isinstance(items, str):
        try:
            return [int(items)]
        except Exception:
            return []
    if isinstance(items, dict):
        for k in ("port", "portid", "number"):
            if k in items:
                try:
                    ports.add(int(items[k]))
                except Exception:
                    pass
        return sorted(ports)

    if isinstance(items, list):
        for it in items:
            if isinstance(it, int):
                ports.add(it)
            elif isinstance(it, str):
                try:
                    ports.add(int(it))
                except Exception:
                    pass
            elif isinstance(it, dict):
                for k in ("port", "portid", "number"):
                    if k in it:
                        try:
                            ports.add(int(it[k]))
                        except Exception:
                            pass
    return sorted(ports)


def _uniq_keep_order(items: Iterable[str], limit: int = 30) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        s = (x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def generate_markdown_report(*, target_dir: Path, report_name: str = "reconix_report.md") -> Path:
    ndjson_path = target_dir / "reconix.ndjson"
    if not ndjson_path.exists():
        raise FileNotFoundError(f"Missing {ndjson_path}")

    # detect mode + target label
    mode = "unknown"
    target_label = target_dir.name
    for obj in _iter_ndjson(ndjson_path):
        mode = str(obj.get("mode") or "unknown").lower()
        target_label = str(obj.get("target") or target_label)
        break

    snapshot_path = None
    if mode == "quick":
        snapshot_path = target_dir / "quick_snapshot.json"
    elif mode == "normal":
        snapshot_path = target_dir / "normal_snapshot.json"
    elif mode == "deep":
        snapshot_path = target_dir / "deep_snapshot.json"

    snap = _safe_load_json(snapshot_path)

    records = list(_iter_ndjson(ndjson_path))

    discovered = len(records)
    verified = [r for r in records if (r.get("dns") or {}).get("resolved") is True]
    unverified = [r for r in records if (r.get("dns") or {}).get("resolved") is not True]

    live = [r for r in records if (r.get("http") or {}).get("alive") is True and (r.get("http") or {}).get("url")]
    live_urls = [str((r.get("http") or {}).get("url")) for r in live]
    live_hosts = sorted({_host_from_url(u) for u in live_urls if _host_from_url(u)})

    tech_by_host: Dict[str, Set[str]] = {}
    waf_by_host: Dict[str, Set[str]] = {}
    ports_by_host: Dict[str, Set[int]] = {}
    endpoints: List[str] = []
    dirs: List[str] = []

    for r in records:
        sub = str(r.get("subdomain") or "").strip().lower().rstrip(".")
        http = r.get("http") or {}
        url = http.get("url") or ""
        host = _host_from_url(url) if url else sub

        tech = http.get("tech") or []
        if isinstance(tech, str):
            tech = [tech]
        if isinstance(tech, list) and host:
            for t in tech:
                tt = str(t).strip()
                if tt:
                    tech_by_host.setdefault(host, set()).add(tt)

        waf = r.get("waf")
        if host and waf:
            if isinstance(waf, dict):
                wafs = waf.get("wafs") or waf.get("waf") or []
                if isinstance(wafs, str):
                    wafs = [wafs]
                if isinstance(wafs, list):
                    for w in wafs:
                        ww = str(w).strip()
                        if ww:
                            waf_by_host.setdefault(host, set()).add(ww)
            elif isinstance(waf, list):
                for w in waf:
                    ww = str(w).strip()
                    if ww:
                        waf_by_host.setdefault(host, set()).add(ww)
            elif isinstance(waf, str):
                ww = waf.strip()
                if ww:
                    waf_by_host.setdefault(host, set()).add(ww)

        if host:
            for p in _normalize_ports(r.get("ports")):
                ports_by_host.setdefault(host, set()).add(p)
            for p in _normalize_ports(r.get("ports_naabu")):
                ports_by_host.setdefault(host, set()).add(p)

        ulist = r.get("urls") or []
        if isinstance(ulist, list):
            endpoints.extend([str(x) for x in ulist if str(x).strip()])

        dlist = r.get("directories") or []
        if isinstance(dlist, list):
            dirs.extend([str(x) for x in dlist if str(x).strip()])

    top_urls = _uniq_keep_order(endpoints, limit=30)
    top_dirs = _uniq_keep_order(dirs, limit=30)

    report_path = target_dir / report_name
    lines: List[str] = []

    lines += [
        "# ReconiX Report",
        "",
        f"**Generated:** {_now_local_iso()}",
        f"**Mode:** {mode.upper()}",
        f"**Target:** {target_label}",
        "",
        "## Summary",
        f"- Discovered targets: **{discovered}**",
        f"- Verified (DNS resolved): **{len(verified)}**",
        f"- Unverified: **{len(unverified)}**",
        f"- Live web hosts: **{len(live_hosts)}**",
        "",
    ]

    if snap and isinstance(snap, dict):
        lines += ["## Snapshot", f"- Snapshot time: `{snap.get('timestamp', '(unknown)')}`"]
        if mode == "quick":
            lines += [
                f"- Wayback kept: `{snap.get('wayback_kept', 0)}` (total `{snap.get('wayback_total', 0)}`)",
                f"- OSINT enabled: `{snap.get('osint_enabled', False)}`",
                f"- GitHub OSINT: `{snap.get('github_osint', False)}`",
            ]
        if mode == "normal":
            lines += [
                f"- Katana total URLs: `{(snap.get('katana') or {}).get('total_urls', 0)}`",
                f"- FFUF total hits: `{(snap.get('ffuf') or {}).get('total_hits', 0)}`",
            ]
        lines.append("")

    lines += ["## Live Targets"]
    lines += ["- (none)"] if not live_urls else [f"- {u}" for u in sorted(set(live_urls))[:50]]
    lines.append("")

    lines += ["## Tech Fingerprint"]
    lines += ["- (none)"] if not tech_by_host else [f"- **{h}**: {', '.join(sorted(tech_by_host[h]))}" for h in sorted(tech_by_host)]
    lines.append("")

    lines += ["## WAF"]
    lines += ["- (none detected)"] if not waf_by_host else [f"- **{h}**: {', '.join(sorted(waf_by_host[h]))}" for h in sorted(waf_by_host)]
    lines.append("")

    lines += ["## Ports"]
    if not ports_by_host:
        lines += ["- (none)"]
    else:
        for h in sorted(ports_by_host):
            ps = sorted(ports_by_host[h])
            if ps:
                lines.append(f"- **{h}**: {', '.join(str(p) for p in ps)}")
    lines.append("")

    lines += ["## Key Endpoints"]
    lines += ["- (none)"] if not top_urls else [f"- {u}" for u in top_urls]
    lines.append("")

    lines += ["## Directory Discovery Hits"]
    lines += ["- (none)"] if not top_dirs else [f"- {d}" for d in top_dirs]
    lines.append("")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path

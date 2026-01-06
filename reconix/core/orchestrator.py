# reconix/core/orchestrator.py
from __future__ import annotations

import json
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from reconix import __version__
from reconix.utils import ui
from reconix.utils.fs import ensure_dir, safe_target_name
from reconix.utils.report import generate_markdown_report

from reconix.modules.subdomains import run_subfinder, run_crtsh
from reconix.modules.github_osint import run_github_subdomains
from reconix.modules.assetfinder import run_assetfinder
from reconix.modules.sublist3r import run_sublist3r
from reconix.modules.dns import run_dnsx
from reconix.modules.http import run_httpx
from reconix.modules.katana import run_katana
from reconix.modules.nmap import run_nmap
from reconix.modules.dirsearch import run_dirsearch
from reconix.modules.wayback import fetch_wayback_urls

# optional
try:
    from reconix.modules.naabu import run_naabu  # type: ignore
except Exception:
    run_naabu = None  # type: ignore

try:
    from reconix.modules.wafw00f import run_wafw00f  # type: ignore
except Exception:
    run_wafw00f = None  # type: ignore

try:
    from reconix.modules.cve_candidates import (
        build_queries_from_tech,
        cve_candidates_from_queries,
    )
except Exception:
    build_queries_from_tech = None  # type: ignore
    cve_candidates_from_queries = None  # type: ignore

# provider-config generator (fail-soft)
try:
    from reconix.utils.subfinder_provider import write_subfinder_provider_config
except Exception:
    write_subfinder_provider_config = None  # type: ignore


# ----------------------------
# Generic config helpers
# ----------------------------
def cfg_get(cfg: dict, key: str, default=None):
    cur: Any = cfg
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def resolve_val(cfg: dict, key: str, override, default):
    return override if override is not None else cfg_get(cfg, key, default)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def norm_host(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    return h


def host_from_url(u: str) -> str:
    try:
        return norm_host(urlparse(u).hostname or "")
    except Exception:
        return ""


# ----------------------------
# Targets: --file parsing
# ----------------------------
_TARGET_WS_RE = re.compile(r"\s")
def _normalize_target_line(raw: str) -> Optional[str]:
    s = (raw or "").strip()
    if not s or s.startswith("#"):
        return None

    if "://" in s:
        try:
            u = urlparse(s)
            host = u.hostname or ""
        except Exception:
            host = ""
    else:
        host = s.split("/", 1)[0]
        host = host.split(":", 1)[0]

    host = norm_host(host)
    if not host:
        return None

    if "." not in host:
        return None

    if _TARGET_WS_RE.search(host):
        return None

    return host


def load_targets_file(path: str) -> List[str]:
    p = Path(path)
    out: List[str] = []
    seen: Set[str] = set()
    try:
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            t = _normalize_target_line(line)
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
    except Exception:
        return []
    return out


# ----------------------------
# TXT helpers
# ----------------------------
def _txt_line(f, s: str = ""):
    f.write(s + "\n")


def _txt_list(f, key: str, items: List[Any]):
    _txt_line(f, f"{key}:")
    if not items:
        _txt_line(f, "  (none)")
        return
    for it in items:
        _txt_line(f, f"  - {it}")


# ----------------------------
# Export subdomains
# ----------------------------
def write_subdomains_export(
    *,
    path: str,
    domain_label: str,
    verified: List[str],
    unverified: List[str],
):
    ts = datetime.now().astimezone().isoformat(timespec="seconds")
    v = sorted(set(norm_host(x) for x in (verified or []) if norm_host(x)))
    u = sorted(set(norm_host(x) for x in (unverified or []) if norm_host(x)) - set(v))

    with open(path, "w", encoding="utf-8") as f:
        f.write("# ReconiX subdomains export\n")
        f.write(f"# target: {domain_label}\n")
        f.write(f"# generated: {ts}\n\n")
        f.write("# verified\n")
        for h in v:
            f.write(h + "\n")
        f.write("\n# unverified\n")
        for h in u:
            f.write(h + "\n")


# ----------------------------
# Confidence / Status
# ----------------------------
def _status(is_resolved: bool) -> str:
    return "VERIFIED" if is_resolved else "UNVERIFIED"


def _confidence(is_resolved: bool, sources: List[str]) -> str:
    if not is_resolved:
        return "LOW"
    return "HIGH" if len(sources) >= 2 else "MED"


def _print_section(
    title: str,
    hosts: List[str],
    src_map: Dict[str, List[str]],
    resolved_set: Set[str],
    limit: int = 25,
):
    ui.section(f"{title} ({len(hosts)})")
    if not hosts:
        ui.note("(none)")
        return

    for h in hosts[:limit]:
        sources = src_map.get(h, []) or []
        is_resolved = h in resolved_set
        conf = _confidence(is_resolved, sources)
        src_txt = ", ".join(sources) if sources else "(none)"
        if is_resolved:
            ui.console.print(f"  [key][{conf:<4}][/key] [value]{h:<35}[/value] [muted](sources: {src_txt})[/muted]")
        else:
            ui.console.print(f"  [key][{conf:<4}][/key] [value]{h:<35}[/value] [muted](sources: {src_txt}) dns: unresolved[/muted]")

    if len(hosts) > limit:
        ui.note(f"... and {len(hosts) - limit} more")


# ----------------------------
# OSINT-lite (passive, fail-soft)
# ----------------------------
def _osint_rdap(domain: str, timeout: int = 12) -> Dict[str, Any]:
    try:
        import requests
    except Exception:
        return {}

    url = f"https://rdap.org/domain/{domain}"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconiX"})
        r.raise_for_status()
        j = r.json()

        events = j.get("events", []) or []
        event_map: Dict[str, str] = {}
        for e in events:
            act = str(e.get("eventAction", "")).strip()
            dt = str(e.get("eventDate", "")).strip()
            if act and dt:
                event_map[act] = dt

        return {
            "domain": j.get("ldhName") or domain,
            "status": j.get("status", []) or [],
            "events": event_map,
        }
    except Exception:
        return {}


def _dns_q(name: str, rtype: str) -> List[str]:
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return []
    try:
        return [str(x).strip() for x in dns.resolver.resolve(name, rtype)]
    except Exception:
        return []


def _clean_txt(txt: List[str]) -> List[str]:
    cleaned: List[str] = []
    for t in txt:
        s = (t or "").strip()
        s = s.strip('"').strip("'")
        cleaned.append(s)
    return cleaned


def _osint_dns(domain: str) -> Dict[str, Any]:
    ns = _dns_q(domain, "NS")
    mx = _dns_q(domain, "MX")
    txt_raw = _dns_q(domain, "TXT")
    txt = _clean_txt(txt_raw)

    dmarc_raw = _dns_q(f"_dmarc.{domain}", "TXT")
    dmarc = _clean_txt(dmarc_raw)

    spf = [x for x in txt if x.lower().startswith("v=spf1")]

    return {
        "NS": ns,
        "MX": mx,
        "SPF": spf,
        "DMARC": dmarc,
        "TXT_count": len(txt),
        "TXT_sample": txt[:10],
    }


def run_osint_lite(domain: str) -> Dict[str, Any]:
    return {"rdap": _osint_rdap(domain), "dns": _osint_dns(domain)}


def _print_osint_summary(osint_data: Dict[str, Any], github_count: int):
    if not osint_data:
        return
    rdap = osint_data.get("rdap") or {}
    dnsd = osint_data.get("dns") or {}

    ui.section("OSINT Summary (passive)")
    if rdap:
        dom = rdap.get("domain") or "(unknown)"
        status = rdap.get("status") or []
        ui.console.print(f"  [key]RDAP domain[/key]: [value]{dom}[/value]")
        ui.console.print(f"  [key]RDAP status[/key]: [value]{', '.join(status) if status else '(none)'}[/value]")
    else:
        ui.console.print("  [key]RDAP[/key]: [muted](unavailable)[/muted]")

    ns = dnsd.get("NS") or []
    mx = dnsd.get("MX") or []
    spf = dnsd.get("SPF") or []
    dmarc = dnsd.get("DMARC") or []
    ui.console.print(f"  [key]NS[/key]: [value]{', '.join(ns[:3]) if ns else '(none)'}[/value]")
    ui.console.print(f"  [key]MX[/key]: [value]{', '.join(mx[:3]) if mx else '(none)'}[/value]")
    ui.console.print(f"  [key]SPF[/key]: [value]{spf[0] if spf else '(none)'}[/value]")
    ui.console.print(f"  [key]DMARC[/key]: [value]{dmarc[0] if dmarc else '(none)'}[/value]")
    ui.console.print(f"  [key]GitHub subdomains[/key]: [value]{github_count}[/value]")


# ----------------------------
# Wayback prioritization
# ----------------------------
STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".css", ".js", ".map", ".woff", ".woff2",
    ".ico", ".pdf", ".zip", ".tar", ".gz", ".7z",
    ".mp4", ".mp3", ".avi", ".mov"
)

INTEREST_KEYWORDS = (
    "admin", "login", "signin", "sign-in", "auth", "oauth", "sso",
    "dashboard", "panel", "portal",
    "/api", "graphql", "swagger", "openapi",
    "config", ".env", "backup", "dump", "db", "sql", "export",
    ".git", "gitlab", "jenkins"
)

INTEREST_EXT = (".php", ".aspx", ".jsp", ".json", ".xml", ".yml", ".yaml", ".conf", ".bak", ".old")


def _score_wayback_url(u: str) -> int:
    low = (u or "").lower()
    if not low:
        return -999
    if low.endswith(STATIC_EXT):
        return -999

    s = 0
    if "?" in low:
        s += 3
    if "#" in low:
        s -= 1

    for kw in INTEREST_KEYWORDS:
        if kw in low:
            s += 5

    for ext in INTEREST_EXT:
        if low.endswith(ext):
            s += 4

    try:
        path = urlparse(u).path or ""
    except Exception:
        path = ""
    s += min(path.count("/"), 6)
    return s


def _pick_top_wayback(urls: List[str], k: int = 50) -> List[str]:
    seen: Set[str] = set()
    scored: List[Tuple[int, str]] = []

    for u in urls:
        u = (u or "").strip()
        if not u:
            continue
        try:
            p = urlparse(u)
            u_norm = p._replace(fragment="").geturl()
        except Exception:
            u_norm = u

        if u_norm in seen:
            continue
        seen.add(u_norm)

        sc = _score_wayback_url(u_norm)
        if sc <= -100:
            continue
        scored.append((sc, u_norm))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [u for _, u in scored[:k]]


# ----------------------------
# Snapshot helpers (delta)
# ----------------------------
def _load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        p = Path(path)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_json(path: str, obj: Dict[str, Any]) -> None:
    try:
        Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _delta(prev: Optional[Dict[str, Any]], cur: Dict[str, Any]) -> Dict[str, Any]:
    if not prev:
        return {"has_prev": False, "added": {}, "removed": {}}

    added: Dict[str, List[str]] = {}
    removed: Dict[str, List[str]] = {}

    for key in ["subdomains", "resolved", "live_hosts", "unverified"]:
        prev_set = set(prev.get(key, []) or [])
        cur_set = set(cur.get(key, []) or [])
        a = sorted(cur_set - prev_set)
        r = sorted(prev_set - cur_set)
        if a:
            added[key] = a
        if r:
            removed[key] = r

    return {"has_prev": True, "added": added, "removed": removed}


def _set_delta(old: List[str], new: List[str]) -> Dict[str, List[str]]:
    o = set(old or [])
    n = set(new or [])
    return {"added": sorted(n - o), "removed": sorted(o - n)}


def _map_list_delta(old: Dict[str, List[Any]], new: Dict[str, List[Any]]) -> Dict[str, Any]:
    old = old or {}
    new = new or {}
    changed: Dict[str, Any] = {}

    all_keys = set(old.keys()) | set(new.keys())
    for k in sorted(all_keys):
        a = set(old.get(k) or [])
        b = set(new.get(k) or [])
        add = sorted(b - a)
        rem = sorted(a - b)
        if add or rem:
            changed[k] = {"added": add, "removed": rem}

    return {
        "keys_added": sorted(set(new.keys()) - set(old.keys())),
        "keys_removed": sorted(set(old.keys()) - set(new.keys())),
        "changed": changed,
    }


def _print_normal_delta(delta_obj: Dict[str, Any]):
    ui.section("Delta since last NORMAL scan")
    vh = delta_obj.get("verified_hosts") or {}
    uh = delta_obj.get("unverified_hosts") or {}
    lu = delta_obj.get("live_urls") or {}
    waf = delta_obj.get("waf") or {}
    tech = delta_obj.get("tech") or {}
    ports = delta_obj.get("ports") or {}

    ui.console.print(f"  [key]Verified hosts[/key]: [value]+{len(vh.get('added', []))} / -{len(vh.get('removed', []))}[/value]")
    ui.console.print(f"  [key]Unverified[/key]:     [value]+{len(uh.get('added', []))} / -{len(uh.get('removed', []))}[/value]")
    ui.console.print(f"  [key]Live URLs[/key]:      [value]+{len(lu.get('added', []))} / -{len(lu.get('removed', []))}[/value]")

    ui.console.print(f"  [key]WAF changes[/key]:    [value]{len((waf.get('changed') or {}))} hosts changed[/value]")
    ui.console.print(f"  [key]Tech changes[/key]:   [value]{len((tech.get('changed') or {}))} hosts changed[/value]")
    ui.console.print(f"  [key]Port changes[/key]:   [value]{len((ports.get('changed') or {}))} hosts changed[/value]")

    k = delta_obj.get("katana_total_urls") or {}
    f = delta_obj.get("ffuf_total_hits") or {}
    if k:
        ui.console.print(f"  [key]Katana total[/key]:   [value]{k.get('old', 0)} -> {k.get('new', 0)} (diff {k.get('diff', 0):+d})[/value]")
    if f:
        ui.console.print(f"  [key]FFUF hits[/key]:      [value]{f.get('old', 0)} -> {f.get('new', 0)} (diff {f.get('diff', 0):+d})[/value]")


def _build_normal_snapshot(
    *,
    target: str,
    timestamp: str,
    verified_hosts: List[str],
    unverified_hosts: List[str],
    live_urls: List[str],
    waf_by_host: Dict[str, List[str]],
    tech_by_host: Dict[str, List[str]],
    ports_by_host: Dict[str, List[int]],
    katana_total_urls: int,
    katana_top_urls: List[str],
    ffuf_total_hits: int,
    ffuf_top_hits: List[str],
) -> Dict[str, Any]:
    return {
        "tool": "reconix",
        "version": __version__,
        "mode": "normal",
        "target": target,
        "timestamp": timestamp,
        "verified_hosts": sorted(set(verified_hosts or [])),
        "unverified_hosts": sorted(set(unverified_hosts or [])),
        "live_urls": sorted(set(live_urls or [])),
        "waf": waf_by_host or {},
        "tech": tech_by_host or {},
        "ports": ports_by_host or {},
        "katana": {"total_urls": int(katana_total_urls or 0), "top_urls": (katana_top_urls or [])[:20]},
        "ffuf": {"total_hits": int(ffuf_total_hits or 0), "top_hits": (ffuf_top_hits or [])[:20]},
    }


def _compute_normal_delta(old_snap: Dict[str, Any], new_snap: Dict[str, Any]) -> Dict[str, Any]:
    old_snap = old_snap or {}
    new_snap = new_snap or {}

    return {
        "verified_hosts": _set_delta(old_snap.get("verified_hosts", []), new_snap.get("verified_hosts", [])),
        "unverified_hosts": _set_delta(old_snap.get("unverified_hosts", []), new_snap.get("unverified_hosts", [])),
        "live_urls": _set_delta(old_snap.get("live_urls", []), new_snap.get("live_urls", [])),
        "waf": _map_list_delta(old_snap.get("waf") or {}, new_snap.get("waf") or {}),
        "tech": _map_list_delta(old_snap.get("tech") or {}, new_snap.get("tech") or {}),
        "ports": _map_list_delta(old_snap.get("ports") or {}, new_snap.get("ports") or {}),
        "katana_total_urls": {
            "old": int(((old_snap.get("katana") or {}).get("total_urls") or 0)),
            "new": int(((new_snap.get("katana") or {}).get("total_urls") or 0)),
            "diff": int(((new_snap.get("katana") or {}).get("total_urls") or 0))
            - int(((old_snap.get("katana") or {}).get("total_urls") or 0)),
        },
        "ffuf_total_hits": {
            "old": int(((old_snap.get("ffuf") or {}).get("total_hits") or 0)),
            "new": int(((new_snap.get("ffuf") or {}).get("total_hits") or 0)),
            "diff": int(((new_snap.get("ffuf") or {}).get("total_hits") or 0))
            - int(((old_snap.get("ffuf") or {}).get("total_hits") or 0)),
        },
    }


# ----------------------------
# Output policy enforcement
# ----------------------------
def _enforce_output_policy(target_dir: str, keep_txt: bool, mode: str, keep_subdomains_export: bool):
    allowed = {"reconix.ndjson", "reconix_report.md"}
    if keep_txt:
        allowed.add("reconix.txt")
    if mode == "quick":
        allowed.add("quick_snapshot.json")
    if mode == "normal":
        allowed.add("normal_snapshot.json")

    p = Path(target_dir)
    if not p.exists():
        return

    for child in p.iterdir():
        try:
            if child.is_file():
                if keep_subdomains_export and child.name.startswith("reconix_subdomains_") and child.name.endswith(".txt"):
                    continue
                if child.name not in allowed:
                    child.unlink(missing_ok=True)
            elif child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
        except Exception:
            pass


# ----------------------------
# Subfinder "-all" decision (no keys => no -all)
# ----------------------------
def _subfinder_has_keys(cfg: dict) -> bool:
    sf = (cfg.get("subfinder", {}) or {}).get("providers", {}) or {}
    for _, keys in sf.items():
        if keys and len(keys) > 0:
            return True
    return False


def _run_subfinder_smart(domain: str, provider_cfg_path: Optional[str], use_all: bool) -> List[str]:
    try:
        return run_subfinder(domain, provider_cfg_path=provider_cfg_path, use_all=use_all)  # type: ignore
    except TypeError:
        if provider_cfg_path:
            return run_subfinder(domain, provider_cfg_path=provider_cfg_path)  # type: ignore
        return run_subfinder(domain)  # type: ignore


# ----------------------------
# WAF + ports + summaries
# ----------------------------
def _parse_waf_by_host(waf_by_url: Dict[str, Any], live_urls: List[str]) -> Dict[str, List[str]]:
    waf_by_host: Dict[str, List[str]] = {}
    if not waf_by_url or not live_urls:
        return waf_by_host
    for u in live_urls:
        obj = waf_by_url.get(u) or {}
        if isinstance(obj, dict) and obj.get("detected") and obj.get("wafs"):
            h = host_from_url(u)
            if h:
                wafs = [str(x).strip() for x in (obj.get("wafs") or []) if str(x).strip()]
                if wafs:
                    waf_by_host[h] = wafs
    return waf_by_host


def _extract_ports_from_nmap_value(v: Any) -> List[int]:
    if isinstance(v, int):
        return [v]
    if isinstance(v, str):
        try:
            return [int(v)]
        except Exception:
            return []
    if isinstance(v, dict):
        p = v.get("port") or v.get("portid") or v.get("number")
        try:
            return [int(p)]
        except Exception:
            return []
    return []


def _merge_ports(
    live_hosts: List[str],
    ports_by_host: Dict[str, List[Any]],
    naabu_ports: Dict[str, List[int]],
) -> Dict[str, List[int]]:
    merged: Dict[str, List[int]] = {}

    for h, items in (ports_by_host or {}).items():
        hh = norm_host(h)
        if not hh:
            continue
        for it in (items or []):
            for p in _extract_ports_from_nmap_value(it):
                merged.setdefault(hh, []).append(p)

    for h, ps in (naabu_ports or {}).items():
        hh = norm_host(h)
        if not hh:
            continue
        for p in ps or []:
            try:
                merged.setdefault(hh, []).append(int(p))
            except Exception:
                continue

    clean: Dict[str, List[int]] = {}
    for h, ps in merged.items():
        uniq = sorted(set(int(x) for x in ps if isinstance(x, int) or str(x).isdigit()))
        clean[h] = uniq

    live_set = set(norm_host(x) for x in (live_hosts or []) if norm_host(x))
    if live_set:
        clean = {h: ps for h, ps in clean.items() if h in live_set}
    return clean


def _collect_tech_by_host(http_rows: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    tech_by_host: Dict[str, List[str]] = {}
    for r in http_rows or []:
        url = r.get("url")
        host = host_from_url(url) if url else norm_host(r.get("host") or r.get("input") or "")
        if not host:
            continue
        tech = r.get("tech") or []
        if isinstance(tech, str):
            tech = [tech] if tech.strip() else []
        if not isinstance(tech, list):
            tech = []
        cleaned = [str(x).strip() for x in tech if str(x).strip()]
        if not cleaned:
            continue
        cur = tech_by_host.get(host, [])
        for t in cleaned:
            if t not in cur:
                cur.append(t)
        tech_by_host[host] = cur
    return tech_by_host


def _print_waf_detected(waf_by_url: Dict[str, Any], live_urls: List[str], limit: int = 25):
    ui.section("WAF Detected")
    if not live_urls:
        ui.note("(no live URLs)")
        return

    detected: List[Tuple[str, List[str]]] = []
    for u in live_urls:
        info_obj = waf_by_url.get(u) or {}
        if not isinstance(info_obj, dict):
            continue
        if info_obj.get("detected") and (info_obj.get("wafs") or []):
            host = host_from_url(u)
            wafs = info_obj.get("wafs") or []
            wafs = [str(x).strip() for x in wafs if str(x).strip()]
            detected.append((host, wafs))

    by_host: Dict[str, List[str]] = {}
    for h, wafs in detected:
        if not h:
            continue
        cur = by_host.get(h, [])
        for w in wafs:
            if w not in cur:
                cur.append(w)
        by_host[h] = cur

    if not by_host:
        ui.note(f"(none detected)  [0/{len(live_urls)}]")
        return

    items = sorted(by_host.items(), key=lambda x: x[0])
    ui.console.print(f"  [muted]Detected on {len(items)}/{len(live_urls)} live hosts:[/muted]")
    for h, wafs in items[:limit]:
        ui.console.print(f"  - [value]{h}[/value] -> [accent]{', '.join(wafs)}[/accent]")
    if len(items) > limit:
        ui.note(f"... and {len(items)-limit} more")


def _print_ports_flat(ports: Dict[str, List[int]], limit: int = 50):
    ui.section("Open Ports")
    flat: List[str] = []
    for h, ps in (ports or {}).items():
        for p in sorted(set(ps or [])):
            flat.append(f"{h}:{p}")

    if not flat:
        ui.note("(none)")
        return
    for x in flat[:limit]:
        ui.console.print(f"  - [value]{x}[/value]")
    if len(flat) > limit:
        ui.note(f"... and {len(flat)-limit} more")


def _print_katana_summary(urls_by_url: Dict[str, List[str]], limit: int = 10):
    total = sum(len(v) for v in (urls_by_url or {}).values())
    ui.section("Katana Summary")
    ui.console.print(f"  [key]Total URLs[/key]: [value]{total}[/value]")
    if total == 0:
        ui.note("(none)")
        return

    scored: List[Tuple[int, str]] = []
    seen: Set[str] = set()
    for _, urls in (urls_by_url or {}).items():
        for u in (urls or []):
            u = (u or "").strip()
            if not u or u in seen:
                continue
            seen.add(u)
            s = _score_wayback_url(u)
            if s > 0:
                scored.append((s, u))

    scored.sort(key=lambda x: x[0], reverse=True)
    top = [u for _, u in scored[:limit]]
    if top:
        ui.console.print("  [muted]Top interesting URLs:[/muted]")
        for u in top:
            ui.console.print(f"  - [value]{u}[/value]")
    else:
        ui.note("(no high-signal URLs matched heuristics)")


def _print_ffuf_summary(dirs_by_url: Dict[str, List[str]], limit: int = 10):
    total = sum(len(v) for v in (dirs_by_url or {}).values())
    ui.section("FFUF Summary")
    ui.console.print(f"  [key]Total hits[/key]: [value]{total}[/value]")
    if total == 0:
        ui.note("(none)")
        return

    flat: List[str] = []
    for _, hits in (dirs_by_url or {}).items():
        for h in (hits or []):
            s = str(h).strip()
            if s:
                flat.append(s)

    for x in flat[:limit]:
        ui.console.print(f"  - [value]{x}[/value]")
    if len(flat) > limit:
        ui.note(f"... and {len(flat)-limit} more")


# ----------------------------
# CVE candidates (searchsploit inferred)
# ----------------------------
def _cve_candidates_enabled(cfg: dict) -> bool:
    return bool(cfg_get(cfg, "normal.cve_candidates.enabled", True))


def _cve_candidates_limits(cfg: dict) -> tuple[int, int, int]:
    max_queries = int(cfg_get(cfg, "normal.cve_candidates.max_queries", 5))
    timeout = int(cfg_get(cfg, "normal.cve_candidates.timeout", 8))
    max_results = int(cfg_get(cfg, "normal.cve_candidates.max_results_per_query", 8))
    return max_queries, timeout, max_results


def _cve_candidates_for_host(cfg: dict, tech_list: List[str]) -> List[Dict[str, Any]]:
    if not _cve_candidates_enabled(cfg):
        return []
    if not tech_list:
        return []
    if build_queries_from_tech is None or cve_candidates_from_queries is None:
        return []

    max_q, tout, max_r = _cve_candidates_limits(cfg)
    queries = build_queries_from_tech(tech_list)[:max_q]
    if not queries:
        return []
    return cve_candidates_from_queries(
        queries,
        max_queries=max_q,
        timeout=tout,
        max_results_per_query=max_r,
    )


# ----------------------------
# Main entry
# ----------------------------
def run_scan(
    *,
    mode: str,
    domain: Optional[str],
    targets_file: Optional[str],
    focus: bool,
    out_dir: str,
    cfg: dict,
    txt: bool,
    export_subdomains: bool,
    report: bool,
    wayback_all: bool,
    no_osint: bool,
    osint_github: bool,
    port_scan: bool,
    dir_search: bool,
    port_tool: Optional[str],
    nmap_timing: Optional[str],
    naabu_rate: Optional[int],
    naabu_timeout: Optional[int],
) -> None:
    mode = (mode or "quick").lower().strip()
    if mode not in {"quick", "normal"}:
        mode = "quick"

    start_total = time.time()

    # --- output paths ---
    target_dir = str(Path(out_dir))
    ensure_dir(target_dir)

    out_file = str(Path(target_dir) / "reconix.ndjson")
    txt_file = str(Path(target_dir) / "reconix.txt")
    quick_snapshot = str(Path(target_dir) / "quick_snapshot.json")
    normal_snapshot = str(Path(target_dir) / "normal_snapshot.json")

    prev_quick = _load_json(quick_snapshot) if mode == "quick" else None
    prev_normal = _load_json(normal_snapshot) if mode == "normal" else None

    # --- provider-config.yaml for subfinder (optional) ---
    provider_cfg_path: Optional[str] = None
    if write_subfinder_provider_config is not None:
        try:
            provider_path = Path.home() / ".config" / "reconix" / "subfinder" / "provider-config.yaml"
            write_subfinder_provider_config(cfg, provider_path)
            provider_cfg_path = str(provider_path)
        except Exception:
            provider_cfg_path = None

    use_subfinder_all = _subfinder_has_keys(cfg)

    # --- scope selection ---
    domain_n = norm_host(domain or "")
    scope_targets: List[str] = []
    skip_discovery = False

    if targets_file:
        scope_targets = load_targets_file(targets_file)
        if not scope_targets:
            ui.err("Targets file is empty or has no valid targets.")
            return
        skip_discovery = True
        if osint_github and not domain_n:
            ui.warn("--osint-github requires -d/--domain. Disabling GitHub OSINT.")
            osint_github = False
    else:
        if not domain_n:
            ui.err("Missing target. Use -d/--domain or provide --file.")
            return
        if focus:
            skip_discovery = True
            scope_targets = [domain_n]

    target_label = domain_n if domain_n else (Path(targets_file).stem if targets_file else "targets")

    # --- config (normal) ---
    legacy_dir = cfg.get("dirsearch", {}) or {}
    legacy_nmap = cfg.get("nmap", {}) or {}

    ffuf_cfg = cfg_get(cfg, "normal.ffuf", {}) or legacy_dir
    nmap_cfg = cfg_get(cfg, "normal.nmap", {}) or legacy_nmap
    naabu_cfg = cfg_get(cfg, "normal.naabu", {}) or {}
    portscan_cfg = cfg_get(cfg, "normal.portscan", {}) or {}

    httpx_enabled = bool(cfg_get(cfg, "normal.httpx.enabled", True))
    katana_enabled = bool(cfg_get(cfg, "normal.katana.enabled", True))
    waf_enabled = bool(cfg_get(cfg, "normal.wafw00f.enabled", True))

    # port tool resolve (config-first)
    port_tool_resolved = (port_tool or str(portscan_cfg.get("tool", "both"))).lower().strip()
    if port_tool_resolved not in {"nmap", "naabu", "both"}:
        ui.warn("Invalid port tool. Using: both")
        port_tool_resolved = "both"

    timing = (nmap_timing or str(nmap_cfg.get("timing", "T3"))).upper()
    if timing not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
        timing = "T3"

    # GitHub token from config
    github_token = str((cfg.get("osint", {}) or {}).get("githubkey") or "").strip()

    # ---------------- subdomains / scope ----------------
    if skip_discovery:
        ui.info("Scope selection enabled (skipping subdomain discovery)")
    else:
        ui.info("Starting subdomain discovery")

    t0 = time.time()

    subdomains: Set[str] = set()
    src_map: Dict[str, List[str]] = {}
    github_subs: Set[str] = set()

    if skip_discovery:
        subdomains = {norm_host(x) for x in scope_targets if norm_host(x)}
        for h in subdomains:
            src_map[h] = ["input"]
    else:
        if mode == "quick":
            sf = {norm_host(x) for x in _run_subfinder_smart(domain_n, provider_cfg_path, use_all=use_subfinder_all)}
            cs = {norm_host(x) for x in run_crtsh(domain_n)}

            if osint_github:
                if not github_token:
                    ui.warn("GitHub OSINT requested but githubkey not set. Skipping GitHub OSINT.")
                else:
                    ui.info("Starting GitHub OSINT (passive)")
                    tg = time.time()
                    github_subs = {norm_host(x) for x in run_github_subdomains(domain_n, github_token)}
                    ui.info(f"Finished GitHub OSINT ({len(github_subs)} subdomains) [{int(time.time()-tg)}s]")

            merged = sf | cs | github_subs
            subdomains.update(merged)

            for h in merged:
                sources: List[str] = []
                if h in sf:
                    sources.append("subfinder")
                if h in cs:
                    sources.append("crt.sh")
                if h in github_subs:
                    sources.append("github")
                src_map[h] = sources

        else:
            af = {norm_host(x) for x in run_assetfinder(domain_n)}
            sf = {norm_host(x) for x in _run_subfinder_smart(domain_n, provider_cfg_path, use_all=use_subfinder_all)}
            sl = {norm_host(x) for x in run_sublist3r(domain_n)}
            merged = af | sf | sl
            subdomains.update(merged)

            for h in merged:
                sources = []
                if h in af:
                    sources.append("assetfinder")
                if h in sf:
                    sources.append("subfinder")
                if h in sl:
                    sources.append("sublist3r")
                src_map[h] = sources

    ui.info(f"Finished scope ({len(subdomains)} targets) [{int(time.time()-t0)}s]")

    # ---------------- dnsx ----------------
    ui.info("Starting DNS validation (dnsx)")
    t0 = time.time()
    resolved_raw = run_dnsx(list(subdomains))
    resolved = sorted({norm_host(x) for x in resolved_raw if norm_host(x)})
    resolved_set = set(resolved)
    ui.info(f"Finished dnsx ({len(resolved)} resolved) [{int(time.time()-t0)}s]")

    unverified = sorted(set(subdomains) - resolved_set)

    # ---------------- export-subdomains ----------------
    export_path = None
    if export_subdomains:
        slug = norm_host(domain_n) if domain_n else safe_target_name(target_label)
        export_path = str(Path(target_dir) / f"reconix_subdomains_{slug}.txt")
        write_subdomains_export(path=export_path, domain_label=target_label, verified=resolved, unverified=unverified)
        ui.info(f"Exported subdomains file: {export_path}")

    # ---------------- httpx (NORMAL only) ----------------
    http_rows: List[Dict[str, Any]] = []
    live_urls: List[str] = []
    live_hosts: List[str] = []

    if mode == "normal":
        if httpx_enabled:
            ui.info("Starting HTTP probing (httpx)")
            t0 = time.time()
            http_rows = run_httpx(resolved)
            live_urls = [r.get("url") for r in http_rows if r.get("url")]
            live_hosts = sorted({host_from_url(u) for u in live_urls if host_from_url(u)})
            ui.info(f"Finished httpx ({len(live_hosts)} live hosts) [{int(time.time()-t0)}s]")
        else:
            ui.warn("httpx disabled (config). Skipping live URL probing.")
    else:
        ui.info("HTTP probing disabled in QUICK (passive only)")

    tech_by_host = _collect_tech_by_host(http_rows) if (mode == "normal" and http_rows) else {}

    # ---------------- wafw00f (NORMAL only; fail-soft) ----------------
    waf_by_url: Dict[str, Any] = {}
    if mode == "normal" and httpx_enabled and waf_enabled and live_urls:
        if run_wafw00f is None:
            ui.warn("wafw00f enabled but module not available. Skipping WAF detection.")
        else:
            try:
                ui.info("Starting WAF detection (wafw00f)")
                t0 = time.time()
                waf_by_url = run_wafw00f(live_urls, cfg=cfg)
                ui.info(f"Finished wafw00f [{int(time.time()-t0)}s]")
            except Exception:
                ui.warn("wafw00f failed. Skipping WAF detection.")

    # ---------------- OSINT lite (passive) ----------------
    osint_enabled = (not no_osint) and bool(domain_n)
    osint_data: Dict[str, Any] = {}
    if not no_osint and not domain_n:
        ui.warn("OSINT requires -d/--domain. Skipping OSINT.")
    if osint_enabled:
        ui.info("Starting OSINT (passive)")
        t0 = time.time()
        osint_data = run_osint_lite(domain_n)
        ui.info(f"Finished OSINT [{int(time.time()-t0)}s]")

    # ---------------- wayback (QUICK only) ----------------
    wayback_by_host: Dict[str, List[str]] = {}
    wayback_total = 0
    wayback_kept = 0

    if mode == "quick" and domain_n:
        ui.info("Starting Wayback URL collection (wayback)")
        t0 = time.time()
        try:
            wb_urls = fetch_wayback_urls(domain_n)
        except Exception:
            wb_urls = []

        wayback_total = len(wb_urls)
        chosen = wb_urls if wayback_all else _pick_top_wayback(wb_urls, k=int(cfg_get(cfg, "quick.wayback_top", 50) or 50))
        wayback_kept = len(chosen)

        for u in chosen:
            h = host_from_url(u)
            if not h:
                continue
            wayback_by_host.setdefault(h, []).append(u)

        if wayback_all:
            ui.info(f"Finished wayback ({wayback_total} URLs, kept ALL) [{int(time.time()-t0)}s]")
        else:
            ui.info(f"Finished wayback ({wayback_total} URLs, kept {wayback_kept}) [{int(time.time()-t0)}s]")

    # ---------------- katana (NORMAL only) ----------------
    urls_by_url: Dict[str, List[str]] = {}
    if mode == "normal" and live_urls and katana_enabled:
        ui.info("Starting URL discovery (katana)")
        t0 = time.time()
        urls_by_url = run_katana(live_urls, cfg=cfg)
        total = sum(len(v) for v in urls_by_url.values())
        ui.info(f"Finished katana ({total} URLs) [{int(time.time()-t0)}s]")
    elif mode == "normal" and live_urls and not katana_enabled:
        ui.warn("katana disabled (config). Skipping crawling.")

    # ---------------- ffuf (NORMAL only, explicit flag) ----------------
    dirs_by_url: Dict[str, List[str]] = {}
    if mode == "normal" and dir_search and live_urls:
        ui.info("Starting directory discovery (ffuf)")
        t0 = time.time()
        dirs_by_url = run_dirsearch(
            live_urls,
            wordlist=str(ffuf_cfg.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"),
            threads=int(ffuf_cfg.get("threads", 20)),
            extensions=list(ffuf_cfg.get("extensions", [])) if isinstance(ffuf_cfg.get("extensions", []), list) else [],
            recursive=bool(ffuf_cfg.get("recursive", False)),
            recursion_depth=int(ffuf_cfg.get("recursion_depth", 2)),
        )
        total = sum(len(v) for v in dirs_by_url.values())
        ui.info(f"Finished directory discovery ({total} paths) [{round(time.time()-t0, 2)}s]")

    # ---------------- port scan (NORMAL only, explicit flag) ----------------
    ports_by_host: Dict[str, List[Any]] = {}
    naabu_ports: Dict[str, List[int]] = {}

    if mode == "normal" and port_scan and live_urls:
        hosts = sorted({host_from_url(u) for u in live_urls if host_from_url(u)})

        if not hosts:
            ui.warn("No live hosts to scan ports for.")
        else:
            if port_tool_resolved in {"naabu", "both"}:
                if run_naabu is None:
                    ui.warn("naabu selected but module not available. Skipping naabu.")
                else:
                    try:
                        ui.info("Starting port discovery (naabu)")
                        t0 = time.time()
                        top_ports = int(naabu_cfg.get("top_ports", nmap_cfg.get("top_ports", 100)))
                        rate = int(resolve_val(cfg, "normal.naabu.rate", naabu_rate, naabu_cfg.get("rate", 300)))
                        tout = int(resolve_val(cfg, "normal.naabu.timeout", naabu_timeout, naabu_cfg.get("timeout", 5)))

                        naabu_results = run_naabu(
                            hosts,
                            out_ndjson=None,
                            top_ports=top_ports,
                            rate=rate,
                            timeout=tout,
                        )
                        for r in naabu_results or []:
                            h = norm_host(r.get("host", ""))
                            p = r.get("port")
                            if h and isinstance(p, int):
                                naabu_ports.setdefault(h, []).append(p)

                        ui.info(f"Finished naabu [{int(time.time()-t0)}s]")
                    except Exception:
                        ui.warn("naabu failed. Skipping naabu.")

            if port_tool_resolved in {"nmap", "both"}:
                ui.info("Starting port scan (nmap)")
                t0 = time.time()
                ports_by_host = run_nmap(
                    hosts,
                    top_ports=int(nmap_cfg.get("top_ports", 100)),
                    timing=timing,
                )
                total = sum(len(v) for v in ports_by_host.values())
                ui.info(f"Finished nmap ({total} open ports) [{int(time.time()-t0)}s]")

    # ---------------- write outputs (NDJSON + optional TXT) ----------------
    http_map: Dict[str, Dict[str, Any]] = {}
    for row in http_rows:
        key = norm_host(row.get("host") or row.get("input") or "")
        if not key and row.get("url"):
            key = host_from_url(row["url"])
        if key:
            http_map[key] = row

    txt_handle = open(txt_file, "w", encoding="utf-8") if txt else None

    summary = {
        "discovered": len(subdomains),
        "verified": len(resolved),
        "unverified": len(unverified),
        "http_alive": len(live_hosts) if (mode == "normal" and httpx_enabled) else 0,
    }

    # overwrite file each run
    with open(out_file, "w", encoding="utf-8") as f:
        # OSINT record first (if enabled)
        if osint_enabled:
            f.write(
                json.dumps(
                    {
                        "tool": "reconix",
                        "version": __version__,
                        "mode": mode,
                        "target": target_label,
                        "type": "osint",
                        "data": osint_data,
                        "timestamp": utc_now(),
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

        if txt_handle:
            _txt_line(txt_handle, "SUMMARY:")
            _txt_line(txt_handle, f"  discovered: {summary['discovered']}")
            _txt_line(txt_handle, f"  verified:   {summary['verified']}")
            _txt_line(txt_handle, f"  unverified: {summary['unverified']}")
            _txt_line(txt_handle, f"  http_alive: {summary['http_alive']} ({'enabled' if (mode=='normal' and httpx_enabled) else 'disabled'})")
            _txt_line(txt_handle, f"  katana:     {'enabled' if (mode=='normal' and katana_enabled) else 'disabled'}")
            _txt_line(txt_handle, f"  wafw00f:    {'enabled' if (mode=='normal' and waf_enabled) else 'disabled'}")
            _txt_line(txt_handle, "-" * 60)

        for host in sorted(subdomains):
            is_resolved = host in resolved_set
            sources = src_map.get(host, [])
            st = _status(is_resolved)
            conf = _confidence(is_resolved, sources)

            r = http_map.get(host, {}) if (mode == "normal" and is_resolved and httpx_enabled) else {}
            url = r.get("url") if r else None
            hostname = host_from_url(url) if url else host

            waf_info = None
            if mode == "normal" and url and waf_by_url:
                waf_info = waf_by_url.get(url) or waf_by_url.get(hostname)

            tech_list = (r.get("tech") or []) if isinstance(r, dict) else []
            if isinstance(tech_list, str):
                tech_list = [tech_list] if tech_list.strip() else []
            if not isinstance(tech_list, list):
                tech_list = []

            cve_cands = _cve_candidates_for_host(cfg, [str(x) for x in tech_list]) if (mode == "normal") else []

            record = {
                "tool": "reconix",
                "version": __version__,
                "mode": mode,
                "target": target_label,
                "subdomain": host,
                "subdomain_sources": sources,
                "status": st,
                "confidence": conf,
                "dns": {"resolved": is_resolved},
                "http": {
                    "alive": bool(r),
                    "url": url,
                    "status": r.get("status_code"),
                    "title": r.get("title"),
                    "tech": tech_list,
                    "cve_candidates": cve_cands,
                },
                "waf": waf_info,
                "urls": wayback_by_host.get(host, []) if mode == "quick" else (urls_by_url.get(url, []) if url else []),
                "directories": dirs_by_url.get(url, []) if (mode == "normal" and dir_search and url) else [],
                "ports": ports_by_host.get(hostname, []) if (mode == "normal" and port_scan) else [],
                "ports_naabu": naabu_ports.get(hostname, []) if (mode == "normal" and port_scan and naabu_ports) else [],
                "timestamp": utc_now(),
            }

            f.write(json.dumps(record, ensure_ascii=False) + "\n")

            if txt_handle:
                _txt_line(txt_handle, f"Subdomain: {host}")
                _txt_line(txt_handle, f"  status: {record['status']}")
                _txt_line(txt_handle, f"  confidence: {record['confidence']}")
                _txt_line(txt_handle, f"  subdomain_sources: {', '.join(record['subdomain_sources']) if record['subdomain_sources'] else '(none)'}")
                _txt_line(txt_handle, f"  dns.resolved: {record['dns']['resolved']}")
                _txt_line(txt_handle, f"  http.alive: {record['http']['alive']} ({'enabled' if (mode=='normal' and httpx_enabled) else 'disabled'})")
                _txt_line(txt_handle, f"  http.url: {record['http']['url']}")
                _txt_line(txt_handle, f"  http.status: {record['http']['status']}")
                _txt_line(txt_handle, f"  http.title: {record['http']['title']}")
                _txt_line(txt_handle, f"  http.tech: {', '.join(record['http'].get('tech') or []) if record['http'].get('tech') else '(none)'}")
                if record.get("waf") is not None:
                    _txt_line(txt_handle, f"  waf: {record['waf']}")
                _txt_list(txt_handle, "  urls", record["urls"])
                _txt_list(txt_handle, "  directories", record["directories"])
                _txt_list(txt_handle, "  ports", record["ports"])
                _txt_list(txt_handle, "  ports_naabu", record["ports_naabu"])
                _txt_line(txt_handle, f"  timestamp: {record['timestamp']}")
                _txt_line(txt_handle, "-" * 60)

    if txt_handle:
        txt_handle.close()
        ui.info(f"TXT report written to: {txt_file}")

    # ---------------- snapshots + delta ----------------
    if mode == "quick":
        cur_quick = {
            "tool": "reconix",
            "version": __version__,
            "target": target_label,
            "timestamp": utc_now(),
            "subdomains": sorted(subdomains),
            "resolved": resolved,
            "unverified": unverified,
            "live_hosts": [],
            "wayback_total": wayback_total,
            "wayback_kept": (wayback_total if wayback_all else wayback_kept),
            "wayback_all": bool(wayback_all),
            "osint_enabled": bool(osint_enabled),
            "github_osint": bool(osint_github),
            "summary": summary,
        }

        if bool(cfg_get(cfg, "quick.delta", True)):
            d = _delta(prev_quick, cur_quick)
            if d["has_prev"] and (d["added"] or d["removed"]):
                ui.warn("New assets detected since last QUICK run or removed")
                if d["added"].get("subdomains"):
                    ui.info(f"New subdomains: {len(d['added']['subdomains'])}")
                if d["removed"].get("subdomains"):
                    ui.warn(f"Removed subdomains: {len(d['removed']['subdomains'])}")
                if d["added"].get("resolved"):
                    ui.info(f"New resolved: {len(d['added']['resolved'])}")
                if d["removed"].get("resolved"):
                    ui.warn(f"Removed resolved: {len(d['removed']['resolved'])}")
                if d["added"].get("unverified"):
                    ui.info(f"New unverified: {len(d['added']['unverified'])}")
                if d["removed"].get("unverified"):
                    ui.warn(f"Removed unverified: {len(d['removed']['unverified'])}")

        _save_json(quick_snapshot, cur_quick)

    if mode == "normal":
        waf_by_host = _parse_waf_by_host(waf_by_url, live_urls)
        merged_ports = _merge_ports(live_hosts, ports_by_host, naabu_ports)

        kat_total = sum(len(v) for v in (urls_by_url or {}).values())
        kat_scored: List[Tuple[int, str]] = []
        if urls_by_url:
            seen_u: Set[str] = set()
            for _, urls in urls_by_url.items():
                for u in urls or []:
                    u = (u or "").strip()
                    if not u or u in seen_u:
                        continue
                    seen_u.add(u)
                    s = _score_wayback_url(u)
                    if s > 0:
                        kat_scored.append((s, u))
            kat_scored.sort(key=lambda x: x[0], reverse=True)
        kat_top = [u for _, u in kat_scored[:20]]

        ff_total = sum(len(v) for v in (dirs_by_url or {}).values())
        ff_flat: List[str] = []
        for _, hits in (dirs_by_url or {}).items():
            for h in hits or []:
                s = str(h).strip()
                if s:
                    ff_flat.append(s)
        ff_top = ff_flat[:20]

        cur_normal = _build_normal_snapshot(
            target=target_label,
            timestamp=utc_now(),
            verified_hosts=resolved,
            unverified_hosts=unverified,
            live_urls=live_urls,
            waf_by_host=waf_by_host,
            tech_by_host=tech_by_host,
            ports_by_host=merged_ports,
            katana_total_urls=kat_total,
            katana_top_urls=kat_top,
            ffuf_total_hits=ff_total,
            ffuf_top_hits=ff_top,
        )

        if prev_normal:
            delta_obj = _compute_normal_delta(prev_normal, cur_normal)
            if (
                delta_obj["verified_hosts"]["added"]
                or delta_obj["verified_hosts"]["removed"]
                or delta_obj["unverified_hosts"]["added"]
                or delta_obj["unverified_hosts"]["removed"]
                or delta_obj["live_urls"]["added"]
                or delta_obj["live_urls"]["removed"]
                or (delta_obj.get("waf") or {}).get("changed")
                or (delta_obj.get("tech") or {}).get("changed")
                or (delta_obj.get("ports") or {}).get("changed")
                or (delta_obj.get("katana_total_urls") or {}).get("diff")
                or (delta_obj.get("ffuf_total_hits") or {}).get("diff")
            ):
                _print_normal_delta(delta_obj)

        _save_json(normal_snapshot, cur_normal)

    # ---------------- summary printing ----------------
    ui.ok("Recon completed")

    ui.console.print(f"\n[key]ReconiX v{__version__}[/key]  |  [value]Mode: {mode.upper()}[/value]")
    ui.console.print(f"[key]Target[/key]                 : [value]{target_label}[/value]")
    ui.console.print(f"[key]Subdomains found[/key]        : [value]{summary['discovered']}[/value]")
    ui.console.print(f"[key]DNS-resolved (VERIFIED)[/key] : [value]{summary['verified']}[/value]")
    ui.console.print(f"[key]DNS-unresolved[/key]          : [value]{summary['unverified']}[/value]")
    ui.console.print(f"[key]HTTP alive hosts[/key]        : [value]{summary['http_alive']} ({'enabled' if (mode=='normal' and httpx_enabled) else 'disabled'})[/value]")
    ui.console.print(f"[key]OSINT (passive)[/key]         : [value]{'no' if no_osint else ('yes' if domain_n else 'skipped (no -d)')}[/value]")
    ui.console.print(f"[key]GitHub OSINT[/key]            : [value]{'yes' if osint_github else 'no'}[/value]")

    if mode == "quick" and domain_n:
        if wayback_all:
            ui.console.print(f"[key]Wayback URLs[/key]            : [value]{wayback_total} (ALL)[/value]")
        else:
            ui.console.print(f"[key]Wayback URLs[/key]            : [value]{wayback_total} (top {wayback_kept})[/value]")

    ui.console.print(f"[key]Katana enabled[/key]          : [value]{'yes' if (mode=='normal' and katana_enabled) else 'no'}[/value]")
    ui.console.print(f"[key]WAF detection[/key]           : [value]{'yes' if (mode=='normal' and waf_enabled) else 'no'}[/value]")
    ui.console.print(f"[key]Directory discovery[/key]     : [value]{'yes' if (mode=='normal' and dir_search) else 'no'}[/value]")
    ui.console.print(f"[key]Port scan enabled[/key]       : [value]{'yes' if (mode=='normal' and port_scan) else 'no'}[/value]")
    if mode == "normal" and port_scan:
        ui.console.print(f"[key]Port tool[/key]               : [value]{port_tool_resolved}[/value]")
        ui.console.print(f"[key]nmap timing[/key]             : [value]{timing}[/value]")

    ui.console.print(f"[key]Output written to[/key]       : [value]{out_file}[/value]")
    if txt:
        ui.console.print(f"[key]TXT report written to[/key]   : [value]{txt_file}[/value]")
    if export_path:
        ui.console.print(f"[key]Subdomains export[/key]       : [value]{export_path}[/value]")
    ui.console.print(f"[key]Duration[/key]                : [value]{int(time.time()-start_total)}s[/value]\n")

    verified_hosts = sorted(resolved)
    unverified_hosts = unverified

    _print_section("Verified assets", verified_hosts, src_map, resolved_set)
    _print_section("Unverified discoveries", unverified_hosts, src_map, resolved_set)

    if mode == "quick":
        ui.info("QUICK mode completed (passive only)")
        if domain_n:
            ui.info(f"Suggested next step: reconix scan -d {domain_n} -m normal")

    if mode == "normal":
        if osint_enabled:
            _print_osint_summary(osint_data, github_count=len(github_subs))
        if httpx_enabled and waf_enabled and waf_by_url:
            _print_waf_detected(waf_by_url, live_urls)
        if port_scan:
            merged_ports = _merge_ports(live_hosts, ports_by_host, naabu_ports)
            _print_ports_flat(merged_ports)
        if katana_enabled:
            _print_katana_summary(urls_by_url)
        if dir_search:
            _print_ffuf_summary(dirs_by_url)

    # ---------------- auto report ----------------
    if report:
        try:
            rp = generate_markdown_report(target_dir=Path(target_dir))
            ui.ok(f"Report written to: {rp}")
        except Exception as e:
            ui.warn(f"Report generation failed: {e}")

    # enforce output policy
    _enforce_output_policy(
        target_dir,
        keep_txt=bool(txt),
        mode=mode,
        keep_subdomains_export=bool(export_subdomains),
    )

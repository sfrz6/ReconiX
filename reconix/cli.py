# reconix/cli.py

import time
import json
import shutil
import re
from enum import Enum
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import typer
from typer.core import TyperGroup

from reconix.utils import ui
from reconix.core.config import CONFIG_PATH
from reconix import __version__
from reconix.utils.ui import banner, info, warn, err
from reconix.utils.fs import ensure_dir, safe_target_name

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

from reconix.core.verify import run as verify_run
from reconix.core.config import load_config, save_config

# NEW: generate subfinder provider-config.yaml from ReconiX config
try:
    from reconix.utils.subfinder_provider import write_subfinder_provider_config
except Exception:
    write_subfinder_provider_config = None  # fail-soft

from reconix.utils.report import generate_markdown_report

# NEW: CVE candidates (searchsploit)
try:
    from reconix.modules.cve_candidates import build_queries_from_tech, cve_candidates_from_queries
except Exception:
    build_queries_from_tech = None  # type: ignore
    cve_candidates_from_queries = None  # type: ignore


# =================================================
# HELP FORMATTER
# =================================================
class NiceUsageGroup(TyperGroup):
    def format_usage(self, ctx, formatter):
        formatter.write_usage(ctx.command_path, "[COMMAND]", prefix="Usage: ")


# =================================================
# APP SETUP
# =================================================
app = typer.Typer(add_completion=False, no_args_is_help=True)

config_app = typer.Typer(
    help=(
        "Manage ReconiX configuration.\n\n"
        "Syntax:\n"
        "  reconix config set <key> <value>\n"
        "  reconix config unset <key>\n\n"
        "Examples (OSINT / QUICK):\n"
        '  reconix config set githubkey "TOKEN"\n'
        "  reconix config unset githubkey\n"
        "  reconix config set wayback_top 100\n"
        "  reconix config set osint_lite false\n\n"
        "Examples (NORMAL):\n"
        "  reconix config set httpx.enabled true\n"
        "  reconix config set katana.depth 1\n"
        "  reconix config set wafw00f.timeout 3\n"
        '  reconix config set ffuf.extensions \'[\"php\",\"html\",\"js\"]\'\n'
        "  reconix config set ffuf.extensions php,html,js\n"
        "  reconix config set cve.enabled true\n"
        "  reconix config set cve.require_version true\n\n"
        "Examples (Subfinder providers):\n"
        "  reconix config set virustotal <VT_KEY>\n"
        "  reconix config unset virustotal\n\n"
        "Notes:\n"
        "- QUICK keys are set by name (wayback_top, osint_lite, github_osint, delta)\n"
        "- NORMAL keys use dotted syntax (httpx.enabled, ffuf.wordlist, cve.enabled, ...)\n"
        "- Provider keys are stored under subfinder.providers.<provider> (as a list)\n"
    ),
    cls=NiceUsageGroup,
)
app.add_typer(config_app, name="config")


# =================================================
# Enums (choices in --help)
# =================================================
class PortTool(str, Enum):
    nmap = "nmap"
    naabu = "naabu"
    both = "both"


# =================================================
# Generic config helpers (config-first)
# =================================================
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


def _txt_line(f, s: str = ""):
    f.write(s + "\n")


def _txt_list(f, key: str, items: List[Any]):
    _txt_line(f, f"{key}:")
    if not items:
        _txt_line(f, "  (none)")
        return
    for it in items:
        _txt_line(f, f"  - {it}")


# =================================================
# CONFIG SET/UNSET (NEW SYNTAX)
# =================================================
_QUICK_KEYS = {"wayback_top", "osint_lite", "github_osint", "delta"}
_NORMAL_PREFIXES = {"httpx", "katana", "wafw00f", "portscan", "naabu", "ffuf", "nmap", "cve"}

_KNOWN_SUBFINDER_PROVIDERS = {
    "virustotal",
    "securitytrails",
    "shodan",
    "censys",
    "passivetotal",
    "fullhunt",
    "github",
    "chaos",
    "binaryedge",
    "fofa",
    "zoomeye",
}


def _cfg_get_dotted(cfg: dict, dotted: str, default=None):
    cur: Any = cfg
    for part in (dotted or "").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _set_dotted(cfg: dict, dotted: str, value: Any) -> None:
    parts = [p for p in (dotted or "").split(".") if p]
    if not parts:
        return
    cur = cfg
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value


def _unset_dotted(cfg: dict, dotted: str) -> None:
    parts = [p for p in (dotted or "").split(".") if p]
    if not parts:
        return
    cur = cfg
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            return
        cur = nxt
    cur.pop(parts[-1], None)


def _parse_value(raw: str) -> Any:
    s = (raw or "").strip()
    if s == "":
        return ""

    low = s.lower()
    if low in {"true", "false", "null"}:
        try:
            return json.loads(low)
        except Exception:
            return s

    # If it looks like JSON (list/object/string/number), try JSON parse
    if s.startswith(("{", "[", '"')) or re.fullmatch(r"-?\d+(\.\d+)?", s):
        try:
            return json.loads(s)
        except Exception:
            return s

    return s


def _normalize_extensions_value(v: Any) -> List[str]:
    """
    ffuf.extensions expects list[str]
    Accept:
      - JSON list: ["php","html"]
      - CSV: php,html,js
      - single: php
    """
    if isinstance(v, list):
        out: List[str] = []
        for x in v:
            s = str(x).strip().lstrip(".")
            if s and s not in out:
                out.append(s)
        return out

    if isinstance(v, str):
        s = v.strip()
        if "," in s:
            parts = [p.strip().lstrip(".") for p in s.split(",")]
            out: List[str] = []
            for p in parts:
                if p and p not in out:
                    out.append(p)
            return out
        s = s.lstrip(".")
        return [s] if s else []

    return []


def _map_user_key_to_cfg_path(user_key: str) -> Tuple[str, Optional[str]]:
    """
    Returns (cfg_path, kind)
      kind is used for special parsing/behavior.
    """
    k = (user_key or "").strip()
    if not k:
        return "", None

    # allow power-users to pass full paths
    if k.startswith(("quick.", "normal.", "osint.", "subfinder.")):
        if k.endswith("ffuf.extensions") or k.endswith(".ffuf.extensions"):
            return k, "extensions"
        return k, None

    # OSINT short
    if k == "githubkey":
        return "osint.githubkey", None

    # QUICK short
    if k in _QUICK_KEYS:
        return f"quick.{k}", None

    # NORMAL short: httpx.enabled, ffuf.wordlist, cve.enabled ...
    m = re.match(r"^([a-zA-Z0-9_]+)\.(.+)$", k)
    if m:
        prefix = m.group(1)
        rest = m.group(2)
        if prefix in _NORMAL_PREFIXES:
            if prefix == "ffuf" and rest == "extensions":
                return "normal.ffuf.extensions", "extensions"
            return f"normal.{prefix}.{rest}", None

    # subfinder provider shortcut: virustotal, shodan, ...
    if k in _KNOWN_SUBFINDER_PROVIDERS:
        return f"subfinder.providers.{k}", "subfinder_provider"

    if k.startswith("provider:") or k.startswith("subfinder:"):
        name = k.split(":", 1)[1].strip().lower()
        if name:
            return f"subfinder.providers.{name}", "subfinder_provider"

    if re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{1,40}", k):
        return f"subfinder.providers.{k.lower()}", "subfinder_provider"

    return k, None


def _set_key(cfg: dict, key: str, value_raw: str) -> None:
    cfg_path, kind = _map_user_key_to_cfg_path(key)
    if not cfg_path:
        raise typer.BadParameter("Invalid key")

    parsed = _parse_value(value_raw)

    if kind == "extensions":
        parsed = _normalize_extensions_value(parsed)

    if kind == "subfinder_provider":
        keys: List[str]
        if isinstance(parsed, list):
            keys = [str(x).strip() for x in parsed if str(x).strip()]
        else:
            keys = [str(parsed).strip()] if str(parsed).strip() else []
        _set_dotted(cfg, cfg_path, keys)
        return

    _set_dotted(cfg, cfg_path, parsed)


def _unset_key(cfg: dict, key: str) -> None:
    cfg_path, kind = _map_user_key_to_cfg_path(key)
    if not cfg_path:
        raise typer.BadParameter("Invalid key")

    if kind == "subfinder_provider":
        parts = cfg_path.split(".")
        if len(parts) >= 3 and parts[0] == "subfinder" and parts[1] == "providers":
            provider = parts[2]
            sf = cfg.setdefault("subfinder", {})
            provs = sf.setdefault("providers", {})
            if isinstance(provs, dict):
                provs.pop(provider, None)
            return

    _unset_dotted(cfg, cfg_path)


# =================================================
# Targets: --file parsing + export
# =================================================
def _normalize_target_line(raw: str) -> Optional[str]:
    s = (raw or "").strip()
    if not s:
        return None
    if s.startswith("#"):
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

    if re.search(r"\s", host):
        return None

    return host


def load_targets_file(path: Path) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            t = _normalize_target_line(line)
            if not t:
                continue
            if t in seen:
                continue
            seen.add(t)
            out.append(t)
    except Exception:
        return []
    return out


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


# =================================================
# Confidence / Status
# =================================================
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
    typer.echo(f"\n{title} ({len(hosts)}):")
    if not hosts:
        typer.echo("  (none)")
        return

    for h in hosts[:limit]:
        sources = src_map.get(h, []) or []
        is_resolved = h in resolved_set
        conf = _confidence(is_resolved, sources)
        src_txt = ", ".join(sources) if sources else "(none)"
        if is_resolved:
            typer.echo(f"  [{conf:<4}] {h:<35} (sources: {src_txt})")
        else:
            typer.echo(f"  [{conf:<4}] {h:<35} (sources: {src_txt}) dns: unresolved")

    if len(hosts) > limit:
        typer.echo(f"  ... and {len(hosts) - limit} more")


# =================================================
# OSINT-Lite (passive)
# =================================================
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


def _write_osint_txt(txt_handle, osint_data: Dict[str, Any], github_count: int):
    rdap = osint_data.get("rdap") or {}
    dnsd = osint_data.get("dns") or {}

    _txt_line(txt_handle, "OSINT:")

    if rdap:
        dom = rdap.get("domain") or "(unknown)"
        status = rdap.get("status") or []
        events = rdap.get("events") or {}
        _txt_line(txt_handle, f"  RDAP domain: {dom}")
        _txt_line(txt_handle, f"  RDAP status: {', '.join(status) if status else '(none)'}")
        if events:
            _txt_line(txt_handle, "  RDAP events:")
            for k, v in events.items():
                _txt_line(txt_handle, f"    - {k}: {v}")
        else:
            _txt_line(txt_handle, "  RDAP events: (none)")
    else:
        _txt_line(txt_handle, "  RDAP: (unavailable)")

    _txt_line(txt_handle, "  DNS:")
    ns = dnsd.get("NS") or []
    mx = dnsd.get("MX") or []
    spf = dnsd.get("SPF") or []
    dmarc = dnsd.get("DMARC") or []
    _txt_line(txt_handle, f"    NS: {', '.join(ns) if ns else '(none)'}")
    _txt_line(txt_handle, f"    MX: {', '.join(mx) if mx else '(none)'}")
    _txt_line(txt_handle, f"    SPF: {spf[0] if spf else '(none)'}")
    _txt_line(txt_handle, f"    DMARC: {dmarc[0] if dmarc else '(none)'}")

    _txt_line(txt_handle, f"  GitHub subdomains: {github_count}")
    _txt_line(txt_handle, "-" * 60)


def _print_osint_summary(osint_data: Dict[str, Any], github_count: int):
    if not osint_data:
        return
    rdap = osint_data.get("rdap") or {}
    dnsd = osint_data.get("dns") or {}

    typer.echo("\nOSINT Summary (passive):")
    if rdap:
        dom = rdap.get("domain") or "(unknown)"
        status = rdap.get("status") or []
        typer.echo(f"  RDAP domain: {dom}")
        typer.echo(f"  RDAP status: {', '.join(status) if status else '(none)'}")
    else:
        typer.echo("  RDAP: (unavailable)")

    ns = dnsd.get("NS") or []
    mx = dnsd.get("MX") or []
    spf = dnsd.get("SPF") or []
    dmarc = dnsd.get("DMARC") or []
    typer.echo(f"  NS: {', '.join(ns[:3]) if ns else '(none)'}")
    typer.echo(f"  MX: {', '.join(mx[:3]) if mx else '(none)'}")
    typer.echo(f"  SPF: {spf[0] if spf else '(none)'}")
    typer.echo(f"  DMARC: {dmarc[0] if dmarc else '(none)'}")
    typer.echo(f"  GitHub subdomains: {github_count}")


# ---------- Wayback prioritization ----------
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


# ---------- QUICK snapshot (delta awareness) ----------
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


# ---------- NORMAL snapshot (delta awareness) ----------
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
    typer.echo("\nDelta since last NORMAL scan:")
    vh = delta_obj.get("verified_hosts") or {}
    uh = delta_obj.get("unverified_hosts") or {}
    lu = delta_obj.get("live_urls") or {}
    waf = delta_obj.get("waf") or {}
    tech = delta_obj.get("tech") or {}
    ports = delta_obj.get("ports") or {}

    typer.echo(f"  Verified hosts: +{len(vh.get('added', []))} / -{len(vh.get('removed', []))}")
    typer.echo(f"  Unverified:     +{len(uh.get('added', []))} / -{len(uh.get('removed', []))}")
    typer.echo(f"  Live URLs:      +{len(lu.get('added', []))} / -{len(lu.get('removed', []))}")

    typer.echo(f"  WAF changes:    {len((waf.get('changed') or {}))} hosts changed")
    typer.echo(f"  Tech changes:   {len((tech.get('changed') or {}))} hosts changed")
    typer.echo(f"  Port changes:   {len((ports.get('changed') or {}))} hosts changed")

    k = delta_obj.get("katana_total_urls") or {}
    f = delta_obj.get("ffuf_total_hits") or {}
    if k:
        typer.echo(f"  Katana total:   {k.get('old', 0)} -> {k.get('new', 0)} (diff {k.get('diff', 0):+d})")
    if f:
        typer.echo(f"  FFUF hits:      {f.get('old', 0)} -> {f.get('new', 0)} (diff {f.get('diff', 0):+d})")


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
        "katana": {
            "total_urls": int(katana_total_urls or 0),
            "top_urls": (katana_top_urls or [])[:20],
        },
        "ffuf": {
            "total_hits": int(ffuf_total_hits or 0),
            "top_hits": (ffuf_top_hits or [])[:20],
        },
    }


def _compute_normal_delta(old_snap: Dict[str, Any], new_snap: Dict[str, Any]) -> Dict[str, Any]:
    old_snap = old_snap or {}
    new_snap = new_snap or {}

    delta_obj: Dict[str, Any] = {
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
    return delta_obj


# =================================================
# NORMAL summary printers
# =================================================
def _print_waf_detected(waf_by_url: Dict[str, Any], live_urls: List[str], limit: int = 25):
    typer.echo("\nWAF Detected:")
    if not live_urls:
        typer.echo("  (no live URLs)")
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
        typer.echo(f"  (none detected)  [0/{len(live_urls)}]")
        return

    items = sorted(by_host.items(), key=lambda x: x[0])
    typer.echo(f"  Detected on {len(items)}/{len(live_urls)} live hosts:")
    for h, wafs in items[:limit]:
        typer.echo(f"  - {h} -> {', '.join(wafs)}")
    if len(items) > limit:
        typer.echo(f"  ... and {len(items)-limit} more")


def _extract_ports_from_nmap_value(v: Any) -> List[int]:
    ports: List[int] = []
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


def _print_ports_flat(ports: Dict[str, List[int]], limit: int = 50):
    flat: List[str] = []
    for h, ps in (ports or {}).items():
        for p in sorted(set(ps or [])):
            flat.append(f"{h}:{p}")

    typer.echo("\nOpen Ports:")
    if not flat:
        typer.echo("  (none)")
        return
    for x in flat[:limit]:
        typer.echo(f"  - {x}")
    if len(flat) > limit:
        typer.echo(f"  ... and {len(flat)-limit} more")


def _print_katana_summary(urls_by_url: Dict[str, List[str]], limit: int = 10):
    total = sum(len(v) for v in (urls_by_url or {}).values())
    typer.echo(f"\nKatana Summary:")
    typer.echo(f"  Total URLs: {total}")
    if total == 0:
        typer.echo("  (none)")
        return

    scored: List[Tuple[int, str]] = []
    seen: Set[str] = set()
    for base, urls in (urls_by_url or {}).items():
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
        typer.echo("  Top interesting URLs:")
        for u in top:
            typer.echo(f"  - {u}")
    else:
        typer.echo("  (no high-signal URLs matched heuristics)")


def _print_ffuf_summary(dirs_by_url: Dict[str, List[str]], limit: int = 10):
    total = sum(len(v) for v in (dirs_by_url or {}).values())
    typer.echo(f"\nFFUF Summary:")
    typer.echo(f"  Total hits: {total}")
    if total == 0:
        typer.echo("  (none)")
        return

    flat: List[str] = []
    for base, hits in (dirs_by_url or {}).items():
        for h in (hits or []):
            s = str(h).strip()
            if s:
                flat.append(s)

    for x in flat[:limit]:
        typer.echo(f"  - {x}")
    if len(flat) > limit:
        typer.echo(f"  ... and {len(flat)-limit} more")


def _collect_tech_by_host(http_rows: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Normalize httpx tech output into: host -> ["Tech", "Tech 1.2.3", ...]
    Handles tech being either:
      - list[str]
      - list[dict{name, version, raw}]
      - str
    """
    def _tech_item_to_str(x: Any) -> str:
        if x is None:
            return ""
        if isinstance(x, dict):
            name = str(x.get("name") or "").strip()
            ver = x.get("version")
            raw = str(x.get("raw") or "").strip()

            if ver is not None and str(ver).strip():
                return f"{name} {str(ver).strip()}".strip()
            if raw:
                return raw
            return name

        return str(x).strip()

    tech_by_host: Dict[str, List[str]] = {}

    for r in (http_rows or []):
        url = r.get("url")
        host = host_from_url(url) if url else norm_host(r.get("host") or r.get("input") or "")
        if not host:
            continue

        tech = r.get("tech") or []
        if isinstance(tech, str):
            tech = [tech] if tech.strip() else []
        if not isinstance(tech, list):
            tech = []

        cleaned: List[str] = []
        for x in tech:
            s = _tech_item_to_str(x)
            if s:
                cleaned.append(s)

        if not cleaned:
            continue

        cur = tech_by_host.get(host, [])
        for t in cleaned:
            if t not in cur:
                cur.append(t)
        tech_by_host[host] = cur

    return tech_by_host


# =================================================
# Output files policy enforcement
# =================================================
def _enforce_output_policy(target_dir: str, keep_txt: bool, mode: str, keep_subdomains_export: bool):
    """
    Keep only:
      - reconix.ndjson (always)
      - reconix.txt (if keep_txt)
      - quick_snapshot.json (quick only)
      - normal_snapshot.json (normal only)
      - reconix_subdomains_*.txt (if keep_subdomains_export)
      - reconix_report.md (if generated)
    Remove everything else inside output/<target>/ (files/dirs).
    """
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


# =================================================
# Subfinder “-all” auto decision (no keys => no -all)
# =================================================
def _subfinder_has_keys(cfg: dict) -> bool:
    sf = (cfg.get("subfinder", {}) or {}).get("providers", {}) or {}
    if not isinstance(sf, dict):
        return False
    for _, keys in sf.items():
        if isinstance(keys, list) and len(keys) > 0:
            return True
        if isinstance(keys, str) and keys.strip():
            return True
    return False


def _run_subfinder_smart(domain: str, provider_cfg_path: Optional[str], use_all: bool) -> List[str]:
    """
    Calls run_subfinder with best-effort compatibility:
      - if run_subfinder supports use_all kw: use it
      - otherwise, fallback to old signature
    """
    try:
        return run_subfinder(domain, provider_cfg_path=provider_cfg_path, use_all=use_all)  # type: ignore
    except TypeError:
        if provider_cfg_path:
            return run_subfinder(domain, provider_cfg_path=provider_cfg_path)  # type: ignore
        return run_subfinder(domain)  # type: ignore


def _tech_item_to_str(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, dict):
        name = str(x.get("name") or "").strip()
        ver = x.get("version")
        raw = str(x.get("raw") or "").strip()

        if ver is not None and str(ver).strip():
            return f"{name} {str(ver).strip()}".strip()
        if raw:
            return raw
        return name

    return str(x).strip()


def _tech_list_to_csv(val: Any) -> str:
    if not val:
        return "(none)"
    if isinstance(val, (str, int, float, bool)):
        s = str(val).strip()
        return s if s else "(none)"

    if not isinstance(val, list):
        s = str(val).strip()
        return s if s else "(none)"

    out: List[str] = []
    seen: Set[str] = set()
    for item in val:
        s = _tech_item_to_str(item)
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)

    return ", ".join(out) if out else "(none)"


def _format_cve_candidate_line(c: Dict[str, Any]) -> str:
    src = str(c.get("source") or "searchsploit")
    title = str(c.get("title") or "").strip()
    q = str(c.get("query") or "").strip()
    edb = str(c.get("edb_id") or "").strip()
    cves = c.get("cves") or []
    if isinstance(cves, list):
        cves_txt = ", ".join([str(x).strip() for x in cves if str(x).strip()]) or "(none)"
    else:
        cves_txt = "(none)"
    bits = []
    if title:
        bits.append(title)
    if cves_txt:
        bits.append(f"CVEs: {cves_txt}")
    if edb:
        bits.append(f"EDB-ID: {edb}")
    if q:
        bits.append(f"q={q}")
    return f"[{src}] " + " | ".join(bits)


# =================================================
# SCAN COMMAND
# =================================================
@app.command()
def scan(
    # -------------------- Main Options --------------------
    domain: Optional[str] = typer.Option(
        None,
        "-d",
        "--domain",
        help="Target domain (authorized only). Required unless --file is used.",
        rich_help_panel="Main Options",
    ),
    targets_file: Optional[Path] = typer.Option(
        None,
        "--file",
        help="Targets file (one per line). Lines starting with # are ignored. Using --file skips subdomain discovery.",
        rich_help_panel="Main Options",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    focus: bool = typer.Option(
        False,
        "--focus",
        help="Skip subdomain discovery and scan only the input target(s). With -d scans only that domain; with --file scans only targets in the file.",
        rich_help_panel="Main Options",
    ),
    export_subdomains: bool = typer.Option(
        False,
        "--export-subdomains",
        help="Export verified/unverified subdomains/targets to a TXT file (reusable with --file).",
        rich_help_panel="Main Options",
    ),
    report: bool = typer.Option(
        False,
        "--report",
        help="Generate reconix_report.md automatically after scan finishes.",
        rich_help_panel="Main Options",
    ),
    mode: str = typer.Option(
        "quick",
        "-m",
        "--mode",
        help="Scan mode: quick | normal",
        rich_help_panel="Main Options",
    ),
    out_dir: str = typer.Option(
        "output",
        "--out-dir",
        help="Output directory",
        rich_help_panel="Main Options",
    ),
    txt: bool = typer.Option(
        False,
        "--txt",
        help="Write detailed TXT report",
        rich_help_panel="Main Options",
    ),
    no_banner: bool = typer.Option(
        False,
        "--no-banner",
        help="Disable startup banner",
        rich_help_panel="Main Options",
    ),

    # ------------------- Quick Mode Options -------------------
    wayback_all: bool = typer.Option(
        False,
        "--wayback-all",
        help="Dump ALL wayback URLs (default keeps top 50)",
        rich_help_panel="Quick Mode Options",
    ),
    no_osint: bool = typer.Option(
        False,
        "--no-osint",
        help="Disable passive OSINT-lite enrichment",
        rich_help_panel="Quick Mode Options",
    ),
    osint_github: bool = typer.Option(
        False,
        "--osint-github",
        help="Enable GitHub code OSINT (passive) [requires -d/--domain]",
        rich_help_panel="Quick Mode Options",
    ),

    # ------------------- Normal Mode Options -------------------
    port_scan: bool = typer.Option(
        False,
        "--port-scan",
        help="Enable port scanning stage (naabu/nmap)",
        rich_help_panel="Normal Mode Options",
    ),
    dir_search: bool = typer.Option(
        False,
        "--dir-search",
        help="Enable directory discovery (ffuf)",
        rich_help_panel="Normal Mode Options",
    ),
    cves: bool = typer.Option(
        False,
        "--cves",
        help="Enable CVE candidates stage (searchsploit, local Exploit-DB).",
        rich_help_panel="Normal Mode Options",
    ),
    port_tool: Optional[PortTool] = typer.Option(
        None,
        "--port-tool",
        help="Port scan engine",
        rich_help_panel="Normal Mode Options",
    ),

    # ------------------- Port Scanning Tuning -------------------
    nmap_timing: Optional[str] = typer.Option(
        None,
        "--nmap-timing",
        help="Set nmap timing template: T0..T5 (overrides config)",
        rich_help_panel="Port Scanning Tuning",
    ),
    naabu_rate: Optional[int] = typer.Option(
        None,
        "--naabu-rate",
        help="Naabu rate (default from config)",
        rich_help_panel="Port Scanning Tuning",
    ),
    naabu_timeout: Optional[int] = typer.Option(
        None,
        "--naabu-timeout",
        help="Naabu timeout seconds (default from config)",
        rich_help_panel="Port Scanning Tuning",
    ),
):
    if not no_banner:
        banner(version=__version__)

    mode = mode.lower().strip()
    if mode not in {"quick", "normal"}:
        warn("Invalid mode. Falling back to QUICK.")
        mode = "quick"

    # Resolve scope: --file / --focus
    domain = norm_host(domain or "")
    scope_targets: List[str] = []
    skip_discovery = False

    if targets_file:
        scope_targets = load_targets_file(targets_file)
        if not scope_targets:
            err("Targets file is empty or has no valid targets.")
            raise typer.Exit(1)
        skip_discovery = True
        if focus:
            warn("--focus is redundant with --file (already focused). Ignoring --focus.")
            focus = False
        if osint_github and not domain:
            warn("--osint-github requires -d/--domain. Disabling GitHub OSINT.")
            osint_github = False
    else:
        if not domain:
            err("Missing target. Use -d/--domain or provide --file.")
            raise typer.Exit(1)
        if focus:
            skip_discovery = True
            scope_targets = [norm_host(domain)]

    # Choose label for output/snapshots
    target_label = domain if domain else (targets_file.stem if targets_file else "targets")

    # QUICK guardrails
    if mode == "quick":
        if port_scan:
            warn("--port-scan ignored in QUICK (100% passive)")
            port_scan = False
        if dir_search:
            warn("--dir-search ignored in QUICK (100% passive)")
            dir_search = False
        if cves:
            warn("--cves ignored in QUICK (100% passive)")
            cves = False
        if port_tool is not None:
            warn("--port-tool ignored in QUICK (100% passive)")
            port_tool = None
        if nmap_timing:
            warn("--nmap-timing ignored in QUICK (100% passive)")
            nmap_timing = None
        if naabu_rate is not None or naabu_timeout is not None:
            warn("--naabu-* ignored in QUICK (100% passive)")
            naabu_rate = None
            naabu_timeout = None

    if nmap_timing and not port_scan:
        warn("--nmap-timing ignored (enable --port-scan first)")

    if (port_tool is not None or naabu_rate is not None or naabu_timeout is not None) and not port_scan:
        warn("--port-tool/--naabu-* ignored (enable --port-scan first)")

    # validate nmap timing early
    if nmap_timing:
        allowed = {"T0", "T1", "T2", "T3", "T4", "T5"}
        if nmap_timing.upper() not in allowed:
            err("Invalid --nmap-timing. Use one of: T0 T1 T2 T3 T4 T5")
            raise typer.Exit(1)
        nmap_timing = nmap_timing.upper()

    cfg = load_config()

    legacy_dir = cfg.get("dirsearch", {}) or {}
    legacy_nmap = cfg.get("nmap", {}) or {}

    ffuf_cfg = cfg_get(cfg, "normal.ffuf", {}) or legacy_dir
    nmap_cfg = cfg_get(cfg, "normal.nmap", {}) or legacy_nmap
    naabu_cfg = cfg_get(cfg, "normal.naabu", {}) or {}
    portscan_cfg = cfg_get(cfg, "normal.portscan", {}) or {}

    httpx_enabled = bool(cfg_get(cfg, "normal.httpx.enabled", True))
    katana_enabled = bool(cfg_get(cfg, "normal.katana.enabled", True))
    waf_enabled = bool(cfg_get(cfg, "normal.wafw00f.enabled", True))

    # CVE config-first
    cve_cfg_enabled = bool(cfg_get(cfg, "normal.cve.enabled", False))
    cve_enabled = (mode == "normal") and (cves or cve_cfg_enabled)

    # port tool resolve (config-first)
    if port_tool is not None:
        port_tool_resolved = port_tool.value
    else:
        port_tool_resolved = str(portscan_cfg.get("tool", "both")).lower().strip()

    if port_tool_resolved not in {"nmap", "naabu", "both"}:
        warn("Invalid port tool in config. Using: both")
        port_tool_resolved = "both"

    # nmap timing resolve
    timing = nmap_timing if nmap_timing else str(nmap_cfg.get("timing", "T3")).upper()
    if timing not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
        timing = "T3"

    # GitHub token from config
    github_token = (cfg.get("osint", {}) or {}).get("githubkey")  # stored as githubkey

    # NEW: generate subfinder provider-config.yaml from ReconiX config
    provider_cfg_path: Optional[str] = None
    if write_subfinder_provider_config is not None:
        try:
            provider_path = Path.home() / ".config" / "reconix" / "subfinder" / "provider-config.yaml"
            write_subfinder_provider_config(cfg, provider_path)
            provider_cfg_path = str(provider_path)
        except Exception:
            provider_cfg_path = None

    use_subfinder_all = _subfinder_has_keys(cfg)

    target_dir = f"{out_dir}/{safe_target_name(target_label)}"
    ensure_dir(target_dir)

    out_file = f"{target_dir}/reconix.ndjson"
    txt_file = f"{target_dir}/reconix.txt"
    quick_snapshot = f"{target_dir}/quick_snapshot.json"
    normal_snapshot = f"{target_dir}/normal_snapshot.json"

    prev_quick = _load_json(quick_snapshot) if mode == "quick" else None
    prev_normal = _load_json(normal_snapshot) if mode == "normal" else None

    start_total = time.time()

    try:
        # ---------------- subdomains / scope ----------------
        if skip_discovery:
            info("Scope selection enabled (skipping subdomain discovery)")
        else:
            info("Starting subdomain discovery")
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
                sf = {norm_host(x) for x in _run_subfinder_smart(domain, provider_cfg_path, use_all=use_subfinder_all)}
                cs = {norm_host(x) for x in run_crtsh(domain)}

                if osint_github:
                    info("Starting GitHub OSINT (passive)")
                    tg = time.time()
                    github_subs = {norm_host(x) for x in run_github_subdomains(domain, github_token)}
                    info(f"Finished GitHub OSINT ({len(github_subs)} subdomains) [{int(time.time()-tg)}s]")

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
                af = {norm_host(x) for x in run_assetfinder(domain)}
                sf = {norm_host(x) for x in _run_subfinder_smart(domain, provider_cfg_path, use_all=use_subfinder_all)}
                sl = {norm_host(x) for x in run_sublist3r(domain)}
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

        info(f"Finished scope ({len(subdomains)} targets) [{int(time.time()-t0)}s]")

        # ---------------- dnsx ----------------
        info("Starting DNS validation (dnsx)")
        t0 = time.time()
        resolved_raw = run_dnsx(list(subdomains))
        resolved = sorted({norm_host(x) for x in resolved_raw if norm_host(x)})
        resolved_set = set(resolved)
        info(f"Finished dnsx ({len(resolved)} resolved) [{int(time.time()-t0)}s]")

        unverified = sorted(set(subdomains) - resolved_set)

        # ---------------- export-subdomains ----------------
        export_path = None
        if export_subdomains:
            slug = norm_host(domain) if domain else safe_target_name(target_label)
            export_path = f"{target_dir}/reconix_subdomains_{slug}.txt"
            write_subdomains_export(
                path=export_path,
                domain_label=target_label,
                verified=resolved,
                unverified=unverified,
            )
            info(f"Exported subdomains file: {export_path}")

        # ---------------- httpx (NORMAL only, config-first) ----------------
        http_rows: List[Dict[str, Any]] = []
        live_urls: List[str] = []
        live_hosts: List[str] = []

        if mode == "normal":
            if httpx_enabled:
                info("Starting HTTP probing (httpx)")
                t0 = time.time()
                http_rows = run_httpx(resolved)  # tech fingerprinting handled in module
                live_urls = [r.get("url") for r in http_rows if r.get("url")]
                live_hosts = sorted({host_from_url(u) for u in live_urls if host_from_url(u)})
                info(f"Finished httpx ({len(live_hosts)} live hosts) [{int(time.time()-t0)}s]")
            else:
                warn("httpx disabled (config). Skipping live URL probing.")
        else:
            info("HTTP probing disabled in QUICK (passive only)")

        tech_by_host = _collect_tech_by_host(http_rows) if (mode == "normal" and http_rows) else {}

        # ---------------- wafw00f (NORMAL only; config-first; fail-soft) ----------------
        waf_by_url: Dict[str, Any] = {}
        if mode == "normal" and httpx_enabled and waf_enabled and live_urls:
            try:
                from reconix.modules.wafw00f import run_wafw00f
                info("Starting WAF detection (wafw00f)")
                t0 = time.time()
                waf_by_url = run_wafw00f(live_urls, cfg=cfg)
                info(f"Finished wafw00f [{int(time.time()-t0)}s]")
            except Exception:
                warn("wafw00f enabled but module/tool not available. Skipping WAF detection.")

        # ---------------- OSINT lite (passive) ----------------
        osint_enabled = (not no_osint) and bool(domain)
        osint_data: Dict[str, Any] = {}
        if not no_osint and not domain:
            warn("OSINT requires -d/--domain. Skipping OSINT.")
        if osint_enabled:
            info("Starting OSINT (passive)")
            t0 = time.time()
            osint_data = run_osint_lite(domain)
            info(f"Finished OSINT [{int(time.time()-t0)}s]")

        # ---------------- wayback (QUICK only) ----------------
        wayback_by_host: Dict[str, List[str]] = {}
        wayback_total = 0
        wayback_kept = 0

        if mode == "quick" and domain:
            info("Starting Wayback URL collection (wayback)")
            t0 = time.time()
            try:
                wb_urls = fetch_wayback_urls(domain)
            except Exception:
                wb_urls = []

            wayback_total = len(wb_urls)
            chosen = wb_urls if wayback_all else _pick_top_wayback(wb_urls, k=50)
            wayback_kept = len(chosen)

            for u in chosen:
                h = host_from_url(u)
                if not h:
                    continue
                wayback_by_host.setdefault(h, []).append(u)

            if wayback_all:
                info(f"Finished wayback ({wayback_total} URLs, kept ALL) [{int(time.time()-t0)}s]")
            else:
                info(f"Finished wayback ({wayback_total} URLs, kept {wayback_kept}) [{int(time.time()-t0)}s]")

        # ---------------- katana (NORMAL only, config-first) ----------------
        urls_by_url: Dict[str, List[str]] = {}
        if mode == "normal" and live_urls and katana_enabled:
            info("Starting URL discovery (katana)")
            t0 = time.time()
            urls_by_url = run_katana(live_urls)
            total = sum(len(v) for v in urls_by_url.values())
            info(f"Finished katana ({total} URLs) [{int(time.time()-t0)}s]")
        elif mode == "normal" and live_urls and not katana_enabled:
            warn("katana disabled (config). Skipping crawling.")

        # ---------------- ffuf (NORMAL only, explicit flag) ----------------
        dirs_by_url: Dict[str, List[str]] = {}
        if mode == "normal" and dir_search and live_urls:
            info("Starting directory discovery (ffuf)")
            t0 = time.time()
            dirs_by_url = run_dirsearch(
                live_urls,
                wordlist=ffuf_cfg.get("wordlist"),
                threads=ffuf_cfg.get("threads", 20),
                extensions=ffuf_cfg.get("extensions", []),
                recursive=ffuf_cfg.get("recursive", False),
                recursion_depth=ffuf_cfg.get("recursion_depth", 2),
            )
            total = sum(len(v) for v in dirs_by_url.values())
            info(f"Finished directory discovery ({total} paths) [{round(time.time()-t0, 2)}s]")

        # ---------------- port scan (NORMAL only, explicit flag) ----------------
        ports_by_host: Dict[str, List[Any]] = {}
        naabu_ports: Dict[str, List[int]] = {}

        if mode == "normal" and port_scan and live_urls:
            hosts = sorted({host_from_url(u) for u in live_urls if host_from_url(u)})

            if not hosts:
                warn("No live hosts to scan ports for.")
            else:
                if port_tool_resolved in {"naabu", "both"}:
                    try:
                        from reconix.modules.naabu import run_naabu
                        info("Starting port discovery (naabu)")
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

                        info(f"Finished naabu [{int(time.time()-t0)}s]")
                    except Exception:
                        warn("naabu selected but module/tool not available. Skipping naabu.")

                if port_tool_resolved in {"nmap", "both"}:
                    info("Starting port scan (nmap)")
                    t0 = time.time()
                    ports_by_host = run_nmap(
                        hosts,
                        top_ports=nmap_cfg.get("top_ports", 100),
                        timing=timing,
                    )
                    total = sum(len(v) for v in ports_by_host.values())
                    info(f"Finished nmap ({total} open ports) [{int(time.time()-t0)}s]")

        # ---------------- build http_map (used by TXT/NDJSON and CVE stage) ----------------
        http_map: Dict[str, Dict[str, Any]] = {}
        for row in http_rows:
            key = norm_host(row.get("host") or row.get("input") or "")
            if not key and row.get("url"):
                key = host_from_url(row["url"])
            if key:
                http_map[key] = row

        # ---------------- CVE candidates (NORMAL only; config-first or --cves) ----------------
        cve_queries_by_host: Dict[str, List[str]] = {}
        cve_candidates_by_host: Dict[str, List[Dict[str, Any]]] = {}
        cve_total_candidates = 0

        if cve_enabled:
            if build_queries_from_tech is None or cve_candidates_from_queries is None:
                warn("CVE stage requested but cve_candidates module failed to import. Skipping CVE stage.")
                cve_enabled = False
            else:
                info("Starting CVE candidates (searchsploit)")
                t0 = time.time()

                require_version = bool(cfg_get(cfg, "normal.cve.require_version", False))
                max_queries = int(cfg_get(cfg, "normal.cve.max_queries", 25))
                timeout = int(cfg_get(cfg, "normal.cve.timeout", 10))
                max_results_per_query = int(cfg_get(cfg, "normal.cve.max_results_per_query", 10))

                ignore_cfg = cfg_get(cfg, "normal.cve.ignore", None)
                ignore_set: Optional[Set[str]] = None
                if isinstance(ignore_cfg, list):
                    ignore_set = {str(x).strip().lower() for x in ignore_cfg if str(x).strip()}

                # host -> queries + global unique queries
                all_queries: List[str] = []
                seen_q: Set[str] = set()

                for h in (live_hosts or []):
                    row = http_map.get(norm_host(h)) or {}
                    tech_list = []
                    if isinstance(row, dict):
                        tech_list = row.get("tech") or []
                    if isinstance(tech_list, str):
                        tech_list = [tech_list] if tech_list.strip() else []
                    if not isinstance(tech_list, list):
                        tech_list = []

                    qlist = build_queries_from_tech(
                        tech_list,
                        ignore=ignore_set,
                        require_version=require_version,
                    )

                    # also include webserver hint (helps sometimes)
                    if isinstance(row, dict):
                        ws = str(row.get("webserver") or "").strip()
                        if ws:
                            extra = build_queries_from_tech([{"name": ws, "version": None, "raw": ws}], ignore=ignore_set)
                            for q in extra:
                                if q not in qlist:
                                    qlist.append(q)

                    cve_queries_by_host[norm_host(h)] = qlist

                    for q in qlist:
                        ql = q.lower()
                        if ql not in seen_q:
                            seen_q.add(ql)
                            all_queries.append(q)

                # run searchsploit once per unique query list (capped)
                candidates = cve_candidates_from_queries(
                    all_queries,
                    max_queries=max_queries,
                    timeout=timeout,
                    max_results_per_query=max_results_per_query,
                )

                # group by query
                by_query: Dict[str, List[Dict[str, Any]]] = {}
                for c in candidates or []:
                    q = str(c.get("query") or "").strip()
                    if not q:
                        continue
                    by_query.setdefault(q, []).append(c)

                # map back to host
                for h, qlist in cve_queries_by_host.items():
                    host_out: List[Dict[str, Any]] = []
                    for q in qlist:
                        host_out.extend(by_query.get(q, []))
                    cve_candidates_by_host[h] = host_out
                    cve_total_candidates += len(host_out)

                info(f"Finished CVE candidates ({cve_total_candidates} candidates) [{int(time.time()-t0)}s]")

        # ---------------- write outputs ----------------
        txt_handle = open(txt_file, "w", encoding="utf-8") if txt else None

        summary = {
            "discovered": len(subdomains),
            "verified": len(resolved),
            "unverified": len(unverified),
            "http_alive": len(live_hosts) if (mode == "normal" and httpx_enabled) else 0,
            "cve_candidates_total": int(cve_total_candidates) if (mode == "normal" and cve_enabled) else 0,
        }

        with open(out_file, "w", encoding="utf-8") as f:
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

            if txt_handle and osint_enabled:
                _write_osint_txt(txt_handle, osint_data, github_count=len(github_subs))

            if txt_handle:
                _txt_line(txt_handle, "SUMMARY:")
                _txt_line(txt_handle, f"  discovered: {summary['discovered']}")
                _txt_line(txt_handle, f"  verified:   {summary['verified']}")
                _txt_line(txt_handle, f"  unverified: {summary['unverified']}")
                _txt_line(
                    txt_handle,
                    f"  http_alive: {summary['http_alive']} ({'enabled' if (mode=='normal' and httpx_enabled) else 'disabled'})",
                )
                _txt_line(txt_handle, f"  katana:     {'enabled' if (mode=='normal' and katana_enabled) else 'disabled'}")
                _txt_line(txt_handle, f"  wafw00f:    {'enabled' if (mode=='normal' and waf_enabled) else 'disabled'}")
                _txt_line(txt_handle, f"  cves:       {'enabled' if (mode=='normal' and cve_enabled) else 'disabled'}")
                if mode == "normal" and cve_enabled:
                    _txt_line(txt_handle, f"  cve_candidates_total: {summary['cve_candidates_total']}")
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

                cve_q = cve_queries_by_host.get(hostname, []) if (mode == "normal" and cve_enabled and is_resolved) else []
                cve_cands = cve_candidates_by_host.get(hostname, []) if (mode == "normal" and cve_enabled and is_resolved) else []

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
                        "tech": r.get("tech", []) if isinstance(r, dict) else [],
                    },
                    "waf": waf_info,
                    "urls": wayback_by_host.get(host, []) if mode == "quick" else (urls_by_url.get(url, []) if url else []),
                    "directories": dirs_by_url.get(url, []) if (mode == "normal" and dir_search and url) else [],
                    "ports": ports_by_host.get(hostname, []) if (mode == "normal" and port_scan) else [],
                    "ports_naabu": naabu_ports.get(hostname, []) if (mode == "normal" and port_scan and naabu_ports) else [],
                    "cve_queries": cve_q,
                    "cve_candidates": cve_cands,
                    "timestamp": utc_now(),
                }

                f.write(json.dumps(record, ensure_ascii=False) + "\n\n")

                if txt_handle:
                    _txt_line(txt_handle, f"Subdomain: {host}")
                    _txt_line(txt_handle, f"  status: {record['status']}")
                    _txt_line(txt_handle, f"  confidence: {record['confidence']}")
                    _txt_line(
                        txt_handle,
                        f"  subdomain_sources: {', '.join(record['subdomain_sources']) if record['subdomain_sources'] else '(none)'}",
                    )
                    _txt_line(txt_handle, f"  dns.resolved: {record['dns']['resolved']}")
                    _txt_line(
                        txt_handle,
                        f"  http.alive: {record['http']['alive']} ({'enabled' if (mode=='normal' and httpx_enabled) else 'disabled'})",
                    )
                    _txt_line(txt_handle, f"  http.url: {record['http']['url']}")
                    _txt_line(txt_handle, f"  http.status: {record['http']['status']}")
                    _txt_line(txt_handle, f"  http.title: {record['http']['title']}")
                    _txt_line(txt_handle, f"  http.tech: {_tech_list_to_csv(record['http'].get('tech'))}")

                    if record.get("waf") is not None:
                        _txt_line(txt_handle, f"  waf: {record['waf']}")
                    _txt_list(txt_handle, "  urls", record["urls"])
                    _txt_list(txt_handle, "  directories", record["directories"])
                    _txt_list(txt_handle, "  ports", record["ports"])
                    _txt_list(txt_handle, "  ports_naabu", record["ports_naabu"])

                    if mode == "normal" and cve_enabled and record["dns"]["resolved"]:
                        _txt_line(txt_handle, "  CVE Candidates:")
                        _txt_list(txt_handle, "    queries", record.get("cve_queries") or [])
                        cands = record.get("cve_candidates") or []
                        if cands:
                            _txt_line(txt_handle, "    results:")
                            for line in [_format_cve_candidate_line(x) for x in cands[:25]]:
                                _txt_line(txt_handle, f"      - {line}")
                            if len(cands) > 25:
                                _txt_line(txt_handle, f"      ... and {len(cands) - 25} more")
                        else:
                            _txt_line(txt_handle, "    results: (none)")

                    _txt_line(txt_handle, f"  timestamp: {record['timestamp']}")
                    _txt_line(txt_handle, "-" * 60)

        if txt_handle:
            txt_handle.close()
            info(f"TXT report written to: {txt_file}")

        # ---------------- quick snapshot delta ----------------
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

            d = _delta(prev_quick, cur_quick)
            if d["has_prev"] and (d["added"] or d["removed"]):
                warn("New assets detected since last QUICK run or removed")
                if d["added"].get("subdomains"):
                    info(f"New subdomains: {len(d['added']['subdomains'])}")
                if d["removed"].get("subdomains"):
                    warn(f"Removed subdomains: {len(d['removed']['subdomains'])}")
                if d["added"].get("resolved"):
                    info(f"New resolved: {len(d['added']['resolved'])}")
                if d["removed"].get("resolved"):
                    warn(f"Removed resolved: {len(d['removed']['resolved'])}")
                if d["added"].get("unverified"):
                    info(f"New unverified: {len(d['added']['unverified'])}")
                if d["removed"].get("unverified"):
                    warn(f"Removed unverified: {len(d['removed']['unverified'])}")

            _save_json(quick_snapshot, cur_quick)

        # ---------------- normal snapshot delta ----------------
        if mode == "normal":
            waf_by_host: Dict[str, List[str]] = {}
            if waf_by_url and live_urls:
                for u in live_urls:
                    obj = waf_by_url.get(u) or {}
                    if isinstance(obj, dict) and obj.get("detected") and obj.get("wafs"):
                        h = host_from_url(u)
                        if h:
                            wafs = [str(x).strip() for x in (obj.get("wafs") or []) if str(x).strip()]
                            if wafs:
                                waf_by_host[h] = wafs

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

        # ---------------- summary ----------------
        info("Recon completed")

        typer.echo(f"\nReconiX v{__version__}  |  Mode: {mode.upper()}")
        typer.echo(f"Target                 : {target_label}")
        typer.echo(f"Subdomains found        : {summary['discovered']}")
        typer.echo(f"DNS-resolved (VERIFIED) : {summary['verified']}")
        typer.echo(f"DNS-unresolved          : {summary['unverified']}")
        typer.echo(f"HTTP alive hosts        : {summary['http_alive']} ({'enabled' if (mode=='normal' and httpx_enabled) else 'disabled'})")
        typer.echo(f"OSINT (passive)         : {'no' if no_osint else ('yes' if domain else 'skipped (no -d)')}")
        typer.echo(f"GitHub OSINT            : {'yes' if osint_github else 'no'}")
        if mode == "quick" and domain:
            if wayback_all:
                typer.echo(f"Wayback URLs            : {wayback_total} (ALL)")
            else:
                typer.echo(f"Wayback URLs            : {wayback_total} (top {wayback_kept})")
        typer.echo(f"Katana enabled          : {'yes' if (mode=='normal' and katana_enabled) else 'no'}")
        typer.echo(f"WAF detection           : {'yes' if (mode=='normal' and waf_enabled) else 'no'}")
        typer.echo(f"Directory discovery     : {'yes' if (mode=='normal' and dir_search) else 'no'}")
        typer.echo(f"Port scan enabled       : {'yes' if (mode=='normal' and port_scan) else 'no'}")
        typer.echo(f"CVE candidates          : {'yes' if (mode=='normal' and cve_enabled) else 'no'}")
        if mode == "normal" and cve_enabled:
            typer.echo(f"CVE candidates total    : {summary['cve_candidates_total']}")
        if mode == "normal" and port_scan:
            typer.echo(f"Port tool               : {port_tool_resolved}")
            typer.echo(f"nmap timing             : {timing}")
        typer.echo(f"Output written to       : {out_file}")
        if txt:
            typer.echo(f"TXT report written to   : {txt_file}")
        if export_path:
            typer.echo(f"Subdomains export       : {export_path}")
        typer.echo(f"Duration                : {int(time.time()-start_total)}s\n")

        verified_hosts = sorted(resolved)
        unverified_hosts = unverified

        _print_section("Verified assets", verified_hosts, src_map, resolved_set)
        _print_section("Unverified discoveries", unverified_hosts, src_map, resolved_set)

        if mode == "quick":
            info("QUICK mode completed (passive only)")
            if domain:
                info(f"Suggested next step: reconix scan -d {domain} -m normal")

        if mode == "normal":
            if osint_enabled:
                _print_osint_summary(osint_data, github_count=len(github_subs))

            if httpx_enabled and waf_enabled:
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
                info(f"Report written to: {rp}")
            except Exception as e:
                warn(f"Report generation failed: {e}")

        _enforce_output_policy(
            target_dir,
            keep_txt=bool(txt),
            mode=mode,
            keep_subdomains_export=bool(export_subdomains),
        )

    except FileNotFoundError as e:
        err(str(e))
        warn("Run `reconix verify` to check dependencies.")
        raise typer.Exit(1)


# =================================================
# VERIFY COMMAND
# =================================================
@app.command()
def verify():
    raise typer.Exit(verify_run())


# =================================================
# CONFIG SHOW (colorful, no secrets)
# =================================================
@config_app.command("show")
def config_show():
    from rich.rule import Rule
    from rich.table import Table

    cfg = load_config()

    def rule(title: str):
        ui.console.print(Rule(f"[title]{title}[/title]", style="white", align="left"))

    def kv_table(items: List[Tuple[str, Any]]):
        t = Table(show_header=False, box=None, pad_edge=False)
        t.add_column("k", style="key", no_wrap=True)
        t.add_column("v", style="value")
        for k, v in items:
            t.add_row(str(k), str(v))
        ui.console.print(t)

    ui.console.print(f"[muted]path:[/muted] {CONFIG_PATH}")
    ui.console.print()

    # OSINT
    rule("OSINT")
    gh = ""
    try:
        gh = str(((cfg.get("osint") or {}) if isinstance(cfg.get("osint"), dict) else {}).get("githubkey") or "")
    except Exception:
        gh = ""
    kv_table([("githubkey", "set" if gh.strip() else "not set")])
    ui.console.print()

    # Subfinder providers
    rule("Subfinder Providers")
    providers: Dict[str, Any] = {}
    try:
        providers = (cfg.get("subfinder") or {}).get("providers") or {}
        if not isinstance(providers, dict):
            providers = {}
    except Exception:
        providers = {}

    if not providers:
        kv_table([("(none)", "")])
    else:
        rows: List[Tuple[str, str]] = []
        for name in sorted(providers.keys()):
            val = providers.get(name)
            if isinstance(val, list):
                rows.append((name, f"{'set' if len(val) > 0 else 'not set'} ({len(val)})"))
            elif isinstance(val, str):
                rows.append((name, "set (1)" if val.strip() else "not set (0)"))
            else:
                rows.append((name, "not set (0)"))
        kv_table(rows)
    ui.console.print()

    # QUICK
    rule("QUICK")
    quick = cfg.get("quick") if isinstance(cfg.get("quick"), dict) else {}
    kv_table(
        [
            ("wayback_top", (quick or {}).get("wayback_top", 50)),
            ("osint_lite", (quick or {}).get("osint_lite", True)),
            ("github_osint", (quick or {}).get("github_osint", False)),
            ("delta", (quick or {}).get("delta", True)),
        ]
    )
    ui.console.print()

    # NORMAL blocks
    normal = cfg.get("normal") if isinstance(cfg.get("normal"), dict) else {}

    rule("NORMAL · httpx")
    httpx = (normal or {}).get("httpx") if isinstance((normal or {}).get("httpx"), dict) else {}
    kv_table(
        [
            ("httpx.enabled", (httpx or {}).get("enabled", True)),
            ("httpx.threads", (httpx or {}).get("threads", 80)),
            ("httpx.timeout", (httpx or {}).get("timeout", 8)),
            ("httpx.follow_redirects", (httpx or {}).get("follow_redirects", True)),
            ("httpx.tech_detect", (httpx or {}).get("tech_detect", True)),
        ]
    )
    ui.console.print()

    rule("NORMAL · katana")
    katana = (normal or {}).get("katana") if isinstance((normal or {}).get("katana"), dict) else {}
    kv_table(
        [
            ("katana.enabled", (katana or {}).get("enabled", True)),
            ("katana.depth", (katana or {}).get("depth", 2)),
            ("katana.concurrency", (katana or {}).get("concurrency", 20)),
            ("katana.timeout", (katana or {}).get("timeout", 10)),
            ("katana.js_crawl", (katana or {}).get("js_crawl", False)),
        ]
    )
    ui.console.print()

    rule("NORMAL · wafw00f")
    waf = (normal or {}).get("wafw00f") if isinstance((normal or {}).get("wafw00f"), dict) else {}
    kv_table(
        [
            ("wafw00f.enabled", (waf or {}).get("enabled", True)),
            ("wafw00f.timeout", (waf or {}).get("timeout", 5)),
            ("wafw00f.max_urls", (waf or {}).get("max_urls", 200)),
            ("wafw00f.noredirect", (waf or {}).get("noredirect", True)),
            ("wafw00f.findall", (waf or {}).get("findall", False)),
        ]
    )
    ui.console.print()

    rule("NORMAL · portscan")
    portscan = (normal or {}).get("portscan") if isinstance((normal or {}).get("portscan"), dict) else {}
    kv_table([("portscan.tool", (portscan or {}).get("tool", "both"))])
    ui.console.print()

    rule("NORMAL · ffuf")
    ffuf = (normal or {}).get("ffuf") if isinstance((normal or {}).get("ffuf"), dict) else {}
    exts = (ffuf or {}).get("extensions", ["php", "html", "js"])
    if isinstance(exts, list):
        exts_txt = ",".join([str(x).strip().lstrip(".") for x in exts if str(x).strip()])
    else:
        exts_txt = str(exts)
    kv_table(
        [
            ("ffuf.wordlist", (ffuf or {}).get("wordlist", "/usr/share/wordlists/dirb/common.txt")),
            ("ffuf.extensions", exts_txt),
            ("ffuf.threads", (ffuf or {}).get("threads", 20)),
            ("ffuf.recursive", (ffuf or {}).get("recursive", False)),
            ("ffuf.recursion_depth", (ffuf or {}).get("recursion_depth", 2)),
        ]
    )
    ui.console.print()

    rule("NORMAL · cve")
    cve = (normal or {}).get("cve") if isinstance((normal or {}).get("cve"), dict) else {}
    kv_table(
        [
            ("cve.enabled", (cve or {}).get("enabled", False)),
            ("cve.require_version", (cve or {}).get("require_version", False)),
            ("cve.max_queries", (cve or {}).get("max_queries", 25)),
            ("cve.timeout", (cve or {}).get("timeout", 10)),
            ("cve.max_results_per_query", (cve or {}).get("max_results_per_query", 10)),
        ]
    )
    ui.console.print()


# =================================================
# CONFIG SET/UNSET (NEW, ONE COMMAND)
# =================================================
@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Key (githubkey | wayback_top | httpx.enabled | ffuf.extensions | virustotal)"),
    value: str = typer.Argument(..., help='Value. Use JSON for lists/bools. Example: \'["php","html"]\' or true'),
):
    cfg = load_config()
    _set_key(cfg, key, value)
    save_config(cfg)
    ui.ok(f"set {key}")


@config_app.command("unset")
def config_unset(
    key: str = typer.Argument(..., help="Key to remove (same syntax as set)"),
):
    cfg = load_config()
    _unset_key(cfg, key)
    save_config(cfg)
    ui.ok(f"unset {key}")


# =================================================
# REPORT COMMAND
# =================================================
@app.command()
def report(
    domain: str = typer.Option(..., "-d", "--domain", help="Target folder name (e.g., google.com) OR full output path."),
    out_dir: str = typer.Option("output", "--out-dir", help="Output directory"),
):
    p = Path(domain)

    if "/" in domain or "\\" in domain or p.exists():
        target_dir = p
    else:
        target_dir = Path(out_dir) / safe_target_name(domain)

    report_path = generate_markdown_report(target_dir=target_dir)
    typer.echo(f"Report written to: {report_path}")

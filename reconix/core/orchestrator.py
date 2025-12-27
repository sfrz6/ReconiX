import json
import time
from datetime import datetime, timezone
from pathlib import Path

from reconix.modules.subdomains import run_subfinder
from reconix.modules.dns import run_dnsx
from reconix.modules.http import run_httpx

def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def run_quick(domain: str, out_path: str) -> dict:
    started = time.time()

    subs = run_subfinder(domain)
    resolved = run_dnsx(subs)
    http_rows = run_httpx(resolved)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        http_map = {}
        for r in http_rows:
            key = r.get("input") or r.get("host") or r.get("url")
            if key:
                http_map[key] = r

        for host in resolved:
            r = http_map.get(host, {})
            rec = {
                "tool": "reconix",
                "mode": "quick",
                "target": domain,
                "subdomain": host,
                "dns": {"resolved": True},
                "http": {
                    "alive": bool(r),
                    "url": r.get("url"),
                    "status": r.get("status_code"),
                    "title": r.get("title"),
                },
                "timestamp": utc_now(),
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    duration_s = int(time.time() - started)

    return {
        "target": domain,
        "mode": "quick",
        "subdomains_found": len(subs),
        "dns_resolved": len(resolved),
        "live_http": sum(1 for r in http_rows if r.get("url")),
        "output": out_path,
        "duration_seconds": duration_s,
    }

# reconix/modules/subdomains.py

import json
import shutil
import subprocess
from typing import List, Optional

import requests


def _norm_host(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    return h


def run_subfinder(
    domain: str,
    timeout: int = 60,
    provider_cfg_path: Optional[str] = None,
    use_all: bool = True,
) -> List[str]:
    """
    Passive subdomain source via subfinder.
    QUICK-safe + fail-soft:
      - If subfinder is missing, returns []
      - If subfinder errors/timeouts, returns []

    provider_cfg_path:
      - Optional path to subfinder provider-config.yaml (API keys)
      - Passed via -pc to enable key-based sources.

    use_all:
      - If True: adds -all (uses all sources; best when API keys exist)
      - If False: do not use -all (faster/cleaner when no keys exist)
    """
    if shutil.which("subfinder") is None:
        return []

    domain = _norm_host(domain)
    if not domain:
        return []

    cmd = ["subfinder", "-silent", "-d", domain]

    # Only use -all when it makes sense (or when caller explicitly wants it)
    if use_all:
        cmd.append("-all")

    # Provider config file enables key-based sources
    if provider_cfg_path:
        cmd += ["-pc", provider_cfg_path]

    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if p.returncode != 0:
            return []

        return sorted({_norm_host(line) for line in p.stdout.splitlines() if _norm_host(line)})
    except Exception:
        return []


def run_crtsh(domain: str, timeout: int = 15) -> List[str]:
    """
    Passive-only subdomain source (QUICK-safe).
    Fail-soft: returns [] if crt.sh is unreachable/blocked/rate-limited.

    Important fix:
      - crt.sh often returns wildcard names (*.example.com)
        We strip "*." instead of skipping.
    """
    base = _norm_host(domain)
    if not base:
        return []

    url = f"https://crt.sh/?q=%25.{base}&output=json"

    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconiX"})
        r.raise_for_status()

        # crt.sh sometimes returns JSON with odd formatting; handle both.
        try:
            rows = r.json()
        except Exception:
            rows = json.loads(r.text)

        out: set[str] = set()
        for row in rows:
            name_value = str(row.get("name_value", ""))
            for host in name_value.splitlines():
                h = _norm_host(host)
                if not h:
                    continue
                if h == base or h.endswith("." + base):
                    out.add(h)

        return sorted(out)
    except Exception:
        return []


def run_quick_subdomains(
    domain: str,
    provider_cfg_path: Optional[str] = None,
    use_all: bool = True,
) -> List[str]:
    """
    QUICK = passive-only: subfinder + crt.sh (deduped).

    provider_cfg_path:
      - passed to subfinder so API keys improve coverage.

    use_all:
      - forwarded to run_subfinder()
    """
    subs = set(run_subfinder(domain, provider_cfg_path=provider_cfg_path, use_all=use_all))
    subs.update(run_crtsh(domain))
    return sorted(subs)

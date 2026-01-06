# reconix/modules/nmap.py

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _cfg_get(cfg: Optional[dict], key: str, default=None):
    if not cfg:
        return default
    cur: Any = cfg
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def run_nmap(
    hosts: List[str],
    *,
    cfg: Optional[dict] = None,
    timing: Optional[str] = None,
    top_ports: Optional[int] = None,
    timeout: int = 180,
) -> Dict[str, List[dict]]:
    """
    Safe NORMAL-mode nmap:
    - -Pn + --top-ports, no scripts, no -sV
    - timing: "T3" (default) or "T4"

    Returns:
      dict[input_host] -> list of ports:
        [{"port": 80, "service": "http", "ip": "1.2.3.4"}, ...]
    """

    if not shutil.which("nmap"):
        raise FileNotFoundError("Missing binary: nmap")

    # Config-first defaults
    cfg_top_ports = int(_cfg_get(cfg, "nmap.top_ports", 100))
    cfg_timing = str(_cfg_get(cfg, "nmap.timing", "T3"))

    top_ports = cfg_top_ports if top_ports is None else int(top_ports)
    timing = cfg_timing if timing is None else str(timing)

    if timing not in {"T3", "T4"}:
        timing = "T3"

    # Normalize hosts
    host_list = [h.strip() for h in (hosts or []) if (h or "").strip()]
    if not host_list:
        return {}

    results: Dict[str, List[dict]] = {}

    for target in host_list:
        cmd = [
            "nmap",
            "-Pn",
            f"-{timing}",
            "--top-ports",
            str(int(top_ports)),
            "-oX",
            "-",
            target,
        ]

        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            # skip slow target
            continue

        if p.returncode != 0 or not (p.stdout or "").strip():
            continue

        try:
            root = ET.fromstring(p.stdout)
        except ET.ParseError:
            continue

        # Try to extract IP from the scan result (best effort)
        ip_addr = None
        addr = root.find(".//host/address[@addrtype='ipv4']")
        if addr is not None:
            ip_addr = addr.get("addr")

        ports_out: List[dict] = []
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = port.get("portid")
            try:
                port_i = int(portid) if portid is not None else None
            except Exception:
                port_i = None
            if port_i is None:
                continue

            service = port.find("service")
            svc_name = service.get("name") if service is not None else None

            rec = {
                "port": port_i,
                "service": svc_name,
            }
            if ip_addr:
                rec["ip"] = ip_addr

            ports_out.append(rec)

        if ports_out:
            results[target] = ports_out

    return results

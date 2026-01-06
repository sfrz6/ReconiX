# reconix/core/verify.py

from __future__ import annotations

import shutil

from reconix.core.config import load_config
from reconix.utils.ui import section, table, kv, ok, warn, err


def _which(name: str) -> str | None:
    return shutil.which(name)


def _mk_rows(tools: list[tuple[str, str, bool]]) -> list[dict]:
    """
    tools: [(tool_name, note, required)]
    returns rows for ui.table()
    """
    rows: list[dict] = []
    for tool, note, required in tools:
        path = _which(tool)
        present = path is not None
        rows.append(
            {
                "Status": "✓" if present else "✗",
                "Tool": tool,
                "Path": path or "not found",
                "Required": "yes" if required else "no",
                "Notes": note or "",
            }
        )
    return rows


def run() -> int:
    cfg = load_config()

    section("ReconiX Verify")

    # QUICK: passive only (your QUICK pipeline)
    quick_required = [
        ("subfinder", "QUICK core", True),
        ("dnsx", "QUICK core", True),
    ]

    # NORMAL: core dependencies (always used in normal)
    normal_required = [
        ("assetfinder", "NORMAL subdomain sources", True),
        ("sublist3r", "NORMAL subdomain sources", True),
        ("httpx", "NORMAL HTTP probing", True),
        ("katana", "NORMAL crawling", True),
    ]

    # wafw00f is NORMAL (enabled by default) but should not hard-fail if missing
    waf_enabled = bool(((cfg.get("normal", {}) or {}).get("wafw00f", {}) or {}).get("enabled", True))
    waf_note = f"NORMAL WAF detection (config enabled={str(waf_enabled).lower()}); skipped if missing"
    waf_tools = [("wafw00f", waf_note, False)]

    # CVE candidates stage (optional, config gated)
    cve_enabled = bool(((cfg.get("normal", {}) or {}).get("cve", {}) or {}).get("enabled", False))

    # Optional stages (only with flags / config)
    optional_tools = [
        ("naabu", "Port stage (used with --port-scan --port-tool naabu/both)", False),
        ("nmap", "Port stage (used with --port-scan --port-tool nmap/both)", False),
        ("ffuf", "Dir stage (used with --dir-search)", False),
        (
            "searchsploit",
            "CVE candidates stage (cve.enabled=true). Tip: run `searchsploit -u` to update the local Exploit-DB index.",
            False,
        ),
    ]

    # Print tables
    table("Quick mode dependencies", _mk_rows(quick_required), columns=["Status", "Tool", "Path", "Required", "Notes"])
    table("Normal mode dependencies", _mk_rows(normal_required), columns=["Status", "Tool", "Path", "Required", "Notes"])
    table("Normal integrations", _mk_rows(waf_tools), columns=["Status", "Tool", "Path", "Required", "Notes"])
    table("Optional stages", _mk_rows(optional_tools), columns=["Status", "Tool", "Path", "Required", "Notes"])

    # Compute required status
    quick_ok = all(_which(t[0]) is not None for t in quick_required)
    normal_ok = all(_which(t[0]) is not None for t in normal_required)

    section("Summary")
    kv("Quick required OK", "yes" if quick_ok else "no")
    kv("Normal required OK", "yes" if normal_ok else "no")
    kv("wafw00f enabled (config)", str(waf_enabled).lower())
    kv("cve enabled (config)", str(cve_enabled).lower())

    # Helpful warnings (don’t fail verify for optional stages)
    if waf_enabled and _which("wafw00f") is None:
        warn("wafw00f is enabled in config, but tool not found. WAF stage will be skipped.")

    if cve_enabled and _which("searchsploit") is None:
        warn("CVE stage enabled but searchsploit not found. Install exploitdb/searchsploit or disable cve.enabled.")

    if quick_ok and normal_ok:
        ok("ReconiX environment looks good.")
        return 0

    err("ReconiX environment missing required dependencies.")
    if not quick_ok:
        warn("Fix QUICK requirements first (subfinder, dnsx).")
    if not normal_ok:
        warn("Fix NORMAL requirements (assetfinder, sublist3r, httpx, katana).")
    return 1

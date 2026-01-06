# reconix/modules/dirsearch.py
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional
from urllib.parse import urljoin


def run_dirsearch(
    base_urls: List[str],
    *,
    wordlist: str,
    threads: int = 20,
    extensions: Optional[List[str]] = None,
    recursive: bool = False,
    recursion_depth: int = 2,
    timeout: int = 120,
) -> Dict[str, List[str]]:
    """
    Directory discovery using ffuf (safe defaults).
    Returns: { base_url: [found_urls] }

    Notes:
    - No shell=True (stable & safer)
    - No -retries (your ffuf doesn't support it)
    - Writes JSON to a temp file (so ReconiX does NOT create extra output files)
    """
    if shutil.which("ffuf") is None:
        raise FileNotFoundError("Missing binary: ffuf")

    if not base_urls:
        return {}

    if recursion_depth < 1:
        recursion_depth = 1
    if recursion_depth > 5:
        recursion_depth = 5  # safety cap

    results: Dict[str, List[str]] = {}

    # build -e argument (ffuf expects .ext sometimes; yours works with plain too)
    ext_list: List[str] = []
    for e in (extensions or []):
        e = (e or "").strip()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        ext_list.append(e)

    for base in base_urls:
        base = (base or "").strip()
        if not base:
            continue

        target = f"{base.rstrip('/')}/FUZZ"

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=True) as tmp:
            out_path = tmp.name

            cmd: List[str] = [
                "ffuf",
                "-u", target,
                "-w", wordlist,
                "-t", str(int(threads)),
                "-timeout", "5",
                "-mc", "200,204,301,302,307,401,403",
                "-fs", "0",
                "-H", "User-Agent: reconix",
                "-of", "json",
                "-o", out_path,
                "-noninteractive",
                "-s",
            ]

            if ext_list:
                cmd += ["-e", ",".join(ext_list)]

            # recursion is OPT-IN only
            if recursive:
                cmd += ["-recursion", "-recursion-depth", str(int(recursion_depth))]

            # Run once; if recursion flags aren't supported on some builds, fallback without them
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                if p.returncode != 0:
                    # fallback: rerun without recursion flags if user enabled recursion
                    if recursive and ("flag provided but not defined" in (p.stderr or "").lower()):
                        cmd2 = [x for x in cmd if x not in ["-recursion", "-recursion-depth", str(int(recursion_depth))]]
                        p2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=timeout)
                        if p2.returncode != 0:
                            continue
                    else:
                        continue
            except Exception:
                continue

            # parse JSON output
            try:
                tmp.seek(0)
                data = json.load(tmp)
            except Exception:
                continue

        hits: List[str] = []
        for r in (data or {}).get("results", []) or []:
            fuzz = (r.get("input") or {}).get("FUZZ")
            if not fuzz:
                continue
            hits.append(urljoin(base.rstrip("/") + "/", str(fuzz).lstrip("/")))

        if hits:
            seen = set()
            deduped: List[str] = []
            for u in hits:
                if u not in seen:
                    seen.add(u)
                    deduped.append(u)
            results[base] = deduped

    return results

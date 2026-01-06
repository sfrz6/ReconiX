# reconix/modules/naabu.py
from __future__ import annotations

import json
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


def run_naabu(
    hosts: Iterable[str],
    out_ndjson: Optional[Path] = None,
    *,
    top_ports: int = 100,
    rate: int = 300,
    timeout: int = 5,
    ports: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Run naabu against a list of hosts (authorized only).

    - If out_ndjson is provided: writes ReconiX-style NDJSON results there.
    - If out_ndjson is None: does NOT write any files (temp files only, auto-cleaned).

    Record example:
      {"type":"port_open","tool":"naabu","host":"a.example.com","ip":"1.2.3.4","port":443,"timestamp":"..."}
    """
    naabu = shutil.which("naabu")
    if not naabu:
        raise RuntimeError("naabu not found in PATH. Install it (e.g., `sudo apt install naabu`).")

    host_list = _dedup_keep_order(hosts)
    if not host_list:
        if out_ndjson is not None:
            out_ndjson.parent.mkdir(parents=True, exist_ok=True)
            out_ndjson.write_text("", encoding="utf-8")
        return []

    # Prepare output writer (optional)
    w = None
    try:
        if out_ndjson is not None:
            out_ndjson.parent.mkdir(parents=True, exist_ok=True)
            w = out_ndjson.open("w", encoding="utf-8")

        results: List[Dict[str, Any]] = []

        # Use temporary directory for any naabu intermediate files
        with tempfile.TemporaryDirectory(prefix="reconix-naabu-") as td:
            td_path = Path(td)
            inp = td_path / "hosts.txt"
            raw_out = td_path / "raw.jsonl"

            inp.write_text("\n".join(host_list) + "\n", encoding="utf-8")

            cmd: List[str] = [
                naabu,
                "-list",
                str(inp),
                "-json",
                "-o",
                str(raw_out),
                "-rate",
                str(int(rate)),
                "-timeout",
                str(int(timeout)),
                "-silent",
                "-no-color",
            ]

            if ports:
                # explicit port list e.g. "80,443,8080"
                cmd += ["-p", str(ports)]
            else:
                cmd += ["-top-ports", str(int(top_ports))]

            if extra_args:
                cmd += list(extra_args)

            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                raise RuntimeError(f"naabu failed (exit {proc.returncode}): {stderr[:400]}")

            if not raw_out.exists():
                # naabu produced no output
                if w is not None:
                    w.write("")
                return []

            with raw_out.open("r", encoding="utf-8", errors="ignore") as r:
                for line in r:
                    line = (line or "").strip()
                    if not line:
                        continue

                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    host = (obj.get("host") or obj.get("hostname") or obj.get("domain") or "").strip()
                    ip = (obj.get("ip") or obj.get("address") or "").strip()
                    port = obj.get("port")

                    try:
                        port_i = int(port) if port is not None else None
                    except Exception:
                        port_i = None

                    if port_i is None:
                        continue
                    if not host and not ip:
                        continue

                    rec: Dict[str, Any] = {
                        "type": "port_open",
                        "tool": "naabu",
                        "host": host or None,
                        "ip": ip or None,
                        "port": port_i,
                        "timestamp": _utc_now(),
                    }
                    # remove None values
                    rec = {k: v for k, v in rec.items() if v is not None}

                    results.append(rec)
                    if w is not None:
                        w.write(json.dumps(rec, ensure_ascii=False) + "\n")

        return results

    finally:
        if w is not None:
            w.close()

import json
import shutil
import subprocess

def _require(bin_name: str):
    if shutil.which(bin_name) is None:
        raise FileNotFoundError(f"Missing binary: {bin_name}")

def run_httpx(hosts: list[str]) -> list[dict]:
    _require("httpx")
    if not hosts:
        return []

    # httpx -silent -json -title -status-code
    p = subprocess.run(
        ["httpx", "-silent", "-json", "-title", "-status-code"],
        input="\n".join(hosts),
        capture_output=True, text=True
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "httpx failed")

    out = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            # ignore malformed line
            pass
    return out

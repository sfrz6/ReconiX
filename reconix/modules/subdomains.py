import shutil
import subprocess

def _require(bin_name: str):
    if shutil.which(bin_name) is None:
        raise FileNotFoundError(f"Missing binary: {bin_name}")

def run_subfinder(domain: str) -> list[str]:
    _require("subfinder")
    # subfinder -silent -d example.com
    p = subprocess.run(
        ["subfinder", "-silent", "-d", domain],
        capture_output=True, text=True
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "subfinder failed")
    subs = sorted({line.strip() for line in p.stdout.splitlines() if line.strip()})
    return subs

import shutil
import subprocess

def _require(bin_name: str):
    if shutil.which(bin_name) is None:
        raise FileNotFoundError(f"Missing binary: {bin_name}")

def run_dnsx(subdomains: list[str]) -> list[str]:
    _require("dnsx")
    if not subdomains:
        return []

    p = subprocess.run(
        ["dnsx", "-silent"],
        input="\n".join(subdomains),
        capture_output=True, text=True
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "dnsx failed")
    resolved = sorted({line.strip() for line in p.stdout.splitlines() if line.strip()})
    return resolved

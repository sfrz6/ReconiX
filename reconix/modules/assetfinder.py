import shutil, subprocess

def run_assetfinder(domain: str) -> list[str]:
    if not shutil.which("assetfinder"):
        raise FileNotFoundError("Missing binary: assetfinder")

    p = subprocess.run(
        ["assetfinder", "--subs-only", domain],
        capture_output=True, text=True
    )
    if p.returncode != 0:
        raise RuntimeError("assetfinder failed")

    return list({l.strip() for l in p.stdout.splitlines() if l.strip()})

import shutil, subprocess

def run_sublist3r(domain: str) -> list[str]:
    if not shutil.which("sublist3r"):
        raise FileNotFoundError("Missing binary: sublist3r")

    p = subprocess.run(
        ["sublist3r", "-d", domain, "-n", "-o", "/dev/stdout"],
        capture_output=True, text=True
    )
    if p.returncode != 0:
        return []

    return list({l.strip() for l in p.stdout.splitlines() if l.strip()})

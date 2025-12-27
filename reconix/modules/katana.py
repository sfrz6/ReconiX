import shutil
import subprocess
import json

def run_katana(hosts: list[str]) -> dict[str, list[str]]:
    if not shutil.which("katana"):
        raise FileNotFoundError("Missing binary: katana")

    # Shallow + polite defaults
    cmd = [
        "katana",
        "-silent",
        "-json",
        "-depth", "1",
        "-nc",              # no color
        "-kf",              # keep failed (avoid retries)
        "-rl", "50"         # rate limit
    ]

    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    p.stdin.write("\n".join(hosts))
    p.stdin.close()

    results: dict[str, list[str]] = {}

    for line in p.stdout:
        try:
            row = json.loads(line)
            host = row.get("host")
            url = row.get("url")
            if host and url:
                results.setdefault(host, []).append(url)
        except json.JSONDecodeError:
            continue

    return results

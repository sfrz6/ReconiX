import shutil
import subprocess
import json
from urllib.parse import urljoin


def run_dirsearch(
    base_urls: list[str],
    *,
    wordlist: str,
    threads: int = 20,
    extensions: list[str] | None = None,
    recursive: bool = False,
    recursion_depth: int = 2,
) -> dict[str, list[str]]:
    """
    Directory discovery using ffuf (safe defaults).
    Returns: { base_url: [found_urls] }
    """
    if not shutil.which("ffuf"):
        raise FileNotFoundError("Missing binary: ffuf")

    if recursion_depth < 1:
        recursion_depth = 1
    if recursion_depth > 5:
        recursion_depth = 5  # safety cap

    results: dict[str, list[str]] = {}

    ext_arg = ""
    if extensions:
        ext_arg = f"-e {','.join(extensions)}"

    recursion_args = ""
    if recursive:
        recursion_args = f"-recursion -recursion-depth {recursion_depth}"

    for base in base_urls:
        cmd = (
            f"ffuf -u {base.rstrip('/')}/FUZZ "
            f"ffuf -u {base.rstrip('/')}/FUZZ "
            f"-w {wordlist} "
            f"-t {threads} "
            f"-timeout 5 "
            f"-retries 1 "
            f"-mc 200,204,301,302,307,401,403 "
            f"-fs 0 "
            f"-H 'User-Agent: reconix' "
            f"{recursion_args} "
            f"{ext_arg} "
            f"-of json -o - "
            f"-noninteractive -s"
        )

        p = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
        )

        if p.returncode != 0 or not p.stdout.strip():
            continue

        try:
            data = json.loads(p.stdout)
        except json.JSONDecodeError:
            continue

        hits = []
        for r in data.get("results", []):
            path = r.get("input", {}).get("FUZZ")
            if path:
                hits.append(urljoin(base.rstrip("/") + "/", path))

        if hits:
            # Deduplicate while preserving order
            seen = set()
            deduped = []
            for u in hits:
                if u not in seen:
                    seen.add(u)
                    deduped.append(u)
            results[base] = deduped

    return results

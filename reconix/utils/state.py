import json
from pathlib import Path

def load_state(state_dir: str, target: str) -> dict:
    p = Path(state_dir) / f"{target}.json"
    if not p.exists():
        return {"subdomains": [], "urls": []}
    return json.loads(p.read_text(encoding="utf-8"))

def save_state(state_dir: str, target: str, cur: dict) -> None:
    p = Path(state_dir)
    p.mkdir(parents=True, exist_ok=True)
    (p / f"{target}.json").write_text(json.dumps(cur, indent=2), encoding="utf-8")

def diff(prev: list[str], cur: list[str]) -> tuple[list[str], list[str]]:
    p, c = set(prev), set(cur)
    return sorted(c - p), sorted(p - c)  # added, removed

import os
from pathlib import Path
import json

def append_ndjson(path: str, obj: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def ensure_dir(path: str) -> str:
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

def safe_target_name(t: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in t)

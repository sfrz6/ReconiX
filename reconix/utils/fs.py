import os
from pathlib import Path

def ensure_dir(path: str) -> str:
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

def safe_target_name(t: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in t)

from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def rec(rtype: str, target: str, mode: str, data: Dict[str, Any],
        source: Optional[str]=None, confidence: Optional[str]=None) -> Dict[str, Any]:
    out = {
        "type": rtype,
        "schema": "1.0",
        "ts": utc_now(),
        "target": target,
        "mode": mode,
        "data": data,
    }
    if source: out["source"] = source
    if confidence: out["confidence"] = confidence
    return out

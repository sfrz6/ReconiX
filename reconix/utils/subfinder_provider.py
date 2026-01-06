from pathlib import Path

def write_subfinder_provider_config(cfg: dict, out_path: Path) -> None:
    providers = (cfg.get("subfinder", {}) or {}).get("providers", {}) or {}

    lines = []
    for provider, keys in providers.items():
        keys = [str(k).strip() for k in (keys or []) if str(k).strip()]
        if not keys:
            continue
        lines.append(f"{provider}:")
        for k in keys:
            lines.append(f"  - {k}")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(("\n".join(lines).strip() + "\n") if lines else "", encoding="utf-8")

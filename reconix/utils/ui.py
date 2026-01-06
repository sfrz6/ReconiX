# reconix/utils/ui.py
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.table import Table
from rich.theme import Theme

theme = Theme(
    {
        "banner": "bold cyan",
        "title": "bold cyan",
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "muted": "dim",
        "key": "bold white",
        "value": "white",
        "accent": "bold magenta",
    }
)

console = Console(theme=theme)


def banner(version: str):
    logo = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
"""
    console.print(logo, style="banner")
    console.print(f"ReconiX v{version}  —  Modular Recon Orchestrator", style="bold white")
    console.print("by ▸ SFRZ\n", style="muted")


# --- status lines (keep your old API) ---
def info(msg: str):
    console.print(f"[ok][+][/ok] {msg}")


def warn(msg: str):
    console.print(f"[warn][!][/warn] {msg}")


def err(msg: str):
    console.print(f"[err][-][/err] {msg}")


def ok(msg: str):
    console.print(f"[ok][✓][/ok] {msg}")


def note(msg: str):
    console.print(f"[accent][•][/accent] {msg}")


# --- formatting helpers ---
def hr(title: Optional[str] = None):
    """A nice horizontal divider."""
    console.print(Rule(title or "", style="muted"))


def section(title: str):
    """Big section header."""
    console.print(Rule(f"[title]{title}[/title]", style="title"))


def panel(title: str, body: str, *, style: str = "muted"):
    console.print(Panel(body, title=title, style=style, expand=False))


def kv(key: str, value: Any, *, indent: int = 0):
    """Key-value line with consistent coloring."""
    pad = " " * indent
    console.print(f"{pad}[key]{key}[/key]: [value]{value}[/value]")


def bullets(items: Iterable[str], *, indent: int = 2, bullet: str = "•"):
    pad = " " * indent
    for x in items:
        x = (x or "").strip()
        if not x:
            continue
        console.print(f"{pad}[accent]{bullet}[/accent] {x}")


def table(
    title: str,
    rows: Iterable[Mapping[str, Any]],
    *,
    columns: Optional[list[str]] = None,
):
    """
    Simple table helper.
    rows: iterable of dict-like rows.
    columns: optional explicit column order.
    """
    rows = list(rows)
    if not rows:
        panel(title, "(none)", style="muted")
        return

    if columns is None:
        # union of keys, stable-ish order
        columns = list(rows[0].keys())

    t = Table(title=title, show_header=True, header_style="bold cyan", show_lines=False)
    for c in columns:
        t.add_column(str(c), overflow="fold")

    for r in rows:
        t.add_row(*[str(r.get(c, "")) for c in columns])

    console.print(t)

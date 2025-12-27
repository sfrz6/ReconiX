import shutil
from rich.console import Console

console = Console()

QUICK_TOOLS = ["subfinder", "dnsx", "httpx"]
NORMAL_TOOLS = ["assetfinder", "sublist3r", "katana"]
OPTIONAL_TOOLS = {
    "nmap": "--port-scan",
    "ffuf": "--dir-search",
}


def run() -> int:
    console.print("\n[bold cyan]ReconiX Verify[/bold cyan]\n")

    missing_quick = False

    console.print("[bold]Quick mode dependencies:[/bold]")
    for tool in QUICK_TOOLS:
        path = shutil.which(tool)
        if path:
            console.print(f"[green][✓][/green] {tool:<12} {path}")
        else:
            console.print(f"[red][✗][/red] {tool:<12} NOT FOUND")
            missing_quick = True

    console.print("\n[bold]Normal mode dependencies:[/bold]")
    for tool in NORMAL_TOOLS:
        path = shutil.which(tool)
        if path:
            console.print(f"[green][✓][/green] {tool:<12} {path}")
        else:
            console.print(f"[yellow][!][/yellow] {tool:<12} optional (NORMAL)")

    console.print("\n[bold]Optional features:[/bold]")
    for tool, flag in OPTIONAL_TOOLS.items():
        path = shutil.which(tool)
        if path:
            console.print(f"[green][✓][/green] {tool:<12} enabled via {flag}")
        else:
            console.print(f"[yellow][!][/yellow] {tool:<12} missing (used with {flag})")

    if missing_quick:
        console.print("\n[red]Missing QUICK dependencies. ReconiX cannot run.[/red]\n")
        return 1

    console.print("\n[green]ReconiX environment looks good.[/green]\n")
    return 0

from rich.console import Console

console = Console()


def banner(version: str):
    logo = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
"""
    console.print(logo, style="bold cyan")
    console.print(
        f"ReconiX v{version}  —  Modular Recon Orchestrator",
        style="bold white"
    )
    console.print(f"by ▸ SFRZ\n", style="dim italic cyan")


def info(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")


def warn(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def err(msg: str):
    console.print(f"[bold red][-][/bold red] {msg}")

import time
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import typer
from typer.core import TyperGroup

from reconix import __version__
from reconix.utils.ui import banner, info, warn, err
from reconix.utils.fs import ensure_dir, safe_target_name

from reconix.modules.subdomains import run_subfinder
from reconix.modules.assetfinder import run_assetfinder
from reconix.modules.sublist3r import run_sublist3r
from reconix.modules.dns import run_dnsx
from reconix.modules.http import run_httpx
from reconix.modules.katana import run_katana
from reconix.modules.nmap import run_nmap
from reconix.modules.dirsearch import run_dirsearch

from reconix.core.verify import run as verify_run
from reconix.core.config import load_config, save_config


# =================================================
# HELP FORMATTER (FIXES Usage line)
# =================================================
class NiceUsageGroup(TyperGroup):
    def format_usage(self, ctx, formatter):
        formatter.write_usage(
            ctx.command_path,
            "[COMMAND]",
            prefix="Usage: ",
        )


# =================================================
# APP SETUP
# =================================================
app = typer.Typer(add_completion=False, no_args_is_help=True)

config_app = typer.Typer(help="Manage ReconiX configuration")
app.add_typer(config_app, name="config")

config_set_app = typer.Typer(
    help="Set ReconiX configuration values",
    cls=NiceUsageGroup,
)
config_app.add_typer(config_set_app, name="set")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# =================================================
# SCAN COMMAND
# =================================================
@app.command()
def scan(
    domain: str = typer.Option(..., "-d", "--domain", help="Target domain (authorized only)"),
    mode: str = typer.Option("quick", "-m", "--mode", help="Scan mode: quick | normal"),
    port_scan: bool = typer.Option(False, "--port-scan", help="Enable port scanning (nmap)"),
    nmap_fast: bool = typer.Option(False, "--nmap-fast", help="Use faster nmap timing (-T4)"),
    dir_search: bool = typer.Option(False, "--dir-search", help="Enable directory discovery (ffuf)"),
    out_dir: str = typer.Option("output", "--out-dir", help="Output directory"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Disable startup banner"),
):
    """Run ReconiX reconnaissance scan."""

    if not no_banner:
        banner(version=__version__)

    mode = mode.lower().strip()
    if mode not in {"quick", "normal"}:
        warn("Invalid mode. Falling back to QUICK.")
        mode = "quick"

    if nmap_fast and not port_scan:
        warn("--nmap-fast ignored (enable --port-scan first)")

    cfg = load_config()
    dir_cfg = cfg.get("dirsearch", {})
    nmap_cfg = cfg.get("nmap", {})

    ensure_dir(out_dir)
    out_file = f"{out_dir}/reconix_{safe_target_name(domain)}.ndjson"

    start_total = time.time()

    try:
        # -------------------------------------------------
        # SUBDOMAIN DISCOVERY
        # -------------------------------------------------
        info("Starting subdomain discovery")
        t0 = time.time()

        subdomains = set()
        if mode == "quick":
            subdomains.update(run_subfinder(domain))
        else:
            subdomains.update(run_assetfinder(domain))
            subdomains.update(run_subfinder(domain))
            subdomains.update(run_sublist3r(domain))

        info(f"Finished subdomain discovery ({len(subdomains)} found) [{int(time.time()-t0)}s]")

        # -------------------------------------------------
        # DNS VALIDATION
        # -------------------------------------------------
        info("Starting DNS validation (dnsx)")
        t0 = time.time()
        resolved = run_dnsx(list(subdomains))
        info(f"Finished dnsx ({len(resolved)} resolved) [{int(time.time()-t0)}s]")

        # -------------------------------------------------
        # HTTP PROBING
        # -------------------------------------------------
        info("Starting HTTP probing (httpx)")
        t0 = time.time()
        http_rows = run_httpx(resolved)
        live_urls = [r.get("url") for r in http_rows if r.get("url")]
        info(f"Finished httpx ({len(live_urls)} live) [{int(time.time()-t0)}s]")

        # -------------------------------------------------
        # URL DISCOVERY (KATANA)
        # -------------------------------------------------
        urls_by_url = {}
        if mode == "normal" and live_urls:
            info("Starting URL discovery (katana)")
            t0 = time.time()
            urls_by_url = run_katana(live_urls)
            total = sum(len(v) for v in urls_by_url.values())
            info(f"Finished katana ({total} URLs) [{int(time.time()-t0)}s]")

        # -------------------------------------------------
        # DIRECTORY DISCOVERY (FFUF)
        # -------------------------------------------------
        dirs_by_url = {}
        if mode == "normal" and dir_search and live_urls:
            info("Starting directory discovery (ffuf)")
            t0 = time.time()
            dirs_by_url = run_dirsearch(
                live_urls,
                wordlist=dir_cfg.get("wordlist"),
                threads=dir_cfg.get("threads", 20),
                extensions=dir_cfg.get("extensions", []),
                recursive=dir_cfg.get("recursive", False),
                recursion_depth=dir_cfg.get("recursion_depth", 2),
            )
            total = sum(len(v) for v in dirs_by_url.values())
            elapsed = round(time.time() - t0, 2)
            info(f"Finished directory discovery ({total} paths) [{elapsed}s]")


        # -------------------------------------------------
        # PORT SCANNING (NMAP)
        # -------------------------------------------------
        ports_by_host = {}
        if mode == "normal" and port_scan and live_urls:
            info("Starting port scan (nmap)")
            t0 = time.time()

            hosts = {urlparse(u).hostname for u in live_urls if urlparse(u).hostname}
            ports_by_host = run_nmap(
                list(hosts),
                top_ports=nmap_cfg.get("top_ports", 100),
                timing="T4" if nmap_fast else nmap_cfg.get("timing", "T3"),
            )

            total = sum(len(v) for v in ports_by_host.values())
            info(f"Finished nmap ({total} open ports) [{int(time.time()-t0)}s]")

        # -------------------------------------------------
        # WRITE NDJSON OUTPUT
        # -------------------------------------------------
        http_map = {r.get("host") or r.get("url"): r for r in http_rows}

        with open(out_file, "w", encoding="utf-8") as f:
            for host in resolved:
                r = http_map.get(host, {})
                url = r.get("url")
                hostname = urlparse(url).hostname if url else host

                record = {
                    "tool": "reconix",
                    "version": __version__,
                    "mode": mode,
                    "target": domain,
                    "subdomain": host,
                    "dns": {"resolved": True},
                    "http": {
                        "alive": bool(r),
                        "url": url,
                        "status": r.get("status_code"),
                        "title": r.get("title"),
                    },
                    "urls": urls_by_url.get(url, []),
                    "directories": dirs_by_url.get(url, []) if dir_search else [],
                    "ports": ports_by_host.get(hostname, []) if port_scan else [],
                    "timestamp": utc_now(),
                }

                f.write(json.dumps(record) + "\n")

        # -------------------------------------------------
        # SUMMARY
        # -------------------------------------------------
        info("Recon completed")

        typer.echo(f"\nReconiX v{__version__}  |  Mode: {mode.upper()}")
        typer.echo(f"Target                 : {domain}")
        typer.echo(f"Subdomains found        : {len(subdomains)}")
        typer.echo(f"DNS-resolved            : {len(resolved)}")
        typer.echo(f"Live HTTP hosts         : {len(live_urls)}")
        typer.echo(f"Directory discovery     : {'yes' if dir_search else 'no'}")
        typer.echo(f"Port scan enabled       : {'yes' if port_scan else 'no'}")
        typer.echo(f"Output written to       : {out_file}")
        typer.echo(f"Duration                : {int(time.time()-start_total)}s\n")

    except FileNotFoundError as e:
        err(str(e))
        warn("Run `reconix verify` to check dependencies.")
        raise typer.Exit(1)


# =================================================
# VERIFY COMMAND
# =================================================
@app.command()
def verify():
    """Verify required external dependencies."""
    raise typer.Exit(verify_run())


# =================================================
# CONFIG SHOW
# =================================================
@config_app.command("show")
def config_show():
    """Show current ReconiX configuration."""
    cfg = load_config()
    d = cfg.get("dirsearch", {})
    n = cfg.get("nmap", {})

    typer.echo("\nReconiX Configuration\n")

    # Directory discovery
    typer.echo("Directory Discovery (ffuf)")
    typer.echo("──────────────────────────")
    typer.echo(f"{'wordlist':<18} {d.get('wordlist')}")
    typer.echo(f"{'extensions':<18} {', '.join(d.get('extensions', []))}")
    typer.echo(f"{'threads':<18} {d.get('threads')}")
    typer.echo(f"{'recursive':<18} {str(d.get('recursive')).lower()}")
    typer.echo(f"{'recursion-depth':<18} {d.get('recursion_depth')}\n")

    # Nmap
    typer.echo("Port Scanning (nmap)")
    typer.echo("───────────────────")
    typer.echo(f"{'top-ports':<18} {n.get('top_ports')}")
    typer.echo(f"{'timing':<18} {n.get('timing')}\n")



# =================================================
# CONFIG SET SUBCOMMANDS
# =================================================
@config_set_app.command("wordlist")
def set_wordlist(path: str = typer.Argument(..., help="Path to directory wordlist")):
    cfg = load_config()
    cfg.setdefault("dirsearch", {})["wordlist"] = path
    save_config(cfg)
    typer.echo("Wordlist updated successfully.")


@config_set_app.command("extensions")
def set_extensions(ext: str = typer.Argument(..., help="Comma-separated extensions")):
    cfg = load_config()
    cfg.setdefault("dirsearch", {})["extensions"] = [e.strip() for e in ext.split(",") if e.strip()]
    save_config(cfg)
    typer.echo("Extensions updated successfully.")


@config_set_app.command("threads")
def set_threads(threads: int = typer.Argument(..., help="Number of ffuf threads")):
    if not 1 <= threads <= 100:
        err("Threads must be between 1 and 100")
        raise typer.Exit(1)

    cfg = load_config()
    cfg.setdefault("dirsearch", {})["threads"] = threads
    save_config(cfg)
    typer.echo("Threads updated successfully.")


@config_set_app.command("recursive")
def set_recursive(enabled: bool = typer.Argument(..., help="Enable recursive directory discovery")):
    cfg = load_config()
    cfg.setdefault("dirsearch", {})["recursive"] = enabled
    save_config(cfg)
    typer.echo(f"Recursive directory discovery set to {enabled}.")


@config_set_app.command("recursion-depth")
def set_recursion_depth(depth: int = typer.Argument(..., help="Recursion depth (1–5)")):
    if not 1 <= depth <= 5:
        err("Recursion depth must be between 1 and 5")
        raise typer.Exit(1)

    cfg = load_config()
    cfg.setdefault("dirsearch", {})["recursion_depth"] = depth
    save_config(cfg)
    typer.echo("Recursion depth updated successfully.")

import shutil
import subprocess
import xml.etree.ElementTree as ET


def run_nmap(hosts: list[str], *, timing: str = "T3", top_ports: int = 100) -> dict[str, list[dict]]:
    """
    Safe NORMAL-mode nmap:
    -Pn + top ports, no scripts, no -sV
    timing: "T3" (default) or "T4"
    """
    if not shutil.which("nmap"):
        raise FileNotFoundError("Missing binary: nmap")

    if timing not in {"T3", "T4"}:
        timing = "T3"

    results: dict[str, list[dict]] = {}

    for host in hosts:
        cmd = [
            "nmap",
            "-Pn",
            f"-{timing}",
            "--top-ports", str(top_ports),
            "-oX", "-",
            host,
        ]

        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode != 0 or not p.stdout.strip():
            continue

        try:
            root = ET.fromstring(p.stdout)
        except ET.ParseError:
            continue

        ports = []
        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid")),
                    "service": service.get("name") if service is not None else None,
                })

        if ports:
            results[host] = ports

    return results

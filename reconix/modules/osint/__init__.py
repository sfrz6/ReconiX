from .rdap import run_rdap
from .dns_records import run_dns_osint

def run_osint(domain: str) -> dict:
    return {
        "rdap": run_rdap(domain),
        "dns": run_dns_osint(domain),
    }

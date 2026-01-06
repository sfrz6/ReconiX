import dns.resolver

def _q(name: str, rtype: str) -> list[str]:
    try:
        return [str(x).strip() for x in dns.resolver.resolve(name, rtype)]
    except Exception:
        return []

def run_dns_osint(domain: str) -> dict:
    txt = _q(domain, "TXT")
    dmarc = _q(f"_dmarc.{domain}", "TXT")

    return {
        "NS": _q(domain, "NS"),
        "MX": _q(domain, "MX"),
        "TXT": txt,
        "SPF": [x for x in txt if x.lower().startswith("v=spf1")],
        "DMARC": dmarc,
    }

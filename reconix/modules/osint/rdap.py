import requests

def run_rdap(domain: str, timeout: int = 12) -> dict:
    url = f"https://rdap.org/domain/{domain}"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconiX"})
        r.raise_for_status()
        j = r.json()

        # keep it minimal/clean
        events = j.get("events", []) or []
        status = j.get("status", []) or []

        return {
            "domain": j.get("ldhName") or domain,
            "status": status,
            "events": events,  # created/updated/expiration often here
        }
    except Exception:
        return {}

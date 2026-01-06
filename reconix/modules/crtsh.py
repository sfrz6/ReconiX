import json
import requests

def fetch_subdomains(domain: str, timeout: int = 15) -> set[str]:
    # crt.sh JSON endpoint
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconiX"})
    r.raise_for_status()

    out = set()
    try:
        data = r.json()
    except Exception:
        data = json.loads(r.text)

    for row in data:
        name = row.get("name_value", "")
        for line in name.splitlines():
            s = line.strip().lower()
            if not s or "*" in s:
                continue
            if s.endswith("." + domain) or s == domain:
                out.add(s)
    return out

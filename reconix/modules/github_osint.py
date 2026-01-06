# reconix/modules/github_osint.py
import re
import time
from typing import List, Set, Optional

import requests

API = "https://api.github.com/search/code"
UA = "ReconiX"


def _extract_hosts(text: str, domain: str) -> Set[str]:
    domain = domain.strip().lower().rstrip(".")
    if not text:
        return set()

    # match sub.example.com
    rgx = re.compile(rf"(?i)\b([a-z0-9][a-z0-9\-\._]*\.{re.escape(domain)})\b")
    out: Set[str] = set()

    for m in rgx.findall(text):
        h = m.lower().strip().rstrip(".")
        if not h or "*" in h:
            continue
        if h == domain or h.endswith("." + domain):
            out.add(h)

    return out


def run_github_subdomains(
    domain: str,
    token: Optional[str],
    pages: int = 2,
    per_page: int = 50,
    timeout: int = 15,
) -> List[str]:
    """
    Passive OSINT: searches public GitHub code for references to the domain,
    extracts subdomains from snippets (text_matches) or metadata.
    Fail-soft: returns [] on errors/rate limits.
    """
    headers = {
        "User-Agent": UA,
        # text-match gives snippet fragments when available
        "Accept": "application/vnd.github.text-match+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    found: Set[str] = set()
    q = f'"{domain}"'

    for page in range(1, pages + 1):
        try:
            r = requests.get(
                API,
                headers=headers,
                params={"q": q, "per_page": per_page, "page": page},
                timeout=timeout,
            )

            # rate limit / forbidden -> stop and return what we have
            if r.status_code in (401, 403):
                return sorted(found)

            r.raise_for_status()
            data = r.json()
            items = data.get("items", []) or []

            for it in items:
                # Best case: snippets exist
                text_parts: List[str] = []

                for tm in (it.get("text_matches") or []):
                    frag = tm.get("fragment")
                    if frag:
                        text_parts.append(str(frag))

                # Fallback: metadata
                text_parts += [
                    str(it.get("name", "")),
                    str(it.get("path", "")),
                    str(it.get("html_url", "")),
                    str((it.get("repository") or {}).get("full_name", "")),
                ]

                found |= _extract_hosts(" ".join(text_parts), domain)

            time.sleep(0.2)

        except Exception:
            continue

    return sorted(found)

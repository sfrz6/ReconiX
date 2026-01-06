# ReconiX

Modular recon orchestrator for **authorized** security testing.  
Runs QUICK (passive) and NORMAL (active) recon pipelines and outputs **NDJSON** for easy parsing + automation.

>  **Disclaimer:** Use only on targets you own or have explicit permission to test.

---

## Features

### QUICK (passive)
- Subdomain discovery: **subfinder + crt.sh**
- DNS validation: **dnsx**
- Optional OSINT-lite: **RDAP + DNS records**
- Optional Wayback URLs: **top-K** (default) or **all**
- Outputs: `reconix.ndjson` + `quick_snapshot.json`

### NORMAL (active)
- Multi-source subdomain discovery: **assetfinder + subfinder + sublist3r**
- DNS validation: **dnsx**
- HTTP probing + tech detection: **httpx**
- URL discovery (crawler): **katana**
- WAF detection: **wafw00f** *(fail-soft if missing)*
- Optional directory discovery: **ffuf**
- Optional port scanning: **naabu / nmap**
- Optional **CVE candidates**: **searchsploit** *(local Exploit-DB index)*
- Host-focused scanning: **`--focus`** and **`--file`**
- Outputs: `reconix.ndjson` + `normal_snapshot.json` *(+ optional `reconix.txt`)*

---

## Installation (Kali/Debian)

### 1) System packages
```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip golang-go jq
sudo apt install -y sublist3r nmap ffuf

# optional (CVE candidates uses searchsploit):
sudo apt install -y exploitdb

# optional (WAF):
sudo apt install -y wafw00f
```

### 2) Go tools (ProjectDiscovery + others)

#### Add Go bin to PATH (bash/zsh)
Check your shell:
```bash
echo $SHELL
```

If you use **bash**:
```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

If you use **zsh**:
```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
source ~/.zshrc
```

#### Install tools
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

Verify tools are visible:
```bash
which subfinder dnsx httpx katana assetfinder naabu
```

---

## Install ReconiX
```bash
git clone https://github.com/sfrz6/ReconiX.git
cd ReconiX

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

---

## Quick start

### Verify environment
```bash
reconix verify
```

### QUICK scan (passive)
```bash
reconix scan -d example.com
```

### NORMAL scan (active)
```bash
reconix scan -d example.com -m normal
```

### NORMAL + dir discovery (ffuf)
```bash
reconix scan -d example.com -m normal --dir-search
```

### NORMAL + port scan (naabu/nmap)
```bash
reconix scan -d example.com -m normal --port-scan
```

### Host-focused scan (skip subdomain discovery)
Only scan the exact input domain:
```bash
reconix scan -d example.com -m normal --focus
```

Scan a custom target list (one per line):
```bash
reconix scan --file targets.txt -m normal
```

---

## Output

All outputs are written under:
```
output/<target>/
```

### NDJSON (always)
- `reconix.ndjson` — line-delimited JSON records

### Snapshots
- QUICK: `quick_snapshot.json`
- NORMAL: `normal_snapshot.json`

### Optional TXT report
- `reconix.txt` when using `--txt`

### Optional subdomains export
- `reconix_subdomains_<target>.txt` when using `--export-subdomains`

### Optional Markdown report
- `reconix_report.md` when using `--report`

---

## Config

Show current config:
```bash
reconix config show
```

Set a value:
```bash
reconix config set <key> <value>
```

Unset a value:
```bash
reconix config unset <key>
```

Examples:
```bash
# OSINT token
reconix config set githubkey "TOKEN"
reconix config unset githubkey

# QUICK tuning
reconix config set wayback_top 100
reconix config set osint_lite false

# NORMAL tuning (dotted keys)
reconix config set httpx.enabled true
reconix config set katana.depth 1
reconix config set wafw00f.timeout 3

# ffuf extensions (CSV or JSON list)
reconix config set ffuf.extensions php,html,js
reconix config set ffuf.extensions '["php","html","js"]'

# subfinder provider keys (stored under subfinder.providers.<provider>)
reconix config set virustotal "<VT_KEY>"
reconix config unset virustotal
```

---

## CVE candidates (NORMAL)

ReconiX can generate **CVE candidates** based on detected tech/service strings by querying **searchsploit** (local Exploit-DB index).  
This is **inferred** information and **not a validated finding**.

Requirements:
- `searchsploit` installed (`sudo apt install exploitdb`)
- Exploit-DB index available locally (handled by the package on Kali)

Enable in config:
```bash
reconix config set cve.enabled true
```

Optional tuning:
```bash
reconix config set cve.require_version false
reconix config set cve.max_queries 25
reconix config set cve.timeout 10
reconix config set cve.max_results_per_query 10
```

---

## Notes

- QUICK is designed to be **100% passive**.
- NORMAL includes active probing/crawling; use responsibly.
- Some tool builds differ by distro; ReconiX is written to be tolerant where possible.



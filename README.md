# ReconiX
Modular recon orchestrator for authorized security testing.

## Features
QUICK: subdomains → DNS → HTTP

NORMAL: multi-source subdomains + katana + optional ffuf + optional nmap

NDJSON output

reconix verify dependency check

reconix config for tuning

## Install
sudo apt install pipx

pipx ensurepath

pipx install git+https://github.com/sfrz6/ReconiX.git

## Usage
reconix verify

reconix scan -d example.com

reconix scan -d example.com -m normal

reconix scan -d example.com -m normal --dir-search

reconix scan -d example.com -m normal --port-scan

## Config
reconix config show

reconix config set wordlist /path/to/wordlist.txt

reconix config set extensions php,html,js

reconix config set threads 30

reconix config set recursive true

reconix config set recursion-depth 2

## Output
Writes NDJSON to output/reconix_<Target>.ndjson

## Disclaimer
ReconiX is for authorized testing only. Do not scan targets without permission.

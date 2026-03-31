# Portable Subdomain Console Scanner

A **single-file**, **portable** subdomain discovery tool with:

- **CLI** and **web console (browser UI)** modes
- **No mandatory API keys**
- **Passive data sources** + optional **open‑source tools** (if installed)
- **Enriched output** (DNS, HTTP status, basic service classification, WHOIS snippet, lightweight reputation)
- Results saved as **TXT** in the current working directory

Tested on **Linux** and **macOS** with Python 3.8+.

---

## Features

- **Input**: one or multiple root domains (e.g. `example.com`, `example.org`)
- **Discovery sources (no keys required)**:
  - `crt.sh` (Certificate Transparency logs)
  - Rapid7 Sonar via `dns.bufferover.run`
  - HackerTarget `hostsearch` API
  - AnubisDB (`jldc.me`)
- **Optional external tools** (auto-detected, skipped if not installed):
  - `amass`
  - `subfinder`
  - `sublist3r`
  - `theHarvester`
  - `assetfinder`
  - `findomain`
  - `knockpy`
  - `dnsrecon`
  - `oneforall`
  - `puredns`
  - `gobuster`
  - `SubDomainizer`
- **Enrichment per subdomain**:
  - DNS:
    - `A` records (IPv4/IPv6)
    - `CNAME` (via `dig` if available)
  - HTTP:
    - Status code for `http://sub.domain`
    - Service note (e.g. `alive (200)`, `likely unclaimed / placeholder (200)`, `redirect (301)`, `client error (404)`, etc.)
  - WHOIS:
    - First ~10 lines of `whois -H sub.domain` (if `whois` installed); otherwise a note
  - Reputation (very lightweight, no external services):
    - Marks “only private / internal IPs” when all resolved IPs are RFC1918/loopback
- **Output**:
  - Plain-text file: `Git_scanner_results_YYYYMMDD_HHMMSS.txt`
  - Stored in the **current working directory** (where you run the script)

---

## Requirements

### Mandatory

- **Python**: 3.8 or newer
- **Network**: outbound HTTPS access to:
  - `https://crt.sh`
  - `https://dns.bufferover.run`
  - `https://api.hackertarget.com`
  - `https://jldc.me`

### Optional (for richer results)

If present, these are automatically used; if not, they’re **skipped gracefully**:

- **DNS / WHOIS**:
  - `dig` (for CNAME lookups)
  - `whois` (for WHOIS snippet)
- **Subdomain tools**:
  - `amass`, `subfinder`, `sublist3r`, `theHarvester`, `assetfinder`, `findomain`,
    `knockpy`, `dnsrecon`, `oneforall`, `puredns`, `gobuster`, `SubDomainizer`

> The script never fails just because a tool is missing; it just marks its status as `skip` in the report.

---

## Installation

No package install needed. Clone this repo (or copy the script file) and you’re done.

```bash
git clone https://github.com/youruser/yourrepo.git
cd yourrepo

# Make script executable (optional on Linux/macOS)
chmod +x portable_subdomain_console_scanner.py

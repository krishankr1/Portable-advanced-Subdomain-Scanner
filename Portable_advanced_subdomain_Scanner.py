#!/usr/bin/env python3
"""
Portable Subdomain Scanner (CLI + Web Console)

Runs on Linux/macOS with Python 3.8+.
No mandatory API keys. Uses:
  - Public passive sources (crt.sh, Rapid7 bufferover, HackerTarget, AnubisDB)
  - Optional local OSS tools (if installed): amass, subfinder, sublist3r,
    theHarvester, assetfinder, findomain, knockpy, dnsrecon, oneforall,
    puredns, gobuster, SubDomainizer

Output is always stored as TXT in the current working directory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

USER_AGENT = "PortableSubdomainScanner/1.0"
DEFAULT_TIMEOUT = 120


def now_utc() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def is_domain(s: str) -> bool:
    s = s.strip().lower().rstrip(".")
    if len(s) < 3 or "." not in s:
        return False
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", s))


def normalize_domain(s: str) -> str:
    return s.strip().lower().rstrip(".")


def split_domains(raw: str) -> list[str]:
    parts = re.split(r"[\s,;]+", raw.strip())
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        if not p:
            continue
        d = normalize_domain(p)
        if is_domain(d) and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def extract_subdomains(lines: str, domain: str) -> set[str]:
    out: set[str] = set()
    domain = domain.lower()
    for raw in lines.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = line.split(",")[0].strip()
        line = line.split()[0].strip()
        line = line.strip("*.").strip(".")
        if line.endswith("." + domain) or line == domain:
            if is_domain(line):
                out.add(line)
    return out


def http_get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


@dataclass
class SourceResult:
    source: str
    found: set[str] = field(default_factory=set)
    status: str = "ok"
    note: str = ""


@dataclass
class HostInfo:
    hostname: str
    a_records: list[str] = field(default_factory=list)
    cname: str | None = None
    http_status: int | None = None
    service_note: str = ""
    whois_note: str = ""
    reputation: str = ""


def source_crtsh(domain: str) -> SourceResult:
    sr = SourceResult(source="crt.sh")
    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        raw = http_get(url, timeout=35)
        data = json.loads(raw) if raw.strip() else []
        for row in data:
            name_val = str(row.get("name_value", "")).lower()
            for name in name_val.splitlines():
                n = name.strip("*. ").strip(".")
                if n.endswith("." + domain) or n == domain:
                    if is_domain(n):
                        sr.found.add(n)
    except Exception as e:
        sr.status = "error"
        sr.note = str(e)
    return sr


def source_rapid7_bufferover(domain: str) -> SourceResult:
    sr = SourceResult(source="Rapid7/Sonar (bufferover)")
    try:
        url = f"https://dns.bufferover.run/dns?q=.{urllib.parse.quote(domain)}"
        raw = http_get(url, timeout=30)
        data = json.loads(raw)
        for key in ("FDNS_A", "RDNS"):
            for item in data.get(key, []) or []:
                line = str(item)
                host = line.split(",", 1)[-1].strip().lower().strip("*.").strip(".")
                if host.endswith("." + domain) or host == domain:
                    if is_domain(host):
                        sr.found.add(host)
    except Exception as e:
        sr.status = "error"
        sr.note = str(e)
    return sr


def source_hackertarget(domain: str) -> SourceResult:
    sr = SourceResult(source="HackerTarget hostsearch")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        raw = http_get(url, timeout=30)
        if "error" in raw.lower():
            sr.status = "warn"
            sr.note = raw.strip()[:200]
            return sr
        for line in raw.splitlines():
            host = line.split(",", 1)[0].strip().lower().strip(".")
            if host.endswith("." + domain) or host == domain:
                if is_domain(host):
                    sr.found.add(host)
    except Exception as e:
        sr.status = "error"
        sr.note = str(e)
    return sr


def source_anubisdb(domain: str) -> SourceResult:
    sr = SourceResult(source="AnubisDB")
    try:
        url = f"https://jldc.me/anubis/subdomains/{urllib.parse.quote(domain)}"
        raw = http_get(url, timeout=30)
        data = json.loads(raw)
        if isinstance(data, list):
            for entry in data:
                host = str(entry).strip().lower().strip("*.").strip(".")
                if host.endswith("." + domain) or host == domain:
                    if is_domain(host):
                        sr.found.add(host)
    except Exception as e:
        sr.status = "error"
        sr.note = str(e)
    return sr


TOOL_COMMANDS: dict[str, Callable[[str, int], list[str]]] = {
    "amass": lambda d, t: ["amass", "enum", "-passive", "-d", d, "-timeout", str(max(1, t // 60))],
    "subfinder": lambda d, t: ["subfinder", "-silent", "-d", d, "-timeout", str(max(1, t // 60))],
    "sublist3r": lambda d, t: ["sublist3r", "-d", d, "-n"],
    "theHarvester": lambda d, t: ["theHarvester", "-d", d, "-b", "all", "-f", "/tmp/theharvester_out"],
    "assetfinder": lambda d, t: ["assetfinder", "--subs-only", d],
    "findomain": lambda d, t: ["findomain", "-t", d, "-q"],
    "knockpy": lambda d, t: ["knockpy", d],
    "dnsrecon": lambda d, t: ["dnsrecon", "-d", d, "-t", "std"],
    "oneforall": lambda d, t: ["oneforall", "--target", d, "--fmt", "txt"],
    "puredns": lambda d, t: ["puredns", "bruteforce", "/dev/null", d],
    "gobuster": lambda d, t: ["gobuster", "dns", "-d", d, "-w", "subdomains.txt", "-q"],
    "SubDomainizer": lambda d, t: ["SubDomainizer", "-u", f"https://{d}"],
}


PASSIVE_SOURCE_FUNCS = [
    source_crtsh,
    source_rapid7_bufferover,
    source_hackertarget,
    source_anubisdb,
]


@dataclass
class ScanReport:
    started_at: str
    domains: list[str]
    mode: str
    timeout: int
    source_results: list[SourceResult]
    tool_results: list[SourceResult]
    merged: dict[str, set[str]]
    host_info: dict[str, HostInfo]
    output_file: str


def run_tool(tool_name: str, domain: str, timeout: int) -> SourceResult:
    sr = SourceResult(source=f"tool:{tool_name}")
    if tool_name not in TOOL_COMMANDS:
        sr.status = "skip"
        sr.note = "not configured"
        return sr
    exe = TOOL_COMMANDS[tool_name](domain, timeout)[0]
    if shutil.which(exe) is None:
        sr.status = "skip"
        sr.note = "not installed"
        return sr
    cmd = TOOL_COMMANDS[tool_name](domain, timeout)
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        sr.found = extract_subdomains(text, domain)
        if proc.returncode != 0 and not sr.found:
            sr.status = "warn"
            sr.note = f"exit={proc.returncode}"
    except subprocess.TimeoutExpired:
        sr.status = "error"
        sr.note = "timeout"
    except Exception as e:
        sr.status = "error"
        sr.note = str(e)
    return sr


def get_local_hostname_domains() -> set[str]:
    out: set[str] = set()
    try:
        fqdn = socket.getfqdn().lower().strip(".")
        if is_domain(fqdn):
            out.add(fqdn)
    except Exception:
        pass
    return out


def _have_cmd(name: str) -> bool:
    return shutil.which(name) is not None


def dns_enrich(host: str) -> tuple[list[str], str | None]:
    ips: set[str] = set()
    cname: str | None = None
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(host, None, family=fam)
            except socket.gaierror:
                continue
            for _family, _type, _proto, _canonname, sockaddr in infos:
                ip = sockaddr[0]
                ips.add(ip)
    except Exception:
        pass

    if _have_cmd("dig"):
        try:
            proc = subprocess.run(
                ["dig", "+short", "CNAME", host],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=8,
                check=False,
            )
            first = (proc.stdout or "").splitlines()
            if first:
                cname = first[0].strip().rstrip(".")
        except Exception:
            pass
    return sorted(ips), cname


def _classify_http(status: int | None, body_sample: str) -> str:
    if status is None:
        return "no HTTP response"
    low = body_sample.lower()
    if status in (301, 302, 303, 307, 308):
        return f"redirect ({status})"
    if status == 200:
        if any(
            phrase in low
            for phrase in (
                "there is no app configured",
                "there is no site here",
                "project not found",
                "no such app",
                "unknown domain",
                "no such site",
                "page not found",
                "repository not found",
            )
        ):
            return "likely unclaimed / placeholder (200)"
        return "alive (200)"
    if 400 <= status < 500:
        return f"client error ({status})"
    if status >= 500:
        return f"server error ({status})"
    return f"http status {status}"


def http_enrich(host: str, timeout: int) -> tuple[int | None, str]:
    url = f"http://{host}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=min(timeout, 15)) as resp:
            status = getattr(resp, "status", None) or 0
            body = resp.read(4096).decode("utf-8", errors="replace")
            note = _classify_http(status, body)
            return status, note
    except Exception as e:
        return None, f"http error: {str(e).splitlines()[0][:120]}"


def whois_enrich(host: str, timeout: int) -> str:
    if not _have_cmd("whois"):
        return "whois: tool not installed"
    try:
        proc = subprocess.run(
            ["whois", "-H", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=min(timeout, 25),
            check=False,
        )
        txt = (proc.stdout or "").strip().splitlines()
        head = "\n".join(txt[:10])
        return head[:400] or "whois: empty response"
    except Exception as e:
        return f"whois error: {str(e).splitlines()[0][:120]}"


def reputation_from_ips(ips: list[str]) -> str:
    if not ips:
        return "no IPs resolved"
    private = [
        ip
        for ip in ips
        if ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("127.")
    ]
    if private and len(private) == len(ips):
        return "only private / internal IPs"
    return "no automatic reputation (not checked)"


def enrich_hosts(
    merged: dict[str, set[str]],
    timeout: int,
    max_hosts: int = 500,
) -> dict[str, HostInfo]:
    host_info: dict[str, HostInfo] = {}
    all_hosts: list[str] = []
    for subs in merged.values():
        for h in subs:
            if h not in all_hosts:
                all_hosts.append(h)
    all_hosts = all_hosts[:max_hosts]
    for h in all_hosts:
        ips, cname = dns_enrich(h)
        status, http_note = http_enrich(h, timeout)
        whois_note = whois_enrich(h, timeout)
        rep = reputation_from_ips(ips)
        host_info[h] = HostInfo(
            hostname=h,
            a_records=ips,
            cname=cname,
            http_status=status,
            service_note=http_note,
            whois_note=whois_note,
            reputation=rep,
        )
    return host_info


def run_scan(domains: list[str], mode: str, timeout: int) -> ScanReport:
    started = now_utc()
    merged: dict[str, set[str]] = {d: set() for d in domains}
    source_results: list[SourceResult] = []
    tool_results: list[SourceResult] = []

    for d in domains:
        for func in PASSIVE_SOURCE_FUNCS:
            sr = func(d)
            source_results.append(sr)
            merged[d].update(sr.found)

    if mode in ("tools", "all"):
        for d in domains:
            for tool in TOOL_COMMANDS:
                sr = run_tool(tool, d, timeout)
                tool_results.append(sr)
                merged[d].update(sr.found)

    for d in domains:
        for h in get_local_hostname_domains():
            if h.endswith("." + d) or h == d:
                merged[d].add(h)

    host_info = enrich_hosts(merged, timeout=timeout)
    output_file = write_report(
        started,
        domains,
        mode,
        timeout,
        source_results,
        tool_results,
        merged,
        host_info,
    )
    return ScanReport(
        started_at=started,
        domains=domains,
        mode=mode,
        timeout=timeout,
        source_results=source_results,
        tool_results=tool_results,
        merged=merged,
        host_info=host_info,
        output_file=output_file,
    )


def write_report(
    started: str,
    domains: list[str],
    mode: str,
    timeout: int,
    source_results: list[SourceResult],
    tool_results: list[SourceResult],
    merged: dict[str, set[str]],
    host_info: dict[str, HostInfo],
) -> str:
    ts = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = Path.cwd() / f"Git_scanner_results_{ts}.txt"
    lines: list[str] = []
    lines.append("Portable Subdomain Scanner Results")
    lines.append("=" * 80)
    lines.append(f"Started (UTC): {started}")
    lines.append(f"Mode: {mode}")
    lines.append(f"Timeout per tool: {timeout}s")
    lines.append(f"Domains: {', '.join(domains)}")
    lines.append("")
    lines.append("Sources / Tools")
    lines.append("-" * 80)
    for sr in source_results + tool_results:
        lines.append(f"{sr.source:30} status={sr.status:6} found={len(sr.found):5} note={sr.note}")
    lines.append("")
    lines.append("Discovered Subdomains (enriched)")
    lines.append("-" * 80)
    for d in domains:
        subs = sorted(s for s in merged[d] if s != d)
        lines.append(f"[{d}] total={len(subs)}")
        for s in subs:
            hi = host_info.get(s)
            if hi is None:
                lines.append(f"{s}")
                continue
            a_str = ", ".join(hi.a_records) if hi.a_records else "-"
            cname_str = hi.cname or "-"
            http_str = str(hi.http_status) if hi.http_status is not None else "-"
            status_str = hi.service_note or "-"
            rep_str = hi.reputation or "-"
            lines.append(f"{s}")
            lines.append(f"    A={a_str}")
            lines.append(f"    CNAME={cname_str}  HTTP={http_str}  service={status_str}")
            lines.append(f"    reputation={rep_str}")
            if hi.whois_note:
                whois_lines = hi.whois_note.splitlines()
                lines.append("    whois:")
                for wl in whois_lines:
                    lines.append(f"      {wl}")
            lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return str(out_path)


def format_summary_html(rep: ScanReport) -> str:
    rows = []
    for d in rep.domains:
        rows.append(f"<h3>{html.escape(d)} ({len(rep.merged[d])} found)</h3>")
        rows.append("<pre>")
        for s in sorted(rep.merged[d]):
            rows.append(html.escape(s))
        rows.append("</pre>")
    return f"""
    <h2>Scan Finished</h2>
    <p><b>Output file:</b> {html.escape(rep.output_file)}</p>
    <p><b>Mode:</b> {html.escape(rep.mode)} | <b>Started:</b> {html.escape(rep.started_at)}</p>
    {''.join(rows)}
    """


FORM_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Portable Subdomain Scanner</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; max-width: 1000px; }
    textarea { width: 100%; height: 140px; }
    input, select, button { padding: 8px; margin: 6px 0; }
    .box { background: #f6f8fa; padding: 12px; border-radius: 8px; }
  </style>
</head>
<body>
  <h1>Portable Subdomain Scanner</h1>
  <div class="box">
    <form method="POST" action="/scan">
      <label>Domains (comma/newline separated):</label><br/>
      <textarea name="domains" placeholder="example.com&#10;example.org"></textarea><br/>
      <label>Mode:</label>
      <select name="mode">
        <option value="passive">passive (public datasets only)</option>
        <option value="all">all (passive + installed tools)</option>
        <option value="tools">tools only</option>
      </select><br/>
      <label>Timeout per tool (seconds):</label><br/>
      <input name="timeout" value="120"/><br/>
      <button type="submit">Start Scan</button>
    </form>
  </div>
  <p>Results are saved in current directory as <code>Git_scanner_results_YYYYMMDD_HHMMSS.txt</code>.</p>
</body>
</html>
"""


class WebHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(FORM_HTML.encode("utf-8"))

    def do_POST(self) -> None:
        if self.path != "/scan":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = urllib.parse.parse_qs(raw)
        domains = split_domains(form.get("domains", [""])[0])
        mode = form.get("mode", ["passive"])[0]
        timeout = int(form.get("timeout", [str(DEFAULT_TIMEOUT)])[0] or DEFAULT_TIMEOUT)
        if not domains:
            body = "<h2>No valid domain provided</h2><a href='/'>Back</a>"
        else:
            rep = run_scan(domains, mode=mode, timeout=timeout)
            body = format_summary_html(rep) + "<p><a href='/'>Run another</a></p>"
        page = f"<!doctype html><html><body>{body}</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


def run_web(host: str, port: int) -> None:
    srv = ThreadingHTTPServer((host, port), WebHandler)
    print(f"[+] Web console live: http://{host}:{port}")
    print(f"[+] Output TXT files will be created in: {Path.cwd()}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Portable subdomain scanner (CLI + web console).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              python3 portable_subdomain_console_scanner.py --domains example.com
              python3 portable_subdomain_console_scanner.py --domains "example.com,example.org" --mode all
              python3 portable_subdomain_console_scanner.py --web --host 0.0.0.0 --port 8080
            """
        ),
    )
    p.add_argument("--domains", help="Comma/space/newline separated domains.")
    p.add_argument("--domain-file", help="Path to file containing domains.")
    p.add_argument("--mode", choices=["passive", "tools", "all"], default="passive")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout seconds per tool process.")
    p.add_argument("--web", action="store_true", help="Launch web console.")
    p.add_argument("--host", default="127.0.0.1", help="Web host (default: 127.0.0.1).")
    p.add_argument("--port", type=int, default=8080, help="Web port (default: 8080).")
    return p.parse_args()


def load_domains(args: argparse.Namespace) -> list[str]:
    all_raw = []
    if args.domains:
        all_raw.append(args.domains)
    if args.domain_file:
        p = Path(args.domain_file)
        if p.exists():
            all_raw.append(p.read_text(encoding="utf-8", errors="replace"))
    if not all_raw:
        return []
    return split_domains("\n".join(all_raw))


def main() -> int:
    args = parse_args()
    if args.web:
        run_web(args.host, args.port)
        return 0

    domains = load_domains(args)
    if not domains:
        print("No valid domains provided. Use --domains or --domain-file.")
        return 1
    rep = run_scan(domains, mode=args.mode, timeout=args.timeout)
    print(f"[+] Scan done. Output saved: {rep.output_file}")
    for d in domains:
        print(f"    {d}: {len(rep.merged[d])} found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


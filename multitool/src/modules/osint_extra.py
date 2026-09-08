"""TALOS — EXTRA OSINT MODULES (26-30).

26 reverse DNS lookup
27 Wayback Machine lookup
28 email header analyzer
29 DNS records dump (AXFR zone transfer check)
30 open port finder (fast SYN-style via requests)

Every network call carries a timeout; every module degrades to a clean
message when the network or an upstream service is unavailable.
"""
from __future__ import annotations

import ipaddress
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from src.core import progress
from src.core.context import Session
from src.core.table import print_table

_USER_AGENT = (
    "Mozilla/5.0 (compatible; TALOS/2.0; +https://example.invalid/talos)"
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


def _import_requests():
    try:
        import requests  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "the 'requests' library is not installed. Run: "
            f"{sys.executable} -m pip install requests"
        ) from exc
    return requests


# ---------------------------------------------------------------------------
# [26] Reverse DNS Lookup
# ---------------------------------------------------------------------------
def reverse_dns(session: Session) -> None:
    """Resolve an IP to hostname(s) via PTR and check forward confirmation.

    Uses dnspython with an explicit lifetime (the blocking system resolver
    can hang for many seconds on unresponsive DNS). On top of the plain PTR
    lookup it performs a *forward-confirmed* reverse DNS (FCrDNS) check:
    the returned hostname is resolved back to an address and compared with
    the input IP. A match means the mapping is trustworthy; a mismatch is
    exactly what spam filters and security tools flag.
    """
    print("  Resolves an IP address back to its hostname using PTR records.")
    print("  Also verifies forward confirmation (hostname -> IP consistency).")
    print()
    ip = _ask("IPv4/IPv6 address to reverse-lookup (e.g. 8.8.8.8)", session.target_ip or "")
    if not ip:
        print("[ERROR] No IP address given; aborting.")
        return
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[ERROR] '{ip}' is not a valid IP address.")
        return
    try:
        import dns.reversename  # noqa: PLC0415
        import dns.resolver  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "the 'dnspython' library is not installed. Run: "
            f"{sys.executable} -m pip install dnspython"
        ) from exc

    print(f"\n[INFO] Performing reverse DNS lookup for {ip} ...")
    ptr_name = dns.reversename.from_address(ip)
    ptrs: List[str] = []
    try:
        answer = dns.resolver.resolve(ptr_name, "PTR", lifetime=6)
        ptrs = [str(rdata.target).rstrip(".") for rdata in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            dns.resolver.LifetimeTimeout):
        pass
    except Exception as exc:
        print(f"[ERROR] Reverse DNS failed: {type(exc).__name__}")
        return

    if not ptrs:
        print(f"[INFO] No PTR record found for {ip} (this is normal for many IPs).")
        session.set_result("reverse_dns", {"ip": ip, "hostname": None, "aliases": []})
        return

    hostname = ptrs[0]
    aliases = ptrs[1:]
    rows: List[Tuple[str, str]] = [("ip", ip), ("hostname", hostname)]
    if aliases:
        rows.append(("other ptrs", ", ".join(aliases)))

    # Forward confirmation: does hostname resolve back to this IP?
    fcr = "no"
    if hostname:
        fwd_ips: set = set()
        for record_type in ("A", "AAAA"):
            try:
                answer = dns.resolver.resolve(hostname, record_type, lifetime=4)
                fwd_ips.update(str(r.address) for r in answer)
            except Exception:
                pass
        if ip in fwd_ips:
            fcr = "yes"
        rows.append(("forward-confirmed", fcr))
        if fcr != "yes":
            rows.append(("note", "PTR and A records disagree — treat as untrusted"))

    print()
    print_table(["field", "value"], rows)
    session.set_result("reverse_dns", {
        "ip": ip, "hostname": hostname, "aliases": aliases,
        "forward_confirmed": fcr == "yes",
    })
    print("\n[INFO] Reverse DNS data stored as 'reverse_dns' in session.")


# ---------------------------------------------------------------------------
# [27] Wayback Machine Lookup
# ---------------------------------------------------------------------------
def wayback_lookup(session: Session) -> None:
    """Check the Internet Archive Wayback Machine for archived snapshots of a URL.

    Queries the Wayback Machine CDX API to find historical snapshots of
    a webpage. Shows: capture timestamps, HTTP status codes, and MIME types.
    Useful for:
    - Finding deleted or changed content
    - Investigating website history
    - Recovering old versions of pages
    """
    requests = _import_requests()
    print("  Queries the Internet Archive Wayback Machine for archived snapshots.")
    print("  Shows: when the page was captured, HTTP status, and content type.")
    print("  Useful for finding deleted content or investigating site history.")
    print()
    url = _ask("URL or domain to look up (e.g. example.com or https://example.com/page)", session.target_domain or "")
    if not url:
        print("[ERROR] No URL given; aborting.")
        return
    if "://" not in url:
        url = f"https://{url}"

    # Use the CDX API for a compact listing. ``collapse=digest`` removes
    # near-duplicate captures of the same page (the archive often stores
    # hundreds of byte-identical copies), so the list shows real revisions.
    cdx_url = "https://web.archive.org/cdx/search/cdx"
    print(f"\n[INFO] Querying Wayback Machine for {url} ...")
    try:
        resp = requests.get(
            cdx_url,
            params={
                "url": url,
                "output": "json",
                "limit": 500,
                "collapse": "digest",
                "fl": "timestamp,statuscode,mimetype",
            },
            timeout=20,
            headers={"User-Agent": _USER_AGENT},
        )
        resp.raise_for_status()
        rows_raw = resp.json()
    except Exception as exc:
        print(f"[ERROR] Wayback Machine query failed: {type(exc).__name__}")
        return

    if not rows_raw or len(rows_raw) <= 1:
        print(f"[INFO] No archived snapshots found for {url}.")
        print("[INFO] The page may never have been archived, or the URL may be incorrect.")
        session.set_result("wayback", {"url": url, "snapshots": []})
        return

    # First row is headers, rest are data
    headers_row = rows_raw[0]
    data_rows = rows_raw[1:]

    rows: List[Tuple[str, str, str]] = []
    for row in data_rows:
        ts = row[0] if len(row) > 0 else ""
        status = row[1] if len(row) > 1 else ""
        mime = row[2] if len(row) > 2 else ""
        # Parse timestamp
        try:
            dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
            date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            date_str = ts
        rows.append((date_str, status, mime))

    print()
    print_table(["timestamp", "status", "mime type"], rows)
    total = len(data_rows)
    session.set_result("wayback", {"url": url, "snapshots": data_rows, "total": total})
    print(f"\n[INFO] {total} snapshot(s) found. Stored as 'wayback' in session.")
    print("[INFO] Tip: visit https://web.archive.org/web/*/{url} to browse all snapshots.")


# ---------------------------------------------------------------------------
# [28] Email Header Analyzer
# ---------------------------------------------------------------------------
def email_header_analyzer(session: Session) -> None:
    """Parse raw email headers and extract key routing/security information.

    Email headers contain a wealth of forensic information:
    - From/To/Subject/Date: basic message metadata
    - Received: full routing chain showing every server the email passed through
    - Authentication-Results: SPF, DKIM, DMARC verification status

    To get email headers: in Gmail click 'Show original', in Outlook go to
    File > Properties > Internet Headers, in Thunderbird press Ctrl+U.
    """
    print("  Analyzes raw email headers for routing and security info.")
    print("  Extracts: From, To, Subject, Date, Received chain, SPF/DKIM/DMARC.")
    print()
    print("  HOW TO GET EMAIL HEADERS:")
    print("    Gmail:       Open email > 3-dot menu > 'Show original' > Copy")
    print("    Outlook:     Open email > File > Properties > Internet Headers")
    print("    Thunderbird: Open email > press Ctrl+U")
    print("    Yahoo:       Open email > 3-dot menu > 'View raw message'")
    print()
    print("  Paste the headers below (finish with an empty line):")
    lines: List[str] = []
    try:
        while True:
            line = input("  > ")
            if not line and lines:
                break
            lines.append(line)
    except EOFError:
        pass

    if not lines:
        print("[ERROR] No headers provided; aborting.")
        return

    raw_headers = "\n".join(lines) + "\n\n"

    # A real RFC-5322 parser (stdlib email) instead of line scanning: it
    # unfolds wrapped header lines (long Received / DKIM-Signature fields
    # span several lines), which line-based parsing got wrong.
    from email import policy  # noqa: PLC0415
    from email.parser import Parser  # noqa: PLC0415

    try:
        message = Parser(policy=policy.default).parsestr(raw_headers)
    except Exception as exc:
        print(f"[ERROR] Could not parse the headers: {type(exc).__name__}")
        return
    items = list(message.items())
    if not items:
        print("[ERROR] No headers provided; aborting.")
        return

    # Extract key fields (unfolded by the parser).
    fields: Dict[str, str] = {}
    for key in ("From", "To", "Subject", "Date", "Message-ID",
                "Return-Path", "Reply-To"):
        value = message.get(key, "")
        if value:
            fields[key] = str(value).strip()

    # Full Received chain — email headers list the newest hop first, so
    # hop 0 is closest to the original sender's server.
    received_chain: List[str] = [
        str(value).replace("\n ", " ").replace("\n", " ")
        for name, value in items if name.lower() == "received"
    ]

    # Security analysis across every Authentication-Results field.
    auth_lines = [
        str(value) for name, value in items
        if name.lower() == "authentication-results"
    ]
    spf_result = dkim_result = dmarc_result = None
    for auth_line in auth_lines:
        if "spf=" in auth_line.lower():
            m = re.search(r"spf=(\S+)", auth_line, re.IGNORECASE)
            if m:
                spf_result = m.group(1)
        if "dkim=" in auth_line.lower():
            m = re.search(r"dkim=(\S+)", auth_line, re.IGNORECASE)
            if m:
                dkim_result = m.group(1)
        if "dmarc=" in auth_line.lower():
            m = re.search(r"dmarc=(\S+)", auth_line, re.IGNORECASE)
            if m:
                dmarc_result = m.group(1)

    rows: List[Tuple[str, str]] = []
    for key in ("From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To"):
        value = fields.get(key)
        if value:
            if len(value) > 80:
                value = value[:80] + "..."
            rows.append((key, value))

    rows.append(("", ""))
    rows.append(("SPF", spf_result or "not found in headers"))
    rows.append(("DKIM", dkim_result or "not found in headers"))
    rows.append(("DMARC", dmarc_result or "not found in headers"))
    rows.append(("received hops", str(len(received_chain))))

    print()
    print_table(["field", "value"], rows)

    # Security assessment
    print()
    if spf_result and "pass" in spf_result.lower():
        print("  [??] SPF: pass reported by an untrusted Authentication-Results header")
    elif spf_result:
        print(f"  [!!] SPF: {spf_result} — may indicate spoofing or misconfiguration")
    else:
        print("  [??] SPF: not found — domain may not have SPF configured")

    if dkim_result and "pass" in dkim_result.lower():
        print("  [??] DKIM: pass reported by an untrusted Authentication-Results header")
    elif dkim_result:
        print(f"  [!!] DKIM: {dkim_result} — signature may be forged or missing")
    else:
        print("  [??] DKIM: not found — domain may not have DKIM configured")

    if dmarc_result and "pass" in dmarc_result.lower():
        print("  [??] DMARC: pass reported by an untrusted Authentication-Results header")
    elif dmarc_result:
        print(f"  [!!] DMARC: {dmarc_result} — domain policy may not be enforced")
    else:
        print("  [??] DMARC: not found — domain may not have DMARC configured")

    if received_chain:
        print(f"\n  [Routing Chain] ({len(received_chain)} hop(s)):")
        for i, hop in enumerate(received_chain, 1):
            short = hop[:100] + "..." if len(hop) > 100 else hop
            print(f"    {i}. {short}")

    session.set_result("email_headers", {
        "fields": {k: v for k, v in fields.items() if v},
        "spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result,
        "authentication_results_unverified": bool(auth_lines),
        "received_count": len(received_chain),
    })
    print("\n[INFO] Email header analysis stored as 'email_headers' in session.")


# ---------------------------------------------------------------------------
# [29] DNS Records Dump (Zone Transfer Check)
# ---------------------------------------------------------------------------
def dns_zone_transfer(session: Session) -> None:
    """Query NS records and attempt an AXFR zone transfer (tests for misconfiguration).

    A DNS zone transfer (AXFR) is a legitimate DNS replication mechanism
    between nameservers. However, if a nameserver allows zone transfers to
    ANY client, it leaks the entire DNS zone (all hostnames, IPs, etc.).

    This module:
    1. Resolves the domain's NS (nameserver) records
    2. Attempts an AXFR zone transfer against each nameserver
    3. Reports whether the transfer succeeded (VULNERABLE) or was refused (safe)
    """
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        import dns.rdatatype
    except ImportError as exc:
        raise RuntimeError(
            "the 'dnspython' library is not installed. Run: "
            f"{sys.executable} -m pip install dnspython"
        ) from exc

    print("  Tests if a domain's nameservers allow DNS zone transfers (AXFR).")
    print("  A successful zone transfer leaks ALL DNS records for the domain.")
    print("  This is a common security misconfiguration on poorly managed DNS.")
    print()
    print("  Steps: 1) Find NS records  2) Try AXFR against each NS  3) Report results")
    print()
    domain = _ask("Domain to test (e.g. example.com)", session.target_domain or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"^www\.", "", domain)
    if not domain or "." not in domain:
        print("[ERROR] A valid domain is required (e.g. example.com).")
        return
    session.target_domain = domain

    # First, resolve NS records
    print(f"\n[INFO] Resolving NS records for {domain} ...")
    ns_servers: List[str] = []
    try:
        answer = dns.resolver.resolve(domain, "NS", lifetime=10)
        for rdata in answer:
            ns_servers.append(str(rdata.target).rstrip("."))
    except Exception as exc:
        print(f"[ERROR] NS resolution failed: {type(exc).__name__}")
        return

    if not ns_servers:
        print("[INFO] No NS records found.")
        return

    print(f"[INFO] Found {len(ns_servers)} nameserver(s): {', '.join(ns_servers)}")
    bar = progress.LiveBar(total=len(ns_servers), label=f"AXFR against {domain}")
    bar.log("attempting zone transfer against each nameserver", level="info")

    # Try zone transfer against each NS
    transfer_error = getattr(dns, "xfr", None)
    transfer_error = getattr(transfer_error, "TransferError", None) or dns.exception.FormError
    rows: List[Tuple[str, str, str]] = []
    for ns in ns_servers:
        try:
            # Consume the whole transfer: a refused AXFR makes dnspython
            # raise TransferError, so reaching the end of the generator is
            # proof that zone data really was transferred.
            messages = list(dns.query.xfr(ns, domain, lifetime=10))
            if messages:
                rows.append((ns, "VULNERABLE", f"{len(messages)} transfer message(s) received"))
            else:
                rows.append((ns, "refused", "empty response"))
        except transfer_error:
            rows.append((ns, "refused", "AXFR rejected (normal/secure)"))
        except dns.exception.FormError:
            rows.append((ns, "refused", "AXFR rejected (normal/secure)"))
        except dns.exception.Timeout:
            rows.append((ns, "timeout", "connection timed out"))
        except Exception as exc:
            rows.append((ns, "error", str(type(exc).__name__)))
        bar.advance(ns)
    bar.finish("zone transfer checks finished")
    print()
    print_table(["nameserver", "status", "detail"], rows)

    vulnerable = [ns for ns, status, _ in rows if status == "VULNERABLE"]
    if vulnerable:
        print(f"\n[CRITICAL] Zone transfer SUCCEEDED on: {', '.join(vulnerable)}")
        print("[CRITICAL] This is a serious security misconfiguration!")
        print("[CRITICAL] An attacker can enumerate all subdomains and hosts.")
        print("[CRITICAL] Fix: restrict AXFR to authorized secondary nameservers only.")
    else:
        print("\n[INFO] No zone transfers succeeded — all nameservers refused or errored.")
        print("[INFO] This is the expected secure configuration.")

    session.set_result("zone_transfer", {"domain": domain, "nameservers": rows})


# ---------------------------------------------------------------------------
# [30] Open Port Finder (quick check via HTTP/HTTPS)
# ---------------------------------------------------------------------------
def open_port_finder(session: Session) -> None:
    """Quick-check a list of common ports by attempting TCP connections.

    Faster than a full nmap scan — uses direct TCP connect() with a short
    timeout. Checks 30 common ports by default. Reports open ports with
    their well-known service names. Useful for quick reconnaissance before
    running a more detailed scan.
    """
    import socket

    print("  Fast TCP connect scan on common ports (1.5s timeout each).")
    print("  Reports open ports with service names. Good for quick recon.")
    print()
    print("  Default ports cover: FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3,")
    print("  IMAP, HTTPS, SMB, MySQL, RDP, PostgreSQL, VNC, Redis,")
    print("  HTTP-Proxy, HTTPS-Proxy, Elasticsearch, MongoDB, and more.")
    print()
    host = _ask("Target host or IP (e.g. 192.168.1.1 or scanme.nmap.org)", session.target_ip or "")
    if not host:
        print("[ERROR] No target given; aborting.")
        return
    print()
    print("  Enter specific ports as a comma-separated list (e.g. 22,80,443,3306)")
    print("  or press ENTER for the default list of 30 common ports.")
    ports_spec = _ask("Ports to scan", "")
    if ports_spec:
        try:
            ports = sorted({int(p.strip()) for p in ports_spec.split(",") if p.strip()})
        except ValueError:
            print("[ERROR] Invalid port list; expected numbers separated by commas (e.g. 22,80,443).")
            return
        if any(port < 1 or port > 65535 for port in ports):
            print("[ERROR] Ports must be integers in the range 1-65535.")
            return
        if not 0 < len(ports) <= 200:
            print("[ERROR] Provide between 1 and 200 ports.")
            return
    else:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 1433, 1521, 1723, 2049, 3306,
            3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 9200, 27017,
        ]
        print(f"  Using default list of {len(ports)} common ports.")

    bar = progress.LiveBar(total=len(ports), label=f"quick scan of {host}")
    bar.log(f"scanning {host} ({len(ports)} ports, 64 workers, 1.5s timeout)", level="info")
    open_ports: List[Tuple[int, str]] = []
    lock = threading.Lock()
    done = {"count": 0}

    def probe(port: int) -> Optional[str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result != 0:
                return None
            try:
                return socket.getservbyport(port, "tcp")
            except OSError:
                return "unknown"
        except (socket.error, OSError):
            return None

    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(probe, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                service = future.result()
            except Exception:  # pragma: no cover - defensive
                service = None
            with lock:
                done["count"] += 1
                if service:
                    open_ports.append((port, service))
                    bar.log(f"port {port} open — {service}", level="ok")
            bar.step_to(done["count"], f"port {port}")
    bar.finish("quick port scan finished")
    open_ports.sort(key=lambda item: item[0])
    if not open_ports:
        print("[INFO] No open ports found in the scanned range.")
        print("[INFO] The host may be down, behind a firewall, or blocking all ports.")
    else:
        print()
        print_table(["port", "service"], open_ports)
    print(f"\n[INFO] {len(open_ports)}/{len(ports)} port(s) open.")

    if open_ports:
        print("\n  Port descriptions:")
        port_descriptions = {
            21: "FTP — file transfer (check for anonymous login)",
            22: "SSH — remote shell (check for weak credentials)",
            23: "Telnet — unencrypted remote access (insecure)",
            25: "SMTP — email sending (may relay spam if open)",
            53: "DNS — name resolution (check for zone transfers)",
            80: "HTTP — web server",
            110: "POP3 — email retrieval (unencrypted)",
            143: "IMAP — email retrieval",
            443: "HTTPS — encrypted web server",
            445: "SMB — file sharing (Common target for exploits)",
            3306: "MySQL — database (check for default creds)",
            3389: "RDP — Windows remote desktop (Common brute-force target)",
            5432: "PostgreSQL — database",
            5900: "VNC — remote desktop (unencrypted by default)",
            6379: "Redis — in-memory database (often unauthenticated)",
            8080: "HTTP-Proxy — web proxy or alt web server",
            9200: "Elasticsearch — search engine (often unauthenticated)",
            27017: "MongoDB — NoSQL database (check for auth)",
        }
        for port, service in open_ports:
            desc = port_descriptions.get(port, "")
            if desc:
                print(f"    {port}/{service}: {desc}")

    session.set_result("open_port_finder", [port for port, _ in open_ports])
    print("\n[INFO] Results stored as 'open_port_finder' in session.")

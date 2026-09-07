"""TALOS — EXTRA NETWORK MODULES (21-25).

21 port banner grabber
22 SSL/TLS certificate checker
23 HTTP security headers analyzer
24 IP geolocation lookup
25 ping flood test (safe, rate-limited)

All network calls carry timeouts; every module degrades to a clean message
when the network or an upstream service is unavailable.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import List, Optional, Tuple

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


def _safe_banner(raw: bytes) -> str:
    """Decode + sanitise one banner: strip control chars, cap its length."""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() or ch in "\t" else " " for ch in text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:200]


_HTTP_PROBE_PORTS = frozenset({80, 8000, 8080, 8888, 443, 8443, 9000})
_HTTPS_PORTS = frozenset({443, 8443})


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Fetch a service banner from one open port; None when nothing speaks.

    Follows how banner-grabbers behave in practice: some services (SSH, FTP,
    SMTP, POP3/IMAP, MySQL) send their greeting unprompted as soon as you
    connect, while HTTP(S) servers only answer after a request. HTTPS ports
    are wrapped in TLS *before* any byte is sent, otherwise you read cipher
    garbage instead of a banner.
    """
    import select

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in _HTTPS_PORTS:
            context = ssl.create_default_context()
            try:
                sock = context.wrap_socket(sock, server_hostname=host)
            except (ssl.SSLError, OSError):
                return None  # not actually a TLS service on this port

        # 1) banner-first services: is anything already waiting?
        readable, _, _ = select.select([sock], [], [], 0.4)
        if readable:
            data = sock.recv(2048)
            if data:
                return _safe_banner(data)

        # 2) HTTP: send a minimal request. Everything else: poke it with CRLF
        #    so SMTP/FTP-style servers answer with their greeting.
        if port in _HTTP_PROBE_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        else:
            sock.sendall(b"\r\n")
        data = sock.recv(2048)
        if data:
            return _safe_banner(data)
        # 3) some servers need a moment before they flush their greeting
        sock.settimeout(timeout)
        try:
            data = sock.recv(2048)
        except socket.timeout:
            data = b""
        return _safe_banner(data) if data else None
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# [21] Port Banner Grabber
# ---------------------------------------------------------------------------
_DEFAULT_BANNER_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]

_BANNER_PORTS_HELP = (
    "Common ports & their services:\n"
    "  21=FTP  22=SSH  23=Telnet  25=SMTP  53=DNS\n"
    "  80=HTTP  110=POP3  143=IMAP  443=HTTPS\n"
    "  993=IMAPS  995=POP3S  3306=MySQL  3389=RDP\n"
    "  5432=PostgreSQL  8080=HTTP-Proxy"
)


def banner_grabber(session: Session) -> None:
    """Connect to common ports and grab the service banner (text greeting).

    A banner is the first piece of text a service sends when you connect.
    It often reveals the software name and version (e.g. 'OpenSSH_8.9p1'),
    which is useful for service fingerprinting and vulnerability assessment.
    """
    print("  Connects to each port, reads the greeting/banner text.")
    print("  Useful for identifying what software + version a service is running.")
    print()
    host = _ask("Target host or IP (e.g. 192.168.1.1 or scanme.nmap.org)", session.target_ip or "")
    if not host:
        print("[ERROR] No target given; aborting.")
        return
    print()
    print(f"  {_BANNER_PORTS_HELP}")
    print()
    ports_spec = _ask(
        "Ports to scan (comma-separated, e.g. 22,80,443)\n"
        "  or press ENTER for the default list of 15 common ports",
        ""
    )
    if ports_spec:
        try:
            ports = sorted({int(p.strip()) for p in ports_spec.split(",") if p.strip()})
        except ValueError:
            print("[ERROR] Invalid port list; expected numbers separated by commas (e.g. 22,80,443).")
            return
        if any(port < 1 or port > 65535 for port in ports):
            print("[ERROR] Ports must be integers in the range 1-65535.")
            return
        if not 0 < len(ports) <= 100:
            print("[ERROR] Provide between 1 and 100 ports.")
            return
    else:
        ports = _DEFAULT_BANNER_PORTS
        print(f"  Using default ports: {', '.join(str(p) for p in ports)}")

    rows: List[Tuple[int, str, str]] = []
    no_banner = 0
    bar = progress.LiveBar(total=len(ports), label=f"banners from {host}")
    bar.log(f"grabbing banners from {host} ({len(ports)} ports)", level="info")
    for port in ports:
        banner = _grab_banner(host, port)
        if banner:
            rows.append((port, "open", banner))
            bar.log(f"port {port} → {banner[:60]}", level="ok")
        else:
            no_banner += 1
        bar.advance(f"port {port}")

    bar.finish("banner grabbing finished")
    if not rows:
        print("[INFO] Could not grab banners from any port (all closed, filtered, "
              "or silent services).")
        return
    print_table(["port", "state", "banner"], rows)
    session.set_result("banners", {port: banner for port, _, banner in rows})
    print(f"\n[INFO] {len(rows)} banner(s) captured. Stored as 'banners' in session.")
    if no_banner:
        print(f"[INFO] {no_banner} open-but-silent port(s) produced no banner "
              "(services may require an authenticated session).")


# ---------------------------------------------------------------------------
# [22] SSL/TLS Certificate Checker
# ---------------------------------------------------------------------------
def ssl_checker(session: Session) -> None:
    """Connect to a host over TLS and display the certificate details.

    Shows: who issued the cert, which domains it covers (SANs), when it
    expires, which TLS protocol version and cipher suite are negotiated.
    Useful for verifying certificate validity, checking expiry dates, or
    debugging HTTPS connection issues.
    """
    print("  Connects to a host over HTTPS and reads its TLS certificate.")
    print("  Shows: issuer, subject, SANs, expiry, TLS version, cipher suite.")
    print("  Useful for checking cert expiry or verifying HTTPS setup.")
    print()
    host = _ask("Hostname or domain (e.g. example.com or 192.168.1.1)", session.target_domain or "")
    if not host:
        print("[ERROR] No host given; aborting.")
        return
    host = host.replace("https://", "").replace("http://", "").split("/")[0].strip()
    print()
    print("  The TLS port is almost always 443 for HTTPS.")
    print("  Only change this if the service runs on a non-standard port.")
    port_str = _ask("TLS port number", "443")
    try:
        port = int(port_str)
    except ValueError:
        port = 443
    session.target_domain = host

    print(f"\n[INFO] Connecting to {host}:{port} over TLS ...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
    except Exception as exc:
        print(f"[ERROR] TLS connection failed: {type(exc).__name__}. {exc}")
        return

    # Parse subject/issuer
    def _dn_str(dn: Tuple[Tuple[Tuple[str, str], ...], ...]) -> str:
        parts = []
        for rdn in dn:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
        return ", ".join(parts)

    rows: List[Tuple[str, str]] = [
        ("subject", _dn_str(cert.get("subject", ()))),
        ("issuer", _dn_str(cert.get("issuer", ()))),
        ("serial number", cert.get("serialNumber", "-")),
        ("not before", cert.get("notBefore", "-")),
        ("not after", cert.get("notAfter", "-")),
        ("SAN", ", ".join(v for t, v in cert.get("subjectAltName", ()) if t == "DNS")),
        ("TLS version", version or "-"),
    ]
    if cert_der:
        digest = hashlib.sha256(cert_der).hexdigest()
        rows.append(("sha256 fingerprint", ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))))
    if cipher:
        rows.append(("cipher", f"{cipher[0]} {cipher[1]}-{cipher[2]}"))

    # Expiry countdown — the number people actually need day to day.
    days_left: Optional[int] = None
    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days
        except ValueError:
            days_left = None
    if days_left is not None:
        rows.append(("expires in", f"{days_left} day(s)"))

    print()
    print_table(["field", "value"], rows)
    print()
    if days_left is None:
        print("[INFO] Could not compute the expiry date from the certificate.")
    elif days_left < 0:
        print(f"[WARN] This certificate EXPIRED {-days_left} day(s) ago.")
    elif days_left <= 14:
        print(f"[WARN] Certificate expires in {days_left} day(s) — renew immediately.")
    elif days_left <= 30:
        print(f"[WARN] Certificate expires in {days_left} day(s) — schedule a renewal.")
    else:
        print(f"[OK] Certificate is valid for {days_left} more day(s).")
    session.set_result("ssl_cert", {k: v for k, v in rows})
    print("\n[INFO] Certificate details stored as 'ssl_cert' in session.")


# ---------------------------------------------------------------------------
# [23] HTTP Security Headers Analyzer
# ---------------------------------------------------------------------------
_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]


_COOKIE_HEADER = "Set-Cookie"


def _header_value(headers, name: str) -> Optional[str]:
    """Case-insensitive header lookup (requests lower-cases response headers)."""
    value = headers.get(name.lower()) or headers.get(name)
    return (value or "").strip() or None


def _cookie_issues(set_cookie: str) -> List[str]:
    """Which hardening flags are missing from the session cookies."""
    issues: List[str] = []
    # Split multiple Set-Cookie values (requests joins them with ', ').
    parts = re.split(r",(?=\s*[^;,=]+=)", set_cookie)
    for cookie in parts:
        cookie = cookie.strip()
        if not cookie or "=" not in cookie:
            continue
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        if "secure" not in lowered:
            issues.append(f"{name}: no Secure (sent over HTTP too)")
        if "httponly" not in lowered:
            issues.append(f"{name}: no HttpOnly (readable by scripts)")
        if "samesite" not in lowered:
            issues.append(f"{name}: no SameSite attribute")
    return issues


def http_headers(session: Session) -> None:
    """Fetch a URL and analyze HTTP security headers + cookie hardening.

    Checks the ten security headers and, going further than a bare
    presence/absence list, also inspects *config quality* of the ones that
    are set (weak CSP values, HSTS max-age without includeSubDomains, ...)
    and the Secure/HttpOnly/SameSite flags of every session cookie.
    """
    requests = _import_requests()
    print("  Fetches the URL and checks for security headers:")
    print("  HSTS, CSP, X-Frame-Options, X-Content-Type-Options,")
    print("  Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.")
    print("  Also inspects weak header values and cookie flags.")
    print()
    target = _ask("URL or domain to scan (e.g. https://example.com)", session.target_domain or "")
    if not target:
        print("[ERROR] No URL given; aborting.")
        return
    inferred = "://" not in target
    target = f"https://{target}" if inferred else target

    response = None
    for candidate in ([target] if not inferred else [target, target.replace("https://", "http://", 1)]):
        try:
            response = requests.get(candidate, timeout=10, headers={"User-Agent": _USER_AGENT})
            if response.status_code >= 400:
                response = None
                continue
            break
        except Exception:
            continue
    if response is None:
        print(f"[ERROR] Could not fetch {target}.")
        return
    headers = response.headers
    over_https = (response.url or candidate).lower().startswith("https")

    present = []
    missing = []
    for hdr in _SECURITY_HEADERS:
        value = _header_value(headers, hdr)
        if value:
            present.append((hdr, value))
        else:
            missing.append((hdr, "NOT SET"))

    all_rows: List[Tuple[str, str]] = []
    if present:
        all_rows.extend(present)
    if missing:
        all_rows.extend(missing)
    for info_hdr in ("Server", "X-Powered-By"):
        value = _header_value(headers, info_hdr)
        if value:
            all_rows.append((f"(info) {info_hdr}", value))

    if not all_rows:
        print("[INFO] No headers found.")
        return
    print()
    print_table(["header", "value"], all_rows)

    # ---- config-quality findings on the headers that ARE present ----
    findings: List[str] = []
    present_map = {name.lower(): value for name, value in present}
    csp = present_map.get("content-security-policy", "")
    if csp:
        low = csp.lower()
        if "unsafe-inline" in low and "nonce-" not in low and "'sha256-" not in low:
            findings.append("CSP allows 'unsafe-inline' — weak against XSS")
        if "unsafe-eval" in low:
            findings.append("CSP allows 'unsafe-eval'")
        url_re = re.compile(r"(?:https?:)?//\S+")
        if any("http:" in token for token in url_re.findall(csp)):
            findings.append("CSP permits mixed/plain-http sources")
    hsts = present_map.get("strict-transport-security", "")
    if hsts:
        if not over_https:
            findings.append("HSTS is set but the site answered over plain HTTP")
        else:
            low_hsts = hsts.lower()
            m = re.search(r"max-age=(\d+)", low_hsts)
            if m and int(m.group(1)) < 15552000:
                findings.append("HSTS max-age < 180 days (recommended >= 15552000)")
            if "includesubdomains" not in low_hsts:
                findings.append("HSTS missing includeSubDomains")
    xfo = present_map.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append(f"X-Frame-Options '{xfo}' is not DENY/SAMEORIGIN")
    referrer = present_map.get("referrer-policy", "")
    if referrer and "unsafe-url" in referrer.lower():
        findings.append("Referrer-Policy 'unsafe-url' leaks full URLs")

    if findings:
        print()
        print_table(["finding", "detail"], [(f"[weak] {f}", "") for f in findings])

    # ---- cookie hardening ----
    set_cookie = _header_value(headers, _COOKIE_HEADER)
    cookie_notes: List[str] = []
    if set_cookie:
        cookie_notes = _cookie_issues(set_cookie)
    if cookie_notes:
        print()
        print_table(["cookie", "flag issue"], [(" ", c) for c in cookie_notes])

    # ---- weighted score: not every header matters equally ----
    essential = {"strict-transport-security", "content-security-policy",
                 "x-content-type-options", "x-frame-options", "referrer-policy"}
    score = len(present)
    total = len(_SECURITY_HEADERS)
    print(f"\n[INFO] Security header score: {score}/{total} present.")
    weak = len(findings) + len(cookie_notes)
    if weak:
        print(f"[INFO] {weak} configuration issue(s) found in headers/cookies.")
    present_names = {h.lower() for h, _ in present}
    missing_essential = sorted(essential.difference(present_names))
    if score == total and not weak:
        print("[INFO] Excellent — all security headers are configured well.")
    elif missing_essential:
        print("[WARN] Missing essential headers: " + ", ".join(missing_essential).upper())
        print("[WARN] These mitigate XSS, clickjacking, MIME sniffing and other "
              "common web attacks.")
    elif score >= 7:
        print("[INFO] Good — most security headers are in place.")
    else:
        print("[WARN] Moderate or poor header coverage.")
    session.set_result("security_headers", {
        "present": [h for h, _ in present],
        "missing": [h for h, _ in missing],
        "findings": findings,
        "cookie_issues": cookie_notes,
        "score": f"{score}/{total}",
    })


# ---------------------------------------------------------------------------
# [24] IP Geolocation Lookup
# ---------------------------------------------------------------------------
def ip_geolocation(session: Session) -> None:
    """Look up the geographic location of an IP (two free providers).

    Primary: ip-api.com (free, no key, 45 req/min). If that service is
    unreachable or refuses, falls back to ipwho.is over HTTPS so the module
    still returns accurate data instead of a bare error.
    """
    requests = _import_requests()
    print("  Looks up the geographic location of an IP address.")
    print("  Uses ip-api.com with an automatic ipwho.is fallback.")
    print("  Returns: country, city, coordinates, ISP, timezone, and more.")
    print("  Leave blank to auto-detect your own public IP.")
    print()
    ip = _ask("IPv4 or IPv6 address (leave blank to use your own IP)", "")
    if not ip:
        print("  Auto-detecting your public IP ...")
        try:
            resp = requests.get("https://api.ipify.org", timeout=5)
            ip = resp.text.strip()
            print(f"  Your public IP: {ip}")
        except Exception:
            print("[ERROR] Could not auto-detect your IP (no internet?).")
            return
    if not ip or "/" in ip:
        print("[ERROR] Invalid IP address.")
        return

    # ---- primary: ip-api.com ----
    data = None
    provider = "ip-api.com"
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=8,
            params={"fields": "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as"},
        )
        payload = resp.json()
        if payload.get("status") == "success":
            data = payload
        else:
            print(f"[WARN] ip-api.com: {payload.get('message', 'lookup failed')}")
    except Exception as exc:
        print(f"[WARN] ip-api.com unreachable ({type(exc).__name__}); "
              "trying ipwho.is ...")

    # ---- fallback: ipwho.is (HTTPS) ----
    if data is None:
        provider = "ipwho.is"
        try:
            resp = requests.get(f"https://ipwho.is/{ip}", timeout=8,
                                headers={"User-Agent": _USER_AGENT})
            payload = resp.json()
            if payload.get("success"):
                conn = payload.get("connection") or {}
                data = {
                    "country": payload.get("country"),
                    "regionName": payload.get("region"),
                    "city": payload.get("city"),
                    "zip": payload.get("postal"),
                    "lat": payload.get("latitude"),
                    "lon": payload.get("longitude"),
                    "timezone": payload.get("timezone") and payload["timezone"].get("id"),
                    "isp": conn.get("isp"),
                    "org": conn.get("org"),
                    "as": conn.get("asn"),
                }
        except Exception as exc:
            print(f"[ERROR] Geolocation lookup failed: {type(exc).__name__}")
            return
    if data is None:
        print(f"[ERROR] Geolocation lookup failed for {ip}.")
        return

    rows: List[Tuple[str, str]] = [
        ("ip", ip),
        ("country", str(data.get("country") or "-")),
        ("region", str(data.get("regionName") or "-")),
        ("city", str(data.get("city") or "-")),
        ("zip", str(data.get("zip") or "-")),
        ("latitude", str(data.get("lat") if data.get("lat") is not None else "-")),
        ("longitude", str(data.get("lon") if data.get("lon") is not None else "-")),
        ("timezone", str(data.get("timezone") or "-")),
        ("ISP", str(data.get("isp") or "-")),
        ("org", str(data.get("org") or "-")),
        ("AS", str(data.get("as") or "-")),
    ]
    print()
    print_table(["field", "value"], rows)
    session.set_result("geolocation", {k: v for k, v in rows})
    print(f"\n[INFO] Geolocation data stored as 'geolocation' in session (source: {provider}).")


# ---------------------------------------------------------------------------
# [25] Ping Flood Test (safe, rate-limited)
# ---------------------------------------------------------------------------
def ping_flood(session: Session) -> None:
    """Send a configurable number of pings and report packet loss statistics.

    Sends 5-100 ICMP echo requests and reports: packets sent/received,
    packet loss %, and min/avg/max round-trip times. Useful for testing
    network reliability and latency to a target. This is a safe, normal
    ping test — not a DoS attack.
    """
    import subprocess
    import platform

    print("  Sends multiple ICMP pings and reports loss/latency stats.")
    print("  Reports: packets sent, received, loss %, min/avg/max RTT.")
    print("  Safe and rate-limited (max 100 pings). NOT a DoS tool.")
    print()
    host = _ask("Target host or IP (e.g. 8.8.8.8 or google.com)", session.target_ip or "")
    if not host:
        print("[ERROR] No target given; aborting.")
        return
    print()
    print("  How many pings to send (5-100). More pings = more accurate stats")
    print("  but takes longer. 20 is a good default for a quick reliability test.")
    count_str = _ask("Number of pings to send", "20")
    try:
        count = max(5, min(100, int(count_str)))
    except ValueError:
        count = 20

    print(f"\n[INFO] Sending {count} pings to {host} ...")
    if platform.system().lower() == "windows":
        command = ["ping", "-n", str(count), "-w", "1000", host]
    else:
        command = ["ping", "-c", str(count), "-W", "2", host]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=count * 3 + 10,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"[ERROR] Ping flood test failed: {type(exc).__name__}")
        return

    output = result.stdout
    # Parse stats line
    import re
    transmitted = received = 0
    t_match = re.search(r"(\d+)\s+(?:packets?\s+)?transmitted", output)
    r_match = re.search(r"(\d+)\s+(?:packets?\s+)?received", output)
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss", output)
    rtt_match = re.search(
        r"rtt[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output, re.IGNORECASE
    )

    if t_match:
        transmitted = int(t_match.group(1))
    if r_match:
        received = int(r_match.group(1))
    loss_pct = float(loss_match.group(1)) if loss_match else (100.0 * (1 - received / transmitted) if transmitted else 0)

    rows: List[Tuple[str, str]] = [
        ("target", host),
        ("sent", str(transmitted)),
        ("received", str(received)),
        ("packet loss", f"{loss_pct:.1f}%"),
    ]
    if rtt_match:
        rows.append(("avg RTT", f"{rtt_match.group(2)} ms"))
        rows.append(("min RTT", f"{rtt_match.group(1)} ms"))
        rows.append(("max RTT", f"{rtt_match.group(3)} ms"))

    print()
    print_table(["field", "value"], rows)
    session.set_result("ping_flood", {k: v for k, v in rows})
    print(f"\n[INFO] {received}/{transmitted} packets received ({loss_pct:.1f}% loss).")
    if loss_pct == 0:
        print("[INFO] Excellent — no packet loss detected.")
    elif loss_pct < 5:
        print("[INFO] Good — very low packet loss.")
    elif loss_pct < 20:
        print("[WARN] Moderate — some packets are being dropped.")
    else:
        print("[WARN] High packet loss — network may be unreliable or target may be blocking ICMP.")

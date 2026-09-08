"""TALOS — NETWORK SCANNERS (01-07).

Design rules honored here:
* every ``subprocess`` call has a ``timeout`` and captures stdout/stderr;
* every network request has a ``timeout``;
* third-party libraries are imported lazily, so a missing package or a dead
  network connection can never crash the tool — the menu guard still logs any
  residual exception to ``logs/error.log``.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from src.core import progress
from src.core.context import Session
from src.core.table import print_table

# Common TCP ports with well-known service names (module 04 / 24).
COMMON_PORTS: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongod",
}

#: Ports probed to decide a host is alive when it blocks ICMP (module 02).
_TCP_ALIVE_PORTS = (22, 80, 443)
_TCP_ALIVE_TIMEOUT = 0.6


def _service_name(port: int) -> str:
    """Best-known service for a port: curated map, then the OS registry."""
    known = COMMON_PORTS.get(port)
    if known:
        return known
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def _tcp_alive(host: str) -> bool:
    """True when the host accepts a TCP connection on a common port.

    Used as the ICMP fallback: many firewalls silently drop echo requests
    while still allowing connect() to real services, so ping-only discovery
    would write those hosts off as down.
    """
    for port in _TCP_ALIVE_PORTS:
        try:
            # create_connection() resolves hostnames and handles IPv6 too.
            with socket.create_connection((host, port), timeout=_TCP_ALIVE_TIMEOUT):
                return True
        except OSError:
            continue
    return False


def _host_sort_key(host: str):
    """Sort key that works for IPv4, IPv6 and hostnames alike."""
    try:
        return tuple(ipaddress.ip_address(host).packed)
    except ValueError:
        return (host,)

_USER_AGENT = (
    "Mozilla/5.0 (compatible; TALOS/2.0; +https://example.invalid/talos)"
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _need(package: str, pip_name: Optional[str] = None) -> None:
    """Raise a clean error when an optional library is unavailable."""
    raise RuntimeError(
        f"the '{package}' library is not installed. Run: "
        f"{sys.executable} -m pip install {pip_name or package}"
    )


def _import_requests():
    try:
        import requests  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - defensive
        raise RuntimeError(
            "the 'requests' library is not installed. Run: "
            f"{sys.executable} -m pip install requests"
        ) from exc
    return requests


def _ping_command(host: str) -> Tuple[List[str], bool]:
    """Return (argv, is_windows_style)."""
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", "1000", host], True
    return ["ping", "-c", "1", "-W", "1", host], False


def _ping_host(host: str) -> bool:
    """One-shot reachability probe; never raises."""
    command, _windows = _ping_command(host)
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return True
        # Windows can still report success via output even on odd exit codes.
        haystack = (result.stdout + result.stderr).lower()
        return "ttl=" in haystack
    except (subprocess.TimeoutExpired, OSError):
        return False


def _ping_stats(host: str) -> Tuple[Optional[float], Optional[int]]:
    """Return (rtt_ms, ttl) for one ping; (None, None) when it fails."""
    command, _windows = _ping_command(host)
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None, None
    output = result.stdout + result.stderr
    rtt_match = re.search(r"time[=<]\s*([0-9.]+)\s*ms", output, re.IGNORECASE)
    ttl_match = re.search(r"ttl\s*=\s*(\d+)", output, re.IGNORECASE)
    rtt = float(rtt_match.group(1)) if rtt_match else None
    ttl = int(ttl_match.group(1)) if ttl_match else None
    if rtt is None and ttl is None and result.returncode != 0:
        return None, None
    return rtt, ttl


def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


# ---------------------------------------------------------------------------
# [01] Show My IP
# ---------------------------------------------------------------------------
def show_my_ip(session: Session) -> None:
    """Show the public IPv4/IPv6 with ipify fallback -> ifconfig.me."""
    requests = _import_requests()
    sources = ("https://api.ipify.org", "https://ifconfig.me/ip")
    discovered = None
    used_source = None
    failures: List[str] = []
    for url in sources:
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            candidate = response.text.strip()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                failures.append(f"{url}: invalid IP response")
                continue
            discovered = candidate
            used_source = url
            break
        except Exception as exc:  # try the fallback before giving up
            failures.append(f"{url}: {type(exc).__name__}")
    if not discovered:
        print("[ERROR] Could not determine the public IP address.")
        print("[INFO] No internet connectivity, or both services are unreachable.")
        return
    session.set_result("my_ip", discovered)
    print_table(["field", "value"], [("public ip", discovered), ("source", used_source)])
    print("[INFO] Stored in session results as 'my_ip'.")


# ---------------------------------------------------------------------------
# [02] IP Scanner (Ping Sweep)
# ---------------------------------------------------------------------------
def _expand_hosts(spec: str) -> List[str]:
    """Turn '1.2.3.4', '1.2.3.0/24' or '1.2.3.4-10' into a host list."""
    spec = spec.strip()
    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    if "-" in spec:
        base, _, tail = spec.rpartition("-")
        if not base or not tail:
            raise ValueError(f"invalid range: {spec!r}")
        start_ip = ipaddress.ip_address(base)
        try:
            end_value = int(tail)
        except ValueError as exc:
            raise ValueError(f"invalid range end in {spec!r}") from exc
        if start_ip.version != 4:
            raise ValueError("ranges are only supported for IPv4")
        parts = str(start_ip).split(".")
        start_value = int(parts[3])
        if end_value < start_value or end_value > 255:
            raise ValueError(f"range end must be {start_value}-255 in {spec!r}")
        return [f"{'.'.join(parts[:3])}.{i}" for i in range(start_value, end_value + 1)]
    ipaddress.ip_address(spec)  # raises ValueError when malformed
    return [spec]


def ip_scanner(session: Session) -> None:
    """Discover live hosts: ICMP ping, with a TCP-connect fallback probe.

    Mirrors how mature discovery tools behave (nmap ``-sn``, angry IP
    scanner): a host counts as alive when it answers an ICMP echo **or**
    accepts a TCP connection on a common port (22/80/443). Ping-only
    discovery misses every host that silently drops ICMP but still serves
    real traffic — the TCP pass catches those.
    """
    spec = _ask("Target (IP, CIDR or range like 192.168.1.1-254)", session.target_ip or "")
    if not spec:
        print("[ERROR] No target given; aborting sweep.")
        return
    try:
        hosts = _expand_hosts(spec)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return
    if len(hosts) > 2048:
        print(f"[ERROR] Refusing to sweep {len(hosts)} hosts (max 2048).")
        return

    alive: List[str] = []
    icmp_alive: int = 0
    lock = threading.Lock()

    # ---- stage 1: ICMP echo ----
    bar = progress.LiveBar(total=len(hosts), label="ping sweep")
    bar.log(f"sweeping {len(hosts)} host(s)", level="info")
    maybe_down: List[str] = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_ping_host, host): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            bar.advance(host)
            try:
                if future.result():
                    with lock:
                        alive.append(host)
                        icmp_alive += 1
                    bar.log(f"{host} responded to ping", level="ok")
                else:
                    with lock:
                        maybe_down.append(host)
            except Exception:  # pragma: no cover - defensive
                continue
    bar.finish("ping sweep finished")

    # ---- stage 2: TCP probe for hosts that ignored ICMP (bounded) ----
    tcp_alive = 0
    if maybe_down and len(maybe_down) <= 1024:
        bar2 = progress.LiveBar(total=len(maybe_down), label="TCP probe")
        bar2.log(
            f"{len(maybe_down)} host(s) ignored ICMP — probing TCP ports "
            f"{', '.join(str(p) for p in _TCP_ALIVE_PORTS)}",
            level="info",
        )
        with ThreadPoolExecutor(max_workers=64) as pool:
            futures = {pool.submit(_tcp_alive, host): host for host in maybe_down}
            for future in as_completed(futures):
                host = futures[future]
                bar2.advance(host)
                try:
                    if future.result():
                        with lock:
                            alive.append(host)
                            tcp_alive += 1
                        bar2.log(f"{host} alive via TCP connect", level="ok")
                except Exception:  # pragma: no cover - defensive
                    continue
        bar2.finish("TCP probe finished")

    alive.sort(key=_host_sort_key)
    if not alive:
        print("[INFO] No hosts answered ICMP or TCP. Hosts may be down, "
              "firewalled, or behind a network that blocks both.")
        return
    print_table(["#", "host"], [(i + 1, host) for i, host in enumerate(alive)])
    method_hint = []
    if icmp_alive:
        method_hint.append(f"{icmp_alive} via ICMP")
    if tcp_alive:
        method_hint.append(f"{tcp_alive} via TCP probe")
    session.set_result("alive_hosts", alive)
    suffix = f" ({', '.join(method_hint)})" if method_hint else ""
    print(f"[INFO] {len(alive)} host(s) alive{suffix}. Stored as 'alive_hosts'.")


# ---------------------------------------------------------------------------
# [03] IP Pinger (RTT / TTL)
# ---------------------------------------------------------------------------
def ip_pinger(session: Session) -> None:
    """Ping one host 5 times and print RTT/TTL, plus the average RTT."""
    host = _ask("Target", session.target_ip or "")
    if not host:
        print("[ERROR] No target given; aborting.")
        return
    bar = progress.LiveBar(total=5, label=f"pings to {host}")
    bar.log(f"pinging {host} 5 times", level="info")
    rows: List[Tuple[int, str, str]] = []
    rtts: List[float] = []
    for attempt in range(1, 6):
        rtt, ttl = _ping_stats(host)
        if rtt is None:
            rows.append((attempt, "-", "-"))
        else:
            rtts.append(rtt)
            rows.append((attempt, f"{rtt:.1f} ms", str(ttl or "-")))
        bar.advance(f"probe {attempt}/5 — {rtts[-1]:.1f} ms" if rtt is not None else f"probe {attempt}/5 — no reply")
    bar.finish("ping sequence finished")
    print_table(["probe", "rtt", "ttl"], rows)
    if rtts:
        average = sum(rtts) / len(rtts)
        print(f"[INFO] Average RTT: {average:.1f} ms over {len(rtts)} reply(ies).")
    else:
        print("[INFO] No replies received; host may be down or blocking ICMP.")


# ---------------------------------------------------------------------------
# [04] IP Port Scanner
# ---------------------------------------------------------------------------
def port_scanner(session: Session) -> None:
    """Threaded TCP connect() scan (max 50 threads, 1s timeout per port)."""
    host = _ask("Target", session.target_ip or "")
    if not host:
        print("[ERROR] No target given; aborting scan.")
        return
    ports_spec = _ask("Ports (comma separated, empty = common 20)", "")
    if ports_spec:
        try:
            ports = sorted({int(part.strip()) for part in ports_spec.split(",") if part.strip()})
        except ValueError:
            print("[ERROR] Invalid port list; expected numbers separated by commas.")
            return
        if any(port < 1 or port > 65535 for port in ports):
            print("[ERROR] Ports must be integers in the range 1-65535.")
            return
        if not 0 < len(ports) <= 1000:
            print("[ERROR] Provide between 1 and 1000 ports.")
            return
    else:
        ports = sorted(COMMON_PORTS)

    open_ports: List[Tuple[int, str]] = []
    closed_count = 0
    filtered_count = 0
    errors: List[str] = []
    lock = threading.Lock()

    def probe(port: int) -> Tuple[int, str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(1.0)
            code = sock.connect_ex((host, port))
        except PermissionError:
            return port, "permission"  # raw-socket style denial -> see note below
        except socket.error:
            return port, "filtered"
        finally:
            try:
                sock.close()
            except OSError:
                pass
        if code == 0:
            return port, "open"
        if code in (socket.errno.ECONNREFUSED, 111):
            return port, "closed"
        return port, "filtered"

    bar = progress.LiveBar(total=len(ports), label=f"ports on {host}")
    bar.log(f"scanning {host} ({len(ports)} ports, 50 workers, 1.0s timeout)", level="info")
    try:
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(probe, port) for port in ports]
            for future in as_completed(futures):
                port, state = future.result()
                service = _service_name(port)
                with lock:
                    if state == "open":
                        open_ports.append((port, service))
                        bar.log(f"port {port} open — {service}", level="ok")
                    elif state == "closed":
                        closed_count += 1
                    elif state == "filtered":
                        filtered_count += 1
                    else:
                        errors.append(str(port))
                bar.advance(f"port {port} {state}")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[ERROR] Scan aborted: {exc}")
        return
    bar.finish("port scan finished")

    if open_ports:
        print_table(["port", "state", "service"], [(p, "open", s) for p, s in sorted(open_ports)])
    else:
        print("[INFO] No open ports found.")
    print(f"[INFO] Closed: {closed_count}   Filtered/timed-out: {filtered_count}")
    if errors:
        print("[INFO] Note: TCP connect scans do not need root. If the OS refused "
              "raw sockets, results above already used the unprivileged connect() path.")
    session.set_result("open_ports", [p for p, _ in sorted(open_ports)])
    print("[INFO] Open ports stored in session results as 'open_ports'.")


# ---------------------------------------------------------------------------
# [05] Website Info Scanner
# ---------------------------------------------------------------------------
def _extract_host(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).netloc.split("@")[-1].split(":")[0]


def _extract_headers(response) -> Dict[str, str]:
    """Pull the informative header fields out of a response (case-insensitive)."""
    picked: Dict[str, str] = {}
    by_lower = {key.lower(): key for key in response.headers}
    for wanted in ("Server", "X-Powered-By", "Content-Type", "Via"):
        actual = by_lower.get(wanted.lower())
        if actual:
            picked[wanted] = (response.headers.get(actual) or "").strip()
    return picked


def website_info(session: Session) -> None:
    """HTTP(S) header fingerprint + TLS certificate expiry/issuer.

    When the user typed a bare domain the scan prefers HTTPS and only falls
    back to plain HTTP when the TLS attempt fails (certificate errors,
    port 443 closed, ...), so HTTP-only servers still get fingerprinted.
    """
    requests = _import_requests()
    target = _ask("Website (domain or URL)", session.target_domain or "")
    if not target:
        print("[ERROR] No website given; aborting.")
        return
    inferred_scheme = "://" not in target
    target = f"https://{target}" if inferred_scheme else target
    host = _extract_host(target)
    session.target_domain = host

    # Candidate URLs: explicit scheme -> that one only; bare domain -> https
    # then http (many http-only servers refuse TLS).
    candidates = [target]
    if inferred_scheme:
        candidates.append(target.replace("https://", "http://", 1))

    response = None
    used_url = None
    last_error: Optional[BaseException] = None
    for candidate in candidates:
        for method in ("head", "get"):  # some servers reject HEAD
            try:
                response = getattr(requests, method)(
                    candidate,
                    timeout=10,
                    headers={"User-Agent": _USER_AGENT},
                    allow_redirects=True,
                )
                used_url = candidate
                break
            except Exception as exc:
                last_error = exc
                continue
        if response is not None:
            break
    if response is None:
        hint = f" ({type(last_error).__name__})" if last_error else ""
        print(f"[ERROR] Could not reach the website to fetch headers{hint}.")
        return

    final_url = response.url or used_url or target
    final_host = _extract_host(final_url)
    headers = _extract_headers(response)
    status_code = response.status_code

    rows: List[Tuple[str, object]] = [("url", final_url), ("http status", status_code)]
    if final_url != target:
        rows.append(("redirected from", target))
    for key in ("Server", "X-Powered-By", "Content-Type", "Via"):
        rows.append((key, headers.get(key, "-")))
    print_table(["field", "value"], rows)
    host = final_host if final_url.lower().startswith("https") else host

    # TLS certificate
    try:
        pem = ssl.get_server_certificate((host, 443), timeout=10)
    except Exception as exc:
        print(f"[WARN] TLS certificate unavailable: {type(exc).__name__}")
        return
    try:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.backends import default_backend  # noqa: PLC0415
    except ImportError:
        print("[WARN] 'cryptography' not installed; cannot decode the certificate.")
        return
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        not_after = cert.not_valid_after_utc
        issuer = cert.issuer.rfc4514_string()
        days_left = (not_after.replace(tzinfo=None) - _now_naive()).days
        print_table(
            ["tls field", "value"],
            [
                ("subject", cert.subject.rfc4514_string()),
                ("issuer", issuer),
                ("not after", not_after.isoformat()),
                ("days until expiry", f"{days_left} day(s)"),
            ],
        )
    except Exception as exc:
        print(f"[WARN] Could not parse the TLS certificate: {type(exc).__name__}")


def _now_naive():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# [06] DNS Lookup
# ---------------------------------------------------------------------------
_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def dns_lookup(session: Session) -> None:
    """Resolve the main record types for a domain via dnspython."""
    try:
        import dns.resolver  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "the 'dnspython' library is not installed. Run: "
            f"{sys.executable} -m pip install dnspython"
        ) from exc
    domain = _ask("Domain", session.target_domain or "").strip().lower()
    if not domain:
        print("[ERROR] No domain given; aborting.")
        return
    session.target_domain = domain

    try:
        dns.resolver.resolve(domain, "A", lifetime=3)
    except Exception:
        print("[WARN] DNS resolution failed, check connectivity.")
        return

    rows: List[Tuple[str, str]] = []
    for record_type in _RECORD_TYPES:
        values: List[str] = []
        try:
            answer = dns.resolver.resolve(domain, record_type, lifetime=5)
            for rdata in answer:
                if record_type == "TXT":
                    values.append(" ".join(part.decode() if isinstance(part, bytes) else str(part) for part in rdata.strings))
                else:
                    values.append(str(rdata))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception as exc:  # timeout / lifetime per record type
            values.append(f"(error: {type(exc).__name__})")
        if values:
            rows.append((record_type, ", ".join(values)))

    if not rows:
        print(f"[INFO] No records found for {domain}.")
        return
    print_table(["record", "value(s)"], rows)
    session.set_result("dns_records", dict(rows))
    print(f"[INFO] Records stored as 'dns_records'.")


# ---------------------------------------------------------------------------
# [07] Traceroute
# ---------------------------------------------------------------------------
def traceroute(session: Session) -> None:
    """Trace the network path to a host using the system traceroute binary."""
    host = _ask("Target", session.target_ip or "")
    if not host:
        print("[ERROR] No target given; aborting.")
        return
    if platform.system().lower() == "windows":
        command = ["tracert", "-d", "-h", "20", host]
    else:
        import shutil

        if shutil.which("traceroute") is None:
            print("[ERROR] 'traceroute' is not installed. Install it via your OS "
                  "package manager (e.g. apt install traceroute).")
            return
        command = ["traceroute", "-n", "-m", "20", "-w", "1", host]
    print(f"[INFO] Tracing route to {host} (max 20 hops) ...")
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=90,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"[ERROR] Traceroute failed: {type(exc).__name__}")
        return
    output = result.stdout.strip()
    if not output:
        print("[WARN] Traceroute produced no output.")
        return
    lines = output.splitlines()
    start = 0
    for index, line in enumerate(lines):
        if _is_hop_line(line):
            start = index
            break
    for line in lines[start : start + 25]:
        print(f"  {line}")
    session.set_result("traceroute", output)


def _is_hop_line(line: str) -> bool:
    """Best-effort detection of traceroute hop lines (they start with a hop #)."""
    stripped = line.strip()
    if not stripped:
        return False
    first = stripped.split(" ", 1)[0].rstrip(".")
    return first.isdigit() and "traceroute to" not in stripped.lower()

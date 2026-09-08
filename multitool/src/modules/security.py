"""Security-focused TALOS menu modules.

The functions in this module are intentionally defensive assessment helpers:
they make bounded, read-only requests, report useful evidence, and keep
network failures from escaping into the menu engine.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from src.core.context import Session
from src.core.table import print_table
from src.logging_utils import get_logger

LOGGER = get_logger("talos.security")
_TIMEOUT = 8.0
_MAX_BODY = 200_000
_USER_AGENT = "TALOS/2.0 security-audit"


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


def _url(raw: str, default_scheme: str = "http") -> str:
    value = raw.strip()
    if not value.startswith(("http://", "https://")):
        value = f"{default_scheme}://{value}"
    return value.rstrip("/")


def _response_row(response: Any) -> Tuple[int, int, str]:
    return response.status_code, len(response.content), response.url


def _network_error(exc: BaseException) -> None:
    LOGGER.warning("network operation failed: %s: %s", type(exc).__name__, exc)
    print(f"[ERROR] Network request failed ({type(exc).__name__}); no result was stored.")


def http_method_tester(session: Session) -> None:
    """Probe safe HTTP methods and identify methods accepted by a target."""
    target = _url(_ask("Target URL", session.target_domain or ""))
    if not target or target == "http://":
        print("[ERROR] No target URL given; aborting.")
        return
    methods = ("HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE")
    requests = _import_requests()
    rows: List[Tuple[str, str, str, str]] = []
    result: Dict[str, Any] = {"url": target, "methods": {}}
    try:
        for method in methods:
            response = requests.request(
                method, target, headers={"User-Agent": _USER_AGENT},
                timeout=_TIMEOUT, allow_redirects=False,
            )
            allowed = 200 <= response.status_code < 300
            body_sample = response.text[:160].replace("\n", " ") if method == "TRACE" else ""
            assessment = "accepted (2xx)" if allowed else "not confirmed"
            rows.append((method, response.status_code, len(response.content), assessment))
            result["methods"][method] = {
                "status": response.status_code, "length": len(response.content),
                "allowed": allowed, "allow": response.headers.get("Allow", ""),
                "trace_reflection": body_sample[:80] if method == "TRACE" else "",
            }
        print_table(["method", "status", "bytes", "assessment"], rows)
        session.set_result("http_methods", result)
        LOGGER.info("HTTP method test target=%s methods=%s", target, result["methods"])
    except requests.RequestException as exc:
        _network_error(exc)


def vhost_scanner(session: Session) -> None:
    """Enumerate virtual hosts by comparing bounded Host-header responses."""
    target = _ask("Target IP or URL", session.target_ip or "")
    if not target:
        print("[ERROR] No target given; aborting.")
        return
    base = _url(target)
    host = urlparse(base).hostname or target
    wordlist = _ask("Host names (comma-separated, or file path)", "www,admin,dev,staging,api")
    names = _load_words(wordlist, limit=100)
    if not names:
        print("[ERROR] No host names supplied; aborting.")
        return
    requests = _import_requests()
    baseline: Optional[Tuple[int, int]] = None
    rows: List[Tuple[str, int, int, str]] = []
    findings: List[Dict[str, Any]] = []
    try:
        baseline_response = requests.get(
            base,
            headers={"Host": host, "User-Agent": _USER_AGENT},
            timeout=_TIMEOUT,
            allow_redirects=False,
        )
        baseline = _http_signature(baseline_response)
        for name in names:
            candidate = name if "." in name else f"{name}.{host}"
            response = requests.get(
                base,
                headers={"Host": candidate, "User-Agent": _USER_AGENT},
                timeout=_TIMEOUT,
                allow_redirects=False,
            )
            repeat = requests.get(
                base,
                headers={"Host": candidate, "User-Agent": _USER_AGENT},
                timeout=_TIMEOUT,
                allow_redirects=False,
            )
            signature = _http_signature(response)
            stable = signature == _http_signature(repeat)
            interesting = signature != baseline
            assessment = "candidate" if interesting and stable else "unstable" if interesting else "baseline"
            rows.append((candidate, response.status_code, len(response.content), assessment))
            if interesting and stable:
                findings.append({
                    "host": candidate,
                    "status": response.status_code,
                    "length": len(response.content),
                    "location": response.headers.get("Location", ""),
                    "confidence": "candidate",
                })
        print_table(["host", "status", "bytes", "comparison"], rows)
        data = {"target": base, "baseline": baseline, "candidates": findings, "tested": len(names), "note": "Candidates require manual verification; response differences are not proof of a virtual host."}
        session.set_result("vhosts", data)
        LOGGER.info("vhost scan target=%s tested=%d findings=%d", base, len(names), len(findings))
    except requests.RequestException as exc:
        _network_error(exc)


def _load_words(spec: str, limit: int = 100) -> List[str]:
    try:
        if os.path.isfile(spec):
            with open(spec, "r", encoding="utf-8", errors="ignore") as handle:
                values = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
        else:
            values = [item.strip() for item in spec.split(",") if item.strip()]
    except OSError as exc:
        print(f"[ERROR] Could not read wordlist: {exc}")
        return []
    return list(dict.fromkeys(values))[:limit]


def _http_signature(response: Any) -> Tuple[int, int, str, str]:
    """Create a repeatable, bounded response signature for comparisons."""
    body = re.sub(r"\s+", " ", response.text[:_MAX_BODY]).strip()
    body = re.sub(r"\b\d{2,}\b", "#", body)
    digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]
    return response.status_code, len(response.content), response.headers.get("Location", ""), digest


def web_directory_bruteforcer(session: Session) -> None:
    """Discover common web paths with status and response-size evidence."""
    target = _url(_ask("Target URL", session.target_domain or ""))
    if not target or target == "http://":
        print("[ERROR] No target URL given; aborting.")
        return
    spec = _ask("Paths (comma-separated, or wordlist file)", "admin,backup,.env,wp-config.php.bak,robots.txt,sitemap.xml")
    paths = _load_words(spec, limit=150)
    if not paths:
        print("[ERROR] No paths supplied; aborting.")
        return
    requests = _import_requests()
    rows: List[Tuple[str, int, int, str]] = []
    findings: List[Dict[str, Any]] = []
    try:
        control_path = "/.talos-nonexistent-" + hashlib.sha256(target.encode()).hexdigest()[:12]
        control = requests.get(target + control_path, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT, allow_redirects=False)
        control_signature = _http_signature(control)
        for path in paths:
            path = "/" + path.lstrip("/")
            response = requests.get(target + path, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT, allow_redirects=False)
            status = response.status_code
            same_as_control = _http_signature(response) == control_signature
            if same_as_control:
                label = "wildcard/not found"
            elif status in (401, 403):
                label = "access-controlled candidate"
            elif 200 <= status < 300:
                label = "candidate"
            elif 300 <= status < 400:
                label = "redirect candidate"
            else:
                label = "not found"
            rows.append((path, status, len(response.content), label))
            if label.endswith("candidate"):
                findings.append({"path": path, "status": status, "length": len(response.content), "location": response.headers.get("Location", ""), "confidence": "candidate"})
        print_table(["path", "status", "bytes", "assessment"], rows)
        data = {"url": target, "tested": len(paths), "candidates": findings, "control": {"path": control_path, "status": control.status_code, "length": len(control.content)}, "note": "Candidates exclude responses matching the wildcard control and require manual verification."}
        session.set_result("directories", data)
        LOGGER.info("directory scan target=%s tested=%d findings=%d", target, len(paths), len(findings))
    except requests.RequestException as exc:
        _network_error(exc)


def waf_detection(session: Session) -> None:
    """Compare normal and suspicious probes to identify WAF response signals."""
    target = _url(_ask("Target URL", session.target_domain or ""))
    if not target or target == "http://":
        print("[ERROR] No target URL given; aborting.")
        return
    requests = _import_requests()
    probes = ("normal", "' OR 1=1 --", "<script>alert(1)</script>", "../../etc/passwd")
    rows: List[Tuple[str, int, int, str]] = []
    evidence: List[str] = []
    try:
        for label, payload in (("baseline", ""),) + tuple((f"probe-{i}", p) for i, p in enumerate(probes[1:], 1)):
            response = requests.get(target, params={"talos_probe": payload} if payload else None, headers={"User-Agent": _USER_AGENT}, timeout=_TIMEOUT, allow_redirects=False)
            text = response.text[:_MAX_BODY].lower()
            vendor = next((name for name in ("cloudflare", "akamai", "modsecurity", "aws", "imperva", "f5", "barracuda") if name in text or name in " ".join(response.headers).lower()), "")
            signal = "possible WAF signal" if response.status_code in (403, 406, 429, 503) or vendor else "no obvious signal"
            rows.append((label, response.status_code, len(response.content), signal + (f" ({vendor})" if vendor else "")))
            if signal != "no obvious signal":
                evidence.append(f"{label}: status={response.status_code}, vendor={vendor or 'unknown'}")
        print_table(["probe", "status", "bytes", "assessment"], rows)
        data = {"url": target, "evidence": evidence, "possible_waf": bool(evidence), "confidence": "low" if evidence else "none", "note": "HTTP behavior alone cannot prove WAF presence or vendor identity."}
        session.set_result("waf", data)
        LOGGER.info("WAF detection target=%s likely=%s evidence=%d", target, bool(evidence), len(evidence))
    except requests.RequestException as exc:
        _network_error(exc)


def jwt_token_analyzer(session: Session) -> None:
    """Decode a JWT and flag algorithm, expiry, and signature risks."""
    token = _ask("JWT token", "")
    parts = token.split(".") if token else []
    if len(parts) != 3:
        print("[ERROR] A JWT must contain exactly three dot-separated parts.")
        return
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
        signature_bytes = _b64decode(parts[2]) if parts[2] else b""
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Invalid JWT encoding or JSON: {exc}")
        return
    algorithm = str(header.get("alg", "")).upper()
    findings: List[str] = []
    if algorithm in ("NONE", ""):
        findings.append("algorithm is none or missing; signature may be bypassable")
    if algorithm in ("HS1", "HS256", "HS384", "HS512"):
        findings.append("HMAC algorithm requires controlled secret-key validation")
    if "exp" in payload:
        try:
            expiry = datetime.fromtimestamp(float(payload["exp"]), tz=timezone.utc)
            expired = expiry <= datetime.now(timezone.utc)
            if expired:
                findings.append("token is expired")
        except (TypeError, ValueError, OSError):
            findings.append("exp claim is not a valid Unix timestamp")
    else:
        findings.append("no expiration claim present")
    signature = parts[2]
    if not signature:
        findings.append("signature segment is empty")
    rows = [("algorithm", algorithm), ("header", json.dumps(header, sort_keys=True)), ("payload", json.dumps(payload, sort_keys=True)), ("signature bytes", str(len(signature_bytes))), ("findings", "; ".join(findings) or "none")]
    print_table(["field", "value"], rows)
    data = {"header": header, "payload": payload, "algorithm": algorithm, "findings": findings, "signature_present": bool(signature)}
    session.set_result("jwt", data)
    LOGGER.info("JWT analyzed algorithm=%s findings=%d", algorithm, len(findings))


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def http2_tls_checker(session: Session) -> None:
    """Check ALPN HTTP/2 support and probe deprecated TLS versions."""
    raw = _ask("TLS hostname or URL", session.target_domain or "")
    host = urlparse(_url(raw, "https")).hostname if raw else ""
    if not host:
        print("[ERROR] No hostname given; aborting.")
        return
    port_text = _ask("TLS port", "443")
    try:
        port = max(1, min(65535, int(port_text)))
    except ValueError:
        port = 443
    rows: List[Tuple[str, str, str]] = []
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as sock:
                rows.append(("HTTP/2 ALPN", "supported" if sock.selected_alpn_protocol() == "h2" else "not negotiated", sock.version() or "-"))
                rows.append(("current TLS", sock.version() or "-", str(sock.cipher())))
        for version, label in ((getattr(ssl.TLSVersion, "TLSv1", None), "TLS 1.0"), (getattr(ssl.TLSVersion, "TLSv1_1", None), "TLS 1.1"), (getattr(ssl.TLSVersion, "SSLv3", None), "SSLv3")):
            if version is None:
                rows.append((label, "unsupported by local OpenSSL", "-"))
                continue
            probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            probe.check_hostname = False
            probe.verify_mode = ssl.CERT_NONE
            try:
                probe.minimum_version = version
                probe.maximum_version = version
                with socket.create_connection((host, port), timeout=_TIMEOUT) as raw_sock:
                    with probe.wrap_socket(raw_sock, server_hostname=host):
                        rows.append((label, "accepted", "deprecated protocol enabled"))
            except (ssl.SSLError, OSError, ValueError):
                rows.append((label, "rejected", "good"))
        print_table(["check", "result", "detail"], rows)
        data = {"host": host, "port": port, "checks": rows}
        session.set_result("http2_tls", data)
        LOGGER.info("HTTP2/TLS check host=%s port=%d", host, port)
    except (OSError, ssl.SSLError) as exc:
        _network_error(exc)


def leaked_credential_checker(session: Session) -> None:
    """Query HIBP's k-anonymity email endpoint when an API key is configured."""
    value = _ask("Email address or domain", "")
    if not value:
        print("[ERROR] No email or domain supplied; aborting.")
        return
    is_email = "@" in value
    if is_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        print("[ERROR] Enter a complete email address or a domain name.")
        return
    if not is_email and not re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        print("[ERROR] Enter a complete email address or a domain name.")
        return
    api_key = os.environ.get("HIBP_API_KEY", "").strip()
    if not api_key:
        print("[INFO] HIBP_API_KEY is not configured; no breach query was made.")
        LOGGER.info("HIBP lookup skipped because HIBP_API_KEY is absent")
        session.set_result("breach_lookup", {"query": value, "status": "not_configured", "breaches": []})
        return
    requests = _import_requests()
    try:
        endpoint = "breachedaccount" if is_email else "breacheddomain"
        response = requests.get(
            "https://haveibeenpwned.com/api/v3/" + endpoint + "/" + requests.utils.quote(value, safe=""),
            headers={"hibp-api-key": api_key, "user-agent": _USER_AGENT}, timeout=_TIMEOUT,
        )
        if response.status_code == 404:
            breaches: List[Dict[str, Any]] = []
        elif response.status_code == 200:
            breaches = response.json()
        else:
            print(f"[ERROR] HIBP returned HTTP {response.status_code}; try again later.")
            return
        if is_email:
            rows = [(item.get("Name", "-"), item.get("BreachDate", "-"), item.get("DataClasses", "-")) for item in breaches]
        else:
            rows = [(breach, "-", ", ".join(sorted(emails)) if isinstance(emails, list) else str(emails)) for breach, emails in breaches.items()]
        print_table(["breach", "date", "exposed data"], rows or [("-", "-", "no known breaches")])
        data = {"query": value, "status": "found" if breaches else "none_found", "breaches": breaches}
        session.set_result("breach_lookup", data)
        LOGGER.info("HIBP lookup query_hash=%s breaches=%d", hashlib.sha256(value.encode()).hexdigest()[:12], len(breaches))
    except (requests.RequestException, ValueError) as exc:
        _network_error(exc)


def subdomain_takeover_checker(session: Session) -> None:
    """Find dangling CNAMEs and compare answers with known takeover signatures."""
    domain = _ask("Subdomains (comma-separated, or wordlist file)", session.target_domain or "")
    names = _load_words(domain, limit=100)
    if not names:
        print("[ERROR] No subdomains supplied; aborting.")
        return
    try:
        import dns.resolver  # noqa: PLC0415
    except ImportError as exc:
        print("[ERROR] dnspython is not installed; DNS check unavailable.")
        LOGGER.warning("subdomain takeover DNS import failed: %s", exc)
        return
    signatures = {"herokuapp.com": "Heroku", "github.io": "GitHub Pages", "amazonaws.com": "AWS", "s3.amazonaws.com": "AWS S3", "azurewebsites.net": "Azure", "netlify.app": "Netlify", "fastly.net": "Fastly", "pantheonsite.io": "Pantheon"}
    rows: List[Tuple[str, str, str, str]] = []
    findings: List[Dict[str, str]] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = _TIMEOUT
    resolver.lifetime = _TIMEOUT
    for name in names:
        try:
            answers = resolver.resolve(name, "CNAME")
            cname = str(answers[0]).rstrip(".")
            provider = next((label for suffix, label in signatures.items() if cname.endswith(suffix)), "unknown")
            rows.append((name, "CNAME", cname, "potential candidate" if provider != "unknown" else "no known signature"))
            if provider != "unknown":
                findings.append({"name": name, "cname": cname, "provider": provider, "confidence": "candidate"})
        except Exception as exc:  # DNS libraries vary exception classes by version.
            rows.append((name, "-", "no CNAME", "unresolved"))
            LOGGER.debug("DNS lookup failed for %s: %s", name, exc)
    print_table(["name", "record", "target", "assessment"], rows)
    data = {"tested": len(names), "candidates": findings, "note": "A matching provider CNAME is not proof of takeover; provider-specific unclaimed-resource verification is required."}
    session.set_result("takeover", data)
    LOGGER.info("takeover check tested=%d findings=%d", len(names), len(findings))

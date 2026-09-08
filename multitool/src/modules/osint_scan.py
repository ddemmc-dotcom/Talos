"""TALOS — OSINT MODULES (fully implemented).

08 username tracker
09 subdomain finder (wordlist + DNS)
10 email / contact finder (mailto crawl of a page)
11 phone number lookup (Veriphone free API)
12 metadata extractor (HTML meta tags)
13 whois lookup (RDAP over HTTPS, no key required)
14 certificate transparency lookup (crt.sh)

Every network call carries a timeout; every module degrades to a clean
message when the network or an upstream service is unavailable.
"""
from __future__ import annotations

import html
import ipaddress
import re
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.core import progress
from src.core.context import Session
from src.core.table import print_table

DEFAULT_SUBDOMAINS = [
    # mail / messaging
    "www", "mail", "webmail", "smtp", "pop", "pop3", "imap", "mx", "mail2",
    "exchange", "owa", "outlook", "autodiscover", "autoconfig", "m",
    # dns / infra
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "localhost",
    "router", "gateway", "firewall", "fw", "proxy", "webproxy", "squid",
    "vpn", "remote", "rdp", "citrix", "webdisk",
    # web / app layers
    "www2", "www3", "web", "webserver", "web1", "web2", "app", "apps",
    "api", "api2", "graphql", "ws", "socket", "cdn", "static", "assets",
    "images", "img", "media", "video", "download", "downloads", "files",
    "uploads", "ftp2", "sftp", "storage", "object", "backup", "archive",
    "blog", "cms", "wp", "wordpress", "shop", "store", "forum", "community",
    "support", "help", "helpdesk", "status", "docs", "wiki", "kb", "news",
    "portal", "dashboard", "panel", "cp", "manage", "admin", "secure",
    "login", "auth", "sso", "id", "identity", "account", "accounts",
    # dev / ci / monitoring
    "dev", "test", "qa", "staging", "stage", "uat", "preprod", "demo",
    "beta", "ci", "cd", "build", "jenkins", "gitlab", "git", "svn",
    "jira", "confluence", "nexus", "artifactory", "registry", "docker",
    "grafana", "kibana", "prometheus", "sentry", "monitoring", "metrics",
    "logs", "log", "elk", "graylog", "analytics", "stats", "piwik",
    # data
    "db", "database", "db1", "db2", "mysql", "pgsql", "postgres", "mongo",
    "mongodb", "redis", "cache", "memcached", "elastic", "es", "solr",
    "search", "mq", "rabbitmq", "kafka", "consul", "etcd",
    # misc
    "calendar", "meet", "chat", "team", "teams", "intranet", "internal",
    "erp", "crm", "billing", "invoice", "office", "go", "new", "old",
    "mobile", "info", "start", "sip", "voip", "asterisk", "pbx",
    "camera", "cctv", "printer", "print", "nas", "san", "vm", "vcenter",
    "esxi", "hyperv", "kvm", "proxmox", "pve",
]
# de-duplicate while keeping order (the literal list above is hand-curated)
DEFAULT_SUBDOMAINS = list(dict.fromkeys(DEFAULT_SUBDOMAINS))

_USER_AGENT = (
    "Mozilla/5.0 (compatible; TALOS/2.1; +https://example.invalid/talos)"
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IMAGE_TLDS = {"png", "jpg", "jpeg", "gif", "webp", "svg", "css", "js", "ico"}


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


def _fetch(url: str, timeout: int = 12):
    """GET with a UA header; returns the response or raises a clean error."""
    requests = _import_requests()
    return requests.get(url, timeout=timeout, headers={"User-Agent": _USER_AGENT})


# ---------------------------------------------------------------------------
# [08] Username Tracker
# ---------------------------------------------------------------------------
# Checking a username means more than "HTTP 200 = found": many sites answer
# 200 OK with a generic page for ANY username (a "soft 404"), and others sit
# behind bot walls that 403 everyone. Like Sherlock and other OSINT tools,
# each service below is fingerprinted with content markers — text that only
# appears on a real profile (``found``) or only on a dead/placeholder page
# (``missing``). As a second line of defence every "found" result is
# confirmed against a random, almost-certainly-unused username: when the
# control username also "exists", the site is a catch-all and the result is
# reported as inconclusive instead of a false positive.
#
# Verdicts: FOUND / MISSING / BLOCKED (bot-wall or rate limit) / UNKNOWN.

_FOUND = "found"
_MISSING = "missing"
_BLOCKED = "blocked"
_UNKNOWN = "unknown"

#: name -> checker spec. ``json_identity`` means the endpoint returns JSON
#: whose ``kind`` (reddit) or ``login`` (github) field identifies a profile.
_USER_SERVICES: Dict[str, Dict[str, object]] = {
    "github": {
        "url": "https://api.github.com/users/{u}",
        "json_identity": "login",
        "blocked_markers": ("rate limit", "api rate limit exceeded"),
    },
    "gitlab": {
        "url": "https://gitlab.com/users/{u}",
        "status_found": True,
        "blocked_markers": ("rate limit", "you have been blocked"),
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{u}/about.json",
        "json_kind": "t2",
        "blocked_markers": ("blocked", "too many requests", "rate limit"),
    },
    "instagram": {
        "url": "https://www.instagram.com/{u}/",
        "found_markers": ("og:title", "userInteractionCount"),
        "missing_markers": ("page not found", "this page isn't available"),
        "blocked_markers": ("log in to instagram", "login required"),
    },
    "telegram": {
        "url": "https://t.me/{u}",
        "found_markers": ("tgme_page_title",),
        "missing_markers": ("this page isn't available", "page not found"),
    },
    "keybase": {
        "url": "https://keybase.io/{u}",
        "status_found": True,
        "blocked_markers": ("rate limit", "attention required"),
    },
    "pastebin": {
        "url": "https://pastebin.com/u/{u}",
        "status_found": True,
        "missing_markers": ("the page you are looking for",),
    },
    "dev.to": {
        "url": "https://dev.to/{u}",
        "status_found": True,
    },
    "replit": {
        "url": "https://replit.com/@{u}",
        "status_found": True,
        "blocked_markers": ("rate limit", "are you a robot"),
    },
    "codepen": {
        "url": "https://codepen.io/{u}",
        "status_found": True,
        "missing_markers": ("not found",),
    },
}

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,28}[A-Za-z0-9_])?$")


def _check_one_service(
    name: str,
    spec: Dict[str, object],
    username: str,
    requests,
    timeout: int,
) -> Tuple[str, str, str, str]:
    """Check one service; return (name, verdict, http_code, detail)."""
    url = str(spec["url"]).format(u=username)
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT},
            allow_redirects=True,
        )
    except requests.exceptions.Timeout:
        return name, _UNKNOWN, "-", "timeout"
    except Exception as exc:
        return name, _UNKNOWN, "-", type(exc).__name__

    code = response.status_code
    text = (response.text or "")
    lower = text.lower()[:200_000]

    # JSON-based identity checks are the most accurate (no soft-404 risk).
    json_identity = spec.get("json_identity")
    json_kind = spec.get("json_kind")
    if json_identity or json_kind:
        try:
            payload = response.json()
        except Exception:
            payload = None
        if payload is not None:
            if json_identity and payload.get(json_identity):
                return name, _FOUND, str(code), "api hit"
            if json_kind and payload.get("kind") == json_kind:
                return name, _FOUND, str(code), "api hit"
        if code in (404, 410):
            return name, _MISSING, str(code), "api 404"
        if code in (401, 403, 429):
            return name, _BLOCKED, str(code), "api refused"
        return name, _UNKNOWN, str(code), "unrecognised api response"

    if code in (404, 410):
        return name, _MISSING, str(code), "http 404"
    if code == 429:
        return name, _BLOCKED, str(code), "rate limited"
    if code in (401, 403):
        blocked_markers = spec.get("blocked_markers") or ()
        if any(marker in lower for marker in blocked_markers):
            return name, _BLOCKED, str(code), "bot wall"
        return name, _UNKNOWN, str(code), "http {}".format(code)

    for marker in spec.get("missing_markers") or ():
        if marker in lower:
            return name, _MISSING, str(code), "soft-404 marker"
    for marker in spec.get("found_markers") or ():
        if marker in lower:
            return name, _FOUND, str(code), "profile marker"
    if code == 200 and spec.get("status_found"):
        return name, _FOUND, str(code), "profile page"
    return name, _UNKNOWN, str(code), "no conclusive marker"


def username_tracker(session: Session) -> None:
    """Check a username across profile services with false-positive control.

    Each service is fingerprinted by content markers (not bare status codes)
    so soft-404 pages are not reported as profiles; any "found" result is
    then re-checked against a random control username to catch services that
    answer 200 for every name.
    """
    raw = _ask("Username").strip().lstrip("@")
    username = raw.split("/")[-1] if "/" in raw else raw
    if not username:
        print("[ERROR] No username given; aborting.")
        return
    if not _USERNAME_RE.match(username) or ".." in username:
        print("[ERROR] Invalid username: use letters, digits, '_' '.' '-' "
              "(2-30 chars, no consecutive/leading/trailing dots).")
        return
    session.set_result("username", username)

    requests = _import_requests()
    services = _USER_SERVICES
    bar = progress.LiveBar(total=len(services), label=f"profiles for @{username}")
    bar.log(f"checking {len(services)} profile services for '{username}'", level="info")

    verdicts: Dict[str, Tuple[str, str, str]] = {}
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_check_one_service, name, spec, username, requests, 8): name
            for name, spec in services.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
            except Exception:  # pragma: no cover - per-site resilience
                result = (name, _UNKNOWN, "-", "exception")
            with lock:
                verdicts[name] = result[1:]
            bar.advance(f"{name} → {result[1]}")
            if result[1] == _FOUND:
                bar.log(f"found @{username} on {name}", level="ok")
    bar.finish("username lookup finished")

    # ---- negative control: confirm every "found" with a random username ----
    control = f"talos_nouser_{uuid.uuid4().hex[:10]}"
    controlled: Dict[str, str] = {}
    suspects = [n for n, (v, _c, _d) in verdicts.items() if v == _FOUND]
    if suspects:
        bar2 = progress.LiveBar(total=len(suspects), label="false-positive check")
        bar2.log(
            f"verifying {len(suspects)} hit(s) against control username '{control}'",
            level="info",
        )
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                pool.submit(_check_one_service, name, services[name], control, requests, 8): name
                for name in suspects
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    c_verdict = future.result()[1]
                except Exception:  # pragma: no cover
                    c_verdict = _UNKNOWN
                controlled[name] = c_verdict
                bar2.advance(f"{name} control → {c_verdict}")
        bar2.finish("false-positive check finished")

    rows: List[Tuple[str, str, str, str]] = []
    found: List[str] = []
    for name in sorted(services):
        verdict, code, detail = verdicts.get(name, (_UNKNOWN, "-", "not checked"))
        control_verdict = controlled.get(name)
        if verdict == _FOUND and control_verdict == _FOUND:
            # The control username "exists" too — the site is a catch-all.
            verdict = _UNKNOWN
            detail = "catch-all page: answers for every username"
        elif verdict == _FOUND and control_verdict == _MISSING:
            detail = "confirmed (control username missing)"
        elif verdict == _FOUND and name in controlled:
            verdict = _UNKNOWN
            detail = f"control inconclusive ({control_verdict}); not counted as found"
        if verdict == _FOUND:
            found.append(name)
            rows.append((name, "Found", code or "200", detail))
        elif verdict == _MISSING:
            rows.append((name, "Not Found", code or "404", detail))
        elif verdict == _BLOCKED:
            rows.append((name, "Blocked / Limited", code or "-", detail))
        else:
            rows.append((name, "Unknown", code or "-", detail))

    print_table(["service", "status", "http", "evidence"], rows)
    session.set_result("username_hits", found)
    session.set_result("username_report", {n: v for n, v, _c, _d in rows})
    print(f"[INFO] Confirmed on {len(found)} of {len(services)} services.")
    if found:
        print("[INFO] A 'Found' row was only counted after a random username "
              "was rejected by the same service — soft-404 pages are excluded.")


# ---------------------------------------------------------------------------
# [09] Subdomain Finder
# ---------------------------------------------------------------------------
def _resolve_a(fqdn: str, lifetime: float = 4.0):
    """(ips, cname) for one name; ([], "") when the name does not resolve."""
    import dns.resolver  # noqa: PLC0415

    ips: List[str] = []
    cname = ""
    try:
        answer = dns.resolver.resolve(fqdn, "A", lifetime=lifetime)
        ips = sorted({str(rdata.address) for rdata in answer})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            dns.resolver.LifetimeTimeout):
        return ips, cname
    try:  # best-effort CNAME capture (alias target for the same name)
        cname_answer = dns.resolver.resolve(fqdn, "CNAME", lifetime=2.0)
        if cname_answer:
            cname = str(cname_answer[0].target).rstrip(".")
    except Exception:
        pass
    return ips, cname


def _wildcard_answer(domain: str, resolver) -> Optional[Tuple[frozenset, str]]:
    """Probe a random name to detect *.domain wildcard DNS.

    Returns (frozenset(ips), cname) when the wildcard answers, else None.
    Brute forcing against a wildcard domain is meaningless — every random
    name "resolves" — so callers must filter lookalike answers.
    """
    probe = f"talos-nx-{uuid.uuid4().hex[:12]}.{domain}"
    ips, cname = _resolve_a(probe, lifetime=3.0)
    if not ips:
        return None
    return frozenset(ips), cname


def subdomain_finder(session: Session) -> None:
    """Enumerate subdomains via DNS with wildcard filtering (no false hits).

    Best practice used by dnsrecon / puredns: before brute forcing, a random
    name is resolved to detect ``*.domain`` wildcard DNS. Every candidate is
    then compared against that baseline answer set, so wildcard lookalikes
    (and hosts that share the wildcard's IP) are not reported as real
    subdomains. CNAME aliases are captured alongside the A records.
    """
    domain = _ask("Domain", session.target_domain or "").strip().lower().strip(".")
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"^www\.", "", domain)
    if not domain or "." not in domain:
        print("[ERROR] A valid domain is required (e.g. example.com).")
        return
    session.target_domain = domain

    try:
        import dns.resolver  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "the 'dnspython' library is not installed. Run: "
            f"{sys.executable} -m pip install dnspython"
        ) from exc

    try:
        dns.resolver.resolve(domain, "A", lifetime=2)
    except Exception:
        print("[WARN] DNS resolution failed, check connectivity.")
        return

    # --- wildcard detection: the single biggest source of false positives ---
    wildcard = _wildcard_answer(domain, dns.resolver)
    wildcard_ips: frozenset = frozenset()
    wildcard_cname = ""
    if wildcard is not None:
        wildcard_ips, wildcard_cname = wildcard
        print(f"[WARN] Wildcard DNS detected (*.{domain} resolves to "
              f"{', '.join(sorted(wildcard_ips)) or 'an IP'}).")
        print("[WARN] Candidates that only reproduce the wildcard answer "
              "will be filtered out as false positives.")
    else:
        print("[INFO] No wildcard DNS detected — brute-force results will "
              "not contain wildcard noise.")

    wordlist = DEFAULT_SUBDOMAINS
    extra = _ask("Path to a custom wordlist (empty = default list)", "")
    if extra:
        try:
            with open(extra, "r", encoding="utf-8", errors="replace") as handle:
                loaded = [line.strip() for line in handle if line.strip()]
            if loaded:
                wordlist = list(dict.fromkeys(loaded))
        except OSError as exc:
            print(f"[WARN] Could not read wordlist {extra!r} ({exc}); using the default.")

    def _is_wildcard_hit(ips: List[str], cname: str) -> bool:
        if not wildcard_ips:
            return False
        if frozenset(ips) == wildcard_ips:
            return True
        return bool(wildcard_cname) and cname == wildcard_cname

    bar = progress.LiveBar(total=len(wordlist), label=f"subdomains of {domain}")
    bar.log(f"checking {len(wordlist)} candidate subdomains of {domain}", level="info")
    found: Dict[str, List[str]] = {}
    aliases: Dict[str, str] = {}
    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_resolve_a, f"{sub}.{domain}"): sub for sub in wordlist}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                ips, cname = future.result()
            except Exception:  # pragma: no cover - per-host resilience
                continue
            if ips and not _is_wildcard_hit(ips, cname):
                fqdn = f"{sub}.{domain}"
                with lock:
                    found[fqdn] = ips
                    if cname:
                        aliases[fqdn] = cname
                bar.log(f"{fqdn} resolves to {', '.join(ips)}", level="ok")
            bar.advance(sub)
    bar.finish("subdomain search finished")
    if not found:
        if wildcard_ips:
            print("[INFO] No real subdomains found (the wildcard would have "
                  "made everything else look alive).")
        else:
            print("[INFO] No subdomains found with the current wordlist.")
        return
    rows: List[Tuple[str, str]] = []
    for fqdn in sorted(found):
        display = fqdn
        alias = aliases.get(fqdn)
        resolved = ", ".join(found[fqdn])
        if alias:
            display = f"{fqdn} (→ {alias})"
        rows.append((display, resolved))
    print_table(["subdomain", "resolved ip(s)"], rows)
    session.set_result("subdomains", found)
    session.set_result("subdomain_aliases", aliases)
    print(f"[INFO] {len(found)} subdomain(s) found. Stored as 'subdomains'.")


# ---------------------------------------------------------------------------
# [10] Email / Contact Finder
# ---------------------------------------------------------------------------
#: ``_CONTACT_PATHS`` — pages almost every site keeps its contact addresses on.
_CONTACT_PATHS = (
    "/contact", "/contact-us", "/contactus", "/about", "/about-us",
    "/team", "/impressum", "/imprint", "/legal", "/legal-notice",
    "/privacy", "/privacy-policy", "/support", "/help", "/mail",
)
_MAX_CRAWL_PAGES = 10
#: domains whose sample/placeholder addresses would pollute the results
_PLACEHOLDER_DOMAINS = frozenset({"example.com", "example.org", "example.net",
                                  "example.edu", "domain.com", "yourdomain.com",
                                  "sentry.io", "wixpress.com"})


def _clean_emails(text: str) -> set:
    """All plausible e-mail addresses in ``text``, minus obvious junk."""
    found = set()
    for email in _EMAIL_RE.findall(html.unescape(text)):
        email = email.lower().rstrip(".")
        tld = email.split(".")[-1].lower()
        local, _, domain = email.partition("@")
        if tld in _IMAGE_TLDS or not domain or len(domain) < 4:
            continue
        if domain in _PLACEHOLDER_DOMAINS:
            continue
        if email.startswith(("example.", "sentry")):
            continue
        if local.startswith(("data:", "javascript:", "mailto:")):
            continue
        found.add(email)
    return found


def _same_registered_host(a: str, b: str) -> bool:
    """True when two URLs share a host (allow subdomains like www/mail)."""
    host_a = (urlparse(a).hostname or "").lower().lstrip("www.")
    host_b = (urlparse(b).hostname or "").lower().lstrip("www.")
    return bool(host_a) and host_a == host_b


def email_finder(session: Session) -> None:
    """Crawl a site's key pages for e-mail addresses (mailto: or visible).

    Real contact harvesters do not stop at the homepage: addresses live on
    /contact, /about, /imprint ... This module fetches the seed URL plus a
    small set of well-known contact paths on the same host (capped, with a
    timeout per page) and merges every address it finds.
    """
    requests = _import_requests()
    target = _ask("URL or domain", session.target_domain or "")
    if not target:
        print("[ERROR] No URL given; aborting.")
        return
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if not parsed.hostname:
        print("[ERROR] Invalid URL.")
        return

    # Legacy HTTP-only servers: the HTTPS probe fails on TLS/connect, so
    # retry with plain HTTP and keep that scheme for the whole crawl.
    if parsed.scheme == "https":
        try:
            requests.get(target, timeout=8, headers={"User-Agent": _USER_AGENT})
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            http_target = target.replace("https://", "http://", 1)
            try:
                probe = requests.get(http_target, timeout=8,
                                     headers={"User-Agent": _USER_AGENT})
                if probe.status_code < 400:
                    target = http_target
                    print("[INFO] HTTPS unavailable — scanning over plain HTTP.")
            except requests.exceptions.RequestException:
                pass
        parsed = urlparse(target)

    # Build the page list: seed + contact-ish paths on the same host.
    base = f"{parsed.scheme}://{parsed.netloc}"
    pages: List[str] = [target]
    for path in _CONTACT_PATHS:
        if (base + path) not in pages:
            pages.append(base + path)

    sources: Dict[str, set] = {}
    fetched = 0
    bar = progress.LiveBar(total=min(len(pages), _MAX_CRAWL_PAGES), label="page crawl")
    bar.log(f"crawling up to {_MAX_CRAWL_PAGES} pages of {base}", level="info")
    for url in pages:
        if fetched >= _MAX_CRAWL_PAGES:
            break
        try:
            response = requests.get(
                url, timeout=10, headers={"User-Agent": _USER_AGENT}, allow_redirects=True
            )
            if response.status_code != 200 or not _same_registered_host(url, response.url):
                continue
            found_on_page = _clean_emails(response.text)
            final_url = response.url or url
            if found_on_page:
                for email in found_on_page:
                    sources.setdefault(email, set()).add(final_url)
                for email in found_on_page:
                    bar.log(f"{email} (on {final_url})", level="ok")
        except Exception:
            continue  # one dead page must not kill the crawl
        finally:
            fetched += 1
            bar.advance(url)
    bar.finish("crawl finished")

    if not sources:
        print("[INFO] No e-mail addresses found on the crawled pages.")
        return
    rows: List[Tuple[int, str, str]] = []
    for index, email in enumerate(sorted(sources), start=1):
        where = ", ".join(sorted(sources[email]))
        rows.append((index, email, where[:72]))
    print_table(["#", "email", "first seen on"], rows)
    session.set_result("emails", sorted(sources))
    session.set_result("email_sources", {e: sorted(s) for e, s in sources.items()})
    print(f"[INFO] {len(sources)} address(es) found across {fetched} page(s). "
          f"Stored as 'emails'.")


# ---------------------------------------------------------------------------
# [11] Phone Number Lookup
# ---------------------------------------------------------------------------
def _normalise_phone(raw: str) -> Optional[str]:
    """Strip formatting (spaces, dashes, brackets) and keep a leading '+'. """
    value = re.sub(r"[\s\-().]+", "", raw.strip())
    if not value:
        return None
    if not value.startswith("+"):
        # A bare number is ambiguous but worth trying with the country
        # prefix the user most likely means: keep as-is and let the API
        # validate; Veriphone needs E.164 (+country code) to be accurate.
        pass
    if not re.fullmatch(r"\+?\d{7,15}", value):
        return None
    return value


def phone_lookup(session: Session) -> None:
    """Look up carrier/geo metadata for an international phone number."""
    raw = _ask("Phone number (international, e.g. +14155552671)").strip()
    if not raw:
        print("[ERROR] No phone number given; aborting.")
        return
    number = _normalise_phone(raw)
    if number is None:
        print(f"[ERROR] '{raw}' is not a valid E.164 number. Use e.g. "
              "+1 415 555 2671 (country code, then the number).")
        return
    if not number.startswith("+"):
        print("[WARN] No '+' country code: the number will be treated as-is; "
              "add the country code (e.g. +44...) for accurate results.")
    try:
        import requests  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "the 'requests' library is not installed. Run: "
            f"{sys.executable} -m pip install requests"
        ) from exc
    try:
        resp = requests.get(
            "https://api.veriphone.io/v2/verify",
            params={"phone": number},
            timeout=10,
            headers={"User-Agent": _USER_AGENT},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        print(f"[ERROR] Phone lookup failed: {type(exc).__name__}. "
              "Check connectivity or the number format.")
        return
    if not data.get("phone_valid", False):
        reason = data.get("status") or data.get("phone_region") or ""
        suffix = f" ({reason})" if reason else ""
        print(f"[INFO] '{number}' does not look like a valid phone number{suffix}.")
        return
    rows: List[Tuple[str, object]] = [
        ("phone", data.get("international_format") or number),
        ("country", data.get("country") or "-"),
        ("country prefix", data.get("country_prefix") or "-"),
        ("location", data.get("location") or "-"),
        ("carrier", data.get("carrier") or "-"),
        ("line type", data.get("line_type") or "-"),
    ]
    print_table(["field", "value"], rows)
    session.set_result("phone_lookup", data)
    print("[INFO] Lookup stored as 'phone_lookup'.")


# ---------------------------------------------------------------------------
# [12] Metadata Extractor
# ---------------------------------------------------------------------------
_META_ORDER = (
    "generator", "author", "description", "keywords", "viewport", "robots",
    "theme-color", "og:site_name", "og:title", "og:description", "og:type",
    "og:url", "og:image", "twitter:card", "twitter:site", "canonical",
)


class _MetaPageParser(HTMLParser):
    """Robust <title>/<meta>/<link rel=canonical> extractor.

    ``HTMLParser`` handles real-world markup that the old regex missed:
    single-quoted attributes, unquoted values, tags split across lines,
    malformed spacing, entities, and case variations.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: Optional[str] = None
        self.metas: List[Tuple[str, str]] = []
        self.canonical: str = ""
        self._in_title = False
        self._title_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: N802
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            name = (
                attrs.get("name") or attrs.get("property")
                or attrs.get("http-equiv") or attrs.get("itemprop")
            )
            content = attrs.get("content")
            if name and content is not None and content.strip():
                self.metas.append((name.strip().lower(), content.strip()))
        elif tag == "title":
            self._in_title = True
            self._title_chunks = []
        elif tag == "link":
            rel = attrs.get("rel", "").lower()
            if "canonical" in rel.split() and attrs.get("href"):
                self.canonical = attrs["href"]

    def handle_endtag(self, tag: str) -> None:  # noqa: N802
        if tag == "title" and self._in_title:
            self._in_title = False
            text = "".join(self._title_chunks).strip()
            self.title = text or None

    def handle_data(self, data: str) -> None:  # noqa: N802
        if self._in_title:
            self._title_chunks.append(data)


def metadata_extractor(session: Session) -> None:
    """Extract <title> and <meta> tags from a page (framework/author hints).

    Uses a real HTML parser (not regex) so attribute quoting, line breaks
    and entities are handled the way a browser would read them.
    """
    target = _ask("URL", session.target_domain or "")
    if not target:
        print("[ERROR] No URL given; aborting.")
        return
    inferred = "://" not in target
    target = f"https://{target}" if inferred else target

    response = None
    for candidate in ([target] if not inferred else [target, target.replace("https://", "http://", 1)]):
        try:
            response = _fetch(candidate, timeout=12)
            if response.status_code >= 400:
                response = None
                continue
            break
        except Exception:
            continue
    if response is None:
        print(f"[ERROR] Could not fetch {target}.")
        return

    parser = _MetaPageParser()
    try:
        parser.feed(response.text or "")
    except Exception:  # pragma: no cover - HTMLParser is very tolerant
        pass

    meta: Dict[str, str] = {}
    for key, value in parser.metas:  # first occurrence wins, like the old code
        if key not in meta:
            meta[key] = value
    if parser.title and "title" not in meta:
        meta["title"] = parser.title
    if parser.canonical and "canonical" not in meta:
        meta["canonical"] = parser.canonical

    ordered = [(k, meta[k]) for k in _META_ORDER if k in meta]
    for key, value in sorted(meta.items()):
        if key not in _META_ORDER and key != "title":
            ordered.append((key, value))
    if not ordered:
        print("[INFO] No metadata tags found on that page.")
        return
    print_table(["field", "value"], ordered)
    session.set_result("page_metadata", dict(ordered))
    print("[INFO] Metadata stored as 'page_metadata'.")


# ---------------------------------------------------------------------------
# [13] Whois Lookup (RDAP)
# ---------------------------------------------------------------------------
def whois_lookup(session: Session) -> None:
    """Query RDAP (no API key) for domains, IPs (v4/v6) and AS numbers."""
    raw_target = _ask("Domain, IP or ASN", session.target_domain or session.target_ip or "")
    if not raw_target:
        print("[ERROR] No target given; aborting.")
        return
    target = re.sub(r"^https?://", "", raw_target.strip().lower()).rstrip("/")
    if not target:
        print("[ERROR] No target given; aborting.")
        return

    # Classify: IPv4/IPv6 -> ip, AS<number> -> autnum, otherwise domain.
    try:
        ipaddress.ip_address(target)
        kind = "ip"
    except ValueError:
        asn_match = re.fullmatch(r"as(\d{1,10})", target)
        if asn_match:
            target = f"AS{asn_match.group(1)}"
            kind = "autnum"
        elif "." in target:
            kind = "domain"
        else:
            print("[ERROR] Expected a domain (example.com), an IPv4/IPv6 "
                  "address, or an AS number (AS15169).")
            return
    if kind == "domain":
        session.target_domain = target
    else:
        session.target_ip = target

    url = f"https://rdap.org/{kind}/{target}"
    try:
        response = _fetch(url, timeout=15)
        if response.status_code in (404, 400):
            print(f"[INFO] No RDAP registration found for {target}.")
            return
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        print(f"[ERROR] Whois lookup failed: {type(exc).__name__}. "
              "Check connectivity.")
        return

    rows: List[Tuple[str, object]] = [("target", target)]
    if kind == "autnum" and data.get("name"):
        rows.append(("network name", data.get("name")))
    rows.append(("handle", data.get("handle", "-")))
    if data.get("country"):
        rows.append(("country", data.get("country")))
    if data.get("startAddress") and data.get("endAddress"):
        rows.append(("ip range", f"{data.get('startAddress')} - {data.get('endAddress')}"))
    status = data.get("status") or []
    if status:
        rows.append(("status", ", ".join(status[:4])))
    events = {event.get("eventAction", ""): event.get("eventDate", "") for event in data.get("events", [])}
    for label, key in (("registration", "registration"), ("expiration", "expiration"),
                       ("last changed", "last changed")):
        if events.get(key):
            rows.append((label, events[key]))
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
    if nameservers:
        rows.append(("nameservers", ", ".join(n for n in nameservers if n)))
    entities = data.get("entities", [])
    orgs: List[str] = []
    for entity in entities:
        for entry in entity.get("vcardArray", [])[1:]:
            if isinstance(entry, list):
                for field in entry:
                    if isinstance(field, list) and len(field) >= 2 and field[0] == "fn":
                        orgs.append(field[3])
    orgs = list(dict.fromkeys(o for o in orgs if o))
    if orgs:
        rows.append(("registrant", ", ".join(orgs[:3])))
    print_table(["field", "value"], rows)
    session.set_result("whois", dict(rows))
    print("[INFO] Whois data stored as 'whois'.")


# ---------------------------------------------------------------------------
# [14] Certificate Transparency Lookup (crt.sh)
# ---------------------------------------------------------------------------
def ct_lookup(session: Session) -> None:
    """List certificates issued for a domain via the crt.sh CT database."""
    domain = _ask("Domain", session.target_domain or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).rstrip("/")
    if not domain or "." not in domain:
        print("[ERROR] A valid domain is required (e.g. example.com).")
        return
    session.target_domain = domain
    try:
        response = _fetch(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20
        )
        response.raise_for_status()
        entries = response.json()
    except Exception as exc:
        print(f"[ERROR] Certificate transparency lookup failed: "
              f"{type(exc).__name__}. Check connectivity.")
        return
    names: List[str] = []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("name_value"):
            for name in entry["name_value"].split("\n"):
                cleaned = name.strip().lstrip("*.")
                if cleaned and cleaned not in names:
                    names.append(cleaned)
    names.sort()
    if not names:
        print(f"[INFO] No certificates found for {domain}.")
        return
    print_table(["#", "certificate name"], [(i + 1, name) for i, name in enumerate(names)])
    session.set_result("ct_names", names)
    print(f"[INFO] {len(names)} certificate name(s) found. Stored as 'ct_names'.")

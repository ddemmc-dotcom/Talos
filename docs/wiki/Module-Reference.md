# Module Reference

All modules live in **one flat numbered list** — type the number, answer the
prompts, get the report. Results marked 🗂 are stored in the session and
reusable by later modules (see [Architecture](Architecture)).

## Network (01–11)

| # | Module | What it does | Needs |
| - | ------ | ------------ | ----- |
| 01 | Show My IP | Public IPv4/IPv6 via ipify with ifconfig.me fallback | internet | 🗂 `my_ip` |
| 02 | IP Scanner (Ping Sweep) | ICMP sweep + TCP-connect fallback (22/80/443) for hosts that block ping; IP/CIDR/range targets, max 2048 hosts | `ping` | 🗂 `alive_hosts` |
| 03 | IP Pinger (RTT / TTL) | 5 pings, RTT + TTL table, average RTT | `ping` |
| 04 | IP Port Scanner | Threaded TCP connect() scan (50 workers, 1 s timeout), curated port/service map | — | 🗂 `open_ports` |
| 05 | Port Banner Grabber | Reads service banners from open ports | — |
| 06 | SSL/TLS Certificate Checker | Fetches and validates certs: expiry, issuer, chain | internet |
| 07 | HTTP Security Headers | Checks HSTS, CSP, X-Frame-Options, etc. and grades them | internet |
| 08 | Website Info Scanner | Header fingerprint (Server, X-Powered-By) + TLS cert expiry/issuer; HTTPS-first with HTTP fallback | internet | 🗂 |
| 09 | DNS Lookup | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA in one pass | dnspython | 🗂 `dns_records` |
| 10 | Traceroute | Hop-by-hop path, max 20 hops | `traceroute` binary | 🗂 |
| 11 | IP Geolocation Lookup | Country/city/ASN for an IP | internet |

## OSINT (12–24)

| # | Module | What it does | Notes |
| - | ------ | ------------ | ----- |
| 12 | Username Tracker | 10 profile services (github, gitlab, reddit, instagram, telegram, keybase, pastebin, dev.to, replit, codepen). Marker-based fingerprints beat soft-404s; every "found" is re-checked against a random control username | 🗂 `username_hits` |
| 13 | Subdomain Finder | DNS wordlist brute with **wildcard filtering** — a random probe first detects `*.domain` so lookalikes are not reported. Custom wordlist supported | dnspython | 🗂 `subdomains` |
| 14 | Email / Contact Finder | Crawls homepage + `/contact`, `/about`, `/impressum`, … up to 10 pages; filters placeholder domains | internet | 🗂 `emails` |
| 15 | Phone Number Lookup | Carrier/geo/line-type via Veriphone free API | E.164 format (`+1415…`) | 🗂 |
| 16 | Metadata Extractor | `<title>` + meta tags via a real HTML parser (handles quotes, entities, line breaks) | 🗂 `page_metadata` |
| 17 | HTTP Method Tester | OPTIONS/GET/POST/PUT/DELETE/… probe per URL | internet |
| 18 | VHOST Scanner | Host-header enumeration against a base IP | internet |
| 19 | Web Directory Bruteforcer | Wordlist-based path discovery with status filtering | internet |
| 20 | Whois Lookup (RDAP) | Domains, IPv4/IPv6, and AS numbers over HTTPS RDAP — no API key | internet | 🗂 |
| 21 | Certificate Transparency Lookup | Subdomain history via crt.sh | internet | 🗂 |
| 22 | Reverse DNS Lookup | PTR records for IPs / ranges | dnspython |
| 23 | Wayback Machine Lookup | Historical URLs from archive.org | internet |
| 24 | Email Header Analyzer | Parses Received chain, SPF/DKIM/DMARC results from raw headers | — |

## Utilities & security checks (25–35)

| # | Module | What it does |
| - | ------ | ------------ |
| 25 | WAF Detection | Fingerprints Cloudflare/AWS WAF/ModSecurity/… from responses |
| 26 | DNS Zone Transfer Check | Tests AXFR misconfiguration on the domain's NS servers |
| 27 | Open Port Finder (fast) | Quick TCP sweep of common ports, tighter timeouts |
| 28 | Password Generator | Configurable length/charset, cryptographically random |
| 29 | Hash Generator | MD5/SHA-1/SHA-256/SHA-512 of text or file |
| 30 | Session / Target Manager | View/clear the session: target IP, domain, result sets |
| 31 | JWT Token Analyzer | Decodes header/payload, flags `alg:none`, expiry, weak claims |
| 32 | HTTP/2 & Deprecated TLS Checker | ALPN/h2 support, TLSv1.0/1.1, weak ciphers |
| 33 | Leaked Credential Checker | Breach-database lookups for an email/account |
| 34 | Timestamp Converter | Unix ↔ ISO 8601 ↔ human readable, both directions |
| 35 | Subdomain Takeover Checker | CNAMEs pointing at unclaimed services (S3, GH Pages, Azure, …) |

## Attack modules (36–40b) — authorised targets only

These run the real attack engines shared with `scripts/`. See
[Standalone Scripts](Standalone-Scripts) for the CLI equivalents and
[Responsible Use](Responsible-Use) for the rules.

| # | Module | What it does | Notes |
| - | ------ | ------------ | ----- |
| 36 | HTTP Login Brute-Forcer | Basic auth or HTML form mode; rate-limited, capped at 5 000 attempts, wordlist dedup + 200 k-line cap; CSRF/hidden-field replay for forms; hits are `candidate` or `confirmed` (needs success/fail markers for confirmation) | 🗂 |
| 37 | Nmap Vulnerability Scan | NSE `--script vuln` (or any scripts you pick) via the nmap engine; CVE-language detection counts real vulnerability candidates | `nmap` | 🗂 |
| 38 | Auto Vulnerability Audit | **Read-only**: one nmap service/OS scan, then flags outdated versions, default configs and weak-auth surfaces from a built-in knowledge base. Never exploits | `nmap`; `-O` needs root | 🗂 |
| 39 | Metasploit Module Runner | Runs any aux/exploit/post module through `msfrpcd`; auto-wires `RHOSTS`/`PORTS`/payload; ping-check + 2 retries with backoff | msfrpcd + `MSF_RPC_PASSWORD` (see [Configuration](Configuration)) | 🗂 |
| 40 | Data Scraper | Consent-based diagnostics page on all interfaces; streams browser env, LAN IPs, connectivity probes and form data as structured logs; blocker check (self-reach, ngrok, firewall); `--ngrok` or `ssh -R` for public exposure | opens its own console window | 🗂 |
| 40b | Seeker Page | Wraps the bundled upstream Seeker in one operator console; installs Git/PHP deps on demand; `--tunnel` for ngrok | Git, PHP, Python | 🗂 |

## Engine modules (not in the menu)

| Engine | Used by |
| ------ | ------- |
| `nmap_wrapper.NmapModule` | 37, 38, scripts |
| `metasploit_wrapper.MetasploitModule` | 39, `msf_run.py` |
| `attack.HttpBruteforceModule` | 36, `http_bruteforce.py` |
| `auto_audit.AutoAuditModule` | 38, `auto_audit.py` |
| `data_scraper.DataScraperModule` | 40, `data_scraper.py` |
| `seeker.SeekerModule` | 40b, `seeker.py` |

Every module — menu or engine — returns a structured `ToolResult` and is
audited; see [Architecture](Architecture).

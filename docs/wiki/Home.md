# TALOS Wiki — Home

Welcome to the **Talos** wiki. Talos is a keyboard-driven, all-in-one
reconnaissance / OSINT / utility / attack console for **Linux and Windows**.
Everything runs through one flat numbered module list, a full-screen Textual
UI, or standalone scripts — all backed by the same engine, logging and audit
trail.

> ⚠️ **Use only against systems you are authorised to test.** The attacking
> modules (HTTP brute-force, Metasploit runner, Nmap vulnerability scan,
> Seeker) must never be pointed at hosts you do not own or have written
> permission to assess. See [Responsible Use](Responsible-Use).

## Pages

| Page | Contents |
| ---- | -------- |
| [Home](Home) | Project overview, quick start, module map, architecture |
| [Installation](Installation) | Installers, global commands, upgrade & uninstall |
| [Configuration](Configuration) | `.env` settings, Metasploit RPC, self-healing deps |
| [Module Reference](Module-Reference) | All 40 modules and what they do |
| [Standalone Scripts](Standalone-Scripts) | `scripts/` runners: nmap, brute-force, MSF, scraper, Seeker |
| [Logging & Audit Trail](Logging-and-Audit-Trail) | `logs/toolkit.log`, `audit.jsonl`, `error.log` |
| [Architecture](Architecture) | Orchestrator, immutable Context, ToolResult pipeline |
| [Troubleshooting](Troubleshooting) | Common problems and fixes (detailed) |
| [Responsible Use](Responsible-Use) | Authorisation, scope, and ethics |
| [Testing](Testing) | `self_test.py` and what it covers |

---

## What you get

| Entry point | What it is |
| ----------- | ---------- |
| `talos` / `main.py` | Numbered **menu CLI** — the default global command (40 modules) |
| `talos-ui` / `ui.py` | Full-screen **keyboard-driven UI** (arrow keys + Ctrl+S to run) |
| `scripts/…` | Standalone runners: `nmap_vuln.py`, `http_bruteforce.py`, `auto_audit.py`, `msf_run.py`, `data_scraper.py`, `seeker.py` |
| `src/orchestrator.py` | Engine: module discovery, immutable Context, safe execution, audit |

Every module returns a structured `ToolResult`; the same report renderer feeds
the menu, the UI and the standalone scripts, and every run is written to a
JSON audit trail.

## Quick start (from a checkout)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py     # numbered menu
python ui.py       # keyboard-driven UI (auto-installs missing deps)
```

For a global install (the `talos` / `talos-ui` commands), see
[Installation](Installation) — `install.sh` for Linux/macOS and `install.ps1`
for Windows.

## The 40 menu modules at a glance

One flat list, one number = one module (no categories, no sub-menus). Full
descriptions in [Module Reference](Module-Reference).

```
01 Show My IP                  20 Whois Lookup (RDAP)
02 IP Scanner (Ping Sweep)     21 Certificate Transparency Lookup
03 IP Pinger (RTT / TTL)       22 Reverse DNS Lookup
04 IP Port Scanner             23 Wayback Machine Lookup
05 Port Banner Grabber         24 Email Header Analyzer
06 SSL/TLS Certificate Checker 25 WAF Detection
07 HTTP Security Headers       26 DNS Zone Transfer Check
08 Website Info Scanner        27 Open Port Finder (fast)
09 DNS Lookup                  28 Password Generator
10 Traceroute                  29 Hash Generator
11 IP Geolocation Lookup       30 Session / Target Manager
12 Username Tracker            31 JWT Token Analyzer
13 Subdomain Finder (wordlist) 32 HTTP/2 & Deprecated TLS Checker
14 Email / Contact Finder      33 Leaked Credential Checker
15 Phone Number Lookup         34 Timestamp Converter
16 Metadata Extractor          35 Subdomain Takeover Checker
17 HTTP Method Tester          36 HTTP Login Brute-Forcer
18 VHOST Scanner               37 Nmap Vulnerability Scan
19 Web Directory Bruteforcer   38 Auto Vulnerability Audit
                                39 Metasploit Module Runner
                                40 Data Scraper (+ 40b Seeker page)
```

## Architecture in one paragraph

The [Orchestrator](Architecture) discovers every module under `src/modules`,
preflights it with `validate_environment()` (missing binaries/services surface
as clean `ToolResult` diagnostics, never crashes), hands each module a
**deep-copied immutable Context**, validates the module's writes against an
allow-list, and audits every finished run to `logs/audit.jsonl`. Modules never
import UI code: they report progress through a sink, and the menu, TUI and
standalone scripts each attach their own display.

## Logs & audit trail

Written next to the code (or the install prefix for a global install):

```
logs/toolkit.log   rotating debug/activity log
logs/audit.jsonl   one JSON line per finished ToolResult run (rotating)
logs/error.log     full tracebacks of any module failure (timestamped)
```

More detail in [Logging & Audit Trail](Logging-and-Audit-Trail). Set
`NO_COLOR=1` or pipe stdout to disable colour output automatically.

## Where to go next

- New install → [Installation](Installation)
- Metasploit / RPC setup → [Configuration](Configuration)
- Something broke → [Troubleshooting](Troubleshooting)
- Running scans legally → [Responsible Use](Responsible-Use)

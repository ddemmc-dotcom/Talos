# Configuration

Talos needs almost no configuration. The only environment-dependent module is
**Metasploit (39)**, which talks to the `msfrpcd` RPC daemon. Everything else
degrades gracefully when a binary or service is absent.

## `.env` file

Copy `.env.example` to `.env` (repo root) for Metasploit RPC settings. Values
are read by `python-dotenv` on every Metasploit run.

| Variable           | Default   | Purpose                                  |
| ------------------ | --------- | ---------------------------------------- |
| `MSF_RPC_HOST`     | 127.0.0.1 | `msfrpcd` bind address                   |
| `MSF_RPC_PORT`     | 55553     | `msfrpcd` RPC port                       |
| `MSF_RPC_PASSWORD` | —         | **required** to run Metasploit modules   |
| `MSF_RPC_SSL`      | false     | `true` when the daemon uses SSL          |

Start the daemon first:

```bash
msfrpcd -P <password> -a 127.0.0.1 -p 55553
```

Then either export `MSF_RPC_PASSWORD` in your shell or put it in `.env`.
Without it, module 39 returns a clean `MISSING` diagnostic instead of running.

> Keep `.env` out of version control — it is already in `.gitignore`.

## Seeker environment overrides

The Seeker module (`scripts/seeker.py`) accepts defaults via environment
variables:

| Variable                  | Default    | Purpose                          |
| ------------------------- | ---------- | -------------------------------- |
| `SEEKER_DEFAULT_TEMPLATE` | `NearYou`  | Template used when none is given |
| `SEEKER_DEFAULT_PORT`     | `8080`     | Local port for the seeker page   |
| `SEEKER_TIMEOUT`          | `60`       | Seconds to wait for the link     |
| `SEEKER_PATH`             | bundled    | Path to upstream `seeker.py`     |

## Colour output

Colour is enabled only on a real TTY and honours the `NO_COLOR` convention:

- `NO_COLOR=1` — always disable colour
- piping stdout (`talos | tee run.log`) — colour disabled automatically

Pipes and redirected runs also switch live progress bars to milestone log
lines so logs stay clean.

## Self-healing dependencies

`main.py` and `ui.py` re-check `requirements.txt` on every launch:

- `python ui.py --yes` — install anything missing without prompting
- `python ui.py --check-deps` — report what is missing and exit
- `python ui.py --no-install` — launch anyway if core deps exist

Core deps (`textual`, `pydantic`) must be present to start the UI; optional
deps like `pymetasploit3` only matter for the modules that use them and show
up as `MISSING` in the readiness report until installed.

## Data scraper / Seeker ports

Both servers bind to **all interfaces** by design (module 40 prints the LAN
URL so other devices can connect). Pick a port that is free on your network:

```bash
python scripts/data_scraper.py --port 8080
python scripts/seeker.py --template NearYou --port 8081
```

`0.0.0.0` is only a bind address — never type it into a browser. Use
`127.0.0.1:<port>` locally or the printed LAN address from another device.

## Public exposure

For a public URL instead of LAN access:

- Data Scraper: `--ngrok` (requires the `ngrok` binary) or `ssh -R` tunnel
- Seeker: `--tunnel` flag (ngrok)

Both are opt-in; nothing is exposed publicly unless you ask for it.

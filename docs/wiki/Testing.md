# Testing

## The self-test

`scripts/self_test.py` is Talos' built-in end-to-end test suite. It exercises
the real engines, not mocks where real behaviour matters:

```bash
python scripts/self_test.py           # full run (needs network for some modules)
python scripts/self_test.py --no-net  # skip internet-only modules
```

**Exit code `0` = no failures.** Anything else means at least one check
failed — the failing section prints its own diagnostics, and the run is
audited like any other module run.

## What it covers

| Area | How |
| ---- | --- |
| nmap engine | Real `nmap` run against localhost; parses the XML result |
| HTTP brute-force | Mock HTTP login server started locally; verifies hit detection (form + basic) |
| Metasploit | Graceful-degradation check — returns clean `MISSING`/`UNAVAILABLE` `ToolResult` when no daemon is up |
| Data scraper | Server boots, serves the diagnostics page, blocker check runs |
| All 40 menu modules | Driven with scripted input so prompts execute without a human |

`--no-net` skips the modules that require external services (ipify, Veriphone,
crt.sh, RDAP, Wayback, …) so it works in air-gapped CI and offline labs.

## When to run it

- **After a fresh install** — proves the venv, binaries and imports line up.
- **After changing a module** — catch regressions before they reach the menu.
- **Before filing a bug** — see
  [Troubleshooting → Self-test before filing a bug](Troubleshooting).
- **In CI** — `--no-net` is deterministic enough for pipelines.

## Interpreting failures

| Symptom | Likely cause |
| ------- | ------------ |
| nmap section fails, rest passes | `nmap` binary missing/broken — `apt install nmap` |
| brute-force section fails | port 8080-range busy or local firewall blocks loopback connect |
| Metasploit "failure" | it must return a clean degraded result — a raise means the wrapper broke |
| Everything fails immediately | Python/env broken — `python ui.py --check-deps` |

Each failed check names its module; pair the output with
`logs/error.log` (see [Logging & Audit Trail](Logging-and-Audit-Trail)).

# Logging & Audit Trail

Talos writes three log files next to the code (the install prefix for a
global install):

```
logs/
├── toolkit.log    rotating debug/activity log
├── audit.jsonl    one JSON line per finished ToolResult run (rotating)
└── error.log      full tracebacks of any module failure (timestamped)
```

The directory is created on first run and is already covered by `.gitignore`
— logs are runtime artifacts, never committed.

## `toolkit.log` — activity log

A rotating log of everything the tool does at debug/info level: module
discovery at startup (`loaded N module(s): …`), each execution
(`executing module=nmap_vuln`), and the finish line with status and duration:

```
module=37 title=Nmap Vulnerability Scan elapsed_ms=41211.083
    result_keys_added=['nmap_vuln'] total_result_sets=2
```

Use it to reconstruct *when* a module ran and *what* it touched in the
session.

## `audit.jsonl` — the audit trail

One JSON object per finished `ToolResult`, appended (rotating). Typical
shape:

```json
{"module": "nmap_vuln", "status": "SUCCESS", "duration_ms": 41211.0,
 "ok": true, "timestamp_utc": "2026-09-10T12:00:00Z"}
```

Because every entry point (menu, TUI, standalone scripts) funnels through the
same orchestrator, `audit.jsonl` is the single source of truth for *what ran,
where, and how it ended*. Grep it for incident review:

```bash
grep '"module": "http_bruteforce"' logs/audit.jsonl
grep '"ok": false' logs/audit.jsonl | tail
```

## `error.log` — tracebacks

Any module exception that escapes its own handler is caught by the menu
guard, shown to the user as one short `[x] …` line, and written here with a
timestamp and full traceback:

```
[2026-09-10 12:03:44 UTC] module=08 Website Info Scanner
Traceback (most recent call last):
  ...
ConnectionError: ...
```

**Start here when something breaks** — see
[Troubleshooting](Troubleshooting).

## Rotation

All three files rotate by size so long sessions cannot fill a disk. Rotation
keeps a bounded number of historical files next to the current one.

## Clean output for pipes

When stdout is not a TTY (or `NO_COLOR=1`):

- colour codes are disabled automatically;
- live bars degrade to milestone lines (`[..] 128/253 (50.6%) …`) at each
  25 % boundary instead of redrawing with `\r`;
- the rendered `ToolResult` reports contain no ANSI codes at all.

So `talos | tee run.log` and cron captures stay readable — see
[Troubleshooting → UI/terminal rendering](Troubleshooting).

## Reading a run end-to-end

1. `toolkit.log` — discovery + execution + finish lines.
2. `audit.jsonl` — the structured verdict (status, duration, ok).
3. `error.log` — only if something raised.

Together they answer *what ran, when, how long, with what outcome, and with
which session keys added*.

# Architecture

Talos is one engine with three faces: the numbered menu CLI, the Textual TUI,
and standalone scripts. This page explains the machinery they share.

## Layer map

```
┌────────────────────────────────────────────────────────────┐
│  entrypoints:  main.py (menu)   ui.py (TUI)   scripts/*    │
├────────────────────────────────────────────────────────────┤
│  src/core/     menu engine · formatting · progress ·       │
│                report renderer · tables · session context  │
├────────────────────────────────────────────────────────────┤
│  src/orchestrator.py   discovery · immutable Context ·     │
│                        safe execution · audit              │
├────────────────────────────────────────────────────────────┤
│  src/modules/  network_scan · osint_scan · security ·      │
│                utilities(+extra) · attack · data_scraper · │
│                seeker · nmap_wrapper · metasploit_wrapper  │
├────────────────────────────────────────────────────────────┤
│  src/models/tool_result.py · src/errors/registry.py ·      │
│  src/runner/subprocess_runner.py · src/logging_utils.py    │
└────────────────────────────────────────────────────────────┘
```

## The Orchestrator

`src/orchestrator.py` owns execution. For every run it:

1. **Discovers modules** — walks `src/modules` via `pkgutil`, imports each
   package, and registers every `BaseModule` subclass with a non-empty
   `NAME`. A broken module package is skipped with a warning, never fatal.
2. **Preflights** — calls `validate_environment()` on the class. A missing
   binary/library/service raises `ToolError(MISSING)`, which becomes a
   `ToolResult` with a clean diagnostic — the menu never crashes because a
   tool is absent.
3. **Copies the Context** — the module receives `copy.deepcopy()` of the
   current Context (plus any params). The authoritative copy is only ever
   *replaced wholesale on commit*, never mutated in place.
4. **Validates writes** — modules may only write top-level keys in
   `ALLOWED_CONTEXT_KEYS = {target, ports, options, results, session, state}`.
   Added keys outside the allow-list (or a `KeyError`) revert the Context to
   the previous snapshot and mark the result
   `context_reverted=True`.
5. **Audits** — appends the finished result to `logs/audit.jsonl`
   (see [Logging & Audit Trail](Logging-and-Audit-Trail)).

Never raises for tool-level failures: every path returns a `ToolResult`.

## ToolResult

`src/models/tool_result.py` (Pydantic v2) is the universal return type:

| Field | Meaning |
| ----- | ------- |
| `module` | module name |
| `status` | `SUCCESS` / `ERROR` / `TIMEOUT` / `UNAVAILABLE` / … |
| `ok` | convenience bool derived from status |
| `data` | structured payload rendered by the report layer |
| `raw_stdout` / `raw_stderr` | captured subprocess output |
| `duration_ms` | wall time |
| `error_category` | see below |

`src/core/report.py` renders any `ToolResult` into the same human-readable
report for the menu, TUI and scripts — with dedicated renderers for nmap,
Metasploit, brute-force and auto-audit, and a generic key/value renderer for
everything else. Rendered text is intentionally ANSI-free.

## Error categories

`src/errors/registry.py` classifies `ToolError`s:

| Category | Typical cause |
| -------- | ------------- |
| `MISSING` | binary/library/service absent (nmap, msfrpcd, requests…) |
| `PARSE` | bad parameters, unreadable wordlist/file, malformed input |
| `AUTH` | RPC/authentication failures |
| `RESOURCE` | network/socket/subprocess failures |
| `TIMEOUT` | a bounded operation ran out of time |

Categories appear in diagnostics and in `audit.jsonl`, so triage is a grep —
see [Troubleshooting](Troubleshooting).

## Progress sinks (no UI imports in engines)

Engine modules never import UI code. They call
`self.report_progress(message, fraction)`; the runner attaches a sink:

| Runner | Sink |
| ------ | ---- |
| Menu CLI / scripts | `src.core.progress.cli_sink` — live `\r` bar on a TTY, milestone lines otherwise |
| TUI | a thread-safe sink that posts events to a Textual queue |
| none | no-op — a broken sink can never kill a module |

## Session Context (`src/core/context.py`)

One `Session` lives for the whole menu run:

- `target_ip` / `target_domain` — the current target, set by scans and reused
  as prompt defaults;
- `scan_results` — the module→module hand-off dictionary (`my_ip`,
  `alive_hosts`, `open_ports`, `subdomains`, `emails`, …);
- `summary()` — the one-line status under the banner.

Note the two "context" concepts: the orchestrator's **engine Context**
(allow-listed dict passed to engine modules) and the menu **Session** (user
facing state). Menu wrapper functions bridge them.

## Subprocess & network discipline

- every `subprocess.run` carries a `timeout` and captures stdout/stderr;
- every network request carries a timeout;
- third-party libraries are imported lazily, so a missing package or dead
  network surfaces as a `ToolResult`, not a crash;
- the nmap engine runs the **binary** (located via `shutil.which`) and parses
  its XML with the standard library — no python-nmap dependency.

## Module contract

Write your own module by subclassing `BaseModule`:

```python
from src.orchestrator import BaseModule

class MyModule(BaseModule):
    NAME = "my_module"
    DESCRIPTION = "does a thing"

    @classmethod
    def validate_environment(cls) -> None:
        ...  # raise ToolError(MISSING) when prerequisites are absent

    def run(self, context) -> ToolResult:
        ...  # read context["target"], write context["results"], return ToolResult
```

Drop it in `src/modules/` and it is discovered, numbered in the menu, audited
and reportable automatically.

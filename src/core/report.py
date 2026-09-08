"""Human-readable report renderer for :class:`~src.models.tool_result.ToolResult`.

Every module (nmap, Metasploit, the attacking modules, ...) returns a
structured :class:`ToolResult`. This renderer turns that structure into a
clean, aligned, detailed text report so the CLI menu, the standalone attack
scripts and the terminal UI all show the exact same high-quality output.

The rendered text is intentionally free of ANSI colour codes: it must look
right in a pipe, a log file and a Textual ``RichLog`` alike.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from src.models.tool_result import ResultStatus, ToolResult

_REPORT_WIDTH = 88
_LINE = "─" * 60


def _wrap(text: str, width: int = _REPORT_WIDTH - 6, indent: str = "    ") -> List[str]:
    """Word-wrap a possibly multiline string into indented report lines."""
    out: List[str] = []
    for raw_line in str(text).splitlines() or [""]:
        words = raw_line.split()
        if not words:
            out.append(indent)
            continue
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if len(candidate) <= width:
                current = candidate
            else:
                out.append(indent + current)
                current = word
        out.append(indent + current)
    return out


def _kv_rows(rows: Iterable[Tuple[str, Any]]) -> List[str]:
    """Render key/value pairs as one aligned two-column report block."""
    items = [(str(k), _value_text(v)) for k, v in rows]
    if not items:
        return ["  (no details)"]
    width = max(len(k) for k, _ in items)
    lines: List[str] = []
    for key, value in items:
        value_lines = value.splitlines() or [""]
        lines.append(f"  {key.ljust(width)} : {value_lines[0]}")
        for extra in value_lines[1:]:
            lines.append(" " * (width + 5) + extra)
    return lines


def _value_text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, (dict, list)):
        return _compact(value)
    return str(value)


def _compact(value: Any, depth: int = 0) -> str:
    """Flatten small nested structures to one readable line."""
    if isinstance(value, dict):
        if not value:
            return "{}"
        parts = [f"{k}={_compact(v, depth + 1)}" for k, v in value.items()]
        return ", ".join(parts) if depth else " · ".join(parts)
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        return ", ".join(_compact(v, depth + 1) for v in value)
    return str(value)


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> List[str]:
    """Minimal aligned table (same spirit as core/table, no colours)."""
    data: List[List[str]] = [[str(h) for h in headers]]
    for row in rows:
        values = [str(v) if v is not None else "-" for v in row]
        values = (values + [""] * len(headers))[: len(headers)]
        data.append(values)
    if len(data) <= 1:
        return ["  (no rows)"]
    widths = [max(len(cell) for cell in col) for col in zip(*data)]
    lines: List[str] = []
    for index, row in enumerate(data):
        padded = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        if index == 0:
            lines.append("  " + padded)
            lines.append("  " + "  ".join("-" * widths[i] for i in range(len(headers))))
        else:
            lines.append("  " + padded)
    return lines


def _heading(title: str) -> List[str]:
    return ["", _LINE, f"  {title}", _LINE]


def _script_block(label: str, script_id: str, output: str) -> List[str]:
    lines = [f"  {label} {script_id}:"]
    lines.extend(_wrap(output, width=_REPORT_WIDTH - 8, indent="      "))
    return lines


# ---------------------------------------------------------------------------
# module-specific renderers
# ---------------------------------------------------------------------------
def _render_nmap(data: Dict[str, Any], module: str) -> List[str]:
    title = "NMAP VULNERABILITY SCAN" if module == "nmap_vuln" else "NMAP SCAN REPORT"
    lines = _heading(title)

    meta: List[Tuple[str, Any]] = []
    if data.get("command"):
        meta.append(("command", data["command"]))
    if data.get("scan_end"):
        meta.append(("scan finished", data["scan_end"]))
    meta.append(("hosts up", data.get("hosts_up", 0)))
    meta.append(("open ports", data.get("open_ports", 0)))
    meta.append(("output parsed via", data.get("parse_method", "?")))
    lines.extend(_kv_rows(meta))
    if data.get("degraded"):
        lines.append("  [!] XML parsing failed — results were recovered from the plaintext output.")
    if data.get("note"):
        lines.extend(_wrap(data["note"], indent="  "))

    hosts = data.get("hosts") or []
    if not hosts:
        lines.append("")
        lines.append("  No live hosts / no open ports were present in the scan output.")
        return lines

    for index, host in enumerate(hosts):
        name = host.get("hostname") or host.get("host") or "?"
        ip = host.get("ip") or ""
        label = f"{name} ({ip})" if ip and name != ip else (name or ip or "unknown")
        lines.append("")
        lines.append(f"  --- host {index + 1}: {label} ---")
        if host.get("mac"):
            lines.append(f"      mac address     : {host['mac']}")
        ports = host.get("ports") or []
        if ports:
            rows: List[List[Any]] = []
            for port in ports:
                version = port.get("version") or ""
                product = port.get("product") or ""
                version_text = " ".join(x for x in (product, version) if x)
                rows.append(
                    [
                        f"{port.get('port')}/{port.get('protocol', 'tcp')}",
                        port.get("state", ""),
                        port.get("service", ""),
                        version_text,
                    ]
                )
            lines.extend(_table(["port", "state", "service", "version"], rows))
            for port in ports:
                for script in port.get("scripts") or []:
                    lines.extend(_script_block("[script]", script.get("id", "?"), script.get("output", "")))
        else:
            lines.append("      (no open ports listed)")
        for script in host.get("host_scripts") or []:
            lines.extend(_script_block("[host script]", script.get("id", "?"), script.get("output", "")))
        for raw_nse in host.get("nse_lines") or []:
            lines.append(f"      {raw_nse}")
    lines.append("")
    return lines


def _render_metasploit(data: Dict[str, Any]) -> List[str]:
    lines = _heading("METASPLOIT MODULE RUN")
    module_name = data.get("module") or "?"
    module_type = data.get("module_type") or "?"
    lines.extend(
        _kv_rows(
            [
                ("module", f"{module_type}/{module_name}"),
                ("job id", data.get("job_id", "-")),
            ]
        )
    )
    datastore = data.get("datastore") or {}
    if datastore:
        lines.append("")
        lines.append("  datastore options:")
        lines.extend(_kv_rows(sorted(datastore.items())))
    response = data.get("response")
    if response:
        lines.append("")
        lines.append("  module response:")
        lines.extend(_wrap(response, indent="    "))
        if data.get("response_truncated"):
            lines.append("    ... [response truncated]")
    lines.append("")
    return lines


def _render_bruteforce(data: Dict[str, Any]) -> List[str]:
    lines = _heading("HTTP LOGIN BRUTE-FORCE")
    hits = data.get("found") or []
    confirmed = [hit for hit in hits if hit.get("confidence") == "confirmed"]
    candidates = [hit for hit in hits if hit.get("confidence") != "confirmed"]
    meta: List[Tuple[str, Any]] = [
        ("url", data.get("url") or "-"),
        ("method", data.get("mode") or "-"),
        ("username(s)", data.get("users") or "-"),
        ("password wordlist", data.get("wordlist") or "(built-in default)"),
        ("attempts", data.get("attempts", 0)),
        ("confirmed credential(s)", len(confirmed)),
        ("candidate result(s)", len(candidates)),
    ]
    if data.get("note"):
        meta.append(("note", data["note"]))
    lines.extend(_kv_rows(meta))
    lines.append("")
    if hits:
        rows = [[h.get("username", "?"), h.get("password", "?"), h.get("detail", "")] for h in hits]
        lines.extend(_table(["username", "password", "detail"], rows))
        lines.append("")
        if confirmed:
            lines.append("  [+] confirmed by the configured success check; verify against the live service.")
        if candidates:
            lines.append("  [!] candidate responses require manual verification; they are not proof of valid credentials.")
    else:
        if data.get("attempts"):
            lines.append("  No confirmed credentials were found in the tested wordlist(s).")
        else:
            lines.append("  Nothing was attempted (missing parameters?).")
    lines.append("")
    return lines


def _render_auto_audit(data: Dict[str, Any]) -> List[str]:
    """Render the read-only vulnerability audit report.

    Every detected service is listed with its banner and a per-port status:
    the matching CVE(s) when the knowledge base flagged it, otherwise
    "no known issue".  Findings are then detailed below the table.
    """
    lines = _heading("AUTO VULNERABILITY AUDIT")
    summary = data.get("summary") or {}
    hosts = data.get("hosts") or []
    findings = data.get("findings") or []

    meta: List[Tuple[str, Any]] = [
        ("target", data.get("target") or "-"),
        ("hosts up", data.get("hosts_up", 0)),
        ("open ports", data.get("open_ports", 0)),
        ("os fingerprint", data.get("os_status") or ("yes" if data.get("os_detected") else "no")),
        ("findings", summary.get("total", 0)),
        ("critical", summary.get("critical", 0)),
        ("high", summary.get("high", 0)),
        ("medium", summary.get("medium", 0)),
        ("low", summary.get("low", 0)),
    ]
    lines.extend(_kv_rows(meta))
    if data.get("note"):
        lines.extend(_wrap(data["note"], indent="  "))

    # ---- services table: one row per detected service, with status ----
    if hosts:
        lines.append("")
        lines.append("  detected services:")
        for host in hosts:
            name = host.get("hostname") or host.get("host") or "?"
            ip = host.get("ip") or ""
            label = f"{name} ({ip})" if ip and name != ip else (name or ip or "unknown")
            lines.append("")
            lines.append(f"  --- host: {label} ---")
            if host.get("os_guess"):
                lines.append(f"      os guess  : {host.get('os_guess')} "
                             f"(accuracy {host.get('os_accuracy')}%)")
            ports = host.get("ports") or []
            if not ports:
                lines.append("      (no open ports detected)")
                continue
            rows: List[List[Any]] = []
            for port in ports:
                port_label = _port_label(port)
                status = _port_status(port_label, findings)
                product_version = " ".join(
                    x for x in (port.get("product"), port.get("version")) if x
                )
                rows.append([
                    port_label,
                    port.get("service") or "-",
                    product_version or "-",
                    status,
                ])
            lines.extend(_table(["port", "service", "product/version", "status"], rows))
    else:
        lines.append("")
        lines.append("  No live hosts / no open ports were present in the scan output.")
        lines.append("")
        return lines

    # ---- details for every flagged service ---------------------------
    if not findings:
        lines.append("")
        lines.append("  No known-issue matches for the detected services (banner-based check).")
        lines.append("")
        return lines

    lines.append("")
    lines.append("  flagged services (details):")
    for index, finding in enumerate(findings, start=1):
        lines.append("")
        lines.append(f"  {index}. [{finding.get('severity', 'info').upper()}] "
                     f"{finding.get('title', '')}")
        lines.append(f"      host      : {finding.get('host') or finding.get('ip') or '-'}")
        lines.append(f"      port      : {finding.get('port') or '-'}")
        lines.append(f"      service   : {finding.get('service') or '-'}")
        if finding.get("product") or finding.get("version"):
            lines.append(f"      product   : {' '.join(x for x in (finding.get('product'), finding.get('version')) if x)}")
        if finding.get("detail"):
            lines.extend(_wrap(finding["detail"], indent="      "))
        if finding.get("cve"):
            lines.append(f"      cve       : {finding['cve']}")
        if finding.get("reference"):
            lines.append(f"      reference : {finding['reference']}")
        lines.append(f"      confidence: {finding.get('confidence') or 'candidate'}")
    lines.append("")
    return lines


def _port_label(port: Dict[str, Any]) -> str:
    """``22/tcp`` style label for a port dict from the nmap parser."""
    return f"{port.get('port')}/{port.get('protocol', 'tcp')}"


def _port_status(port_label: str, findings: List[Dict[str, Any]]) -> str:
    """Short per-port status: CVE(s) when flagged, else 'no known issue'."""
    port_findings = [f for f in findings if f.get("port") == port_label]
    if not port_findings:
        return "no known issue (banner-based)"
    parts: List[str] = []
    for finding in port_findings:
        severity = str(finding.get("severity", "info")).upper()
        cve = finding.get("cve")
        if cve:
            parts.append(f"{severity} — {cve}")
        else:
            parts.append(f"{severity} — {finding.get('title', 'flagged')}")
    return "; ".join(dict.fromkeys(parts))  # dedupe, keep order


def _render_generic(data: Dict[str, Any], module: str) -> List[str]:
    lines = _heading(f"{module.upper().replace('_', ' ')} — REPORT")
    if not data:
        lines.append("  (result carried no structured data)")
        lines.append("")
        return lines
    for key, value in sorted(data.items()):
        if key in ("raw_stdout", "raw_stderr"):
            continue
        lines.extend(_kv_rows([(key, value)]))
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def render_result(result: ToolResult) -> List[str]:
    """Return the full human-readable report for a finished ToolResult.

    Error / timeout / unavailable results are rendered as a short, clear
    diagnostic block instead of a structured report.
    """
    data = result.data or {}
    if result.status == ResultStatus.ERROR or (
        result.error_category is not None and not result.ok
    ):
        message = str(data.get("error") or result.raw_stderr or result.status.value)
        lines = _heading(f"FAILED — {result.module.upper()}")
        lines.extend(_wrap(message, indent="  "))
        lines.append("")
        return lines
    if result.status in (ResultStatus.TIMEOUT, ResultStatus.UNAVAILABLE):
        message = str(data.get("error") or result.raw_stderr or result.status.value)
        lines = _heading(f"{result.status.value} — {result.module.upper()}")
        lines.extend(_wrap(message, indent="  "))
        lines.append("")
        return lines

    if result.module == "nmap_vuln":
        return _render_nmap(data, "nmap_vuln")
    if result.module == "nmap":
        return _render_nmap(data, "nmap")
    if result.module == "auto_audit":
        return _render_auto_audit(data)
    if result.module == "metasploit":
        return _render_metasploit(data)
    if result.module == "http_bruteforce":
        return _render_bruteforce(data)
    return _render_generic(data, result.module)


def print_result(result: ToolResult) -> None:
    """Print :func:`render_result` output, one line at a time."""
    for line in render_result(result):
        print(line)

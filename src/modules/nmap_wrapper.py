"""Nmap integration module.

Execution model
---------------
One ``nmap`` invocation produces two artifacts:

* XML on stdout (``-oX -``) — the primary, structured source; and
* plaintext output in a temp file (``-oN <tmp>``) — the fallback source.

The XML is parsed with ``xml.etree.ElementTree`` inside a ``try/except``.
If a ``ParseError`` occurs the module **does not crash**: it falls back to a
pure-regex parser over the plaintext ``-oN`` output. Only when that also
fails is a ``ToolResult`` with ``status="PARTIAL"`` (and ``raw_stdout``
populated) returned — the orchestrator always survives either way.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from src.errors.registry import ErrorCategory, ToolError
from src.logging_utils import get_logger
from src.models.tool_result import ResultStatus, ToolResult
from src.orchestrator import BaseModule
from src.runner.subprocess_runner import SubprocessRunner

_REPORTED_STATES = frozenset({"open", "open|filtered", "filtered"})


class NmapModule(BaseModule):
    """Port scanning via the ``nmap`` CLI, hardened against parse failures."""

    NAME = "nmap"
    DESCRIPTION = "Port scanning and service discovery via the nmap CLI"

    # ------------------------------------------------------------------
    # environment
    # ------------------------------------------------------------------
    @classmethod
    def validate_environment(cls) -> None:
        """Raise ToolError(MISSING) unless the ``nmap`` binary is on PATH."""
        if shutil.which("nmap") is None:
            raise ToolError(
                "nmap binary not found on PATH. Install it with your OS package "
                "manager (e.g. 'apt install nmap', 'brew install nmap', "
                "'choco install nmap').",
                category=ErrorCategory.MISSING,
                module=cls.NAME,
            )

    # ------------------------------------------------------------------
    # execution
    # ------------------------------------------------------------------
    def run(self, context: Dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        target = context.get("target")
        if not target:
            return ToolResult.failed(
                self.NAME,
                "scan requires a 'target' in the context",
                category=ErrorCategory.PARSE,
                duration_ms=_elapsed_ms(start),
            )
        options = dict(context.get("options") or {})
        ports = context.get("ports")

        args: List[str] = ["-oX", "-"]
        plain_handle = tempfile.NamedTemporaryFile(
            prefix="nmap_plain_", suffix=".nmap", delete=False
        )
        plain_path = plain_handle.name
        plain_handle.close()
        try:
            args += ["-oN", plain_path]
            if options.get("service_scan"):
                args.append("-sV")
            if options.get("udp"):
                args.append("-sU")
            if options.get("no_ping"):
                args.extend(["-Pn"])
            if ports:
                args.extend(["-p", str(ports)])
            elif options.get("top_ports"):
                args.extend(["--top-ports", str(options["top_ports"])])
            for extra in options.get("extra_args") or []:
                args.append(str(extra))
            args.append(str(target))

            self.report_progress(f"running nmap against {target}")
            self.report_progress("scan in progress — nmap is executing", None)
            try:
                raw = SubprocessRunner().run("nmap", args, timeout=options.get("timeout"))
            except ToolError as exc:
                return ToolResult.from_tool_error(
                    self.NAME, exc, duration_ms=_elapsed_ms(start)
                )
            self.report_progress("nmap finished — parsing scan output", 0.85)

            plaintext = ""
            try:
                with open(plain_path, "r", encoding="utf-8", errors="replace") as handle:
                    plaintext = handle.read()
            except OSError:
                plaintext = ""
            result = self._build_result(raw, plaintext, args)

            if isinstance(result.data, dict) and not isinstance(result.data.get("error"), str):
                context.setdefault("results", {})[self.NAME] = {
                    "status": result.status.value,
                    "hosts_up": result.data.get("hosts_up"),
                    "open_ports": result.data.get("open_ports"),
                    "uncertain_ports": result.data.get("uncertain_ports"),
                    "parse_method": result.data.get("parse_method"),
                    "degraded": bool(result.data.get("degraded")),
                }
            self.report_progress("scan complete", 1.0)
            return result
        finally:
            try:
                os.unlink(plain_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # interpretation / parsing
    # ------------------------------------------------------------------
    def _build_result(
        self, raw: ToolResult, plaintext: str, args: List[str]
    ) -> ToolResult:
        xml_text = raw.raw_stdout
        parsed: Optional[Dict[str, Any]] = None
        xml_failed = False

        # Primary path: strict XML parsing, wrapped so a ParseError can NEVER
        # crash the process.
        try:
            parsed = self._parse_xml(xml_text)
        except ET.ParseError as exc:
            xml_failed = True
            self.logger.warning(
                "nmap XML parse failed (%s); falling back to plaintext regex parser",
                exc,
            )
            # Fallback path: regex over the -oN plaintext output.
            try:
                parsed = self._parse_plaintext(plaintext or xml_text)
            except Exception as exc2:  # regex fallback must also never crash
                self.logger.warning("plaintext regex fallback failed too: %s", exc2)
                parsed = None

        # A timeout dominates every other interpretation.
        if raw.status == ResultStatus.TIMEOUT:
            data = dict(raw.data or {})
            data.update(
                {
                    "timed_out": True,
                    "note": "nmap was killed by the subprocess runner after its timeout",
                }
            )
            return ToolResult(
                status=ResultStatus.TIMEOUT,
                module=self.NAME,
                data=data,
                raw_stdout=xml_text,
                raw_stderr=raw.raw_stderr,
                duration_ms=raw.duration_ms,
                error_category=ErrorCategory.TIMEOUT,
            )

        if xml_failed and (parsed is None or not parsed.get("hosts")):
            # Both the XML parser AND the plaintext fallback failed to recover
            # any host data: degrade to PARTIAL, keeping raw_stdout populated.
            note = "XML parse failed and the plaintext regex fallback recovered no usable host data"
            return ToolResult(
                status=ResultStatus.PARTIAL,
                module=self.NAME,
                data={
                    "hosts_up": 0,
                    "open_ports": 0,
                    "parse_method": "failed",
                    "note": note,
                },
                raw_stdout=xml_text,
                raw_stderr=(raw.raw_stderr + "\n[module] " + note).strip(),
                duration_ms=raw.duration_ms,
                error_category=ErrorCategory.PARSE,
            )

        data = dict(parsed or {})
        data["degraded"] = bool(xml_failed)
        data["command"] = " ".join(args)
        data["returncode"] = (raw.data or {}).get("returncode")
        if xml_failed:
            data["note"] = "XML parsing failed; results recovered via plaintext regex fallback"

        # nmap exits non-zero for several "fine" reasons (privilege warnings);
        # if we still parsed usable output, degrade to PARTIAL instead of ERROR.
        if raw.status == ResultStatus.SUCCESS:
            status = ResultStatus.SUCCESS
            category: Optional[ErrorCategory] = None
        else:
            status = ResultStatus.PARTIAL
            category = ErrorCategory.PARSE if not data.get("hosts") else None
            note = data.get("note", "")
            data["note"] = (
                note + " nmap exited with a non-zero code but its output was parsed"
            ).strip()

        return ToolResult(
            status=status,
            module=self.NAME,
            data=data,
            raw_stdout=xml_text,
            raw_stderr=raw.raw_stderr,
            duration_ms=raw.duration_ms,
            error_category=category,
        )

    # ------------------------------------------------------------------
    # parsers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_xml(xml_text: str) -> Dict[str, Any]:
        """Parse nmap ``-oX`` XML into a normalized summary dict.

        Raises:
            xml.etree.ElementTree.ParseError: on malformed XML — the caller
            catches this and switches to the plaintext regex parser.
        """
        root = ET.fromstring(xml_text)
        hosts: List[Dict[str, Any]] = []
        for host in root.findall("host"):
            status_el = host.find("status")
            if status_el is None or status_el.get("state") != "up":
                continue
            ipv4 = ""
            ipv6 = ""
            mac = ""
            for addr in host.findall("address"):
                atype = addr.get("addrtype", "")
                value = addr.get("addr", "")
                if atype == "ipv4" and not ipv4:
                    ipv4 = value
                elif atype == "ipv6" and not ipv6:
                    ipv6 = value
                elif atype == "mac" and not mac:
                    mac = value
            ip = ipv4 or ipv6
            hostname = ""
            hostname_el = host.find("hostnames/hostname")
            if hostname_el is not None:
                hostname = hostname_el.get("name", "")

            ports: List[Dict[str, Any]] = []
            for port in host.findall("ports/port"):
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state not in _REPORTED_STATES:
                    continue
                entry: Dict[str, Any] = {
                    "port": port.get("portid"),
                    "protocol": port.get("protocol", ""),
                    "state": state,
                }
                service = port.find("service")
                if service is not None:
                    entry["service"] = service.get("name", "")
                    for key in ("product", "version", "extrainfo"):
                        value = service.get(key)
                        if value:
                            entry[key] = value
                # NSE results attached to this port (vuln scans, http-*, ...).
                scripts = [
                    {"id": s.get("id", ""), "output": (s.get("output") or "").strip()}
                    for s in port.findall("script")
                    if s.get("output")
                ]
                if scripts:
                    entry["scripts"] = scripts
                ports.append(entry)

            # Host-level NSE output (e.g. smb-vuln-* run against the whole host).
            host_scripts = [
                {"id": s.get("id", ""), "output": (s.get("output") or "").strip()}
                for s in host.findall("hostscript/script")
                if s.get("output")
            ]
            host_entry: Dict[str, Any] = {
                "host": ip or hostname or "unknown",
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "state": "up",
                "ports": ports,
            }
            if host_scripts:
                host_entry["host_scripts"] = host_scripts
            hosts.append(host_entry)

        finished = root.find("runstats/finished")
        return {
            "hosts": hosts,
            "hosts_up": len(hosts),
            "open_ports": sum(
                sum(port.get("state") == "open" for port in host["ports"])
                for host in hosts
            ),
            "uncertain_ports": sum(
                sum(port.get("state") in {"open|filtered", "filtered"} for port in host["ports"])
                for host in hosts
            ),
            "scan_end": finished.get("timestr", "") if finished is not None else "",
            "parse_method": "xml",
        }

    @staticmethod
    def _parse_plaintext(text: str) -> Dict[str, Any]:
        """Regex parser over nmap ``-oN`` plaintext output.

        Recovers hosts plus their open ports. Designed to never raise: on
        garbage input it simply returns an empty summary.
        """
        host_header = re.compile(r"^Nmap scan report for (.*)$")
        port_line = re.compile(r"^(\d+)/(tcp|udp)\s+(\S+)\s*(.*)$")
        hosts: List[Dict[str, Any]] = []
        current: Optional[Dict[str, Any]] = None

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = host_header.match(line)
            if match:
                content = match.group(1).strip()
                name, ip = content, ""
                inner = re.match(r"^(.*?)\s+\(([^)]+)\)$", content)
                if inner:
                    name, ip = inner.group(1).strip(), inner.group(2).strip()
                current = {
                    "host": ip or name or "unknown",
                    "ip": ip,
                    "mac": "",
                    "hostname": name if ip else "",
                    "state": "up",
                    "ports": [],
                }
                hosts.append(current)
                continue

            port_match = port_line.match(line)
            if port_match is not None and current is not None:
                state = port_match.group(3)
                if state not in _REPORTED_STATES:
                    continue
                entry: Dict[str, Any] = {
                    "port": port_match.group(1),
                    "protocol": port_match.group(2),
                    "state": state,
                }
                rest = port_match.group(4).strip()
                if rest:
                    tokens = rest.split()
                    entry["service"] = tokens[0]
                    if len(tokens) > 1:
                        entry["version"] = " ".join(tokens[1:])
                current["ports"].append(entry)
                continue

            # NSE script output lines ("|_...", "| ...") belong to the current
            # host section; keep them so vuln/script scans stay informative
            # even when the XML stream was unusable.
            if line.startswith("|") and current is not None:
                current.setdefault("nse_lines", []).append(line)

        return {
            "hosts": hosts,
            "hosts_up": len(hosts),
            "open_ports": sum(
                sum(port.get("state") == "open" for port in host["ports"])
                for host in hosts
            ),
            "uncertain_ports": sum(
                sum(port.get("state") in {"open|filtered", "filtered"} for port in host["ports"])
                for host in hosts
            ),
            "scan_end": "",
            "parse_method": "regex-fallback",
        }


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0

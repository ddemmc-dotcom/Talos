"""TALOS — AUTO VULNERABILITY AUDIT (read-only, report-only).

One nmap run gathers ports, service versions (``-sV``) and — when permitted —
an OS fingerprint (``-O``).  The banners are then cross-referenced against
small built-in knowledge bases:

* **outdated services**  — versions with published CVEs or past end-of-life
  (OpenSSH regreSSHion, Apache httpd path traversal, vsftpd backdoor, ...);
* **default configurations** — products that commonly ship with default or
  blank credentials (routers, IPMI, Tomcat manager, Grafana, Redis, ...);
* **weak-authentication surfaces** — read-only NSE checks (``ssh-auth-methods``,
  ``ftp-anon``, ``http-default-accounts``) that detect *whether* weak
  credentials may be accepted, without ever attempting an exploit;
* **end-of-life operating systems** — Windows Server 2003–2012, Windows 7/XP,
  Ubuntu 16.04–20.04, Debian 8–10, CentOS 6/7, ancient Linux kernels, ...

The module is deliberately non-intrusive: it runs ``nmap -sV`` plus read-only
NSE scripts, never modifies the target, never brute-forces, and never
exploits.  Every finding is a **candidate** (banner-based) that must be
verified manually before any action is taken.

Engine contract: a :class:`~src.models.tool_result.ToolResult` whose ``data``
holds ``hosts`` (with per-port ``findings``), a ``summary`` of severity
counts and a plain-language ``note``.  The same report is rendered by the CLI
menu, the TUI and the standalone ``scripts/auto_audit.py`` runner.
"""
from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from src.errors.registry import ErrorCategory
from src.models.tool_result import ResultStatus, ToolResult
from src.modules.nmap_wrapper import NmapModule

#: Read-only NSE scripts used to detect weak-auth surfaces.  These scripts
#: only *check* for well-known default accounts / auth methods; they never
#: run an exploit or a brute-force wordlist.
DEFAULT_NSE_SCRIPTS = "ssh-auth-methods,ftp-anon,http-default-accounts"

#: Severity ordering used when sorting findings (lowest value = most severe).
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ===========================================================================
# version comparison helpers
# ===========================================================================
def _version_tuple(text: str) -> Tuple[int, ...]:
    """Extract the numeric components of a version string.

    ``"8.2p1"`` -> ``(8, 2, 1)``, ``"10.4.24-MariaDB"`` -> ``(10, 4, 24)``.
    """
    return tuple(int(part) for part in re.findall(r"\d+", text or ""))


def _cmp_versions(first: Tuple[int, ...], second: Tuple[int, ...]) -> int:
    """Compare two numeric version tuples, padding the shorter with zeros."""
    length = max(len(first), len(second))
    a = first + (0,) * (length - len(first))
    b = second + (0,) * (length - len(second))
    return (a > b) - (a < b)


def _version_matches(version: str, check: Dict[str, Any]) -> bool:
    """Apply one version rule (eq / ge / lt) to a banner version string."""
    parsed = _version_tuple(version)
    if not parsed:
        return False
    if "eq" in check:
        return _cmp_versions(parsed, _version_tuple(str(check["eq"]))) == 0
    if "ge" in check and _cmp_versions(parsed, _version_tuple(str(check["ge"]))) < 0:
        return False
    if "lt" in check and _cmp_versions(parsed, _version_tuple(str(check["lt"]))) >= 0:
        return False
    return True


# ===========================================================================
# knowledge bases (candidate rules — banner-based, always verify manually)
# ===========================================================================
#: Outdated / vulnerable service versions.  ``product`` is matched as a
#: case-insensitive substring of the nmap product banner.
_VERSION_RULES: List[Dict[str, Any]] = [
    {
        "product": "openssh",
        "title": "OpenSSH regreSSHion (RCE) candidate",
        "checks": [
            {
                "ge": "8.5", "lt": "9.8", "severity": "high",
                "cve": "CVE-2024-6387",
                "detail": "OpenSSH 8.5p1–9.7p1 is affected by CVE-2024-6387 "
                          "(unauthenticated remote code execution under specific "
                          "conditions). Upgrade to 9.8p1 or later.",
            },
            {
                "lt": "8.5", "severity": "medium",
                "detail": "OpenSSH older than 8.5 is past its support window and "
                          "carries multiple known vulnerabilities. Upgrade to a "
                          "current release.",
            },
        ],
    },
    {
        "product": "apache httpd",
        "title": "Apache httpd path traversal candidate",
        "checks": [
            {
                "eq": "2.4.49", "severity": "critical", "cve": "CVE-2021-41773",
                "detail": "Apache httpd 2.4.49 is affected by CVE-2021-41773 "
                          "(path traversal that can escalate to RCE). Upgrade to "
                          "2.4.51+.",
            },
            {
                "eq": "2.4.50", "severity": "high", "cve": "CVE-2021-42013",
                "detail": "Apache httpd 2.4.50 is affected by CVE-2021-42013 "
                          "(path traversal bypass of the 2.4.49 fix). Upgrade to "
                          "2.4.51+.",
            },
            {
                "lt": "2.4.49", "severity": "medium",
                "detail": "Apache httpd older than 2.4.49 is outdated and may "
                          "carry known vulnerabilities. Upgrade to a current "
                          "release.",
            },
        ],
    },
    {
        "product": "vsftpd",
        "title": "vsftpd backdoor candidate",
        "checks": [
            {
                "eq": "2.3.4", "severity": "critical", "cve": "CVE-2011-2523",
                "detail": "vsftpd 2.3.4 contains a backdoor that grants an "
                          "interactive shell on port 6200. Remove or upgrade "
                          "immediately.",
            },
        ],
    },
    {
        "product": "proftpd",
        "title": "ProFTPD mod_copy RCE candidate",
        "checks": [
            {
                "ge": "1.3.3", "lt": "1.3.6", "severity": "high",
                "cve": "CVE-2015-3306",
                "detail": "ProFTPD 1.3.3c–1.3.5b is affected by CVE-2015-3306 "
                          "(unauthenticated copy of arbitrary files via "
                          "mod_copy). Upgrade to 1.3.6+.",
            },
        ],
    },
    {
        "product": "exim",
        "title": "Exim remote command execution candidate",
        "checks": [
            {
                "lt": "4.93", "severity": "high", "cve": "CVE-2019-10149",
                "detail": "Exim 4.87–4.92 is affected by CVE-2019-10149 "
                          "(remote command execution). Upgrade to 4.93+.",
            },
        ],
    },
    {
        "product": "openssl",
        "title": "OpenSSL end-of-life candidate",
        "checks": [
            {
                "lt": "1.1.2", "severity": "medium",
                "detail": "OpenSSL 1.1.1 and older reached end-of-life (1.1.1 "
                          "EOL September 2023). Upgrade to OpenSSL 3.x.",
            },
        ],
    },
    {
        "product": "php",
        "title": "PHP end-of-life candidate",
        "checks": [
            {
                "lt": "8.1", "severity": "medium",
                "detail": "PHP 8.0 and older are end-of-life (8.0 EOL November "
                          "2023) and no longer receive security fixes. Upgrade "
                          "to a supported branch.",
            },
        ],
    },
    {
        "product": "nginx",
        "title": "nginx outdated candidate",
        "checks": [
            {
                "lt": "1.18", "severity": "low",
                "detail": "nginx older than 1.18 is outdated. Upgrade to a "
                          "current stable release.",
            },
        ],
    },
    {
        "product": "apache tomcat",
        "title": "Apache Tomcat end-of-life candidate",
        "checks": [
            {
                "lt": "9", "severity": "medium",
                "detail": "Apache Tomcat 8.x and older are end-of-life (8.5 EOL "
                          "March 2024). Upgrade to a supported branch.",
            },
        ],
    },
    {
        "product": "samba",
        "title": "Samba remote code execution candidate",
        "checks": [
            {
                "lt": "4.13.17", "severity": "high", "cve": "CVE-2021-44142",
                "detail": "Samba below 4.13.17 is affected by CVE-2021-44142 "
                          "(heap overflow in vfs_fruit, RCE). Upgrade to a "
                          "patched release.",
            },
        ],
    },
    {
        "product": "mysql",
        "title": "MySQL end-of-life candidate",
        "checks": [
            {
                "lt": "8.0", "severity": "medium",
                "detail": "MySQL 5.x is end-of-life (5.7 EOL October 2023) and "
                          "no longer receives security fixes. Upgrade to 8.x.",
            },
        ],
    },
    {
        "product": "mariadb",
        "title": "MariaDB end-of-life candidate",
        "checks": [
            {
                "lt": "10.6", "severity": "medium",
                "detail": "MariaDB 10.5 and older reached end-of-life. Upgrade "
                          "to a supported branch.",
            },
        ],
    },
    {
        "product": "postgresql",
        "title": "PostgreSQL end-of-life candidate",
        "checks": [
            {
                "lt": "12", "severity": "medium",
                "detail": "PostgreSQL 11 and older are end-of-life (11 EOL "
                          "November 2023). Upgrade to a supported major.",
            },
        ],
    },
    {
        "product": "microsoft iis",
        "title": "Microsoft IIS outdated candidate",
        "checks": [
            {
                "lt": "10", "severity": "medium",
                "detail": "IIS 8.5 and older are end-of-life (8.5 EOL October "
                          "2023). Upgrade to IIS 10 on a supported Windows "
                          "Server.",
            },
        ],
    },
]

#: Products that frequently ship with default / blank credentials.  These are
#: banner-based candidates only — no login is ever attempted.
_DEFAULT_CONFIG_RULES: List[Dict[str, Any]] = [
    {"match": "mikrotik", "severity": "high",
     "detail": "MikroTik RouterOS devices commonly ship with a blank or "
               "well-known default admin password. Verify the admin "
               "credentials are not left at their factory defaults."},
    {"match": "tp-link", "severity": "medium",
     "detail": "Many TP-LINK devices ship with default admin credentials "
               "(e.g. admin/admin). Verify they were changed."},
    {"match": "d-link", "severity": "medium",
     "detail": "Many D-Link devices ship with default admin credentials. "
               "Verify they were changed."},
    {"match": "netgear", "severity": "medium",
     "detail": "Many NETGEAR devices ship with default admin credentials "
               "(e.g. admin/password). Verify they were changed."},
    {"match": "integrated lights-out", "severity": "high",
     "detail": "HP iLO management interface detected — these commonly ship "
               "with default admin credentials. Verify and change them."},
    {"match": "idrac", "severity": "high",
     "detail": "Dell iDRAC management interface detected — older models ship "
               "with default root/calvin credentials. Verify and change them."},
    {"match": "super micro", "severity": "high",
     "detail": "SuperMicro IPMI/BMC detected — commonly ships with default "
               "ADMIN/ADMIN credentials. Verify and change them."},
    {"match": "apache tomcat", "severity": "medium",
     "detail": "Tomcat's manager app historically ships with default "
               "tomcat/tomcat credentials. Verify the manager and host-manager "
               "roles are not left at defaults."},
    {"match": "jenkins", "severity": "medium",
     "detail": "Jenkins exposes an initial admin token and may be configured "
               "with weak credentials. Verify authentication is enforced."},
    {"match": "grafana", "severity": "medium",
     "detail": "Grafana defaults to admin/admin on first run. Verify the "
               "default account was changed."},
    {"match": "kibana", "severity": "medium",
     "detail": "Kibana may be exposed without authentication. Verify access "
               "control is configured."},
    {"match": "elasticsearch", "severity": "medium",
     "detail": "Elasticsearch is unauthenticated by default (pre-8.x / without "
               "security enabled). Verify authentication is enforced."},
    {"match": "mongodb", "severity": "high",
     "detail": "MongoDB has no authentication by default. Verify "
               "authorization is enabled and the instance is not exposed "
               "without credentials."},
    {"match": "redis", "severity": "high",
     "detail": "Redis has no authentication by default and can be abused for "
               "RCE when exposed. Verify requirepass is set or access is "
               "restricted."},
    {"match": "memcached", "severity": "medium",
     "detail": "Memcached has no authentication. Verify it is not exposed to "
               "untrusted networks."},
    {"match": "couchdb", "severity": "medium",
     "detail": "CouchDB may run in 'admin party' mode with no credentials. "
               "Verify an admin user is configured."},
    {"match": "cisco", "severity": "low",
     "detail": "Some legacy Cisco devices ship with default credentials "
               "(e.g. cisco/cisco). Verify access credentials were changed."},
]

#: End-of-life operating systems, matched against nmap ``osmatch`` names.
#: OS fingerprints are guesses — these findings are low-confidence candidates.
_OS_EOL_RULES: List[Dict[str, Any]] = [
    {"match": "windows server 2003", "severity": "critical",
     "detail": "Windows Server 2003 is end-of-life and unsupported."},
    {"match": "windows server 2008", "severity": "high",
     "detail": "Windows Server 2008/2008 R2 are end-of-life (EOL January 2020)."},
    {"match": "windows server 2012", "severity": "high",
     "detail": "Windows Server 2012/2012 R2 reached end-of-life (October 2023)."},
    {"match": "windows 7", "severity": "high",
     "detail": "Windows 7 is end-of-life (EOL January 2020)."},
    {"match": "windows 8", "severity": "medium",
     "detail": "Windows 8.1 is end-of-life (EOL January 2023)."},
    {"match": "windows xp", "severity": "critical",
     "detail": "Windows XP is end-of-life and unsupported."},
    {"match": "windows 2000", "severity": "critical",
     "detail": "Windows 2000 is end-of-life and unsupported."},
    {"match": "ubuntu 16.04", "severity": "high",
     "detail": "Ubuntu 16.04 is end-of-life (standard support ended 2021)."},
    {"match": "ubuntu 18.04", "severity": "high",
     "detail": "Ubuntu 18.04 is end-of-life (standard support ended 2023)."},
    {"match": "ubuntu 20.04", "severity": "medium",
     "detail": "Ubuntu 20.04 standard support ended April 2025; verify an "
               "upgrade path or ESM coverage."},
    {"match": "debian 8", "severity": "high",
     "detail": "Debian 8 (jessie) is end-of-life."},
    {"match": "debian 9", "severity": "high",
     "detail": "Debian 9 (stretch) is end-of-life (EOL 2022)."},
    {"match": "debian 10", "severity": "medium",
     "detail": "Debian 10 (buster) reached end-of-life (June 2024)."},
    {"match": "centos 6", "severity": "high",
     "detail": "CentOS 6 is end-of-life (EOL November 2020)."},
    {"match": "centos 7", "severity": "medium",
     "detail": "CentOS 7 reached end-of-life (June 2024)."},
    {"match": "rhel 6", "severity": "high",
     "detail": "RHEL 6 is end-of-life (EOL 2020/2024 depending on tier)."},
    {"match": "rhel 7", "severity": "medium",
     "detail": "RHEL 7 reached end-of-life (June 2024)."},
    {"match": "linux 2.6", "severity": "medium",
     "detail": "A Linux 2.6 kernel is very old and unsupported."},
    {"match": "linux 2.4", "severity": "high",
     "detail": "A Linux 2.4 kernel is ancient and unsupported."},
    {"match": "freebsd 10", "severity": "medium",
     "detail": "FreeBSD 10 is end-of-life."},
    {"match": "freebsd 11", "severity": "medium",
     "detail": "FreeBSD 11 is end-of-life."},
]

#: Services whose plain exposure is itself a finding (cleartext, weak-auth or
#: default-community-string risk).  Keyed by nmap service name.
_EXPOSURE_RULES: List[Dict[str, Any]] = [
    {"service": "telnet", "severity": "medium",
     "title": "Telnet exposed (cleartext)",
     "detail": "Telnet transmits credentials and data unencrypted. Replace "
               "with SSH and disable telnet."},
    {"service": "vnc", "severity": "medium",
     "title": "VNC exposed",
     "detail": "VNC is frequently left with weak or no authentication. Verify "
               "a strong password is set and access is restricted."},
    {"service": "snmp", "severity": "low",
     "title": "SNMP exposed",
     "detail": "SNMP commonly uses the default community string 'public'. "
               "Verify community strings were changed and access restricted."},
    {"service": "netbios-ssn", "severity": "low",
     "title": "SMB/NetBIOS exposed",
     "detail": "SMB/NetBIOS exposure can enable unauthenticated enumeration. "
               "Verify guest access is disabled and the service is firewalled."},
]


# ===========================================================================
# the engine module
# ===========================================================================
class AutoAuditModule(NmapModule):
    """Read-only vulnerability audit: ports, services, OS + candidate checks."""

    NAME = "auto_audit"
    DESCRIPTION = (
        "Automated vulnerability audit — port/service/OS scan that flags "
        "outdated services, default configurations and weak-auth surfaces "
        "(reports candidates; never attacks)"
    )

    # ------------------------------------------------------------------
    def run(self, context: Dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        options = dict(context.get("options") or {})
        os_detect = _as_bool(options.get("os_detect", True))
        os_skip_reason = ""
        if os_detect and not can_run_os_detection():
            # nmap -O needs raw sockets (root on POSIX, admin on Windows);
            # unprivileged nmap prints "QUITTING!" and scans nothing.
            os_detect = False
            os_skip_reason = (
                "requires root/admin privileges — run the audit with sudo "
                "to enable -O"
            )
        scripts = str(options.get("nse_scripts") or DEFAULT_NSE_SCRIPTS).strip()

        extra_args: List[str] = []
        if os_detect:
            extra_args.append("-O")
        if scripts:
            extra_args += ["--script", scripts]

        enriched = dict(context)
        enriched["options"] = {
            **options,
            "service_scan": True,  # -sV: service + version banners
            "extra_args": extra_args,
            "timeout": options.get("timeout") or 600,
        }
        self.report_progress(
            f"running service/OS scan against {context.get('target') or 'target'} "
            f"(read-only NSE: {scripts or 'none'})"
        )
        result = super().run(enriched)
        if result.ok and isinstance(result.data, dict):
            try:
                result = self._analyze(result, context, os_skip_reason=os_skip_reason)
            except Exception as exc:  # defensive — analysis must never crash
                self.logger.exception("auto_audit analysis failed")
                result = ToolResult(
                    status=ResultStatus.PARTIAL,
                    module=self.NAME,
                    data={**result.data, "note": (
                        "scan completed but the candidate analysis failed: "
                        f"{exc!r}"
                    )},
                    raw_stdout=result.raw_stdout,
                    raw_stderr=result.raw_stderr,
                    duration_ms=result.duration_ms,
                    error_category=ErrorCategory.PARTIAL,
                )
        result = result.model_copy(update={
            "duration_ms": max(result.duration_ms, (time.perf_counter() - start) * 1000.0),
        })
        self.report_progress("audit complete", 1.0)
        return result

    # ------------------------------------------------------------------
    def _analyze(
        self,
        result: ToolResult,
        context: Dict[str, Any],
        os_skip_reason: str = "",
    ) -> ToolResult:
        """Cross-reference the nmap output against the knowledge bases."""
        data = dict(result.data or {})
        data["target"] = str(context.get("target") or "")
        hosts = data.get("hosts") or []
        os_by_ip = _extract_os_info(result.raw_stdout) if result.raw_stdout else {}

        all_findings: List[Dict[str, Any]] = []
        os_detected = False
        for host in hosts:
            findings: List[Dict[str, Any]] = []
            ip = host.get("ip") or ""
            hostname = host.get("hostname") or host.get("host") or ip

            # ---- OS fingerprint + EOL check --------------------------
            os_matches = os_by_ip.get(ip) or []
            if os_matches:
                os_detected = True
                best = max(os_matches, key=lambda m: int(m.get("accuracy") or 0))
                host["os_guess"] = best.get("name", "")
                host["os_accuracy"] = best.get("accuracy", "")
                for rule in _OS_EOL_RULES:
                    if rule["match"] in (best.get("name") or "").lower():
                        findings.append(_finding(
                            host=hostname, ip=ip, port="", service="os",
                            product=best.get("name", ""), version="",
                            severity=rule["severity"], category="os_eol",
                            title=f"End-of-life OS candidate: {best.get('name', '')}",
                            detail=rule["detail"], confidence="candidate",
                        ))

            # ---- per-port checks -------------------------------------
            for port in host.get("ports") or []:
                service = port.get("service") or ""
                product = port.get("product") or ""
                version = port.get("version") or ""
                label = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
                product_lower = product.lower()

                for rule in _VERSION_RULES:
                    if rule["product"] not in product_lower:
                        continue
                    for check in rule["checks"]:
                        if not _version_matches(version, check):
                            continue
                        findings.append(_finding(
                            host=hostname, ip=ip, port=label, service=service,
                            product=product, version=version,
                            severity=check.get("severity", "low"),
                            category="outdated_version",
                            title=rule["title"],
                            detail=check.get("detail", ""),
                            cve=check.get("cve", ""),
                            confidence="candidate",
                        ))

                haystack = " ".join(
                    part for part in (product, service, port.get("extrainfo") or "")
                    if part
                ).lower()
                for rule in _DEFAULT_CONFIG_RULES:
                    if rule["match"] in haystack:
                        findings.append(_finding(
                            host=hostname, ip=ip, port=label, service=service,
                            product=product, version=version,
                            severity=rule["severity"], category="default_config",
                            title=(f"Possible default configuration: {product or service}"),
                            detail=rule["detail"], confidence="candidate",
                        ))

                for rule in _EXPOSURE_RULES:
                    if rule["service"] == service:
                        findings.append(_finding(
                            host=hostname, ip=ip, port=label, service=service,
                            product=product, version=version,
                            severity=rule["severity"], category="exposure",
                            title=rule["title"], detail=rule["detail"],
                            confidence="candidate",
                        ))

                # ---- read-only NSE script interpretation ------------
                for script in port.get("scripts") or []:
                    findings.extend(
                        _interpret_nse(script, hostname, ip, label, service, product, version)
                    )

            for script in host.get("host_scripts") or []:
                findings.extend(
                    _interpret_nse(script, hostname, ip, "", "", "", "")
                )

            host["findings"] = findings
            all_findings.extend(findings)

        all_findings.sort(
            key=lambda f: (_SEVERITY_ORDER.get(f.get("severity", "info"), 9), f.get("port", ""))
        )
        summary = _severity_summary(all_findings)
        notes = [
            "Banner-based read-only audit — no exploit, brute-force or "
            "credential guessing was performed. All findings are candidates; "
            "verify them manually before acting.",
        ]
        os_requested = _as_bool(
            (context.get("options") or {}).get("os_detect", True)
        )
        if os_skip_reason:
            notes.append(f"OS fingerprinting skipped — {os_skip_reason}.")
        elif os_requested and not os_detected:
            notes.append(
                "OS fingerprinting produced no match for the scanned host(s)."
            )
        os_status = (
            "skipped" if os_skip_reason
            else "yes" if os_detected
            else "off" if not os_requested
            else "no"
        )
        data.update({
            "hosts": hosts,
            "findings": all_findings,
            "summary": summary,
            "finding_quality": "candidate" if all_findings else "informational",
            "note": " ".join(notes),
            "os_detected": os_detected,
            "os_status": os_status,
        })
        return result.model_copy(update={"data": data})


# ===========================================================================
# helpers
# ===========================================================================
def _finding(
    *,
    host: str,
    ip: str,
    port: str,
    service: str,
    product: str,
    version: str,
    severity: str,
    category: str,
    title: str,
    detail: str,
    cve: str = "",
    confidence: str = "candidate",
) -> Dict[str, Any]:
    return {
        "host": host,
        "ip": ip,
        "port": port,
        "service": service,
        "product": product,
        "version": version,
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "cve": cve,
        "reference": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
        "confidence": confidence,
    }


def _interpret_nse(
    script: Dict[str, Any],
    host: str,
    ip: str,
    port: str,
    service: str,
    product: str,
    version: str,
) -> List[Dict[str, Any]]:
    """Turn read-only NSE script output into candidate findings."""
    script_id = script.get("id", "")
    output = str(script.get("output") or "")
    lowered = output.lower()
    findings: List[Dict[str, Any]] = []

    if script_id == "ssh-auth-methods":
        if re.search(r"\bpassword\b|\bkeyboard-interactive\b", lowered):
            findings.append(_finding(
                host=host, ip=ip, port=port, service=service,
                product=product, version=version,
                severity="medium", category="weak_auth",
                title="SSH password authentication enabled",
                detail=("The SSH server accepts password (or "
                        "keyboard-interactive) authentication — a weak-password "
                        "surface. No login was attempted; consider enforcing "
                        "key-based auth."),
                confidence="candidate",
            ))
    elif script_id == "ftp-anon":
        if "anonymous" in lowered and ("allowed" in lowered or "login" in lowered):
            findings.append(_finding(
                host=host, ip=ip, port=port, service=service,
                product=product, version=version,
                severity="high", category="weak_auth",
                title="Anonymous FTP login allowed",
                detail=("The FTP server permits anonymous login. If anonymous "
                        "access is not intended, disable it and restrict the "
                        "service."),
                confidence="candidate",
            ))
    elif script_id == "http-default-accounts":
        if re.search(r"accounts?\s+found|valid accounts?|default account", lowered):
            findings.append(_finding(
                host=host, ip=ip, port=port, service=service,
                product=product, version=version,
                severity="high", category="weak_auth",
                title="Default account detected on HTTP service",
                detail=("The http-default-accounts script reports a well-known "
                        "default account on this service. Confirm and change "
                        "the credentials. No exploit was performed."),
                confidence="candidate",
            ))
    return findings


def _severity_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in summary:
            summary[severity] += 1
    summary["total"] = len(findings)
    return summary


def _extract_os_info(xml_text: str) -> Dict[str, List[Dict[str, Any]]]:
    """Pull ``osmatch`` fingerprints out of the nmap XML (best-effort)."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for host in root.findall("host"):
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6") and not ip:
                ip = addr.get("addr", "")
        if not ip:
            continue
        os_element = host.find("os")
        if os_element is None:
            continue
        matches: List[Dict[str, Any]] = []
        for osmatch in os_element.findall("osmatch"):
            matches.append({
                "name": osmatch.get("name", ""),
                "accuracy": osmatch.get("accuracy", ""),
            })
        if matches:
            by_ip[ip] = matches
    return by_ip


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def can_run_os_detection() -> bool:
    """Can this process run nmap ``-O`` (needs raw sockets)?

    On POSIX that means root (``euid == 0``); on Windows it means an
    elevated/admin session.  When False, the audit skips ``-O`` and notes
    why, so an unprivileged run still scans ports/services normally.
    """
    if os.name == "nt":
        try:
            import ctypes  # noqa: PLC0415

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # pragma: no cover - defensive
            return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:  # pragma: no cover - non-POSIX, non-Windows
        return True
    return geteuid() == 0
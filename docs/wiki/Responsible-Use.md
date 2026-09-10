# Responsible Use

Talos ships real attack capability. This page is the contract that comes with
it.

## The one rule

> **Only run attacking/recon modules against systems you own or have
> explicit, written permission to test.**

That includes modules 36–40b and any scan (02–38) aimed at infrastructure
you do not control. Unauthorised scanning and access attempts are illegal in
most jurisdictions regardless of intent or outcome — computer-misuse,
unauthorised-access and wiretap laws do not have a "just checking" defence.

## What "authorised" means in practice

- You own the asset, or
- you hold a signed engagement letter / scope document (pentest contract,
  bug-bounty program rules, lab agreement), and
- you stay **inside the listed scope** (hosts, CIDRs, domains, rate limits,
  testing windows) — out-of-space findings are still out-of-bounds actions.

Keep the paperwork. If anyone asks, you can point to it.

## Module-specific guidance

| Module | Extra care |
| ------ | ---------- |
| 36 HTTP Brute-Forcer | Rate-limit (`--delay`), tiny wordlists, authorised targets only. Account lockouts and alerting are real. |
| 37 Nmap Vuln Scan | NSE `vuln` scripts can be noisy and touch services; never run `unsafe` scripts on production without explicit approval. |
| 38 Auto Audit | Read-only by design — still a scan; scan only in-scope hosts. |
| 39 Metasploit | Modules can change state or crash services. Exploits in particular: authorised targets, agreed change window, rollback plan. |
| 40 Data Scraper | Collects real visitor data. Inform and obtain consent from the people who open the page; honour local privacy law (GDPR et al.). |
| 40b Seeker | Phishing simulation. Only for employees/users of your own organisation under an agreed awareness program. Never target the public. |

## Secrets hygiene

- `.env` is gitignored — keep `MSF_RPC_PASSWORD` and any tokens there, never
  in committed files, screenshots, or this wiki.
- Wordlists containing real leaked passwords should live outside the repo.
- Audit logs (`logs/audit.jsonl`) can contain target hostnames/IPs — treat
  the `logs/` directory as sensitive and never commit it (it is ignored).

## Reporting vulnerabilities you find

Found a real vulnerability during an authorised test:

1. Follow the target's disclosure policy (security.txt, bounty program).
2. Do not exfiltrate more data than needed to prove the issue.
3. Do not run destructive payloads to "prove impact" without written OK.

## Reporting bugs in Talos

Not a Talos security issue? Open a GitHub issue with:

- the module number and entrypoint (menu / TUI / script);
- the relevant `logs/error.log` traceback section;
- self-test output: `python scripts/self_test.py --no-net`.

**Suspect a security issue in Talos itself** (code execution via crafted
output, credential mishandling, …): **do not open a public issue.** Use
GitHub's *Security tab → Report a vulnerability* or email the address in
[SECURITY.md](https://github.com/ddemmc-dotcom/Talos/blob/main/SECURITY.md).
See that file for the full policy and response timeline.

## Licence

Talos is MIT-licensed. The licence grants no permission to break the law —
unauthorised use is solely on you.

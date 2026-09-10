# Installation

Talos ships two OS-specific installers that create a virtualenv, install all
Python dependencies, register global `talos` / `talos-ui` commands, and
remove themselves after a successful install. Each installer detects the
wrong OS and prints which one to use instead.

## Linux / macOS — `install.sh`

```bash
./install.sh                 # auto: system-wide as root/sudo, else per-user
./install.sh --user          # per-user install under ~/.local (no root)
./install.sh --system        # system-wide install into /opt/talos (uses sudo)
./install.sh --no-os-pkgs    # skip the OS package-manager step
./install.sh --with-msf      # also try the metasploit-framework OS package
./install.sh --uninstall     # remove the install + launchers
```

What it does:

1. Detects the distro and installs OS binaries: `nmap`, `traceroute`,
   `ping`, and Python ≥ 3.10 with venv support.
2. Copies the source tree to the install prefix.
3. Creates a virtualenv and installs everything from `requirements.txt`.
4. Registers global `talos` and `talos-ui` launcher commands.

Environment overrides: `PREFIX=`, `BIN_DIR=`, `PYTHON=` (e.g.
`PYTHON=python3.11 ./install.sh`). Re-running is idempotent — it refreshes
dependencies in place.

## Windows — `install.ps1`

```powershell
.\install.ps1              # default per-user install (no admin needed)
.\install.ps1 -User        # install under %LOCALAPPDATA%\talos
.\install.ps1 -System      # system-wide under C:\talos (requires admin)
.\install.ps1 -NoOSPkgs    # skip nmap installation
.\install.ps1 -Uninstall   # remove the install + launchers
.\install.ps1 -Help        # show help
```

What it does:

1. Verifies Python 3.10+ is installed and on PATH.
2. Installs `nmap` via `winget` when available.
3. Creates a virtualenv and installs Python dependencies.
4. Creates global `talos.bat` / `talos-ui.bat` launchers and adds their
   directory to your user PATH.

> The installer modifies your user PATH automatically. **Restart your
> terminal** (or run `refreshenv`) for the new PATH to take effect.

## Cross-platform detection

| Run on | Result |
| ------ | ------ |
| `install.sh` on Windows | Error: `Use install.ps1 on Windows` |
| `install.ps1` on Linux/macOS | Error: `Use install.sh on Linux/macOS` |

After a successful install, the unused installer is removed automatically.

## Once installed

```bash
talos        # numbered menu, from any directory
talos-ui     # keyboard-driven Textual UI
```

## Requirements

| Requirement | Notes |
| ----------- | ----- |
| Python ≥ 3.10 | with `venv`; `PYTHON=python3.11` override supported |
| `nmap` binary | OS package manager, **not** pip (`apt/brew/choco install nmap`) |
| `traceroute` | optional; needed by module 10 on Linux |
| `ping` | present by default on Linux/Windows |
| Git + PHP + Python | only for the Seeker module (installed on demand) |
| `msfrpcd` | only for the Metasploit module — see [Configuration](Configuration) |

## From a git checkout (no installer)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py
```

`main.py` and `ui.py` self-heal: they re-check `requirements.txt` on every
launch and reinstall any missing pip package automatically.

## Uninstall

```bash
./install.sh --uninstall     # Linux/macOS
.\install.ps1 -Uninstall     # Windows
```

This removes the installed files and the global launchers. Logs written next
to the install prefix (`logs/`) are removed with it.

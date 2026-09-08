#!/usr/bin/env bash
# =============================================================================
#  talos — self-installing global installer
# -----------------------------------------------------------------------------
#  One executable file. Run it on any Linux machine and it will:
#
#    1. Detect your distro / package manager and auto-install the OS-level
#       binaries the tool needs (python 3.10+, nmap, traceroute, ping,
#       python venv support, curl) — no manual apt/brew step required.
#    2. Copy the source code to an install prefix (source is never modified;
#       the original checkout stays exactly as it is).
#    3. Create a virtualenv inside the prefix and `pip install` every
#       dependency declared in requirements.txt (PEP 668 safe — never touches
#       the system Python).
#    4. Register a global `talos` launcher so you can run the tool from any
#       directory:  talos          # numbered module menu (main.py)
#                   talos-ui       # keyboard-driven Textual UI (ui.py)
#
#  Modes
#  -----
#    ./install.sh           # auto: root => system-wide, else per-user (~/.local)
#    ./install.sh --user    # force per-user install, no sudo needed
#    ./install.sh --system  # force system-wide install (/opt/talos), uses sudo
#    ./install.sh --uninstall
#    ./install.sh --no-os-pkgs   # skip OS package step (deps already present)
#    ./install.sh --with-msf      # also try `metasploit-framework` OS package
#                                 # (available on Kali/Parrot apt repos)
#
#  What is NOT auto-installed: the Metasploit RPC daemon (msfrpcd). It is a
#  large, distro-specific optional extra — see `--with-msf` above and the
#  README/.env.example notes. Every other module degrades gracefully without it.
# =============================================================================
set -euo pipefail

# --- cross-platform detection ------------------------------------------------
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]] || command -v cmd.exe >/dev/null 2>&1; then
    echo "[ERROR] This is a Linux/macOS installer. Use install.ps1 on Windows."
    exit 1
fi

# --- hard requirements -------------------------------------------------------
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=10
TOOL_NAME="talos"
UI_NAME="talos-ui"

# Source tree = directory containing this installer.
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_PY="$SOURCE_DIR/main.py"
REQUIREMENTS="$SOURCE_DIR/requirements.txt"
UI_PY="$SOURCE_DIR/ui.py"

# Files/dirs copied verbatim into the install prefix.
COPY_ITEMS=(main.py ui.py requirements.txt .env.example README.md src scripts)

# --- defaults (may be overridden below / by flags / env vars) ----------------
MODE="auto"            # auto | user | system
WITH_MSF=0
NO_OS_PKGS=0
UNINSTALL=0

usage() {
    sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    echo
    echo "Options:"
    echo "  --user          install per-user under ~/.local (no root required)"
    echo "  --system        install system-wide into /opt/$TOOL_NAME (root/sudo)"
    echo "  --no-os-pkgs    skip the OS package-manager step entirely"
    echo "  --with-msf      additionally install the metasploit-framework OS package"
    echo "  --uninstall     remove an existing install and its launcher(s)"
    echo "  -h, --help      show this help"
    echo
    echo "Env overrides: PREFIX=...  BIN_DIR=...  PYTHON=...  (e.g. PYTHON=python3.11)"
}

for arg in "$@"; do
    case "$arg" in
        --user) MODE="user" ;;
        --system) MODE="system" ;;
        --no-os-pkgs) NO_OS_PKGS=1 ;;
        --with-msf) WITH_MSF=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg (use --help)"; exit 2 ;;
    esac
done

# --- coloured helpers (best-effort, degrade on non-tty) -----------------------
if [ -t 1 ]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_DIM=""; C_RESET=""
fi
info()  { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()   { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# sanity checks on the source tree
# -----------------------------------------------------------------------------
[ -f "$MAIN_PY" ] || die "main.py not found next to this installer ($SOURCE_DIR)."
[ -f "$REQUIREMENTS" ] || die "requirements.txt not found next to this installer."
[ -d "$SOURCE_DIR/src" ] || die "src/ directory not found next to this installer."

# -----------------------------------------------------------------------------
# distro / package-manager detection
# -----------------------------------------------------------------------------
OS_ID=""
OS_LIKE=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
fi
case "$OS_ID $OS_LIKE" in
    *debian*|*ubuntu*|*kali*|*parrot*|*mint*|*pop*) PM="apt" ;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*|*amzn*) PM="dnf" ;;
    *arch*|*manjaro*|*endeavouros*) PM="pacman" ;;
    *opensuse*|*suse*) PM="zypper" ;;
    *alpine*) PM="apk" ;;
    *)
        PM=""
        warn "Could not detect a known package manager (ID='$OS_ID')."
        warn "The OS-package step will be skipped — the installer needs python3 >= 3.10,"
        warn "python venv support, nmap, traceroute and ping to already be installed."
        ;;
esac

pkg_lists() {
    case "$PM" in
        apt)    echo "python3 python3-venv python3-pip nmap traceroute iputils-ping curl ca-certificates" ;;
        dnf)    echo "python3 python3-pip nmap traceroute iputils curl" ;;
        pacman) echo "python python-pip nmap traceroute iputils curl" ;;
        zypper) echo "python3 python3-pip nmap traceroute iputils curl" ;;
        apk)    echo "python3 py3-pip nmap traceroute iputils curl" ;;
    esac
}

run_root() {
    # Run a command as root: directly when we are root, else via sudo.
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 127
    fi
}

install_os_packages() {
    [ "$NO_OS_PKGS" -eq 1 ] && { info "Skipping OS package step (--no-os-pkgs)."; return 0; }
    [ -z "$PM" ] && return 0
    info "Installing OS packages via $PM (nmap, traceroute, ping, python venv)..."
    case "$PM" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            run_root apt-get update -y || warn "apt-get update failed; continuing anyway."
            run_root apt-get install -y $(pkg_lists) || die "apt install failed. Re-run with --no-os-pkgs if packages exist."
            if [ "$WITH_MSF" -eq 1 ]; then
                if run_root apt-get install -y metasploit-framework; then
                    ok "metasploit-framework installed (start the RPC daemon with 'msfrpcd -P <pass>' and set MSF_RPC_PASSWORD)."
                else
                    warn "metasploit-framework is not in this distro's repos (it ships with Kali/Parrot)."
                fi
            fi
            ;;
        dnf)
            run_root dnf install -y $(pkg_lists) || die "dnf install failed. Re-run with --no-os-pkgs if packages exist."
            ;;
        pacman)
            run_root pacman -Sy --noconfirm $(pkg_lists) || die "pacman install failed. Re-run with --no-os-pkgs if packages exist."
            ;;
        zypper)
            run_root zypper --non-interactive install $(pkg_lists) || die "zypper install failed. Re-run with --no-os-pkgs if packages exist."
            ;;
        apk)
            run_root apk add --no-cache $(pkg_lists) || die "apk install failed. Re-run with --no-os-pkgs if packages exist."
            ;;
    esac
}

pick_python() {
    # Choose the newest python3 >= 3.10; honour PYTHON= override.
    if [ -n "${PYTHON:-}" ]; then
        command -v "$PYTHON" >/dev/null 2>&1 || die "PYTHON=$PYTHON is not on PATH."
        echo "$PYTHON"; return
    fi
    local cand
    for cand in python3.13 python3.12 python3.11 python3.10 python3; do
        if command -v "$cand" >/dev/null 2>&1; then
            echo "$cand"; return
        fi
    done
    return 1
}

check_python_version() {
    local py="$1" ver major minor
    ver="$("$py" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)"
    [ -n "$ver" ] || die "Could not read '$py --version'."
    major="${ver%%.*}"
    minor="${ver#*.}"; minor="${minor%%.*}"
    if [ "$major" -gt "$MIN_PYTHON_MAJOR" ] || \
       { [ "$major" -eq "$MIN_PYTHON_MAJOR" ] && [ "$minor" -ge "$MIN_PYTHON_MINOR" ]; }; then
        info "Using $py ($ver)."
    else
        die "Python $ver is too old — this tool needs Python >= $MIN_PYTHON_MAJOR.$MIN_PYTHON_MINOR."
    fi
}

# -----------------------------------------------------------------------------
# resolve install prefix + bin dir
# -----------------------------------------------------------------------------
resolve_paths() {
    if [ "$MODE" = "user" ] || { [ "$MODE" = "auto" ] && [ "$(id -u)" -ne 0 ]; }; then
        MODE="user"
        PREFIX="${PREFIX:-$HOME/.local/share/$TOOL_NAME}"
        BIN_DIR="${BIN_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
        NEED_ROOT=0
    else
        MODE="system"
        PREFIX="${PREFIX:-/opt/$TOOL_NAME}"
        BIN_DIR="${BIN_DIR:-/usr/local/bin}"
        NEED_ROOT=1
    fi
}

# -----------------------------------------------------------------------------
# uninstall
# -----------------------------------------------------------------------------
uninstall() {
    resolve_paths
    info "Uninstalling from $PREFIX (launchers in $BIN_DIR)..."
    if [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
        run_root rm -rf "$PREFIX" || true
        run_root rm -f "$BIN_DIR/$TOOL_NAME" "$BIN_DIR/$UI_NAME" || true
    else
        rm -rf "$PREFIX"
        rm -f "$BIN_DIR/$TOOL_NAME" "$BIN_DIR/$UI_NAME"
    fi
    ok "Removed $TOOL_NAME from $PREFIX and $BIN_DIR."
    echo "  The original source in $SOURCE_DIR was left untouched."
    exit 0
}

[ "$UNINSTALL" -eq 1 ] && uninstall

# -----------------------------------------------------------------------------
# main install flow
# -----------------------------------------------------------------------------
resolve_paths
echo
info "TALOS self-installer"
echo
info "Source : $SOURCE_DIR"
info "Target : $PREFIX   (mode: $MODE)"
info "Command: $BIN_DIR/$TOOL_NAME"
echo

# 1) OS-level binaries --------------------------------------------------------
if [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "--system install needs root; run with sudo, or use ./install.sh --user"
    info "System-wide install requested — sudo will be used where needed."
fi
install_os_packages

# 2) pick python ----------------------------------------------------------------
if ! PYTHON_BIN="$(pick_python)"; then
    warn "python3 not found — installing it via the package manager first."
    install_os_packages   # re-run so python3 lands before we check versions
    PYTHON_BIN="$(pick_python)" || die "python3 still not available after install. Aborting."
fi
check_python_version "$PYTHON_BIN"

# 3) copy source ---------------------------------------------------------------
if [ "$SOURCE_DIR" = "$PREFIX" ]; then
    info "Source already lives at the install prefix — skipping copy."
elif [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    info "Copying source to $PREFIX ..."
    run_root rm -rf "$PREFIX"
    run_root mkdir -p "$PREFIX"
    run_root cp -r "${COPY_ITEMS[@]/#/$SOURCE_DIR/}" "$PREFIX/"
    run_root chown -R root:root "$PREFIX"
else
    info "Copying source to $PREFIX ..."
    rm -rf "$PREFIX"
    mkdir -p "$PREFIX"
    cp -r "${COPY_ITEMS[@]/#/$SOURCE_DIR/}" "$PREFIX/"
fi

# 4) virtualenv + pip install ---------------------------------------------------
VENV_DIR="$PREFIX/.venv"
info "Creating virtualenv at $VENV_DIR ..."
if [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    run_root "$PYTHON_BIN" -m venv "$VENV_DIR"
    run_root "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
else
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
fi
VENV_PYTHON="$VENV_DIR/bin/python"
[ -x "$VENV_PYTHON" ] || die "Virtualenv creation failed: $VENV_PYTHON missing."

info "Installing Python dependencies from requirements.txt (this can take a minute)..."
if [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    run_root "$VENV_PYTHON" -m pip install -r "$PREFIX/requirements.txt"
else
    "$VENV_PYTHON" -m pip install -r "$PREFIX/requirements.txt"
fi
ok "Python dependencies installed."

# 5) writable logs dir (system-wide installs run as non-root users later) --------
if [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    run_root mkdir -p "$PREFIX/logs"
    run_root chmod a+rwx "$PREFIX/logs"
else
    mkdir -p "$PREFIX/logs"
    chmod a+rwx "$PREFIX/logs" 2>/dev/null || true
fi

# 6) global launchers ------------------------------------------------------------
make_launcher() {
    # $1 = command name, $2 = entry script (basename inside prefix)
    local name="$1" entry="$2" launcher
    launcher="$(mktemp)"
    cat > "$launcher" <<EOF
#!/usr/bin/env bash
# Generated by install.sh — global launcher for $TOOL_NAME ($entry).
exec "$VENV_PYTHON" "$PREFIX/$entry" "\$@"
EOF
    chmod 755 "$launcher"
    if [ "$NEED_ROOT" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
        run_root mkdir -p "$BIN_DIR"
        run_root install -m 0755 "$launcher" "$BIN_DIR/$name"
    else
        mkdir -p "$BIN_DIR"
        install -m 0755 "$launcher" "$BIN_DIR/$name"
    fi
    rm -f "$launcher"
    ok "Installed '$BIN_DIR/$name'."
}
make_launcher "$TOOL_NAME" "main.py"
make_launcher "$UI_NAME" "ui.py"

# 7) finish -----------------------------------------------------------------------
echo
if [ "$NEED_ROOT" -eq 1 ]; then
    echo "  Install complete (system-wide). You may need a new shell or:"
    echo "      hash -r"
fi
cat <<EOF

${C_GREEN}${C_BOLD}Done! ${TOOL_NAME} is installed globally.${C_RESET}

  Run it from anywhere with:
      ${C_BOLD}$TOOL_NAME${C_RESET}          # interactive module menu (main.py)
      ${C_BOLD}$UI_NAME${C_RESET}            # keyboard-driven terminal UI (ui.py)

  Source code is untouched at:
      $SOURCE_DIR

  Installed copy + virtualenv live at:
      $PREFIX

  Logs / audit trail are written to:
      $PREFIX/logs/  (toolkit.log, audit.jsonl, error.log)

  Notes
  -----
  * If a launcher is not on your PATH, add its directory:
        export PATH="$BIN_DIR:\$PATH"        # add to ~/.bashrc / ~/.zshrc
  * main.py re-checks and auto-installs any missing pip package on every
    launch, so the venv self-heals if requirements grow.
  * The Metasploit module needs a running msfrpcd daemon (see .env.example).
  * Re-run this installer any time to refresh dependencies (idempotent).
  * To remove everything:  $0 --uninstall
EOF

# --- cleanup: remove the Windows installer -----------------------------------
if [ -f "$SOURCE_DIR/install.ps1" ]; then
    info "Removing Windows installer (install.ps1)..."
    rm -f "$SOURCE_DIR/install.ps1"
    ok "Removed install.ps1"
fi

exit 0

# =============================================================================
#  talos — Windows installer (PowerShell)
# -----------------------------------------------------------------------------
#  Run this script on Windows to install TALOS globally.
#
#  It will:
#    1. Verify Python 3.10+ is available
#    2. Install nmap via winget (if available) or prompt manual install
#    3. Create a virtual environment and install Python dependencies
#    4. Create global launchers (talos.bat, talos-ui.bat)
#
#  Options:
#    .\install.ps1              # Default install
#    .\install.ps1 -User        # Install per-user (no admin needed)
#    .\install.ps1 -Uninstall   # Remove an existing install
#    .\install.ps1 -NoOSPkgs    # Skip OS package installation
#    .\install.ps1 -Help        # Show this help
# =============================================================================

param(
    [switch]$User,
    [switch]$System,
    [switch]$Uninstall,
    [switch]$NoOSPkgs,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# --- Constants ---------------------------------------------------------------
$TOOL_NAME    = "talos"
$UI_NAME      = "talos-ui"
$MIN_PYTHON   = [version]"3.10.0"

# --- Cross-platform detection ------------------------------------------------
if ($IsLinux -or $IsMacOS) {
    Write-Host "[ERROR] This is a Windows installer. Use install.sh on Linux/macOS." -ForegroundColor Red
    exit 1
}

# --- Help --------------------------------------------------------------------
if ($Help) {
    Write-Host @"
TALOS Windows Installer

Usage:  .\install.ps1 [options]

Options:
  -User        Install per-user under %LOCALAPPDATA%\talos (no admin needed)
  -System      Install system-wide under C:\talos (requires admin)
  -Uninstall   Remove an existing install and its launchers
  -NoOSPkgs    Skip OS package installation (nmap, etc.)
  -Help        Show this help

"@
    exit 0
}

# --- Colored output helpers --------------------------------------------------
function Write-Info  { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-Ok    { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Die   { param($Msg) Write-Host "[x] $Msg" -ForegroundColor Red; exit 1 }

# --- Sanity checks on source tree -------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainPy      = Join-Path $ScriptDir "main.py"
$Requirements = Join-Path $ScriptDir "requirements.txt"
$UIPy        = Join-Path $ScriptDir "ui.py"
$SrcDir      = Join-Path $ScriptDir "src"

if (-not (Test-Path $MainPy))      { Write-Die "main.py not found next to this installer ($ScriptDir)." }
if (-not (Test-Path $Requirements)) { Write-Die "requirements.txt not found next to this installer ($ScriptDir)." }
if (-not (Test-Path $SrcDir))       { Write-Die "src/ directory not found next to this installer ($ScriptDir)." }

# --- Resolve install paths ---------------------------------------------------
$NeedRoot = $false
if ($System) {
    $NeedRoot = $true
    $Prefix   = "C:\$TOOL_NAME"
    $BinDir   = "C:\Windows"
} elseif ($User -or -not $NeedRoot) {
    $Prefix   = Join-Path $env:LOCALAPPDATA $TOOL_NAME
    $BinDir   = Join-Path $env:LOCALAPPDATA "$TOOL_NAME\bin"
} else {
    $Prefix   = Join-Path $env:LOCALAPPDATA $TOOL_NAME
    $BinDir   = Join-Path $env:LOCALAPPDATA "$TOOL_NAME\bin"
}

# --- Uninstall ---------------------------------------------------------------
if ($Uninstall) {
    Write-Info "Uninstalling TALOS from $Prefix ..."
    if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
    $Launcher1 = Join-Path $BinDir "$TOOL_NAME.bat"
    $Launcher2 = Join-Path $BinDir "$UI_NAME.bat"
    if (Test-Path $Launcher1) { Remove-Item -Force $Launcher1 }
    if (Test-Path $Launcher2) { Remove-Item -Force $Launcher2 }
    Write-Ok "Removed TALOS. Original source in $ScriptDir was left untouched."
    exit 0
}

# --- Check Python ------------------------------------------------------------
Write-Host ""
Write-Info "TALOS Windows Installer"
Write-Info "Source : $ScriptDir"
Write-Info "Target : $Prefix"

$PythonCmd = $null
foreach ($cmd in @("python3", "python")) {
    try {
        $ver = & $cmd --version 2>&1 | Select-String -Pattern "Python (\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }
        if ($ver) {
            $version = [version]"$ver.0"
            if ($version -ge $MIN_PYTHON) {
                $PythonCmd = $cmd
                Write-Info "Using $cmd (Python $ver)"
                break
            }
        }
    } catch { }
}

if (-not $PythonCmd) {
    Write-Die "Python 3.10+ not found. Install it from https://www.python.org/downloads/ or via 'winget install Python.Python.3.12'"
}

# --- Install nmap (optional) -------------------------------------------------
if (-not $NoOSPkgs) {
    Write-Info "Checking for nmap..."
    $nmapPath = Get-Command nmap -ErrorAction SilentlyContinue
    if ($nmapPath) {
        Write-Ok "nmap found at $($nmapPath.Source)"
    } else {
        Write-Warn "nmap not found on PATH."
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($winget) {
            Write-Info "Attempting to install nmap via winget..."
            try {
                winget install --id Insecure.Nmap --accept-source-agreements --accept-package-agreements
                Write-Ok "nmap installed via winget."
            } catch {
                Write-Warn "winget install failed. Please install nmap manually from https://nmap.org/download.html"
            }
        } else {
            Write-Warn "winget not available. Please install nmap manually from https://nmap.org/download.html"
            Write-Warn "TALOS will work but some modules (port scanning) will be limited."
        }
    }
}

# --- Copy source to prefix ---------------------------------------------------
$CopyItems = @("main.py", "ui.py", "requirements.txt", ".env.example", "README.md", "src", "scripts")

Write-Info "Copying source to $Prefix ..."
if (Test-Path $Prefix) { Remove-Item -Recurse -Force $Prefix }
New-Item -ItemType Directory -Path $Prefix -Force | Out-Null

foreach ($item in $CopyItems) {
    $src = Join-Path $ScriptDir $item
    $dst = Join-Path $Prefix $item
    if (Test-Path $src -PathType Container) {
        Copy-Item -Recurse -Force $src $dst
    } elseif (Test-Path $src) {
        Copy-Item -Force $src $dst
    }
}

# --- Create virtual environment ----------------------------------------------
$VenvDir = Join-Path $Prefix ".venv"
Write-Info "Creating virtual environment at $VenvDir ..."
& $PythonCmd -m venv $VenvDir
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip    = Join-Path $VenvDir "Scripts\pip.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Die "Virtual environment creation failed: $VenvPython not found."
}

# --- Install dependencies ----------------------------------------------------
Write-Info "Upgrading pip..."
& $VenvPip install --upgrade pip setuptools wheel 2>&1 | Out-Null

Write-Info "Installing Python dependencies (this can take a minute)..."
$RequirementsPath = Join-Path $Prefix "requirements.txt"
& $VenvPip install -r $RequirementsPath
Write-Ok "Python dependencies installed."

# --- Writable logs directory -------------------------------------------------
$LogsDir = Join-Path $Prefix "logs"
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null

# --- Create launchers --------------------------------------------------------
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null

$Launcher1 = Join-Path $BinDir "$TOOL_NAME.bat"
$Launcher2 = Join-Path $BinDir "$UI_NAME.bat"

# talos launcher
@"
@echo off
"$VenvPython" "$Prefix\main.py" %*
"@ | Set-Content -Path $Launcher1 -Encoding ASCII

# talos-ui launcher
@"
@echo off
"$VenvPython" "$Prefix\ui.py" %*
"@ | Set-Content -Path $Launcher2 -Encoding ASCII

Write-Ok "Installed launcher: $Launcher1"
Write-Ok "Installed launcher: $Launcher2"

# --- Add to user PATH if needed ----------------------------------------------
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*$BinDir*") {
    Write-Info "Adding $BinDir to user PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$BinDir", "User")
    Write-Ok "Added to PATH. You may need to restart your terminal."
}

# --- Cleanup: remove the Linux installer -------------------------------------
$LinuxInstaller = Join-Path $ScriptDir "install.sh"
if (Test-Path $LinuxInstaller) {
    Write-Info "Removing Linux installer (install.sh)..."
    Remove-Item -Force $LinuxInstaller
    Write-Ok "Removed install.sh"
}

# --- Done! -------------------------------------------------------------------
Write-Host ""
Write-Host "Done! TALOS is installed." -ForegroundColor Green -BackgroundColor Black
Write-Host ""
Write-Host "  Run it from anywhere with:" -ForegroundColor White
Write-Host "    $TOOL_NAME`          # interactive module menu (main.py)" -ForegroundColor Yellow
Write-Host "    $UI_NAME`            # keyboard-driven terminal UI (ui.py)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Source code is at:" -ForegroundColor White
Write-Host "    $ScriptDir" -ForegroundColor Gray
Write-Host ""
Write-Host "  Installed copy + virtualenv at:" -ForegroundColor White
Write-Host "    $Prefix" -ForegroundColor Gray
Write-Host ""
Write-Host "  Notes:" -ForegroundColor White
Write-Host "    * Restart your terminal or run: refreshenv" -ForegroundColor Gray
Write-Host "    * The Metasploit module needs msfrpcd running (see .env.example)" -ForegroundColor Gray
Write-Host "    * Re-run this installer anytime to refresh dependencies" -ForegroundColor Gray
Write-Host "    * To remove: .\install.ps1 -Uninstall" -ForegroundColor Gray
Write-Host ""

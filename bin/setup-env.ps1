<#
.SYNOPSIS
    One-time setup for the Find-PAN project environment on Windows (PowerShell).

.DESCRIPTION
    Configures uv so that plain `uv` commands (`uv sync`, `uv run`, `uv add`)
    automatically use a Windows-specific project environment (`.venv-windows`).

    uv has no pyproject.toml setting for the environment path, but it honors
    the UV_PROJECT_ENVIRONMENT variable, and a *relative* value is resolved
    against each project's root. This script persists the variable for your
    Windows user, so every uv project keeps its own platform-named environment
    directory. Sharing a checkout between Windows and WSL/Linux then works
    without either side corrupting the other's environment.

    Run once, then open a NEW shell (so the variable is picked up) and use
    plain uv commands:

        uv run python bin/run-pytest-regression.py

.EXAMPLE
    PS> .\bin\setup-env.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$EnvironmentName = '.venv-windows'

# -- 1. uv must be installed
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine(@'
uv was not found on PATH.
Install it, for example:  winget install --id=astral-sh.uv -e
Then re-run this script.
'@)
    exit 1
}

# -- 2. Persist the per-platform environment name for this user
$previous = [Environment]::GetEnvironmentVariable('UV_PROJECT_ENVIRONMENT', 'User')
[Environment]::SetEnvironmentVariable('UV_PROJECT_ENVIRONMENT', $EnvironmentName, 'User')
$env:UV_PROJECT_ENVIRONMENT = $EnvironmentName

if ($previous -and $previous -ne $EnvironmentName) {
    Write-Host "Replaced previous UV_PROJECT_ENVIRONMENT='$previous'."
}
Write-Host "UV_PROJECT_ENVIRONMENT=$EnvironmentName persisted for your Windows user."
Write-Host "Every uv project keeps its own $EnvironmentName directory."

# -- 3. Create and verify the project environment
Push-Location $ProjectRoot
try {
    uv sync
    uv run python -c 'import pytest; print("pytest", pytest.__version__, "is available.")'
}
finally {
    Pop-Location
}

# -- 4. Clean up a legacy shared .venv, if any (superseded by the per-platform
#       environment; safe to remove since `uv sync` recreates environments)
$legacy = Join-Path $ProjectRoot '.venv'
if (Test-Path $legacy) {
    try {
        Remove-Item -Recurse -Force $legacy
        Write-Host "Removed legacy .venv (replaced by $EnvironmentName)."
    }
    catch {
        Write-Warning "Could not remove legacy .venv ($($_.Exception.Message)). Remove it manually."
    }
}

Write-Host ''
Write-Host 'Setup complete. Open a NEW shell, then:'
Write-Host '  uv run python bin/run-pytest-regression.py'
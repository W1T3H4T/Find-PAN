<#
.SYNOPSIS
    One-time setup for the Find-PAN project environment on Windows (PowerShell).

.DESCRIPTION
    Synchronizes the project-root .venv without changing user-wide settings.

    python-magic needs the libmagic-1.dll native library on Windows.  If the
    -FileWindows switch is used, the file-windows package is installed before
    uv sync so the DLL is available in the virtual environment.  If you prefer to
    manage the DLL yourself, place libmagic-1.dll (and its magic1.mgc database)
    on PATH or in the bin directory.

    Set UV_PROJECT_ENVIRONMENT=.venv when running uv commands directly:

        uv run python bin/run-pytest-regression.py

.PARAMETER FileWindows
    Install the file-windows package into the project environment to provide the
    libmagic-1.dll dependency on Windows.

.PARAMETER Recreate
    Remove the existing .venv before creating a fresh environment.

.EXAMPLE
    PS> .\bin\setup-env.ps1

.EXAMPLE
    PS> .\bin\setup-env.ps1 -FileWindows
#>

[CmdletBinding()]
param(
    [switch]$FileWindows,
    [switch]$Recreate
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot '.venv'

# -- 1. uv must be installed
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine(@'
uv was not found on PATH.
Install it, for example:  winget install --id=astral-sh.uv -e
Then re-run this script.
'@)
    exit 1
}

if ($Recreate) {
    try {
        try { $existing = Get-Item -LiteralPath $VenvPath -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { $existing = $null }
        if ($null -ne $existing) {
            Remove-Item -LiteralPath $VenvPath -Recurse -Force -ErrorAction Stop
            try {
                Get-Item -LiteralPath $VenvPath -Force -ErrorAction Stop | Out-Null
                throw 'The directory still exists after removal.'
            }
            catch [System.Management.Automation.ItemNotFoundException] { }
        }
    }
    catch {
        [Console]::Error.WriteLine("Error: could not remove '$VenvPath': $($_.Exception.Message)")
        [Console]::Error.WriteLine('Manually remove the .venv directory and run this script again.')
        exit 1
    }
}

# -- 2. Create and verify the project environment
$previous = $env:UV_PROJECT_ENVIRONMENT
$env:UV_PROJECT_ENVIRONMENT = '.venv'
Push-Location $ProjectRoot
try {
    if (-not (Test-Path -LiteralPath $VenvPath)) {
        uv venv --seed $VenvPath
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    if ($FileWindows) {
        Write-Host 'Adding file-windows to provide libmagic-1.dll on Windows.'
        uv add file-windows
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    uv sync --locked --inexact
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $Python = Join-Path $VenvPath 'Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $Python)) { $Python = Join-Path $VenvPath 'bin/python' }
    & $Python -m pip --version *> $null
    if ($LASTEXITCODE -ne 0) {
        & $Python -m ensurepip --upgrade
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    $constraints = [System.IO.Path]::GetTempFileName()
    try {
        uv export --locked --no-hashes --no-emit-project --output-file $constraints
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $Python -m pip install --constraint $constraints --requirement (Join-Path $ProjectRoot 'requirements.txt')
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    finally { Remove-Item -LiteralPath $constraints -Force -ErrorAction SilentlyContinue }
    uv run python -c 'import pytest; print("pytest", pytest.__version__, "is available.")'
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    Pop-Location
    $env:UV_PROJECT_ENVIRONMENT = $previous
}

Write-Host ''
Write-Host 'Setup complete. In this shell, run:'
Write-Host "  `$env:UV_PROJECT_ENVIRONMENT = '.venv'"
Write-Host '  uv run python bin/run-pytest-regression.py'

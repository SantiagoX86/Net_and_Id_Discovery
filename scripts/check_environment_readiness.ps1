# WAUIG Bank - Enterprise Security Discovery Orchestration Framework
# M9 WP2 - Windows Environment Readiness Control Gate
#
# This script validates local prerequisites before installation.
# It does not install, repair, or modify OS-level prerequisites.

$ErrorActionPreference = "Stop"

$failures = @()
$tmpVenv = $null

function Record-Pass {
    param([string]$CheckName)
    Write-Host ("[CHECK] {0,-32} PASS" -f $CheckName)
}

function Record-Fail {
    param([string]$CheckName)
    Write-Host ("[CHECK] {0,-32} FAIL" -f $CheckName)
    $script:failures += $CheckName
}

function Cleanup {
    if ($null -ne $tmpVenv -and (Test-Path -LiteralPath $tmpVenv)) {
        Remove-Item -LiteralPath $tmpVenv -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue

    Write-Host "WAUIG Environment Readiness Check"
    Write-Host "---------------------------------"

    if ($null -ne $pythonCmd) {
        Record-Pass "python present"
    }
    else {
        Record-Fail "python present"
    }

    if ($null -ne $pythonCmd) {
        & $pythonCmd.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" *> $null

        if ($LASTEXITCODE -eq 0) {
            Record-Pass "python version >= 3.10"
        }
        else {
            Record-Fail "python version >= 3.10"
        }
    }
    else {
        Record-Fail "python version >= 3.10"
    }

    if ($null -ne $pythonCmd) {
        & $pythonCmd.Source -m pip --version *> $null

        if ($LASTEXITCODE -eq 0) {
            Record-Pass "pip available"
        }
        else {
            Record-Fail "pip available"
        }
    }
    else {
        Record-Fail "pip available"
    }

    if ($null -ne $pythonCmd) {
        $tmpVenv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("wauig-readiness-venv." + [System.Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmpVenv | Out-Null

        & $pythonCmd.Source -m venv (Join-Path -Path $tmpVenv -ChildPath ".venv") *> $null

        if ($LASTEXITCODE -eq 0) {
            Record-Pass "venv creation"
        }
        else {
            Record-Fail "venv creation"
        }
    }
    else {
        Record-Fail "venv creation"
    }

    Write-Host ""

    if ($failures.Count -eq 0) {
        Write-Host "ENVIRONMENT READINESS: PASS"
        Write-Host "Environment prerequisites are available for controlled venv-based installation."
        exit 0
    }

    Write-Host "ENVIRONMENT READINESS: FAIL"
    Write-Host ""
    Write-Host "Failed Checks:"

    foreach ($failure in $failures) {
        Write-Host "- $failure"
    }

    Write-Host ""
    Write-Host "One or more required prerequisites are not available."
    Write-Host "Do not proceed with framework installation until the environment has been remediated through the organization-approved administration and change-control process."
    Write-Host "Re-run this readiness check after remediation is complete."

    exit 1
}
finally {
    Cleanup
}

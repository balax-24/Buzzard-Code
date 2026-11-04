# Buzzard Code installer for Windows.
#   irm https://raw.githubusercontent.com/balax-24/Buzzard-Code/main/install.ps1 | iex
#
# Installs into your user profile, needs no administrator rights, and never reads or sends
# API keys. Optional: BUZZARD_INSTALL_DIR changes the folder, BUZZARD_NO_PATH=1 skips PATH.

function Install-BuzzardCode {
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"
    $archiveUrl = "https://github.com/balax-24/Buzzard-Code/archive/refs/heads/main.zip"
    $installDir = if ($env:BUZZARD_INSTALL_DIR) { $env:BUZZARD_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\BuzzardCode" }
    $binDir = Join-Path $installDir "bin"
    $venvDir = Join-Path $installDir "venv"

    function Write-Step($message) { Write-Host "  > $message" -ForegroundColor Magenta }

    Write-Host ""
    Write-Host "  BUZZARD CODE" -ForegroundColor Magenta
    Write-Host "  Understand. Plan. Build. Verify. Secure." -ForegroundColor DarkGray
    Write-Host ""

    Write-Step "Looking for Python 3.12 or newer"
    $python = $null
    foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
        $exe = $candidate[0]
        $launcherArgs = @($candidate | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $check = "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)"
            & $exe @launcherArgs -c $check 2>$null
            if ($LASTEXITCODE -eq 0) { $python = $candidate; break }
        } catch { continue }
    }
    if (-not $python) {
        throw "Python 3.12 or newer was not found. Install it from https://www.python.org/downloads/ and run this again."
    }

    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ("buzzard-install-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    try {
        Write-Step "Downloading Buzzard Code"
        $zipPath = Join-Path $tempDir "buzzard.zip"
        Invoke-WebRequest -Uri $archiveUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $tempDir
        $sourceDir = (Get-ChildItem -Path $tempDir -Directory | Select-Object -First 1).FullName

        Write-Step "Creating a private Python environment"
        New-Item -ItemType Directory -Force -Path $installDir, $binDir | Out-Null
        $launcher = @($python | Select-Object -Skip 1)
        & $python[0] @launcher -m venv --clear $venvDir
        if ($LASTEXITCODE -ne 0) { throw "Could not create the Python environment." }

        Write-Step "Installing (this can take a few minutes)"
        & (Join-Path $venvDir "Scripts\python.exe") -m pip install --quiet --disable-pip-version-check $sourceDir
        if ($LASTEXITCODE -ne 0) { throw "Installing Buzzard Code failed. See the pip output above." }
    } finally {
        Remove-Item -Recurse -Force -Path $tempDir -ErrorAction SilentlyContinue
    }

    foreach ($name in @("buzzard", "buzzard-code")) {
        $target = Join-Path $venvDir "Scripts\$name.exe"
        Set-Content -Path (Join-Path $binDir "$name.cmd") -Encoding ASCII -Value "@echo off`r`n`"$target`" %*"
    }

    if ($env:BUZZARD_NO_PATH -ne "1") {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $entries = @($userPath -split ";" | Where-Object { $_ })
        if ($entries -notcontains $binDir) {
            [Environment]::SetEnvironmentVariable("Path", (($entries + $binDir) -join ";"), "User")
        }
        if (($env:Path -split ";") -notcontains $binDir) { $env:Path = "$binDir;$env:Path" }
    }

    $version = & (Join-Path $binDir "buzzard.cmd") --version
    Write-Host ""
    Write-Host "  Installed: $version" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next:" -ForegroundColor White
    Write-Host "    buzzard setup       choose your model and save your key"
    Write-Host "    cd your-project"
    Write-Host "    buzzard tui         start working"
    Write-Host ""
}

# Throwing here reports the error without closing the window that ran irm | iex
try {
    Install-BuzzardCode
} catch {
    Write-Host ""
    Write-Host "  Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

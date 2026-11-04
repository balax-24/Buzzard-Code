$env:PYTHONIOENCODING = "utf-8"
$venvExe = Join-Path $PSScriptRoot ".venv\Scripts\buzzard.exe"
if (Test-Path $venvExe) {
    & $venvExe @args
} else {
    & python -m security_agent.cli.main @args
}

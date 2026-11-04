@echo off
setlocal
set PYTHONIOENCODING=utf-8
if exist "%~dp0.venv\Scripts\buzzard.exe" (
    "%~dp0.venv\Scripts\buzzard.exe" %*
) else (
    python -m security_agent.cli.main %*
)

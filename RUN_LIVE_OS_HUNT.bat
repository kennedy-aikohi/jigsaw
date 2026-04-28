@echo off
setlocal
REM Jigsaw live OS usage: export live Windows logs, then hunt the exported artefacts offline.
REM Run as Administrator for Security/Sysmon/System access.
set OUT=%~dp0live_collection
if not exist "%OUT%" mkdir "%OUT%"
powershell -ExecutionPolicy Bypass -File "%~dp0collect_live_windows_logs.ps1" -OutDir "%OUT%"
python "%~dp0jigsaw_cli.py" hunt "%OUT%" --report "%OUT%\jigsaw_live_report.txt" --json "%OUT%\jigsaw_hits.json" --events-json "%OUT%\jigsaw_events.json"
echo.
echo Report: %OUT%\jigsaw_live_report.txt
echo Events: %OUT%\jigsaw_events.json
echo Hits:   %OUT%\jigsaw_hits.json
pause

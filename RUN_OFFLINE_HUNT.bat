@echo off
setlocal
REM Drag a folder or file onto this BAT, or edit TARGET below.
set TARGET=%~1
if "%TARGET%"=="" set TARGET=%~dp0logs_sample
set OUT=%~dp0results
if not exist "%OUT%" mkdir "%OUT%"
python "%~dp0jigsaw_cli.py" hunt "%TARGET%" --report "%OUT%\jigsaw_report.txt" --json "%OUT%\jigsaw_hits.json" --events-json "%OUT%\jigsaw_events.json" --csv "%OUT%\jigsaw_hits.csv"
echo.
echo Parsed target: %TARGET%
echo Report: %OUT%\jigsaw_report.txt
echo Events: %OUT%\jigsaw_events.json
echo Hits:   %OUT%\jigsaw_hits.json
pause

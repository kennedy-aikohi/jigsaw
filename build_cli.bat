@echo off
title Jigsaw XDR+ CLI Build
echo ============================================================
echo  Jigsaw XDR+ OmniParser CLI ^| Author: Kennedy Aikohi
echo ============================================================
python --version >nul 2>&1 || (echo Python not found & pause & exit /b 1)
pip install -r requirements.txt --user
if exist build_cli rmdir /s /q build_cli
if exist dist_cli rmdir /s /q dist_cli
pyinstaller --onefile --console --name jigsaw-cli --distpath dist_cli --workpath build_cli jigsaw_cli.py
echo.
echo Output: dist_cli\jigsaw-cli.exe
pause

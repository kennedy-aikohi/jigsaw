@echo off
:: ============================================================
:: Jigsaw XDR+ OmniParser
:: Build Script
:: Author : Kennedy Aikohi
:: GitHub : https://github.com/kennedy-aikohi
:: ============================================================
title JIGSAW Build

echo.
echo  ============================================================
echo   Jigsaw XDR+ OmniParser  ^|  Kennedy Aikohi
echo  ============================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install Python 3.9+ first.
    pause & exit /b 1
)

echo  [1/4] Installing dependencies...
pip install -r requirements.txt --quiet --user
if errorlevel 1 (
    echo  [WARN] Some packages may not have installed — continuing...
)
echo        Done.

echo  [2/4] Cleaning previous build...
if exist build   rmdir /s /q build
if exist dist    rmdir /s /q dist
echo        Done.

echo  [3/4] Building with PyInstaller...
pyinstaller jigsaw.spec --noconfirm
if errorlevel 1 (
    echo  [ERROR] Build failed. See above output.
    pause & exit /b 1
)

echo  [4/4] Verifying output...
if exist "dist\Jigsaw.exe" (
    echo.
    echo  ============================================================
    echo   BUILD SUCCESSFUL
    echo   Output : dist\Jigsaw.exe
    echo   Note   : Run as Administrator for full EVTX access
    echo  ============================================================
) else (
    echo  [ERROR] Jigsaw.exe not found — check PyInstaller output.
)

pause

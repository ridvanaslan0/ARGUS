@echo off
setlocal
title argus - interactive
cd /d "%~dp0"

if not exist "build\argus.exe" (
    echo.
    echo   [X] Binary not found: build\argus.exe
    echo       Build it first:  build.bat
    echo.
    pause
    exit /b 1
)

chcp 65001 >nul 2>&1
build\argus.exe run

echo.
pause

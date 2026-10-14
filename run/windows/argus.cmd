@echo off
setlocal enabledelayedexpansion
title Argus - interactive

set "HERE=%~dp0"
set "ROOT=%HERE%..\.."
set "EXE=%ROOT%\build\argus.exe"

if not exist "%EXE%" (
    echo.
    echo   [X] Binary not found: %EXE%
    echo       Build it first:  build.bat
    echo.
    pause
    exit /b 1
)

chcp 65001 >nul 2>&1

if "%~1"=="" (
    "%EXE%" run
) else (
    "%EXE%" %*
)

echo.
pause

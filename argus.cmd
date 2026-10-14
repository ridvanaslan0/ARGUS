@echo off
setlocal enabledelayedexpansion
title argus

set "HERE=%~dp0"
set "EXE=%HERE%build\argus.exe"

if not exist "%EXE%" (
    echo.
    echo   [X] build\argus.exe not found.
    echo       Build it first:  build.bat
    echo.
    pause
    exit /b 1
)

chcp 65001 >nul 2>&1
"%EXE%" %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo   [exit 0]  clean, no HIGH or CRITICAL findings
) else if "%RC%"=="2" (
    echo   [exit 2]  not authorized - scan refused
) else if "%RC%"=="3" (
    echo   [exit 3]  a required external tool is missing
) else (
    echo   [exit %RC%]  at least one HIGH or CRITICAL finding
)

echo.
pause
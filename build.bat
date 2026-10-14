@echo off
setlocal enabledelayedexpansion
title argus build

if not exist build mkdir build

set "VSWHERE=%ProgramFiles%"
if not exist "%VSWHERE%\Microsoft Visual Studio" set "VSWHERE=%ProgramFiles(x86)%"

set VCVARS=
if exist "%VSWHERE%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" set VCVARS=%VSWHERE%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat
if not defined VCVARS if exist "%VSWHERE%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set VCVARS=%VSWHERE%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
if not defined VCVARS if exist "%VSWHERE%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" set VCVARS=%VSWHERE%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat
if not defined VCVARS if exist "%VSWHERE%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" set VCVARS=%VSWHERE%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat
if not defined VCVARS if exist "%VSWHERE%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set VCVARS=%VSWHERE%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not defined VCVARS if exist "%VSWHERE%\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set VCVARS=%VSWHERE%\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat

if not defined VCVARS (
    echo [X] MSVC toolchain not found. Install "Desktop development with C++".
    exit /b 1
)

echo   initializing MSVC ...
call "%VCVARS%" >nul
if errorlevel 1 (
    echo [X] vcvars64 failed
    exit /b 1
)

echo   compiling 25 tools ...
echo.

set /a N=0
set OBJS=

call :compile src\main.cpp
call :compile src\registry.cpp
call :compile src\core\hash.cpp
call :compile src\core\aes.cpp
call :compile src\core\util.cpp
call :compile src\core\rng.cpp
call :compile src\core\net.cpp
call :compile src\core\proc.cpp
call :compile src\core\ui.cpp
call :compile src\tools\c01_crypto_basic.cpp
call :compile src\tools\c02_crypto_advanced.cpp
call :compile src\tools\c03_passwords.cpp
call :compile src\tools\c04_network.cpp
call :compile src\tools\c05_web.cpp
call :compile src\tools\c06_defense.cpp
call :compile src\tools\c07_integrity.cpp
call :compile src\tools\c08_forensics.cpp
call :compile src\tools\c09_x509.cpp

if defined FAILED (
    echo.
    echo [X] compilation failed
    exit /b 1
)

echo.
echo   linking ...
link /nologo ws2_32.lib bcrypt.lib advapi32.lib /OUT:build\argus.exe %OBJS%
if errorlevel 1 (
    echo [X] link failed
    exit /b 1
)

echo.
echo   [OK] build\argus.exe
echo.
exit /b 0

:compile
set /a N+=1
set "OBJ=build\obj!N!.obj"
set "OBJS=%OBJS% %OBJ%"
cl /nologo /c /std:c++17 /O2 /EHsc /W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS /I include /I src /Fo"%OBJ%" %1
if errorlevel 1 (
    echo [X] failed: %1
    set FAILED=1
)
exit /b 0
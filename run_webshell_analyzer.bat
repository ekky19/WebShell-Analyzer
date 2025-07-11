@echo off
cls
title WebShell Analyzer
color 0B

REM ========================================
REM   WebShell Analyzer Tool (GUI Version)
REM ========================================

REM Check if argument (server type) is provided
if "%~1"=="" (
    color 0C
    echo [!] No server type specified!
    echo Usage: %0 [iis|apache|nginx]
    color 07
    pause
    exit /b
)

set SERVER_TYPE=%~1

echo ========================================
echo        WebShell Analyzer Tool          
echo ========================================
echo.
echo [*] Running WebShell Analyzer for %SERVER_TYPE%...
echo.

REM Run the EXE
ws_analyzer.exe --type %SERVER_TYPE%

if %ERRORLEVEL% NEQ 0 (
    color 0C
    echo [!] Analyzer execution failed!
) else (
    color 0E
    echo [+] Analyzer completed successfully.
)

echo.
color 07
pause

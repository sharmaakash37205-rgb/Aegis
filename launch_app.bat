@echo off
title Aegis Vault & Security Suite Launcher
echo ===================================================
echo   🛡️  Launching Aegis Vault & Security Suite
echo ===================================================

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py launch_app.py %*
    goto end
)

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python launch_app.py %*
    goto end
)

echo Python launcher not found. Starting directly with Java Security Server...
call run_java_auth.bat

:end

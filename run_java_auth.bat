@echo off
title Aegis Vault Security Node
echo ===================================================
echo   Starting Aegis Vault Security Node & Desktop App
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

if not exist bin (
    echo Compiling Java sources first...
    mkdir bin
    javac -encoding UTF-8 -d bin -sourcepath java_auth\src java_auth\src\com\aegis\AegisAuthApp.java java_auth\src\com\aegis\test\AuthTestSuite.java
    if %ERRORLEVEL% neq 0 (
        echo Compilation failed.
        pause
        exit /b %ERRORLEVEL%
    )
)

java -cp bin com.aegis.AegisAuthApp %*

:end


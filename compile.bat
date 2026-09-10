@echo off
echo ===================================================
echo   Compiling Aegis Java Authentication System
echo ===================================================

if not exist bin mkdir bin

javac -encoding UTF-8 -d bin -sourcepath java_auth\src java_auth\src\com\aegis\AegisAuthApp.java java_auth\src\com\aegis\test\AuthTestSuite.java

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Compilation finished successfully! Classes saved to bin\
) else (
    echo.
    echo [ERROR] Compilation failed with error code %ERRORLEVEL%
)
pause

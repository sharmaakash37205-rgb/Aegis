@echo off
echo ===================================================
echo   Running Aegis Java Test Suite
echo ===================================================

if not exist bin mkdir bin
javac -encoding UTF-8 -d bin -sourcepath java_auth\src java_auth\src\com\aegis\test\AuthTestSuite.java
if %ERRORLEVEL% neq 0 (
    echo Compilation failed.
    pause
    exit /b %ERRORLEVEL%
)

java -cp bin com.aegis.test.AuthTestSuite
pause

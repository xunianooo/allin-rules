@echo off
setlocal
cd /d "%~dp0.."
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 tools\first_sign.py
) else (
  python tools\first_sign.py
)
set "SIGN_RESULT=%errorlevel%"
if not "%SIGN_RESULT%"=="0" echo Signing stopped. Check the message above; existing keys were not replaced.
pause
exit /b %SIGN_RESULT%

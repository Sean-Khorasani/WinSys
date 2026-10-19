@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ACTION=%~1"
set "LEVEL=%~2"
set "PORT=%~3"

if /i "%ACTION%"=="help" goto help
if /i "%ACTION%"=="--help" goto help
if /i "%ACTION%"=="start" goto validate_start
if /i "%ACTION%"=="stop" goto validate_other
if /i "%ACTION%"=="status" goto validate_other
goto usage

:validate_start
if not defined LEVEL set "LEVEL=DEBUG"
if /i "%LEVEL%"=="DEBUG" goto run
if /i "%LEVEL%"=="INFO" goto run
if /i "%LEVEL%"=="WARN" goto run
if /i "%LEVEL%"=="ERROR" goto run
goto usage

:validate_other
if not "%~2"=="" goto usage
set "LEVEL=DEBUG"
set "PORT=45455"

:run
if not defined PORT set "PORT=45455"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0webui-service.ps1" -Action "%ACTION%" -LogLevel "%LEVEL%" -Port "%PORT%"
exit /b %ERRORLEVEL%

:usage
set "USAGE_EXIT=2"
goto usage_text

:help
set "USAGE_EXIT=0"

:usage_text
echo Usage:
echo   webui-service.bat start [DEBUG^|INFO^|WARN^|ERROR] [PORT]
echo   webui-service.bat status
echo   webui-service.bat stop
echo.
echo PORT: optional, defaults to 45455. Pass 0 for an ephemeral port.
echo Uses build\wintcp.exe (the build output).
echo Logs: %%LOCALAPPDATA%%\WinTCP\WebUi\webui.log
exit /b %USAGE_EXIT%

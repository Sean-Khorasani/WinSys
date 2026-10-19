@echo off
REM build.bat - Build WinTCP with MSVC.
REM
REM Usage:
REM     build.bat           incremental: compile only changed .cpp files
REM     build.bat fresh     clean all artifacts, then full rebuild
REM     build.bat rebuild   same as fresh
REM     build.bat web       copy webui assets to build\ only, no compile
REM     build.bat clean     remove build\ and exit
REM     build.bat -Test     build, then run the CLI smoke gate + unit driver
REM
REM This script delegates to build.ps1. fast-build.bat and fast-build.ps1
REM have been superseded and moved to temp/.

setlocal
set "SCRIPT_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%build.ps1" %*
exit /b %ERRORLEVEL%

@echo off
rem fast-build.bat - thin wrapper for fast-build.ps1.
rem The .bat dodges PowerShell execution-policy questions entirely and gives a
rem normal Windows batch face to the same tool. All logic lives in the .ps1.
rem
rem   fast-build.bat -Test      build what changed + CLI smoke + unit
rem   fast-build.bat            build what changed (product exe only)
rem   fast-build.bat -TestOnly  skip the build, just run the tests
rem   fast-build.bat -Force     recompile everything (fast flags)
rem   fast-build.bat -Clean     delete build-fast\
rem
rem Exit code is the .ps1's: 0 ok, 1 build failed, 2 tests failed, 3 setup.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fast-build.ps1" %*
exit /b %ERRORLEVEL%
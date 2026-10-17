@echo off
REM build.bat - Build WinTCP with MSVC (Developer Command Prompt for VS 2022).
REM
REM Usage (from the folder that contains this file):
REM     build.bat
REM   or, to clean first:
REM     build.bat clean
REM
REM Requirements: run this inside "Developer Command Prompt for VS 2022"
REM (or "x64 Native Tools Command Prompt for VS 2022") so that cl.exe,
REM rc.exe and link.exe are on PATH. No admin rights needed.
REM
REM Output: build\wintcp.exe      - standalone console CLI, with NO GUI entry point
REM         build\wintcp-gui.exe  - standalone Windows-subsystem native GUI
REM         build\dev\wintcp-dev.exe - the same product + the in-process UI
REM                                      harness (UiProbe.cpp) and the test
REM                                      driver, for development and for the
REM                                      gates. NOT shipped.

setlocal EnableExtensions EnableDelayedExpansion

REM ---- Optional clean -------------------------------------------------------
if /I "%~1"=="clean" (
    echo Cleaning build directory...
    if exist build rmdir /S /Q build
    shift
)

REM ---- Locate MSVC if cl.exe is not on PATH --------------------------------
where cl.exe >nul 2>&1
if not errorlevel 1 goto :have_cl
echo cl.exe not found on PATH. Trying to set up MSVC via vcvars64.bat...
call :try_vcvars "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles%\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call :try_vcvars "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
:have_cl

where cl.exe >nul 2>&1
if not errorlevel 1 goto :have_cl2
    echo ERROR: cl.exe still not found.
    echo Please open "Developer Command Prompt for VS 2022" (or "x64 Native Tools
    echo Command Prompt for VS 2022") and run build.bat from there.
    exit /b 1
:have_cl2
where rc.exe >nul 2>&1
if not errorlevel 1 goto :have_rc
    echo ERROR: rc.exe not found. Make sure the Windows SDK is installed
    echo with Visual Studio 2022 (Desktop development with C++ workload).
    exit /b 1
:have_rc

REM ---- Build ----------------------------------------------------------------
if not exist build mkdir build

echo [1/2] Compiling resources (wintcp.rc)...
rc /nologo /fo "build\wintcp.res" "wintcp\src\wintcp.rc"
if errorlevel 1 (
    echo ERROR: resource compile failed.
    exit /b 1
)

echo [2/2] Compiling and linking (cl + link)...
REM No firewall import library appears below: BlockConn resolves
REM CLSID_NetFwPolicy2 with __uuidof(NetFwPolicy2), so there is no symbol to
REM import. "hnetfw.lib" is the historical name and does not exist in any
REM current Windows SDK, so linking it fails with LNK1104.
REM /guard:cf (Control Flow Guard): was MISSING here and present in CMake
REM and both .vcxproj files, so the PRIMARY build was the weakest of the four
REM paths - the one that gates every change was the one not instrumented.
REM Added to both the product and the test cl lines. It is a compile AND a
REM link flag, and this script drives cl and link in one command, so one
REM occurrence per line covers both.
REM /SUBSYSTEM:CONSOLE, not WINDOWS: an interactive cmd.exe waits for the CLI
REM child and prints its next prompt only when it has finished. This executable
REM is CLI-only. The separate wintcp-gui.exe is linked with /SUBSYSTEM:WINDOWS
REM and contains its own GUI entry point; neither binary starts the other.
cl /nologo /std:c++17 /EHsc /W4 /WX /permissive- /Zc:__cplusplus /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /DWIN32_LEAN_AND_MEAN /O2 /MT /Gy /GL /GF /Os /guard:cf ^
    /Fo"build/" /Fe"build\wintcp.exe" ^
    "wintcp\src\main.cpp" "wintcp\src\MainWindow.cpp" "wintcp\src\TcpTable.cpp" "wintcp\src\RowEnrichment.cpp" "wintcp\src\ListViewColumns.cpp" "wintcp\src\ConnectionsList.cpp" "wintcp\src\ConnectionsListOwner.cpp" "wintcp\src\AlertMonitor.cpp" "wintcp\src\ViewPresets.cpp" "wintcp\src\BookmarkActions.cpp" "wintcp\src\TrayIcon.cpp" "wintcp\src\ProcessInfo.cpp" "wintcp\src\Utils.cpp" "wintcp\src\ConnectionStore.cpp" "wintcp\src\RefreshEngine.cpp" "wintcp\src\Snapshot.cpp" "wintcp\src\ViewState.cpp" "wintcp\src\SysStats.cpp" "wintcp\src\Commands.cpp" "wintcp\src\CliCommands.cpp" "wintcp\src\Script.cpp" "wintcp\src\WebUi.cpp" "wintcp\src\WebMetrics.cpp" "wintcp\src\WebStatic.cpp" "wintcp\src\DnsResolver.cpp" "wintcp\src\DnsCache.cpp" "wintcp\src\Settings.cpp" "wintcp\src\DetailsDialog.cpp" "wintcp\src\DetailModel.cpp" "wintcp\src\Pcapng.cpp" "wintcp\src\TcpReasm.cpp" "wintcp\src\StreamCapture.cpp" "wintcp\src\TlsDecode.cpp" "wintcp\src\Elevate.cpp" "wintcp\src\Alerts.cpp" "wintcp\src\TypeToJump.cpp" "wintcp\src\Grouping.cpp" "wintcp\src\Freeze.cpp" "wintcp\src\BuildInfo.cpp" "wintcp\src\PromptDialog.cpp" "wintcp\src\ChartExport.cpp" "wintcp\src\ChangeLogWindow.cpp" "wintcp\src\Presets.cpp" "wintcp\src\Bookmarks.cpp" "wintcp\src\GeoIp.cpp" "wintcp\src\BlockConn.cpp" "wintcp\src\BlockedPeersDialog.cpp" "wintcp\src\BookmarkFile.cpp" "wintcp\src\PresetFile.cpp" "wintcp\src\IniFile.cpp" "wintcp\src\EmptyStateActions.cpp" "wintcp\src\ProcessTree.cpp" "wintcp\src\ProcessTreeView.cpp" "wintcp\src\RowAccessible.cpp" "wintcp\src\Sha256.cpp" "wintcp\src\ExposureScore.cpp" "wintcp\src\Cli.cpp" "wintcp\src\EtwTraffic.cpp" "wintcp\src\SocketTraffic.cpp" "wintcp\src\ProcStats.cpp" "wintcp\src\ChartsWindow.cpp" "wintcp\src\FontCache.cpp" "wintcp\src\CrashDump.cpp" "wintcp\src\WinCaps.cpp" "wintcp\src\Opt.cpp"    "wintcp\src\Monitors.cpp" "wintcp\src\Notify.cpp" ^
    "build\wintcp.res" ^
    /link /SUBSYSTEM:CONSOLE iphlpapi.lib ws2_32.lib comctl32.lib psapi.lib user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib crypt32.lib wintrust.lib pdh.lib ole32.lib oleaut32.lib bcrypt.lib delayimp.lib /DELAYLOAD:comdlg32.dll /DELAYLOAD:crypt32.dll /DELAYLOAD:ole32.dll /DELAYLOAD:oleaut32.dll /DELAYLOAD:pdh.dll /DELAYLOAD:shell32.dll /LTCG /OPT:REF /OPT:ICF /DEBUG:NONE
if errorlevel 1 (
    echo ERROR: compile/link failed.
    exit /b 1
)

echo.
echo Build succeeded: build\wintcp.exe
echo Run CLI with:  build\wintcp.exe ^<command^>
echo.
echo Building the standalone no-console GUI...
if not exist build\gui md build\gui
cl /nologo /std:c++17 /EHsc /W4 /WX /permissive- /Zc:__cplusplus /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /DWIN32_LEAN_AND_MEAN /O2 /MT /Gy /GL /GF /Os /guard:cf ^
    /Fo"build/gui/" /c "wintcp\src\GuiMain.cpp"
if errorlevel 1 (
    echo ERROR: the standalone GUI entry point failed to compile.
    exit /b 1
)
set "GUI_OBJECTS="
for %%F in (build\*.obj) do if /I not "%%~nxF"=="main.obj" set "GUI_OBJECTS=!GUI_OBJECTS! "%%F""
cl /nologo /guard:cf /Fe"build\wintcp-gui.exe" %GUI_OBJECTS% "build\gui\GuiMain.obj" "build\wintcp.res" ^
    /link /SUBSYSTEM:WINDOWS /MACHINE:X64 /INCREMENTAL:NO /MANIFEST:NO /LTCG /OPT:REF /OPT:ICF /DEBUG:NONE /GUARD:CF ^
    iphlpapi.lib ws2_32.lib comctl32.lib psapi.lib user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib crypt32.lib wintrust.lib pdh.lib ole32.lib oleaut32.lib bcrypt.lib delayimp.lib ^
    /DELAYLOAD:comdlg32.dll /DELAYLOAD:crypt32.dll /DELAYLOAD:ole32.dll /DELAYLOAD:oleaut32.dll /DELAYLOAD:pdh.dll /DELAYLOAD:shell32.dll
if errorlevel 1 (
    echo ERROR: the standalone GUI failed to link.
    exit /b 1
)
echo Built: build\wintcp-gui.exe
if not exist build\webui md build\webui
xcopy /E /I /Y "wintcp\webui\*" "build\webui\" >nul
if errorlevel 1 (
    echo ERROR: Web UI assets could not be copied beside the binaries.
    exit /b 1
)
echo.
echo Building the development test driver ^(not shipped^)... >&2

REM ---- wintcp-dev.exe -------------------------------------------------------
REM The development binary: the product PLUS everything that exists to test it.
REM
REM   * UiProbe.cpp - the in-process UI harness's in-window half. This is the
REM     file the product link above deliberately does NOT list, so this is the
REM     only reason the two differ from each other.
REM   * TestMain.cpp / Bench.cpp / BenchSync.cpp / UiHarness.cpp - the drivers.
REM
REM It is the direct descendant of the old wintcp-tests.exe, renamed because the
REM pair now has a stated contract: wintcp.exe is what a user runs, this is
REM what a developer (and every gate) runs. Same sources, same flags, same CRT -
REM a test build that differed would let a bug hide in the configuration gap.
REM
REM It links the SAME product sources, minus main.cpp because that file owns
REM wmain and this link has its own (TestMain.cpp). A test that exercised a
REM copy of the logic would prove nothing, so the split is by entry point and
REM link line, never by a second copy of the code.
REM
REM /I wintcp\src is what lets Bench.cpp keep writing #include "Connection.h":
REM rewriting those to ..\src\ would be a 30-file change that adds no isolation
REM and risks exactly the identifier damage this project has already suffered
REM twice.
REM
REM wintcp.res IS linked, and that is not optional: MainWindow::RegisterClass
REM loads IDR_MAINMENU and IDI_APP from the module, and IDR_ACCEL supplies the
REM keyboard shortcuts. Without it the window still constructs, the icons fall
REM back to IDI_APPLICATION and hAccel goes null - so the GUI checks would pass
REM while driving a subtly different program than the one that ships.
if not exist build\dev md build\dev
cl /nologo /std:c++17 /EHsc /W4 /WX /permissive- /Zc:__cplusplus /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /DWIN32_LEAN_AND_MEAN /O2 /MT /Gy /GL /GF /Os /guard:cf /I wintcp\src ^
    /Fo"build/dev/" /Fe"build\dev\wintcp-dev.exe" ^
    "wintcp\src\UiProbe.cpp" "wintcp\tests\TestMain.cpp" "wintcp\tests\Bench.cpp" "wintcp\tests\UiHarness.cpp" "wintcp\tests\BenchSync.cpp" ^
    "wintcp\src\MainWindow.cpp" "wintcp\src\TcpTable.cpp" "wintcp\src\RowEnrichment.cpp" "wintcp\src\ListViewColumns.cpp" "wintcp\src\ConnectionsList.cpp" "wintcp\src\ConnectionsListOwner.cpp" "wintcp\src\AlertMonitor.cpp" "wintcp\src\ViewPresets.cpp" "wintcp\src\BookmarkActions.cpp" "wintcp\src\TrayIcon.cpp" "wintcp\src\ProcessInfo.cpp" "wintcp\src\Utils.cpp" "wintcp\src\ConnectionStore.cpp" "wintcp\src\RefreshEngine.cpp" "wintcp\src\Snapshot.cpp" "wintcp\src\ViewState.cpp" "wintcp\src\SysStats.cpp" "wintcp\src\Commands.cpp" "wintcp\src\CliCommands.cpp" "wintcp\src\Script.cpp" "wintcp\src\WebUi.cpp" "wintcp\src\WebMetrics.cpp" "wintcp\src\WebStatic.cpp" "wintcp\src\DnsResolver.cpp" "wintcp\src\DnsCache.cpp" "wintcp\src\Settings.cpp" "wintcp\src\DetailsDialog.cpp" "wintcp\src\DetailModel.cpp" "wintcp\src\Pcapng.cpp" "wintcp\src\TcpReasm.cpp" "wintcp\src\StreamCapture.cpp" "wintcp\src\TlsDecode.cpp" "wintcp\src\Elevate.cpp" "wintcp\src\Alerts.cpp" "wintcp\src\TypeToJump.cpp" "wintcp\src\Grouping.cpp" "wintcp\src\Freeze.cpp" "wintcp\src\BuildInfo.cpp" "wintcp\src\PromptDialog.cpp" "wintcp\src\ChartExport.cpp" "wintcp\src\ChangeLogWindow.cpp" "wintcp\src\Presets.cpp" "wintcp\src\Bookmarks.cpp" "wintcp\src\GeoIp.cpp" "wintcp\src\BlockConn.cpp" "wintcp\src\BlockedPeersDialog.cpp" "wintcp\src\BookmarkFile.cpp" "wintcp\src\PresetFile.cpp" "wintcp\src\IniFile.cpp" "wintcp\src\EmptyStateActions.cpp" "wintcp\src\ProcessTree.cpp" "wintcp\src\ProcessTreeView.cpp" "wintcp\src\RowAccessible.cpp" "wintcp\src\Sha256.cpp" "wintcp\src\ExposureScore.cpp" "wintcp\src\Cli.cpp" "wintcp\src\EtwTraffic.cpp" "wintcp\src\SocketTraffic.cpp" "wintcp\src\ProcStats.cpp" "wintcp\src\ChartsWindow.cpp" "wintcp\src\FontCache.cpp" "wintcp\src\CrashDump.cpp" "wintcp\src\WinCaps.cpp" "wintcp\src\Opt.cpp"    "wintcp\src\Monitors.cpp" "wintcp\src\Notify.cpp" ^
    "build\wintcp.res" ^
    /link /SUBSYSTEM:CONSOLE iphlpapi.lib ws2_32.lib comctl32.lib psapi.lib user32.lib gdi32.lib comdlg32.lib shell32.lib advapi32.lib crypt32.lib wintrust.lib pdh.lib ole32.lib oleaut32.lib bcrypt.lib delayimp.lib /DELAYLOAD:comdlg32.dll /DELAYLOAD:crypt32.dll /DELAYLOAD:ole32.dll /DELAYLOAD:oleaut32.dll /DELAYLOAD:pdh.dll /DELAYLOAD:shell32.dll /LTCG /OPT:REF /OPT:ICF /DEBUG:NONE
if errorlevel 1 (
    echo ERROR: the development binary failed to build.
    exit /b 1
)

REM ---- Copy to the shared build-fast folder --------------------------------
REM The webui-service uses build-fast\wintcp.exe; keep it current with the
REM full build so both paths serve the same binary.
if not exist build-fast md build-fast
copy /Y "build\wintcp.exe" "build-fast\wintcp.exe" >nul
copy /Y "build\wintcp-gui.exe" "build-fast\wintcp-gui.exe" >nul
copy /Y "build\dev\wintcp-dev.exe" "build-fast\dev\wintcp-dev.exe" 2>nul
xcopy /E /I /Y "build\webui" "build-fast\webui" >nul

endlocal
exit /b 0

REM ---- Subroutines (must be after exit so they do not run as main code) ----
REM Try one vcvars64.bat path. Arg %1 is quoted full path. No-op if missing
REM or if cl.exe is already available. Safe to call on bare lines only:
REM do NOT wrap these calls in an IF (...) block, because %ProgramFiles(x86)%
REM contains parentheses that break block parsing (". was unexpected").
:try_vcvars
if "%~1"=="" goto :eof
if exist "%~1" (
    where cl.exe >nul 2>&1
    if errorlevel 1 call "%~1" >nul
)
goto :eof

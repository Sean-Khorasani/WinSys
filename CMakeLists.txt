# CMakeLists.txt - Alternative CMake build for WinTCP (Windows + MSVC).
#
# Usage (Developer Command Prompt for VS 2022, from the folder with this file):
#   cmake -S . -B build-cmake -G "Visual Studio 17 2022" -A x64
#   cmake --build build-cmake --config Release
# The executable lands at: build-cmake\Release\wintcp.exe
#
# A single-config MSVC command-line alternative with Ninja:
#   cmake -S . -B build-cmake -G Ninja -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-cmake

cmake_minimum_required(VERSION 3.20)

project(wintcp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# All sources live under ./wintcp per the project layout requirement.
#
# No WIN32 flag: the entry point is wmain (see wintcp/src/main.cpp), so this
# must link /SUBSYSTEM:CONSOLE like the project build does. With WIN32 the linker
# expects wWinMain and fails with LNK2019 "unresolved external symbol WinMain"
# after compiling all 41 files - measured, both here and via wintcp.sln, which
# had the same drift (<SubSystem>Windows</SubSystem>). A WINDOWS-subsystem exe
# also hands the prompt back immediately in an interactive cmd.exe, so CLI
# output lands on top of the next prompt instead of after it.
add_executable(wintcp
    wintcp/src/main.cpp
    wintcp/src/MainWindow.cpp
    wintcp/src/MainWindow.h
    wintcp/src/TcpTable.cpp
wintcp/src/RowEnrichment.cpp
wintcp/src/ListViewColumns.cpp
wintcp/src/ConnectionsList.cpp
wintcp/src/ConnectionsListOwner.cpp
wintcp/src/AlertMonitor.cpp
wintcp/src/ViewPresets.cpp
wintcp/src/BookmarkActions.cpp
wintcp/src/TrayIcon.cpp
    wintcp/src/TcpTable.h
    wintcp/src/ProcessInfo.cpp
    wintcp/src/ProcessInfo.h
    wintcp/src/Utils.cpp
    wintcp/src/Utils.h
    wintcp/src/Connection.h
    wintcp/src/Columns.h
    wintcp/src/Version.h
    wintcp/src/EtwTrafficTypes.h
    wintcp/src/ConnectionStore.cpp
    wintcp/src/ConnectionStore.h
    wintcp/src/RefreshEngine.cpp
    wintcp/src/RefreshEngine.h
    wintcp/src/Snapshot.cpp
    wintcp/src/Snapshot.h
    wintcp/src/SysStats.cpp
    wintcp/src/SysStats.h
    wintcp/src/Commands.cpp
    wintcp/src/Commands.h
    wintcp/src/CliCommands.cpp
    wintcp/src/CliCommands.h
    wintcp/src/Script.cpp
    wintcp/src/Script.h
    wintcp/src/Monitors.cpp
    wintcp/src/Notify.cpp
    wintcp/src/Monitors.h
    wintcp/src/WebUi.cpp
    wintcp/src/WebUi.h
    wintcp/src/WebProcesses.cpp
    wintcp/src/WebProcesses.h
    wintcp/src/WebMetrics.cpp
    wintcp/src/WebMetrics.h
    wintcp/src/WebStatic.cpp
    wintcp/src/WebStatic.h
    wintcp/src/ViewState.cpp
    wintcp/src/ViewState.h
    wintcp/src/DnsResolver.cpp
    wintcp/src/DnsCache.cpp
    wintcp/src/DnsResolver.h
    wintcp/src/Settings.cpp
    wintcp/src/Settings.h
    wintcp/src/DetailsDialog.cpp
    wintcp/src/DetailsDialog.h
    wintcp/src/Alerts.cpp
    wintcp/src/Alerts.h
    wintcp/src/BlockConn.cpp
    wintcp/src/BlockConn.h
    wintcp/src/BlockedPeersDialog.cpp
    wintcp/src/BlockedPeersDialog.h
    wintcp/src/BookmarkFile.cpp
    wintcp/src/BookmarkFile.h
    wintcp/src/PresetFile.cpp
    wintcp/src/PresetFile.h
    wintcp/src/IniFile.cpp
    wintcp/src/IniFile.h
    wintcp/src/EmptyStateActions.cpp
    wintcp/src/EmptyStateActions.h
    wintcp/src/ProcessTree.cpp
    wintcp/src/ProcessTree.h
    wintcp/src/ProcessTreeView.cpp
    wintcp/src/ProcessTreeView.h
    wintcp/src/RowAccessible.cpp
    wintcp/src/RowAccessible.h
    wintcp/src/Sha256.cpp
    wintcp/src/Sha256.h
    wintcp/src/ExposureScore.cpp
    wintcp/src/ExposureScore.h
    wintcp/src/Elevate.cpp
    wintcp/src/Elevate.h
    wintcp/src/GeoIp.cpp
    wintcp/src/GeoIp.h
    wintcp/src/Pcapng.cpp
    wintcp/src/Pcapng.h
    wintcp/src/TypeToJump.cpp
    wintcp/src/TypeToJump.h
    wintcp/src/Presets.cpp
    wintcp/src/Presets.h
    wintcp/src/Bookmarks.cpp
    wintcp/src/Bookmarks.h
    wintcp/src/Grouping.cpp
    wintcp/src/Grouping.h
    wintcp/src/Freeze.cpp
    wintcp/src/Freeze.h
    wintcp/src/BuildInfo.cpp
    wintcp/src/BuildInfo.h
    wintcp/src/PromptDialog.cpp
    wintcp/src/PromptDialog.h
    wintcp/src/ChartExport.cpp
    wintcp/src/ChartExport.h
    wintcp/src/ChangeLogWindow.cpp
    wintcp/src/ChangeLogWindow.h
    wintcp/src/StreamCapture.cpp
    wintcp/src/StreamCapture.h
    wintcp/src/TcpReasm.cpp
    wintcp/src/TcpReasm.h
    wintcp/src/TlsDecode.cpp
    wintcp/src/TlsDecode.h
    wintcp/src/DetailModel.cpp
    wintcp/src/DetailModel.h
    wintcp/src/Cli.cpp
    wintcp/src/Cli.h
    wintcp/src/EtwTraffic.cpp
    wintcp/src/EtwTraffic.h
    wintcp/src/SocketTraffic.cpp
    wintcp/src/SocketTraffic.h
    wintcp/src/ProcStats.cpp
    wintcp/src/ProcStats.h
    wintcp/src/ChartsWindow.cpp
    wintcp/src/ChartsWindow.h
    wintcp/src/FontCache.cpp
    wintcp/src/FontCache.h
    wintcp/src/CrashDump.cpp
    wintcp/src/CrashDump.h
    wintcp/src/WinCaps.cpp
    wintcp/src/WinCaps.h
    wintcp/src/Opt.cpp
    wintcp/src/Opt.h
    wintcp/src/resource.h
    wintcp/src/wintcp.rc
)

target_compile_definitions(wintcp PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0601
)

if(MSVC)
    # /utf-8: sources are UTF-8 (no BOM); without it cl assumes the ANSI
    # codepage and every L"—" literal compiles to mojibake.
    # /permissive- + /Zc:__cplusplus: MSVC still defaults to non-conforming
    #    C++17 without these two, so the standard library and the compiler
    #    disagree about otherwise-legal code.
    # /WX: warnings are errors, so /W4 stays meaningful.
    target_compile_options(wintcp PRIVATE /W4 /WX /EHsc /utf-8
                                      /permissive- /Zc:__cplusplus)

    # --- the CRT: /MT, stated explicitly ---------------------------------------
    # CMake's default for MSVC is /MD, so omitting this silently produced a
    # binary needing the VC++ redistributable (MSVCP140.dll, VCRUNTIME140.dll,
    # VCRUNTIME140_1.dll - none of which are present on a clean machine). The
    # failure is a modal "code execution cannot proceed" dialog raised by the
    # loader BEFORE any of WinTCP's code runs, so no capability gating in the
    # app can catch it. For a diagnostic tool that people copy onto machines
    # they do not administer, requiring an installer is exactly backwards, so
    # the static CRT is the deliberate choice - not an accident of a default.
    #
    # Note the Debug suffix: the MT family is MultiThreaded / MultiThreadedDebug.
    # Writing "MultiThreaded" flat would silently break Debug builds.
    set_property(TARGET wintcp PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # Size flags, matching the project build and wintcp.vcxproj. /Os comes after /O2
    # so it wins; measured free on this codebase (the size notes 2).
    # /Gy + /GL + /LTCG is worth -22.5 KB; /GF and /GR- measured 0 KB and are
    # left out rather than added as cargo cult.
    target_compile_options(wintcp PRIVATE $<$<CONFIG:Release>:/Gy /GL /GF /Os>)
    # The app manifest is already embedded via wintcp.rc (RT_MANIFEST id 1).
    # Disable the linker's auto-generated manifest to avoid
    # CVT1100/LNK1123 duplicate-manifest failures.
    target_link_options(wintcp PRIVATE "/MANIFEST:NO")
    # /guard:cf (Control Flow Guard): matches the CMake and VS debug
    # configurations.
    target_link_options(wintcp PRIVATE "/guard:cf")
endif()

target_link_libraries(wintcp PRIVATE
    iphlpapi
    ws2_32
    comctl32
    psapi
    user32
    gdi32
    comdlg32
    shell32
    advapi32
    crypt32
  wintrust
    pdh
    ole32
    oleaut32
    bcrypt
    # --- delay-loaded libraries -------------------------------------------------
    # These resolve on FIRST CALL rather than at process start, so a Windows
    # install missing one of them still starts and still lists connections -
    # only the corresponding feature is disabled, and `wintcp.exe version`
    # reports it as unavailable with the reason. The import table for this
    # build therefore carries only the Win32 basics: kernel32, user32, gdi32,
    # comctl32, advapi32, iphlpapi, ws2_32.
    #
    # THE LIST MUST MATCH the project build, wintcp.vcxproj and kDelayedDlls in
    # wintcp/src/WinCaps.cpp. Nothing checks that at compile time; the failure
    # mode is a delay-load exception on a machine that lacks one of them, i.e.
    # exactly the crash the gating is meant to prevent.
    delayimp
)

# /DELAYLOAD is spelled out rather than using CMake's `delayimp_<dll>` form:
# that form is a target_link_libraries convention CMake does not expand on
# MSVC, so it reaches the linker as a literal filename and fails with
# "cannot open input file 'delayimp_comdlg32.lib'". Link options are the
# mechanism that actually works here.
target_link_options(wintcp PRIVATE
    /DELAYLOAD:comdlg32.dll
    /DELAYLOAD:crypt32.dll
    /DELAYLOAD:ole32.dll
    /DELAYLOAD:oleaut32.dll
    /DELAYLOAD:pdh.dll
    /DELAYLOAD:shell32.dll
    # /LTCG pairs with the /GL above. /DEBUG:NONE is stated explicitly because
    # any form of /DEBUG silently flips the linker defaults to /OPT:NOREF,NOICF,
    # silently costing the whole benefit of /GL.
    $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF /DEBUG:NONE>
)

set_target_properties(wintcp PROPERTIES
    OUTPUT_NAME "wintcp"
    # FALSE, not TRUE: see the add_executable comment above. CMake's default
    # for a plain add_executable is already a console app; stating it keeps the
    # next edit from re-adding WIN32 "to make the GUI work".
    WIN32_EXECUTABLE FALSE
)

# Keep the MSVC debugger working directory at the project root.
set_target_properties(wintcp PROPERTIES
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

add_custom_command(TARGET wintcp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/webui"
            "$<TARGET_FILE_DIR:wintcp>/webui"
    COMMENT "Copying WinTCP local Web UI assets")

# ---- wintcp-gui.exe ----
# Standalone Windows-subsystem application. It links the native GUI and shared
# model directly; no second executable is looked up or launched at runtime.
file(GLOB WINTCP_GUI_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/*.cpp")
list(REMOVE_ITEM WINTCP_GUI_SOURCES
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/main.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/Cli.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/GuiLauncher.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/UiProbe.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/GuiMain.cpp")
add_executable(wintcp-gui WIN32
    wintcp/src/GuiMain.cpp
    wintcp/src/wintcp.rc
    ${WINTCP_GUI_SOURCES})
target_compile_definitions(wintcp-gui PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
if(MSVC)
    target_compile_options(wintcp-gui PRIVATE /W4 /WX /EHsc /utf-8
                           /permissive- /Zc:__cplusplus)
    set_property(TARGET wintcp-gui PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(wintcp-gui PRIVATE $<$<CONFIG:Release>:/Gy /GL /GF /Os>)
    target_link_options(wintcp-gui PRIVATE /guard:cf /MANIFEST:NO
                        /DELAYLOAD:comdlg32.dll /DELAYLOAD:crypt32.dll
                        /DELAYLOAD:ole32.dll /DELAYLOAD:oleaut32.dll
                        /DELAYLOAD:pdh.dll /DELAYLOAD:shell32.dll
                        $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF /DEBUG:NONE>)
endif()
get_target_property(WINTCP_LINK_LIBRARIES wintcp LINK_LIBRARIES)
target_link_libraries(wintcp-gui PRIVATE ${WINTCP_LINK_LIBRARIES})
set_target_properties(wintcp-gui PROPERTIES
    OUTPUT_NAME "wintcp-gui"
    WIN32_EXECUTABLE TRUE
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}")

# ---- wintcp-dev.exe ----
# The development test driver. Bench.cpp (RunSelfTest / RunBench) and
# UiHarness.cpp (RunUiHarness) moved OUT of wintcp.exe on 2026-10-02: they used
# to be compiled into the product, reachable as the `selftest` and `bench` verbs
# and the `--uiharness` switch. The product now carries no test code.
#
# It links the SAME product sources, which is the point - a test that exercised a
# copy of the logic would prove nothing. Two consequences worth stating:
#
#   * src/main.cpp is EXCLUDED. It owns wmain; this target has its own entry
#     point in tests/TestMain.cpp. Linking both would be a duplicate-symbol
#     error, and there is nothing in main.cpp worth unit-testing: its only
#     testable expression is the --uiharness argv scan, which moved with the
#     harness. Everything else in it is process lifecycle that only a real
#     process can exercise - which is what the CLI test suite does, as a
#     black box.
#
#   * wintcp/src is on the include path so the moved files keep writing
#     #include "Connection.h". Rewriting those to ../src/ would touch 30 lines
#     across 2 files to buy no isolation.
#
# The product sources are GLOBBED, not hand-listed, and main.cpp is removed from
# the result. A hand-kept list is how this project got nine identical link
# failures once already (tools/size-matrix.ps1, stale by one file - WinCaps.cpp);
# a second list to keep in step with the first would just relocate that trap.
# CONFIGURE_DEPENDS makes CMake re-glob when the directory changes, so adding a
# source file needs no edit here.
file(GLOB WINTCP_CORE_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/*.cpp")
# The UI harness's in-window half is removed from the product set and added
# back to the dev target below. wintcp.exe links the hand-written list above,
# which has never named it.
list(REMOVE_ITEM WINTCP_CORE_SOURCES
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/main.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/GuiMain.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/GuiLauncher.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/UiProbe.cpp")
file(GLOB WINTCP_CORE_HEADERS CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/wintcp/src/*.h")

add_executable(wintcp-dev
    # The in-process UI harness's in-window half. The ONLY source in
    # wintcp/src that is not also in the product: wintcp.exe links the hand list
    # above, which has never named it, and this target links the glob (which
    # now excludes it) plus this file. Everything else is shared.
    wintcp/src/UiProbe.cpp
    wintcp/tests/TestMain.cpp
    wintcp/tests/Bench.cpp
    wintcp/tests/UiHarness.cpp
    wintcp/tests/BenchSync.cpp
    wintcp/tests/Bench.h
    wintcp/tests/UiHarness.h
    ${WINTCP_CORE_SOURCES}
    ${WINTCP_CORE_HEADERS}
    # The resource script is REQUIRED, not cosmetic: MainWindow::RegisterClass
    # loads IDR_MAINMENU and IDI_APP from the module, and IDR_ACCEL supplies the
    # keyboard shortcuts. Without it the window still constructs - the icons fall
    # back to IDI_APPLICATION and hAccel goes null - so the GUI checks would pass
    # while driving a subtly different program than the one that ships.
    wintcp/src/wintcp.rc
)
target_include_directories(wintcp-dev PRIVATE wintcp/src)
target_compile_definitions(wintcp-dev PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
target_compile_options(wintcp-dev PRIVATE /W4 /WX /EHsc /utf-8 /permissive-
                                       /Zc:__cplusplus)
target_link_libraries(wintcp-dev PRIVATE
    iphlpapi ws2_32 comctl32 psapi user32 gdi32 comdlg32 shell32 advapi32
    crypt32 wintrust pdh ole32 oleaut32 bcrypt delayimp)
target_link_options(wintcp-dev PRIVATE
    # /guard:cf (Control Flow Guard): this target did NOT have it while the
    # product target above did, so the path that gates every change was the
    # uninstrumented one - the same inversion the project build had. The test binary
    # links the same product sources, so a control-flow-validity fault in
    # them is exactly what the suite should be catching.
    "/guard:cf"
    # Same reason as the product target above: wintcp.rc already embeds
    # RT_MANIFEST id 1, and letting the linker generate a second one gives
    # CVT1100 followed by LNK1123. Not optional, and the failure looks nothing
    # like its cause.
    "/MANIFEST:NO"
    /DELAYLOAD:comdlg32.dll /DELAYLOAD:crypt32.dll /DELAYLOAD:ole32.dll
    /DELAYLOAD:oleaut32.dll /DELAYLOAD:pdh.dll /DELAYLOAD:shell32.dll
    $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF /DEBUG:NONE>)
set_target_properties(wintcp-dev PROPERTIES
    OUTPUT_NAME "wintcp-dev"
    WIN32_EXECUTABLE FALSE
    # Per-config variants as well as the base property: with only
    # RUNTIME_OUTPUT_DIRECTORY set, CMake appends the configuration name for
    # multi-config generators, so Release landed in tests\Release\ and Debug
    # would have landed somewhere else. the GUI test harness points at one fixed
    # path, so the path must not depend on the configuration.
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/dev"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/dev"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/dev"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_BINARY_DIR}/dev"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_BINARY_DIR}/dev"
)

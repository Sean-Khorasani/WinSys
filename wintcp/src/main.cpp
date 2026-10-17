// main.cpp
// SPDX-License-Identifier: Apache-2.0
// Console-subsystem entry point for the standalone WinTCP CLI.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <windows.h>
#include <cstdio>

#include "Cli.h"
#include "CliCommands.h"
#include "CrashDump.h"
#include "Elevate.h"
#include "Commands.h"

int wmain(int argc, wchar_t** argv) {
    // Install diagnostics before initializing subsystems that may fail.
    wintcp::InstallCrashHandler();
    wintcp::EnableDebugPrivilege();

    WSADATA wsaData = {};
    if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ::MessageBoxW(nullptr, L"WSAStartup failed; cannot format IP addresses.",
                      L"WinTCP CLI", MB_OK | MB_ICONERROR);
        return 1;
    }

    // The CLI writes UTF-8. Set both console code pages so non-ASCII output is
    // rendered correctly in a standard Windows console.
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    const int result = wintcp::RunCli(argc, argv);
    const bool scanStuck = wintcp::CliScanThreadMayBeLive();
    if (!scanStuck) ::WSACleanup();
    if (scanStuck) {
        // A socket-traffic scan thread is still alive at exit (a per-socket
        // SIO_TCP_INFO probe wedged in the kernel), so the CLI cannot wait for
        // it and must terminate immediately: a normal `return` runs exit() and
        // global destructors that block on that detached, un-joinable thread,
        // and the process would never exit (the same wedge that made the GUI
        // hang). ExitProcess() is what breaks that deadlock.
        //
        // But ExitProcess() does NOT run CRT cleanup and does NOT flush the C
        // runtime's stdio buffers. When stdout/stderr are a console the
        // runtime line-buffers and this would not matter - but the Web UI runs
        // the CLI with its output PIPED, where the runtime uses FULL buffering.
        // Without an explicit flush the command's already-written JSON/table is
        // discarded, the child exits with the correct code but empty output,
        // and an automation script (`let result = list --traffic ...`) shows no
        // result. Flush every stream so piped output is never lost.
        ::_flushall();
        ::ExitProcess(static_cast<UINT>(result));
    }
    return result;
}

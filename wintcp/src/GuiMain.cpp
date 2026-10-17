// GuiMain.cpp
// SPDX-License-Identifier: Apache-2.0
// Windows-subsystem entry point for the standalone native WinTCP GUI.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

#include "CrashDump.h"
#include "Elevate.h"
#include "MainWindow.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")

namespace {
constexpr size_t kStartupMsgChars = 256;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    wintcp::InstallCrashHandler();
    wintcp::EnableDebugPrivilege();

    WSADATA wsaData = {};
    if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ::MessageBoxW(nullptr, L"WSAStartup failed; cannot format IP addresses.",
                      L"WinTCP", MB_OK | MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES |
                ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    ::InitCommonControlsEx(&icc);

    if (!wintcp::MainWindow::RegisterClass(hInstance)) {
        const DWORD error = ::GetLastError();
        wchar_t message[kStartupMsgChars] = {};
        ::swprintf_s(message, L"RegisterClassEx failed (error %lu).",
                     static_cast<unsigned long>(error));
        ::MessageBoxW(nullptr, message, L"WinTCP", MB_OK | MB_ICONERROR);
        ::WSACleanup();
        return 1;
    }

    wintcp::MainWindow window;
    const HWND hwnd = window.Create(hInstance, nCmdShow);
    if (hwnd == nullptr) {
        const DWORD error = ::GetLastError();
        wchar_t message[kStartupMsgChars] = {};
        ::swprintf_s(message, L"CreateWindowEx failed (error %lu).",
                     static_cast<unsigned long>(error));
        ::MessageBoxW(nullptr, message, L"WinTCP", MB_OK | MB_ICONERROR);
        ::WSACleanup();
        return 1;
    }

    MSG message = {};
    const HACCEL accelerator = ::LoadAcceleratorsW(hInstance, MAKEINTRESOURCEW(IDR_ACCEL));
    int result = 0;
    while ((result = ::GetMessageW(&message, nullptr, 0, 0)) != 0) {
        if (result == -1) break;
        if (accelerator != nullptr && ::TranslateAcceleratorW(hwnd, accelerator, &message)) continue;
        ::TranslateMessage(&message);
        ::DispatchMessageW(&message);
    }
    // Do NOT call WSACleanup() before returning - it is the reason the
    // GUI "never exits". At final process exit WSACleanup buys nothing (the
    // kernel reclaims every socket with the process), but it BLOCKS until all
    // in-flight Winsock calls drain. The per-PID traffic scan leaves DETACHED,
    // deliberately-uncancellable probe-pool threads blocked inside
    // WSAIoctl(SIO_TCP_INFO) (and a DNS getnameinfo), so that drain never
    // happens and the main thread parks here forever after the window closes
    // - the "close wintcp-gui.exe and it stays in Task Manager" defect. The
    // CLI entry (main.cpp) already skips WSACleanup for the same reason and
    // hard-exits; mirror it. OnDestroy has already done the ordered, bounded
    // teardown and SaveSettings, and ExitProcess reaps the lingering workers
    // (the OS has been reclaiming them on every normal process exit anyway).
    ::ExitProcess(static_cast<UINT>(message.wParam));
}

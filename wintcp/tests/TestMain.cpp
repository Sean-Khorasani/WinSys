// TestMain.cpp
// Entry point for wintcp-dev.exe. The moved self-test, benchmark and UI
// harness live here now; wintcp.exe does not contain them.
//
// WHY THIS FILE EXISTS. Bench.cpp (RunSelfTest / RunBench) and UiHarness.cpp
// (RunUiHarness) used to be compiled INTO wintcp.exe, reachable as the `selftest`
// and `bench` verbs and the `--uiharness` switch. That put ~280 KB of test code
// and every check's name string into the shipped product, and gave an end user
// three commands that answer questions only the author has. They are moved out
// wholesale, commands and switches included - there is no #ifdef switch here and
// no flag that puts them back.
//
// It links the SAME product sources as wintcp.exe. That is the whole point: a
// test that exercised a copy of the logic would prove nothing (README, the
// `selftest` row). So the split is by entry point and link line, never by a
// second copy of the code.
//
// MODES
//   wintcp-dev.exe unit              the 1057 internal checks; exit 0 on all pass
//   wintcp-dev.exe bench [rows] [iters]
//   wintcp-dev.exe ui                the 68 in-process GUI checks; needs a
//                                      desktop session, because it creates the
//                                      real window and drives the real WndProc
//
// THIS BINARY HAS NO INTERACTIVE WINDOW. Running it with no mode prints this
// usage and exits. The application is wintcp.exe, built from the same sources
// with main.cpp instead of TestMain.cpp; this one exists only to be driven by
// a mode, and every gate drives `unit` or `ui`. That is not an oversight - the
// usage text below says it, because "I ran wintcp-dev.exe and nothing
// happened" is the first thing anyone does with a second binary in the output
// directory.
//
// The counts above are measured, not quoted - read them from the binaries.
// The bootstrap below deliberately mirrors what wintcp.cpp's wmain does -
// console code page, common controls, WSAStartup, RegisterClass - because a test
// driver that skipped setup would exercise a differently-initialised process
// than the product does and would pass while the product broke.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>

#include <cwchar>
#include <cwctype>
#include <string>

#include "Bench.h"
#include "MainWindow.h"
#include "UiHarness.h"
#include "resource.h"

#pragma comment(lib, "comctl32.lib")

namespace {

// Print UTF-8 text to stdout. The checks produce UTF-8 with CRLF endings and
// non-ASCII in several places (the em-dash and box-drawing in the table
// assertions), so without setting the code page first the console renders those
// as mojibake and the output is unreadable.
void WriteOut(const std::string& s) {
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
}

void WriteWide(const std::wstring& s) {
    ::WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), s.c_str(),
                    static_cast<DWORD>(s.size()), nullptr, nullptr);
}

void Usage() {
    WriteOut(
        "wintcp-dev.exe - development test driver for WinTCP\r\n"
        "\r\n"
        "  unit                 internal checks: parsers, snapshot diff, sort,\r\n"
        "                       grouping, filters, formatting, joins, GeoIP,\r\n"
        "                       TLS decode, reassembly, capability report.\r\n"
        "                       Exit 0 only when every check passes.\r\n"
        "\r\n"
        "  bench [rows] [iters] time the view pipeline over synthetic rows.\r\n"
        "\r\n"
        "  ui                   in-process GUI checks against the real window.\r\n"
        "                       Requires an interactive desktop session.\r\n"
        "\r\n"
        "This binary is not shipped to users. wintcp.exe is the tool.\r\n");
}

int RunUnit() {
    const wintcp::TestResult r = wintcp::RunSelfTest();
    WriteOut(r.output);
    return r.exitCode;
}

int RunBenchMode(int argc, LPWSTR* argv) {
    unsigned rows = wintcp::kBenchDefaultRows;
    unsigned iters = wintcp::kBenchDefaultIters;
    // Positionals only, exactly as the old `bench` verb accepted them. The
    // named --rows/--iters switches went away with the verb; if they are wanted
    // back they belong here, not in the product.
    if (argc > 1) {
        wchar_t* end = nullptr;
        const unsigned long v = ::wcstoul(argv[1], &end, 10);
        if (end == argv[1] || (end != nullptr && *end != L'\0')) {
            WriteOut("bench: <rows> must be a number\r\n");
            return 2;
        }
        rows = static_cast<unsigned>(v);
    }
    if (argc > 2) {
        wchar_t* end = nullptr;
        const unsigned long v = ::wcstoul(argv[2], &end, 10);
        if (end == argv[2] || (end != nullptr && *end != L'\0')) {
            WriteOut("bench: <iters> must be a number\r\n");
            return 2;
        }
        iters = static_cast<unsigned>(v);
    }
    WriteOut(wintcp::RunBench(rows, iters));
    return 0;
}

// The GUI checks. Creates the real window and drives the real WndProc, which is
// the only reason this mode cannot be a plain unit test.
int RunUiMode() {
    HINSTANCE hInstance = ::GetModuleHandleW(nullptr);

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    // Same flag set as the product's own init (main.cpp), including the
    // tree-view class the process-tree mode needs. A harness whose flags
    // differ from the product's is a harness that passes where the shipped
    // binary would fail.
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES |
                ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    ::InitCommonControlsEx(&icc);

    if (!wintcp::MainWindow::RegisterClass(hInstance)) {
        DWORD err = ::GetLastError();
        wchar_t msg[256] = {0};
        ::swprintf_s(msg, L"RegisterClassEx failed (error %lu).",
                     static_cast<unsigned long>(err));
        ::MessageBoxW(nullptr, msg, L"wintcp-dev", MB_OK | MB_ICONERROR);
        return 1;
    }

    wintcp::MainWindow window;
    HWND hwnd = window.Create(hInstance, SW_SHOWDEFAULT);
    if (hwnd == nullptr) {
        DWORD err = ::GetLastError();
        wchar_t msg[256] = {0};
        ::swprintf_s(msg, L"CreateWindowEx failed (error %lu).",
                     static_cast<unsigned long>(err));
        ::MessageBoxW(nullptr, msg, L"wintcp-dev", MB_OK | MB_ICONERROR);
        return 1;
    }

    const std::wstring verdict = wintcp::RunUiHarness(window, hwnd);
    WriteWide(verdict);
    WriteWide(L"\r\n");
    // ExitProcess, no drain - identical to the old --uiharness path. A graceful
    // teardown cannot complete here: MainWindow's destructor joins the refresh
    // worker, and a socket-traffic scan thread can be stuck in the kernel
    // indefinitely. That is a property of the environment, not the harness, and
    // the harness has already printed its verdict.
    ::ExitProcess(verdict == L"UI HARNESS PASS" ? 0 : 1);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    if (argc < 2) {
        Usage();
        return 2;
    }

    // Winsock is required for InetNtopW()/InetPtonW(), which several checks and
    // the harness both call.
    WSADATA wsaData = {};
    if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        ::MessageBoxW(nullptr, L"WSAStartup failed.", L"wintcp-dev",
                      MB_OK | MB_ICONERROR);
        return 1;
    }

    const std::wstring mode = (argv[1] == nullptr) ? L"" : argv[1];
    std::wstring lower;
    for (wchar_t ch : mode) {
        lower.push_back(static_cast<wchar_t>(::towlower(ch)));
    }

    int rc;
    if (lower == L"unit") {
        rc = RunUnit();
    } else if (lower == L"bench") {
        // Shift by ONE, not two: RunBenchMode indexes argv[1]/argv[2], so argv
        // must still start at the program name. Passing argc-2/argv+2 made
        // argv[0] the first positional, so `bench 1000 2` set rows=2 - which
        // RunBench then silently clamped up to the 100 minimum, and the run
        // looked plausible while measuring nothing the caller asked for.
        rc = RunBenchMode(argc - 1, argv + 1);
    } else if (lower == L"ui") {
        rc = RunUiMode();
    } else {
        Usage();
        rc = 2;
    }

    ::WSACleanup();
    return rc;
}

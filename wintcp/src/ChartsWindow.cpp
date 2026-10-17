// ChartsWindow.cpp
// SPDX-License-Identifier: Apache-2.0
// See ChartsWindow.h. GDI line charts, double-buffered, DPI-scaled layout.
//
// Fixes live next to the code they address (each carries its
// original defect number in a comment).

#include "ChartsWindow.h"
#include "Alerts.h"   // FormatBps (RateText removed, one rate formatter)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
// ws2tcpip.h must come first: netioapi.h only declares MIB_IF_ROW2 and
// GetIfTable2() when _WS2IPDEF_ (from ws2ipdef.h) is already defined, and
// iphlpapi.h may pull netioapi.h in before we'd get the chance otherwise.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <pdh.h>
#include <pdhmsg.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "Utils.h"
#include "WinCaps.h"   // DllAvailable: pdh.dll is delay-loaded (see kDelayedDlls)
#include "FontCache.h"   // shared, DPI-correct fonts
#include "Theme.h"       // shared system palette + HighContrastActive()
#include "ChartExport.h"   // in-window Export writes the existing CSV form
#include <commdlg.h>     // GetSaveFileNameW for the export picker

namespace wintcp {
namespace {

const UINT_PTR kChartsTimerId = 1;
const UINT kChartsIntervalMs = 1000;   // dev constant (with its ChartExport
                                       // twin below): 1 s sampling is the panels'
                                       // contract, not a preference.

// Ticks of the chart loop to wait before re-opening a failed PDH disk query.
// The loop ticks at kChartsIntervalMs, so 10 is ~10 s of silence: long enough
// to ride out a transient PDH failure, short enough that a disk counter gone
// missing for good does not stay dark all session. SysStats.cpp carries the
// same-named constant for its own sampler loop (same rate, same reasoning) —
// the two must stay in step, see the use site below.
const int kPdhReopenRetryTicks = 10;

// IF_TYPE_SOFTWARE_LOOPBACK - numeric to keep the include surface small.
const ULONG kIfTypeSoftwareLoopback = 24;

// Percentages are reported on a 0..100 scale so a value is renderable as-is.
// Same name as ProcStats.cpp's and SysStats.cpp's copies on purpose - a grep
// should find every place a percent scale is assumed.
const double kPctScale = 100.0;

// Sanity ceiling on a per-direction network rate: 100 Gbit/s. An interface
// table reset (replug, counter rollover) shows up as one enormous delta, and
// without this it would be drawn as a full-height spike that flattens every
// real sample on the panel. 8 bits per byte, so bits become bytes.
const double kNetRateCapBitsPerSec = 100.0e9;
const double kBitsPerByte = 8.0;

// The background, text and grid colours are no
// longer baked in here - LivePalette() (Theme.h) reads them
// from the live system colours, so the charts follow the OS
// theme (light, dark and high contrast) exactly as the main
// window does.  Only the two series colours are the app's
// own brand; they are semantic, not theme, colours.
const COLORREF kLineA = RGB(0x00, 0x78, 0xD7);   // primary (CPU / R)
const COLORREF kLineB = RGB(0xCA, 0x6E, 0x00);   // secondary (W)

// Default window size, in the metric grid every MulDiv in this file is authored
// on. Wide and tall enough that four stacked panels each get a trace that can
// be read rather than a hairline.
const int kChartsDefaultWidth = 680;
const int kChartsDefaultHeight = 640;

// Smallest size the four panels can still be laid out in. Below this the
// per-panel geometry in OnPaint would go negative and draw nothing at all, so
// the window refuses the resize instead.
const int kChartsMinTrackWidth = 420;
const int kChartsMinTrackHeight = 340;

// The DPI every MulDiv in this file scales FROM. It is USER_DEFAULT_SCREEN_DPI
// (96) - the number Utils.cpp and FontCache.cpp carry as kDefaultScreenDpi -
// but here it is the grid the metrics were authored on rather than a fallback,
// so it has its own name to say which role it plays.
const int kMetricsDpi = 96;

// Floor for an auto-scaled byte-rate panel, in bytes/second. Same value and
// name as ChartExport.cpp's kMinAutoScale: the export has to report the
// ceiling the panel draws, so the two floors cannot disagree.
const double kMinAutoScale = 64.0 * 1024.0;

// Panel caption and y-axis label widths. A caption carries two FormatBps
// strings plus byte totals, so it is the longer of the two; every swprintf_s
// in this file truncates rather than overruns, so both are slack.
constexpr size_t kCaptionChars = 160;
constexpr size_t kScaleLabelChars = 64;

// the button row's logical metrics. The row is reserved in OnPaint's
// plot area and the buttons are positioned in WM_SIZE from the same
// numbers, so paint and layout cannot disagree about where the charts end.
constexpr int kBtnRowH96 = 36;
constexpr int kBtnH96 = 26;
constexpr int kBtnWExport96 = 110;
constexpr int kBtnWCopy96 = 110;
constexpr int kBtnGap96 = 6;
constexpr int kBtnMargin96 = 10;

// Child ids, local to this window (no .rc entry, like every other window).
constexpr UINT kIdChartExport = 1;
constexpr UINT kIdChartCopy = 2;

ULONGLONG FtToU64(const FILETIME& ft) {
    ULARGE_INTEGER u = {};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

void PushCapped(std::vector<double>& v, double value, size_t cap) {
    v.push_back(value);
    if (v.size() > cap) v.erase(v.begin(), v.end() - cap);
}

double MaxOf(const std::vector<double>& a, const std::vector<double>& b) {
    double m = 0.0;
    for (double v : a) m = (std::max)(m, v);
    for (double v : b) m = (std::max)(m, v);
    return m;
}

// RateText lived here and did FormatBytes(x) + "/s" — the same job as
// FormatBps (Alerts.h), with a different rounding ("2.0 KB/s" vs "2 KB/s").
// Two same-job formatters is how one surface prints "2.0" and another "2" for
// the same reading. Removed; the three call sites below use FormatBps, whose
// output is pinned by selftest. Visible difference: whole KB/s values lose
// the ".0" on chart captions and the y-axis — same numbers, one spelling.


}  // namespace

const wchar_t* ChartsWindow::kClassName = L"WinTcpChartsWnd";

ChartsWindow::~ChartsWindow() {
    // Close() runs WM_DESTROY synchronously, which already calls
    // DeleteFonts() and CleanupPdh(); the handles are nulled there, so no
    // second cleanup pass is needed (or wanted - it used to double up).
    Close();
}

void ChartsWindow::CenterOnOwner(HWND owner) {
    if (hwnd_ == nullptr) return;
    RECT rcOwner = {};
    if (owner != nullptr && ::GetWindowRect(owner, &rcOwner)) {
        RECT rcSelf = {};
        ::GetWindowRect(hwnd_, &rcSelf);
        const int w = rcSelf.right - rcSelf.left;
        const int h = rcSelf.bottom - rcSelf.top;
        int x = rcOwner.left + ((rcOwner.right - rcOwner.left) - w) / 2;
        int y = rcOwner.top + ((rcOwner.bottom - rcOwner.top) - h) / 2;
        HMONITOR mon = ::MonitorFromRect(&rcOwner, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi = {};
        mi.cbSize = sizeof(mi);
        if (::GetMonitorInfoW(mon, &mi)) {
            const RECT& wa = mi.rcWork;
            if (x + w > wa.right) x = wa.right - w;
            if (y + h > wa.bottom) y = wa.bottom - h;
            if (x < wa.left) x = wa.left;
            if (y < wa.top) y = wa.top;
        }
        ::SetWindowPos(hwnd_, nullptr, x, y, 0, 0,
                       SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

void ChartsWindow::Show(HWND owner, bool dark) {
    dark_ = dark;
    if (hwnd_ == nullptr) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = &ChartsWindow::WindowProc;
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = kClassName;
        if (::RegisterClassExW(&wc) == 0 &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            return;
        const UINT dpi = QueryDpiForWindow(owner);   // owner's monitor DPI
        hwnd_ = ::CreateWindowExW(
            0, kClassName, L"WinTCP - Performance graphs",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT,
            CW_USEDEFAULT, ::MulDiv(kChartsDefaultWidth, static_cast<int>(dpi),
                                    kMetricsDpi),
            ::MulDiv(kChartsDefaultHeight, static_cast<int>(dpi),
                     kMetricsDpi), owner, nullptr,
            ::GetModuleHandleW(nullptr), this);
        if (hwnd_ == nullptr) return;
        CenterOnOwner(owner);
    }
    if (::IsWindowVisible(hwnd_) == FALSE) ::ShowWindow(hwnd_, SW_SHOW);
    StartSampling();                     // timer runs only while visible
    ::SetForegroundWindow(hwnd_);
}

void ChartsWindow::Close() {
    if (hwnd_ != nullptr) {
        ::DestroyWindow(hwnd_);
        // WM_DESTROY runs synchronously and clears hwnd_.
    }
}

bool ChartsWindow::IsVisible() const {
    return hwnd_ != nullptr && ::IsWindowVisible(hwnd_) == TRUE;
}

void ChartsWindow::SetDark(bool dark) {
    dark_ = dark;
    if (hwnd_ != nullptr) ::InvalidateRect(hwnd_, nullptr, TRUE);
}

void ChartsWindow::StartSampling() {
    if (hwnd_ != nullptr && timerOn_ == 0) {
        timerOn_ = ::SetTimer(hwnd_, kChartsTimerId, kChartsIntervalMs,
                              nullptr);
    }
}

void ChartsWindow::StopSampling() {
    if (timerOn_ != 0 && hwnd_ != nullptr) {
        ::KillTimer(hwnd_, kChartsTimerId);
        timerOn_ = 0;
    }
}

void ChartsWindow::CreateFonts() {
    DeleteFonts();
    const UINT dpi = QueryDpiForWindow(hwnd_);
    font_ = FontCache::Get().Get(kBodyPtSize, FW_NORMAL, dpi);
    boldFont_ = FontCache::Get().Get(kBodyPtSize, FW_BOLD, dpi);
}

void ChartsWindow::DeleteFonts() {
    // Deliberately does NOT DeleteObject: these are cache-owned handles, and
    // releasing one here would break every other window holding it. Nulling the
    // local pointers is the whole of what a caller may do.
    font_ = nullptr;
    boldFont_ = nullptr;
}

void ChartsWindow::CleanupPdh() {
    if (pdhQuery_ != nullptr) {
        ::PdhCloseQuery(static_cast<HQUERY>(pdhQuery_));
        pdhQuery_ = nullptr;
    }
    pdhRead_ = pdhWrite_ = nullptr;
    pdhFails_ = 0;
}

LRESULT CALLBACK ChartsWindow::WindowProc(HWND hwnd, UINT msg, WPARAM wParam,
                                          LPARAM lParam) {
    ChartsWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        self = static_cast<ChartsWindow*>(cs->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                            reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
    } else {
        self = reinterpret_cast<ChartsWindow*>(
            ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self != nullptr) return self->HandleMessage(msg, wParam, lParam);
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT ChartsWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            CreateFonts();
            Sample();   // establish baselines immediately (no history yet)
            // focusable Export/Copy buttons. Positioned in WM_SIZE;
            // a null after a failed creation only loses the buttons, and
            // every use site below checks before touching them.
            hwndExport_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Export...",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(
                    static_cast<UINT_PTR>(kIdChartExport)),
                ::GetModuleHandleW(nullptr), nullptr);
            hwndCopy_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Copy values",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kIdChartCopy)),
                ::GetModuleHandleW(nullptr), nullptr);
            if (font_ != nullptr) {
                if (hwndExport_ != nullptr)
                    ::SendMessageW(hwndExport_, WM_SETFONT,
                                   reinterpret_cast<WPARAM>(font_), TRUE);
                if (hwndCopy_ != nullptr)
                    ::SendMessageW(hwndCopy_, WM_SETFONT,
                                   reinterpret_cast<WPARAM>(font_), TRUE);
            }
            return 0;
        case WM_TIMER:
            if (wParam == kChartsTimerId) OnTimer();
            return 0;
        case WM_PAINT:
            OnPaint();
            return 0;
        case WM_SIZE: {
            // the button row lives at the bottom-right; the plot area
            // in OnPaint reserves the same row height, so the buttons never
            // cover a trace.
            const UINT dpi = QueryDpiForWindow(hwnd_);
            const auto dx = [dpi](int v) {
                return ::MulDiv(v, static_cast<int>(dpi), kMetricsDpi);
            };
            const int cx = LOWORD(lParam);
            const int cy = HIWORD(lParam);
            const int m = dx(kBtnMargin96);
            const int btnH = dx(kBtnH96);
            const int btnY = cy - m - btnH;
            if (hwndExport_ != nullptr)
                ::MoveWindow(hwndExport_, cx - m - dx(kBtnWExport96), btnY,
                             dx(kBtnWExport96), btnH, TRUE);
            if (hwndCopy_ != nullptr)
                ::MoveWindow(hwndCopy_,
                             cx - m - dx(kBtnWExport96) - dx(kBtnGap96) -
                                 dx(kBtnWCopy96),
                             btnY, dx(kBtnWCopy96), btnH, TRUE);
            ::InvalidateRect(hwnd_, nullptr, TRUE);
            return 0;
        }
        case WM_SYSCOLORCHANGE:
            // the palette is read live from the system
            // colours on every paint, so a theme or
            // high-contrast change only needs a repaint to
            // take effect - no cached colours to refresh.
            ::InvalidateRect(hwnd_, nullptr, TRUE);
            return 0;
        case WM_GETMINMAXINFO: {
            // Keep all four panels paintable.
            const UINT dpi = QueryDpiForWindow(hwnd_);
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x =
                ::MulDiv(kChartsMinTrackWidth, static_cast<int>(dpi), kMetricsDpi);
            mmi->ptMinTrackSize.y =
                ::MulDiv(kChartsMinTrackHeight, static_cast<int>(dpi), kMetricsDpi);
            return 0;
        }
        case WM_DPICHANGED: {
            // Follow the suggested rect and rebuild DPI-scaled fonts
            //
            CreateFonts();
            const auto* suggested = reinterpret_cast<const RECT*>(lParam);
            ::SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                           suggested->right - suggested->left,
                           suggested->bottom - suggested->top,
                           SWP_NOZORDER | SWP_NOACTIVATE);
            ::InvalidateRect(hwnd_, nullptr, TRUE);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;   // fully painted in OnPaint (double-buffered)
        case WM_KEYDOWN:
            // Esc hides like every other secondary window (the 1 s
            // sampler stops with it, same as the X path, so a hidden
            // window costs nothing).
            if (wParam == VK_ESCAPE) {
                StopSampling();
                ::ShowWindow(hwnd_, SW_HIDE);
                return 0;
            }
            break;
        case WM_CLOSE:
            // Hide AND stop sampling: a background 1 s timer on a hidden
            // window was pure waste.
            StopSampling();
            ::ShowWindow(hwnd_, SW_HIDE);
            return 0;
        case WM_COMMAND:
            // BN_CLICKED only: without the notification check an
            // enable/disable notification would also trigger the command.
            if (HIWORD(wParam) == BN_CLICKED) {
                if (LOWORD(wParam) == kIdChartExport) ExportCharts();
                else if (LOWORD(wParam) == kIdChartCopy) CopyValues();
            }
            return 0;
        case WM_DESTROY:
            StopSampling();
            CleanupPdh();
            DeleteFonts();
            hwndExport_ = nullptr;
            hwndCopy_ = nullptr;
            hwnd_ = nullptr;
            return 0;
        default:
            break;
    }
    return ::DefWindowProcW(hwnd_, msg, wParam, lParam);
}

void ChartsWindow::OnTimer() {
    Sample();
    if (hwnd_ == nullptr) return;
    ::InvalidateRect(hwnd_, nullptr, FALSE);
    // the values move every tick, so the accessible name follows
    // them - the same derivation the captions paint (ValuesText), for
    // screen readers and UIA agents that cannot scrape the traces.
    SetAccessibleName(hwnd_, ValuesText());
}

// ---- sampling ---------------------------------------------------------------

void ChartsWindow::Sample() {
    const ULONGLONG nowTick = ::GetTickCount64();

    // --- CPU (system-wide, from GetSystemTimes) ------------------------------
    FILETIME idle = {}, kernel = {}, user = {};
    if (::GetSystemTimes(&idle, &kernel, &user)) {
        bool cpuOk = false;
        if (haveCpuBase_) {
            const ULONGLONG idleD = FtToU64(idle) - FtToU64(prevIdle_);
            const ULONGLONG totalD =
                (FtToU64(kernel) - FtToU64(prevKernel_)) +
                (FtToU64(user) - FtToU64(prevUser_));
            if (totalD > 0) {
                double busy = 1.0 - static_cast<double>(idleD) /
                                        static_cast<double>(totalD);
                if (busy < 0.0) busy = 0.0;
                if (busy > 1.0) busy = 1.0;
                cpuPct_ = busy * kPctScale;
                cpuOk = true;
            }
        }
        prevIdle_ = idle;
        prevKernel_ = kernel;
        prevUser_ = user;
        haveCpuBase_ = true;
        if (cpuOk) PushCapped(cpuHist_, cpuPct_, kMaxSamples);
    }

    // --- memory --------------------------------------------------------------
    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (::GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys > 0) {
        memTotal_ = ms.ullTotalPhys;
        memUsed_ = ms.ullTotalPhys - ms.ullAvailPhys;
        // Derive the percentage from the same two numbers the caption
        // prints instead of dwMemoryLoad.
        memPct_ = kPctScale * static_cast<double>(memUsed_) /
                  static_cast<double>(memTotal_);
        PushCapped(memHist_, memPct_, kMaxSamples);
    }

    // --- disk (PDH PhysicalDisk _Total, best effort) -------------------------
    //
    // DllAvailable gate: pdh.dll is delay-loaded, so a machine without it would
    // raise a delay-load exception on the first ::PdhOpenQueryW below instead
    // of reporting "counters unavailable" - which is what diskAvailable_=false
    // renders. Same pattern as the SysStats.cpp sampler.
    if (pdhQuery_ == nullptr && DllAvailable("pdh.dll")) {
        if (pdhRetryIn_ <= 0) {
            HQUERY q = nullptr;
            HCOUNTER rd = nullptr, wr = nullptr;
            // PdhAddEnglishCounterW: locale-independent counter path
            //
            if (::PdhOpenQueryW(nullptr, 0, &q) == ERROR_SUCCESS &&
                ::PdhAddEnglishCounterW(
                    q, L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                    0, &rd) == ERROR_SUCCESS &&
                ::PdhAddEnglishCounterW(
                    q, L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                    0, &wr) == ERROR_SUCCESS &&
                ::PdhCollectQueryData(q) == ERROR_SUCCESS) {
                pdhQuery_ = q;
                pdhRead_ = rd;
                pdhWrite_ = wr;
                pdhFails_ = 0;
                diskAvailable_ = true;
            } else {
                if (q != nullptr) ::PdhCloseQuery(q);
                diskAvailable_ = false;
                // Same backoff as SysStats.cpp's disk-counter reopen (which see):
                // both loops tick at ~1 s, so 10 ticks is ~10 s of silence
                // before PDH is asked again. Kept as two same-named constants
                // rather than one shared home on purpose — the members belong
                // to different classes with different tick drivers, and a
                // shared header would couple them falsely. If either tick rate
                // stops being ~1 s, both constants must be revisited together.
                pdhRetryIn_ = kPdhReopenRetryTicks;
            }
        } else {
            --pdhRetryIn_;
        }
    }
    if (pdhQuery_ != nullptr) {
        bool ok = ::PdhCollectQueryData(static_cast<HQUERY>(pdhQuery_)) ==
                  ERROR_SUCCESS;
        PDH_FMT_COUNTERVALUE fv = {};
        if (ok && ::PdhGetFormattedCounterValue(
                       static_cast<HCOUNTER>(pdhRead_), PDH_FMT_DOUBLE,
                       nullptr, &fv) == ERROR_SUCCESS &&
            fv.CStatus == ERROR_SUCCESS) {
            diskReadBps_ = (fv.doubleValue < 0.0) ? 0.0 : fv.doubleValue;
        } else {
            ok = false;
        }
        if (ok && ::PdhGetFormattedCounterValue(
                       static_cast<HCOUNTER>(pdhWrite_), PDH_FMT_DOUBLE,
                       nullptr, &fv) == ERROR_SUCCESS &&
            fv.CStatus == ERROR_SUCCESS) {
            diskWriteBps_ = (fv.doubleValue < 0.0) ? 0.0 : fv.doubleValue;
        } else {
            ok = false;
        }
        if (ok) {
            pdhFails_ = 0;
            diskAvailable_ = true;
            PushCapped(diskReadHist_, diskReadBps_, kMaxSamples);
            PushCapped(diskWriteHist_, diskWriteBps_, kMaxSamples);
        } else if (++pdhFails_ >= 3) {
            // Three consecutive failures = counters really went away;
            // transient hiccups are tolerated.
            CleanupPdh();
            diskAvailable_ = false;
            pdhRetryIn_ = kPdhReopenRetryTicks;
            diskReadHist_.clear();    // panel switches to "n/a", no stale line
            diskWriteHist_.clear();
        }
    }

    // --- network (sum of interface octets, 64-bit via GetIfTable2) -----------
    PMIB_IF_TABLE2 ifTable = nullptr;
    if (::GetIfTable2(&ifTable) == NO_ERROR && ifTable != nullptr) {
        ULONGLONG inOctets = 0;
        ULONGLONG outOctets = 0;
        for (ULONG i = 0; i < ifTable->NumEntries; ++i) {
            const MIB_IF_ROW2& row = ifTable->Table[i];
            if (row.Type == kIfTypeSoftwareLoopback) continue;
            // UINT64 counters: no 4 GiB wrap.
            inOctets += row.InOctets;
            outOctets += row.OutOctets;
        }
        ::FreeMibTable(ifTable);

        bool netOk = false;
        if (haveNetBase_ && nowTick > prevNetTick_) {
            const double secs =
                static_cast<double>(nowTick - prevNetTick_) / 1000.0;
            if (secs > 0.0) {
                const ULONGLONG inD = inOctets - prevNetIn_;
                const ULONGLONG outD = outOctets - prevNetOut_;
                // Guard against table resets (interface replug shows up
                // as a huge spike): clamp to 100 Gbit/s per direction.
                const double cap =
                    kNetRateCapBitsPerSec / kBitsPerByte * secs;
                netRecvBps_ = (static_cast<double>(inD) > cap)
                                  ? 0.0
                                  : static_cast<double>(inD) / secs;
                netSendBps_ = (static_cast<double>(outD) > cap)
                                  ? 0.0
                                  : static_cast<double>(outD) / secs;
                netOk = true;
            }
        }
        prevNetIn_ = inOctets;
        prevNetOut_ = outOctets;
        prevNetTick_ = nowTick;
        haveNetBase_ = true;
        if (netOk) {
            PushCapped(netRecvHist_, netRecvBps_, kMaxSamples);
            PushCapped(netSendHist_, netSendBps_, kMaxSamples);
        }
    }
}

// ---- painting ---------------------------------------------------------------

void ChartsWindow::OnPaint() {
    PAINTSTRUCT ps = {};
    HDC hdc = ::BeginPaint(hwnd_, &ps);
    RECT rc = {};
    ::GetClientRect(hwnd_, &rc);

    const UINT dpi = QueryDpiForWindow(hwnd_);
    const auto px = [dpi](int v) {
        return ::MulDiv(v, static_cast<int>(dpi), kMetricsDpi);
    };

    // Double buffer (avoids flicker at 1 Hz repaints).
    HDC mem = ::CreateCompatibleDC(hdc);
    const int bmpW = (std::max)(rc.right, 1L);
    const int bmpH = (std::max)(rc.bottom, 1L);
    HBITMAP bmp = ::CreateCompatibleBitmap(hdc, bmpW, bmpH);
    HGDIOBJ oldBmp = ::SelectObject(mem, bmp);
    // base colours come from the shared palette (Theme.h), so
    // the charts follow the OS theme exactly as the main window does.
    // Light and high-contrast read the live system colours; dark reads
    // the one shared dark substitute every self-painting window uses -
    // never a per-window copy that can diverge.
    const bool dark = dark_ && !HighContrastActive();
    const SystemPalette pal = LivePalette();
    const COLORREF bg = dark ? kSharedDarkBg : pal.bg;
    const COLORREF fg = dark ? kSharedDarkFg : pal.fg;
    const COLORREF grid = dark ? kSharedDarkGrid : pal.grid;
    HBRUSH bgBrush = ::CreateSolidBrush(bg);
    ::FillRect(mem, &rc, bgBrush);
    ::DeleteObject(bgBrush);

    const int pad = px(10);
    const int gap = px(8);
    const int panels = 4;
    // the bottom row belongs to the Export/Copy buttons (positioned
    // in WM_SIZE from the same kBtnRowH96), so the four traces end above
    // them instead of painting underneath.
    const int plotBottom = rc.bottom - px(kBtnRowH96);
    const int panelH =
        (plotBottom - pad * 2 - gap * (panels - 1)) / panels;

    struct Panel {
        const wchar_t* name;
        const std::vector<double>* a;
        const std::vector<double>* b;   // optional second line
        std::wstring caption;           // current value(s); empty = none yet
        double fixedMax;                // > 0 = fixed 0..fixedMax scale
        const wchar_t* emptyMsg;        // override for "collecting…"
        // Legend labels for the two-line panels. A single-line
        // panel has no legend - one line needs no key - so these are
        // null for CPU and Memory and non-null for Disk (R/W) and
        // Network (down/up), where two differently-coloured lines
        // otherwise cannot be told apart.
        const wchar_t* aLabel;
        const wchar_t* bLabel;
    };

    // Captions exist only once their source produced a real reading
    // no fabricated "0.0 %" before the first delta.
    std::wstring cpuCap, memCap, diskCap, netCap;
    wchar_t buf[kCaptionChars] = {0};
    if (!cpuHist_.empty()) {
        ::swprintf_s(buf, L"%.1f %%", cpuPct_);
        cpuCap = buf;
    }
    if (!memHist_.empty()) {
        ::swprintf_s(buf, L"%.0f %%  (%s / %s)", memPct_,
                     FormatBytes(memUsed_).c_str(),
                     FormatBytes(memTotal_).c_str());
        memCap = buf;
    }
    if (diskAvailable_) {
        if (!diskReadHist_.empty()) {
            ::swprintf_s(buf, L"R %s   W %s", FormatBps(diskReadBps_).c_str(),
                         FormatBps(diskWriteBps_).c_str());
            diskCap = buf;
        }
    } else {
        diskCap = L"counters unavailable";
    }
    if (!netRecvHist_.empty()) {
        ::swprintf_s(buf, L"down %s   up %s", FormatBps(netRecvBps_).c_str(),
                     FormatBps(netSendBps_).c_str());
        netCap = buf;
    }

    const Panel defs[4] = {
        {L"CPU", &cpuHist_, nullptr, cpuCap, kPctScale, nullptr,
         nullptr, nullptr},
        {L"Memory", &memHist_, nullptr, memCap, kPctScale, nullptr,
         nullptr, nullptr},
        {L"Disk", &diskReadHist_, &diskWriteHist_, diskCap, 0.0,
         diskAvailable_ ? nullptr : L"n/a \u2014 performance counters unavailable",
         L"R", L"W"},
        {L"Network", &netRecvHist_, &netSendHist_, netCap, 0.0, nullptr,
         L"down", L"up"},
    };

    HFONT oldFont = static_cast<HFONT>(
        ::SelectObject(mem, (boldFont_ != nullptr) ? boldFont_
                                                   : GetStockObject(
                                                         DEFAULT_GUI_FONT)));
    ::SetBkMode(mem, TRANSPARENT);
    ::SetTextColor(mem, fg);

    const int titleH = px(20);
    // The dim caption tone follows the same dark branch as the base
    // palette above, from the same shared constants.
    const COLORREF dim =
        dark ? kSharedDarkDim : RGB(0x66, 0x66, 0x66);
    // under high contrast the fixed brand blues/oranges can sit on
    // the scheme's own background unreadably, so the two series borrow
    // the system's contrast-picked highlight pair instead. Anywhere else
    // they stay the app's own semantic colours.
    const bool hc = HighContrastActive();
    const COLORREF lineA =
        hc ? ::GetSysColor(COLOR_HIGHLIGHT) : kLineA;
    const COLORREF lineB =
        hc ? ::GetSysColor(COLOR_HOTLIGHT) : kLineB;
    for (int p = 0; p < panels; ++p) {
        const Panel& d = defs[p];
        const int top = pad + p * (panelH + gap);
        const RECT chart = {pad, top + titleH, rc.right - pad, top + panelH};

        // Caption line: name left, value(s) appended (no trailing
        // spaces when there is no value yet); ellipsize instead of
        // overflowing. On a two-line panel the right end of the row
        // is reserved for the colour legend, so a long caption
        // ellipsizes before it rather than running under it.
        std::wstring line = d.name;
        if (!d.caption.empty()) {
            line += L"   ";
            line += d.caption;
        }
        const int rowRight = rc.right - pad;
        int captionRight = rowRight;
        const bool hasLegend =
            (d.b != nullptr && d.aLabel != nullptr &&
             d.bLabel != nullptr);
        if (hasLegend) {
            RECT ra = {}, rb = {};
            ::DrawTextW(mem, d.aLabel, -1, &ra,
                            DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
            ::DrawTextW(mem, d.bLabel, -1, &rb,
                            DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
            const int sampleW = px(12), gapX = px(4),
                      entryGap = px(12);
            captionRight = rowRight -
                ((sampleW + gapX + (ra.right - ra.left)) +
                 entryGap +
                 (sampleW + gapX + (rb.right - rb.left))) -
                px(8);
            if (captionRight < pad + px(48))
                captionRight = pad + px(48);
        }
        RECT titleRc = {pad, top, captionRight, top + titleH};
        ::DrawTextW(mem, line.c_str(), -1, &titleRc,
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE |
                            DT_NOPREFIX | DT_END_ELLIPSIS);

        // Colour legend for a two-line panel: a short sample
        // line in each series' colour beside its label, flush
        // right. Without it the reader cannot tell which of the
        // two lines is read and which is written (Disk), or down
        // and up (Network).
        if (hasLegend) {
            const int sampleW = px(12), gapX = px(4),
                      entryGap = px(12);
            const int cy = top + titleH / 2;
            // Drawn right-to-left: the B entry ends at the
            // row's right edge, the A entry sits one
            // entry-gap to its left.
            const auto entry = [&](const wchar_t* label,
                                       COLORREF color, int rightX) {
                RECT tr = {};
                ::DrawTextW(mem, label, -1, &tr,
                                DT_CALCRECT | DT_SINGLELINE |
                                    DT_NOPREFIX);
                const int lw = tr.right - tr.left;
                const int labelX = rightX - lw;
                const int sampleX = labelX - gapX - sampleW;
                RECT lr = {labelX, top, labelX + lw, top + titleH};
                ::SetTextColor(mem, fg);
                ::DrawTextW(mem, label, -1, &lr,
                                DT_LEFT | DT_VCENTER | DT_SINGLELINE |
                                    DT_NOPREFIX);
                HPEN pen = ::CreatePen(PS_SOLID,
                                         (std::max)(px(2), 2), color);
                HGDIOBJ old = ::SelectObject(mem, pen);
                ::MoveToEx(mem, sampleX, cy, nullptr);
                ::LineTo(mem, sampleX + sampleW, cy);
                ::SelectObject(mem, old);
                ::DeleteObject(pen);
                return sampleX;
            };
            const int bLeft = entry(d.bLabel, lineB, rowRight);
            entry(d.aLabel, lineA, bLeft - entryGap);
        }

        // Border + horizontal gridlines at 25/50/75 %.
        HPEN gridPen = ::CreatePen(PS_SOLID, 1, grid);
        HGDIOBJ oldPen = ::SelectObject(mem, gridPen);
        ::MoveToEx(mem, chart.left, chart.top, nullptr);
        ::LineTo(mem, chart.right, chart.top);
        for (int g = 1; g <= 3; ++g) {
            const int y = chart.top + (chart.bottom - chart.top) * g / 4;
            ::MoveToEx(mem, chart.left, y, nullptr);
            ::LineTo(mem, chart.right, y);
        }
        ::MoveToEx(mem, chart.left, chart.bottom - 1, nullptr);
        ::LineTo(mem, chart.right, chart.bottom - 1);
        ::MoveToEx(mem, chart.left, chart.top, nullptr);
        ::LineTo(mem, chart.left, chart.bottom);
        ::MoveToEx(mem, chart.right, chart.top, nullptr);
        ::LineTo(mem, chart.right, chart.bottom);

        if (d.a->empty()) {
            // Per-panel status: one unavailable source no
            // longer freezes the other three behind "collecting…".
            const wchar_t* msg =
                (d.emptyMsg != nullptr) ? d.emptyMsg : L"collecting\u2026";
            RECT empty = chart;
            ::DrawTextW(mem, msg, -1, &empty,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE |
                            DT_END_ELLIPSIS);
        } else {
            double yMax = d.fixedMax;
            if (yMax <= 0.0) {
                // The "per-series scale" suggestion, assessed and
                // rejected: the two-line panels exist so a reader can
                // COMPARE the two series - disk read against disk write,
                // network send against receive. Scaling each series to
                // its own ceiling would draw both at full height whenever
                // one dwarfed the other, which says "both are maxed"
                // when one is idle. One shared ceiling is what makes
                // "the blue line is flat while the orange spikes" a
                // readable fact. The complaint the suggestion came from
                // - a small series flattened by a big one - is what the
                // kMinAutoScale floor answers for byte-rate panels, and
                // what the log-shaped percent panels do not have at all.
                yMax = MaxOf(*d.a, (d.b != nullptr) ? *d.b : *d.a) * 1.2;
                if (yMax < kMinAutoScale) yMax = kMinAutoScale;
            }
            // Scale label (top-right inside the chart).
            wchar_t scale[kScaleLabelChars] = {0};
            if (d.fixedMax > 0.0)
                ::swprintf_s(scale, L"%.0f %%", yMax);
            else
                ::swprintf_s(scale, L"%s", FormatBps(yMax).c_str());
            RECT scaleRc = {chart.left, chart.top + px(2), chart.right - px(4),
                            chart.top + titleH};
            ::SetTextColor(mem, dim);
            ::DrawTextW(mem, scale, -1, &scaleRc,
                        DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX);
            ::SetTextColor(mem, fg);

            const auto plot = [&](const std::vector<double>& h,
                                  COLORREF color) {
                if (h.size() < 2) return;
                HPEN pen = ::CreatePen(PS_SOLID, px(2) < 2 ? 2 : px(2), color);
                HGDIOBJ old = ::SelectObject(mem, pen);
                const size_t n = h.size();
                const int w = chart.right - chart.left;
                const int hh = chart.bottom - chart.top;
                // Stretch over the samples we actually have: scaling by
                // kMaxSamples squashed the whole line against the right
                // edge until the buffer filled after 2 minutes.
                const double denom =
                    (n > 1) ? static_cast<double>(n - 1) : 1.0;
                for (size_t i = 0; i < n; ++i) {
                    // Oldest sample at the left edge, newest at the right.
                    const int x = chart.right - static_cast<int>(
                      (static_cast<double>(n - 1 - i) / denom) * w);
                    double v = h[i];
                    if (v < 0.0) v = 0.0;
                    if (v > yMax) v = yMax;
                    const int y =
                        chart.bottom - 1 -
                        static_cast<int>(v / yMax * (hh - 1));
                    if (i == 0)
                        ::MoveToEx(mem, x, y, nullptr);
                    else
                        ::LineTo(mem, x, y);
                }
                ::SelectObject(mem, old);
                ::DeleteObject(pen);
            };
            plot(*d.a, lineA);
            if (d.b != nullptr) plot(*d.b, lineB);
        }
        ::SelectObject(mem, oldPen);
        ::DeleteObject(gridPen);
    }

    // before the first baselines land every panel says "collecting…"
    // and nothing says what happens next. One line over the plot area
    // names the wait, so a blank window reads as working rather than
    // broken. (A source that stays dark - the disk "n/a" case - keeps its
    // own per-panel message instead.)
    if (cpuHist_.empty() && memHist_.empty() && diskReadHist_.empty() &&
        netRecvHist_.empty() && diskAvailable_) {
        RECT hint = {pad, pad, rc.right - pad, plotBottom - pad};
        ::SetTextColor(mem, dim);
        ::DrawTextW(mem,
                    L"Collecting first samples \u2014 traces appear within "
                    L"a few seconds; Export and Copy values unlock as data "
                    L"arrives.",
                    -1, &hint,
                    DT_CENTER | DT_VCENTER | DT_WORDBREAK | DT_NOPREFIX);
        ::SetTextColor(mem, fg);
    }

    ::SelectObject(mem, oldFont);
    ::BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
    ::SelectObject(mem, oldBmp);
    ::DeleteObject(bmp);
    ::DeleteDC(mem);
    ::EndPaint(hwnd_, &ps);
}

std::wstring ChartsWindow::ValuesText() const {
    // the one derivation of "what the window currently says".
    // Captions paint it, Copy puts it on the clipboard, and the
    // accessible name announces it - so the three cannot disagree about
    // a value. A panel with no reading yet says so explicitly rather
    // than printing a fabricated zero.
    wchar_t buf[kCaptionChars] = {0};
    std::wstring out = L"WinTCP performance graphs:\r\n";
    if (!cpuHist_.empty()) {
        ::swprintf_s(buf, L"CPU: %.1f %%\r\n", cpuPct_);
    } else {
        ::swprintf_s(buf, L"CPU: no data yet\r\n");
    }
    out += buf;
    if (!memHist_.empty()) {
        ::swprintf_s(buf, L"Memory: %.0f %% (%s / %s)\r\n", memPct_,
                     FormatBytes(memUsed_).c_str(),
                     FormatBytes(memTotal_).c_str());
    } else {
        ::swprintf_s(buf, L"Memory: no data yet\r\n");
    }
    out += buf;
    if (!diskAvailable_) {
        out += L"Disk: counters unavailable\r\n";
    } else if (!diskReadHist_.empty()) {
        ::swprintf_s(buf, L"Disk: read %s, write %s\r\n",
                     FormatBps(diskReadBps_).c_str(),
                     FormatBps(diskWriteBps_).c_str());
        out += buf;
    } else {
        out += L"Disk: no data yet\r\n";
    }
    if (!netRecvHist_.empty()) {
        ::swprintf_s(buf, L"Network: down %s, up %s\r\n",
                     FormatBps(netRecvBps_).c_str(),
                     FormatBps(netSendBps_).c_str());
    } else {
        ::swprintf_s(buf, L"Network: no data yet\r\n");
    }
    out += buf;
    return out;
}

void ChartsWindow::CopyValues() {
    // the keyboard/SR path to the numbers. The same table the
    // captions paint and the accessible name announces, so copying is
    // reading, not a second derivation.
    const std::wstring text = ValuesText();
    if (text.empty() || !::OpenClipboard(hwnd_)) return;
    ::EmptyClipboard();
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hMem != nullptr) {
        void* dst = ::GlobalLock(hMem);
        if (dst != nullptr) {
            ::memcpy(dst, text.c_str(), bytes);
            ::GlobalUnlock(hMem);
            if (::SetClipboardData(CF_UNICODETEXT, hMem) == nullptr)
                ::GlobalFree(hMem);
            hMem = nullptr;
        }
        if (hMem != nullptr) ::GlobalFree(hMem);
    }
    ::CloseClipboard();
}

void ChartsWindow::ExportCharts() {
    // the full histories as CSV through the existing ChartExport
    // module - the window feeds it the same buffers it paints from, so
    // the file holds the numbers on screen. Same picker contract as the
    // change log's SaveToFile.
    if (cpuHist_.empty() && memHist_.empty() && diskReadHist_.empty() &&
        netRecvHist_.empty()) {
        ::MessageBoxW(hwnd_, L"There are no samples to export yet.",
                      L"WinTCP - Performance graphs", MB_OK | MB_ICONINFORMATION);
        return;
    }
    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.lpstrTitle = L"WinTCP - Export performance graphs";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    // comdlg32.dll is delay-loaded; DelayLoadGuard reports its absence, where a
    // bare `return` would look exactly like the user cancelling.
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return;
    if (::GetSaveFileNameW(&ofn) == FALSE) return;

    // Panel order, units and scales mirror the defs[] table in OnPaint
    // exactly (percent panels fixed 0..100, byte-rate panels auto-scaled),
    // so the export's ceilings are the ceilings the traces draw.
    const std::vector<ChartSeriesInfo> series = {
        {L"CPU", L"percent", &cpuHist_, nullptr, kPctScale, nullptr},
        {L"Memory", L"percent", &memHist_, nullptr, kPctScale, nullptr},
        {L"Disk", L"bytes_per_second", &diskReadHist_, &diskWriteHist_,
         0.0, L"write"},
        {L"Network", L"bytes_per_second", &netRecvHist_, &netSendHist_,
         0.0, L"up"},
    };
    ChartExport ex;
    ex.note = L"WinTCP performance graphs";
    // The BOM form, so Excel decodes the UTF-8 without a Text Import
    // Wizard; withBom=false below because the bytes already carry one.
    const std::string csv = SeriesToCsvUtf8Bom(series, ex);
    const std::wstring err = WriteUtf8FileWithBom(path, csv, false);
    if (!err.empty()) {
        ::MessageBoxW(hwnd_,
                      (L"Could not write the performance graphs:\n" + err)
                          .c_str(),
                      L"WinTCP - Performance graphs", MB_OK | MB_ICONERROR);
    }
}

}  // namespace wintcp

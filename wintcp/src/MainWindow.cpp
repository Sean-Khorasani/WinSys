// MainWindow.cpp
// SPDX-License-Identifier: Apache-2.0
// Main window implementation: controls, virtual ListView (LVS_OWNERDATA),
// worker-thread refresh plumbing, filter (debounced, expression-aware),
// sort (with header indicators), selection preservation, export.

#include "MainWindow.h"

#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>            // SHGetStockIconInfo: SIID_SHIELD
#include <tcpmib.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <unordered_map>
#include <unordered_set>

#include "ProcessInfo.h"
#include "TcpTable.h"
#include "Utils.h"
#include "WinCaps.h"   // DllAvailable: shell32.dll is delay-loaded
#include "Version.h"
#include "BuildInfo.h"     // About summary + shortcut sheet
#include "Commands.h"      // abstract layer: BuildDetailModel, preset helpers
#include "Freeze.h"        // FrozenAgeMs
#include "ViewState.h"     // the single place a view is built (stage 1.7)
#include "PromptDialog.h"  // one-line text prompt
#include "BlockedPeersDialog.h"  // View > Blocked peers...
#include "EmptyStateActions.h"   // the empty-state button decision
#include "RowAccessible.h"       // per-row MSAA names over the list
#include "Elevate.h"             // Reelevate for the traffic case
#include "ExposureScore.h"       // the exposure badge predicate
#include "FontCache.h"
#include "Theme.h"       // shared palette + HighContrastActive()
#include "Alerts.h"      // AlertEngine, ShowTrayBalloon
#include "TextSheetDialog.h"
#include "MainWindowInternal.h"   // shared constants + free helpers
#include "resource.h"

namespace wintcp {

// The shared helpers/constants live in MainWindowInternal.h so the window's
// translation units can use them without each owning a copy. Brought in
// unqualified because that is how they read at every call site.
using namespace mw;

const wchar_t* MainWindow::kClassName = L"WinTcpViewerMainWindow";

std::shared_ptr<WorkerSink> MainWindow::Sink() const {
    if (sink_ == nullptr) sink_ = std::make_shared<WorkerSink>();
    return sink_;
}

// ---------------------------------------------------------------------------
// lifecycle -----------------------------------------------------------------

MainWindow::~MainWindow() {
    engine_.Stop();
    enrich_.StopDnsWorker();
    std::lock_guard<std::mutex> lk(Sink()->m);
    for (RefreshResult* p : Sink()->pendingRefresh) delete p;
    Sink()->pendingRefresh.clear();
    for (DnsResolver::Result* p : Sink()->pendingDns) delete p;
    Sink()->pendingDns.clear();
}

bool MainWindow::RegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &MainWindow::WindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = static_cast<HICON>(::LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APP),
                                               IMAGE_ICON, 32, 32, 0));
    if (wc.hIcon == nullptr) wc.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszMenuName = MAKEINTRESOURCEW(IDR_MAINMENU);
    wc.lpszClassName = kClassName;
    wc.hIconSm = static_cast<HICON>(::LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APP),
                                                 IMAGE_ICON, 16, 16, 0));
    if (wc.hIconSm == nullptr) wc.hIconSm = ::LoadIconW(nullptr, IDI_APPLICATION);
    return ::RegisterClassExW(&wc) != 0;
}

HWND MainWindow::Create(HINSTANCE hInstance, int nCmdShow) {
    hInstance_ = hInstance;
    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    // Logical 1080x640 at the system DPI (PerMonitorV2 scales later per
    // monitor via WM_DPICHANGED).
    const UINT sysDpi = QueryDpiForWindow(nullptr);
    const int w = ::MulDiv(kDesignWidth, static_cast<int>(sysDpi), kDpiUnscaled);
    const int h = ::MulDiv(kDesignHeight, static_cast<int>(sysDpi), kDpiUnscaled);
    const HWND hwnd = ::CreateWindowExW(0, kClassName, L"WinTCP - TCP/UDP Connections",
                                        style, CW_USEDEFAULT, CW_USEDEFAULT, w, h,
                                        nullptr, nullptr, hInstance, this);
    if (hwnd == nullptr) return nullptr;

    // Restore the last position/size. Settings were loaded in
    // WM_CREATE, which ran inside CreateWindowEx above. Only honor the
    // rect if it still intersects a live monitor (e.g. after unplugging
    // an external display); otherwise fall back to CW_USEDEFAULT.
    if (settings_.winPlaced && settings_.winW >= kMinRestorableW &&
        settings_.winH >= kMinRestorableH) {
        RECT wr = { settings_.winX, settings_.winY,
                    settings_.winX + settings_.winW,
                    settings_.winY + settings_.winH };
        if (::MonitorFromRect(&wr, MONITOR_DEFAULTTONULL) != nullptr) {
            ::SetWindowPos(hwnd, nullptr, wr.left, wr.top,
                           settings_.winW, settings_.winH,
                           SWP_NOZORDER | SWP_NOACTIVATE);
            if (settings_.showCmd == SW_SHOWMAXIMIZED) nCmdShow = SW_SHOWMAXIMIZED;
        }
    }

    ::ShowWindow(hwnd, nCmdShow);
    ::UpdateWindow(hwnd);
    return hwnd;
}

// ---------------------------------------------------------------------------

LRESULT CALLBACK MainWindow::WindowProc(HWND hwnd, UINT msg, WPARAM wParam,
                                        LPARAM lParam) {
    MainWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        self = static_cast<MainWindow*>(cs->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
    } else {
        self = reinterpret_cast<MainWindow*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self != nullptr) return self->HandleMessage(msg, wParam, lParam);
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWindow::ListSubclassProc(HWND hwnd, UINT msg,
                                              WPARAM wParam, LPARAM lParam,
                                              UINT_PTR, DWORD_PTR refData) {
    auto* self = reinterpret_cast<MainWindow*>(refData);
    if (msg == WM_GETOBJECT && lParam == OBJID_CLIENT && self != nullptr) {
        // The wrapper answers row names/descriptions from the store and
        // delegates everything else to comctl32. A 0 return falls through
        // to DefSubclassProc, which serves comctl32's own object - answering
        // 0 unconditionally would both lie ("no object") and bypass it.
        const LRESULT lr =
            ServeListAccessibleObject(hwnd, wParam, &self->store_);
        if (lr != 0) return lr;
    }
    return ::DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: OnCreate(); return 0;
        case WM_SIZE: OnSize(LOWORD(lParam), HIWORD(lParam)); return 0;
        case WM_GETMINMAXINFO: {
            // the control bar needs ~760 px before the right-anchored
            // Protocol/State combos and the stretching search box stop
            // overlapping, and ~420 px before the list reads as a
            // list. A floor keeps the responsive layout intact instead of
            // letting the window collapse onto itself.
            auto* mm = reinterpret_cast<LPMINMAXINFO>(lParam);
            if (mm != nullptr) {
                mm->ptMinTrackSize.x = S(760);
                mm->ptMinTrackSize.y = S(420);
            }
            return 0;
        }
        case WM_COMMAND: {
            OnCommand(LOWORD(wParam), HIWORD(wParam),
                      reinterpret_cast<HWND>(lParam));
            return 0;
        }
        case WM_NOTIFY: {
            auto* n = reinterpret_cast<NMHDR*>(lParam);
            if (n == nullptr) return 0;
            // The list answers for its own notifications first; whatever it
            // does not consume falls through to this window's handler, which
            // is what keeps the dispatcher a router rather than a second
            // implementation of the list.
            const std::optional<LRESULT> fromList = list_.HandleNotify(n);
            if (fromList.has_value()) return *fromList;
            OnNotify(n, lParam);
            return 0;
        }
        case WM_APP_COLUMNORDER_SYNC:
            SyncColumnOrderFromHeader();
            return 0;
        case WM_TIMER: OnTimer(static_cast<UINT_PTR>(wParam)); return 0;
        // type-to-jump. Only when the LIST has focus: the filter box and
        // the interval combo are ordinary text entry, and stealing their
        // keystrokes would break typing a filter.
        case WM_CHAR:
            // `/` focuses the filter box (vim-style). It is consumed
            // here only when the LIST holds focus - otherwise it falls through
            // to the filter edit, where it is ordinary text input. The keystroke
            // is NOT passed to OnTypeJumpChar, which would consume it as a
            // matching step (`/` is not a prefix of any process name, so it does
            // nothing visible but still eats the key).
            if (list_.Handle() != nullptr &&
                ::GetFocus() == list_.Handle() &&
                static_cast<wchar_t>(wParam) == L'/') {
                FocusFilterBox();
                return 0;
            }
            if (list_.Handle() != nullptr &&
                ::GetFocus() == list_.Handle()) {
                if (OnTypeJumpChar(static_cast<wchar_t>(wParam)))
                    return 0;
            }
            break;
        case WM_SYSCOLORCHANGE:
            RefreshSystemColors();
            return 0;
        case WM_CONTEXTMENU:
            OnContextMenu(reinterpret_cast<HWND>(wParam),
                          static_cast<int>(GET_X_LPARAM(lParam)),
                          static_cast<int>(GET_Y_LPARAM(lParam)));
            return 0;
        case WM_SETFOCUS:
            if (list_.Handle() != nullptr) ::SetFocus(list_.Handle());
            return 0;
        case WM_APP_REFRESH_RESULT:
            OnRefreshResult(reinterpret_cast<RefreshResult*>(lParam));
            return 0;
        case WM_APP_DNS_RESULT:
            OnDnsResult(reinterpret_cast<DnsResolver::Result*>(lParam));
            return 0;
        case WM_APP_DNS_STALLED:
            // wParam = count of lookups abandoned as stalled this session.
            // Append a hint to the status bar; the pending rows already paint
            // the `pending` cell inline.
            dnsStalledHint_ = L"DNS slow - some hosts show \"pending\"";
            UpdateStatusBar(lastError_);
            return 0;
        case WM_APP_TRAY: {
            // Classic (non-V4) tray callback: wParam = icon id, lParam =
            // mouse message.
            const UINT ev = static_cast<UINT>(lParam);
            if (ev == WM_LBUTTONDBLCLK || ev == WM_LBUTTONUP) {
                ::ShowWindow(hwnd_, SW_RESTORE);
                ::SetForegroundWindow(hwnd_);
            } else if (ev == WM_RBUTTONUP) {
                tray_.ShowMenu(hwnd_, topMost_);
            }
            return 0;
        }
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC:
            // Use the system window colors so the control bar follows the
            // user's theme - and, when high contrast is on, the
            // accessibility palette - without any theme of our own.
            if (hwndBrushWindow_ != nullptr) {
                SetTextColor(reinterpret_cast<HDC>(wParam),
                             ::GetSysColor(COLOR_WINDOWTEXT));
                SetBkColor(reinterpret_cast<HDC>(wParam),
                           ::GetSysColor(COLOR_WINDOW));
                return reinterpret_cast<LRESULT>(hwndBrushWindow_);
            }
            break;
        case WM_SYSCOMMAND:
            // Minimize-to-tray while the tray icon is enabled.
            if ((wParam & 0xFFF0) == SC_MINIMIZE) {
                // when the tray icon is off and the user has not yet
                // answered, offer the one-shot "tray or exit" choice before
                // minimizing to the taskbar. ResolveMinimize enables the tray
                // when the user picks it.
                if (!trayEnabled_) {
                    switch (ResolveMinimize()) {
                        case MinimizeTarget::kTray:
                            // trayEnabled_ + trayIconShown_ are now set; fall
                            // through to the hide below.
                            break;
                        case MinimizeTarget::kExit:
                            ::DestroyWindow(hwnd_);
                            return 0;
                        case MinimizeTarget::kTaskbar:
                            // Unchanged default: stay in the taskbar.
                            break;
                    }
                }
                if (trayEnabled_ && tray_.IsShown()) {
                    ::ShowWindow(hwnd_, SW_HIDE);
                    // the first hide explains where the window went and
                    // how to get it back. A window that vanishes with no
                    // explanation reads as a crash; one balloon per process
                    // names the restore gesture (single-click, matching the
                    // WM_APP_TRAY handler) without nagging on every minimize.
                    if (!trayHideBalloonShown_ &&
                        DllAvailable("shell32.dll")) {
                        trayHideBalloonShown_ = true;
                        tray_.Balloon(
                            L"WinTCP",
                            L"WinTCP is still running in the tray. "
                            L"Single-click the icon to restore it; "
                            L"right-click it for options.",
                            NIIF_INFO);
                    }
                    return 0;
                }
            }
            break;
        case WM_INITMENUPOPUP:
            // Re-sync the check marks that can change outside the command
            // handlers: the charts window can be
            // closed with its own X button, and the ETW session can stop
            // on its own during shutdown paths.
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_CHARTS,
                         charts_.IsVisible());
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAFFIC,
                         etw_->Running());
            // Re-sync the View > Columns ticks on every popup open so the
            // menu always reflects the visible mask, even if state changed
            // through a path that did not update the menu itself.
            SyncColumnMenuChecks();
            break;
        case WM_DPICHANGED: {
            // Per-monitor DPI change: follow the suggested rect,
            // refresh the font, re-derive column widths and layout.
            HarvestColumnWidths();               // with the OLD dpi_
            // wParam packs the NEW dpi in the low word and the previous
            // dpi in the high word; taking HIWORD applied the old scale
            // and the 0-fallback then re-read the old value too.
            dpi_ = LOWORD(wParam);
            if (dpi_ == 0) dpi_ = QueryDpiForWindow(hwnd_);
            const auto* suggested = reinterpret_cast<const RECT*>(lParam);
            ::SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                           suggested->right - suggested->left,
                           suggested->bottom - suggested->top,
                           SWP_NOZORDER | SWP_NOACTIVATE);
            RecreateFont();
            RebuildColumns();
            RECT rc = {};
            ::GetClientRect(hwnd_, &rc);
            LayoutControls(rc.right, rc.bottom);
            ::RedrawWindow(hwnd_, nullptr, nullptr,
                           RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
            return 0;
        }
        case WM_CLOSE: ::DestroyWindow(hwnd_); return 0;
        case WM_DESTROY: OnDestroy(); return 0;
        default: break;
    }
    return ::DefWindowProcW(hwnd_, msg, wParam, lParam);
}

void MainWindow::OnCreate() {
    // Member initializers ran before hwnd_ existed; repair the owner now that
    // the window handle is available.
    presetDialogs_.SetOwner(hwnd_);
    bookmarks_.SetOwner(hwnd_);
    etw_ = new EtwTraffic();   // per-PID traffic; leaked by design (MainWindow.h)
    // socketTraffic_: allocated here, never deleted. A scan thread blocked in
    // SIO_TCP_INFO holds a pointer to its sampler and cannot be cancelled, so
    // freeing it while that thread is alive would be a use-after-free; leaking
    // one object at exit is the smaller problem. See ~SocketTrafficSampler.
    socketTraffic_ = new SocketTrafficSampler();
// Built-in column state first, so the portable wintcp.ini below and the
// stored settings after it each override a complete, well-formed default
// rather than half of one.
cols_.Reset();
    // the portable `wintcp.ini` supplies DEFAULTS only, so it is
    // applied BEFORE settings_.Load() and an existing user's saved settings
    // always win. A file that exists but will not parse is reported once
    // rather than swallowed: a portable copy that quietly does nothing is
    // worse than one that says so.
    wchar_t exePath[MAX_PATH] = {0};
    const DWORD pn = ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (pn != 0 && pn < MAX_PATH) {
        std::wstring iniErr;
        if (settings_.ApplyPortableDefaults(exePath, &iniErr) && !iniErr.empty()) {
            UpdateStatusBar(L"wintcp.ini: " + iniErr);
        }
    }
    settings_.Load();                       // (pre-set by Create())

    // auto-load the remembered GeoIP database on startup. This is
    // best-effort and silent - a moved file would pop a nag on every
    // launch, so a failed load just leaves Country as "—", which is the
    // same honest "unknown" as never having picked a database. The next
    // refresh fills the rows via OfferGeoIpForAllRows(); View > GeoIP
    // database still reports the parser's reason on demand.
    if (settings_.geoIpPath[0] != L'\0') {
        std::wstring err;
        if (enrich_.LoadCountry(settings_.geoIpPath, &err)) {
            OfferGeoIpForAllRows();
            ApplyView();
        }
    }
    // Same best-effort, silent contract for the ASN database - see the
    // comment above. Loaded independently of the country one, so either, both or
    // neither survives a relaunch.
    if (settings_.asnIpPath[0] != L'\0') {
        std::wstring asnErr;
        if (enrich_.LoadAsn(settings_.asnIpPath, &asnErr)) {
            OfferAsnForAllRows();
            ApplyView();
        }
    }

// Column geometry from the stored settings: the visible mask, the widths and
// the order in one call, which is what the three separate loops below used to
// be. Settings::Load has validated the order, so no re-check here.
cols_.LoadFromSettings(settings_);
autoRefresh_ = settings_.autoRefresh;
    autoRefreshMs_ = settings_.intervalMs;
    dnsEnabled_ = settings_.resolveHosts;
    topMost_ = settings_.topMost;
    trayEnabled_ = settings_.trayEnabled;
    trayMinimizeChoice_ = settings_.trayMinimizeChoice;
    store_.SetSort(settings_.sortCol, settings_.sortAsc);

    dpi_ = QueryDpiForWindow(hwnd_);
    CreateControls();
    // Backdrop for WM_CTLCOLOR* (filter box + labels). Recreated by
    // RefreshSystemColors() when the theme changes.
    hwndBrushWindow_ = ::CreateSolidBrush(::GetSysColor(COLOR_WINDOW));
    RecreateFont();
    InitFilterControls();
    ::SetWindowTextW(hwndSearchEdit_, settings_.filter);
    if (autoRefresh_) {
        ::SendMessageW(hwndAutoChk_, BM_SETCHECK, BST_CHECKED, 0);
        // select matching interval item
        for (LRESULT i = 0; i < ::SendMessageW(hwndIntervalCbo_, CB_GETCOUNT, 0, 0); ++i) {
            const LRESULT d = ::SendMessageW(hwndIntervalCbo_, CB_GETITEMDATA,
                                             static_cast<WPARAM>(i), 0);
            if (d == static_cast<LRESULT>(autoRefreshMs_)) {
                ::SendMessageW(hwndIntervalCbo_, CB_SETCURSEL,
                               static_cast<WPARAM>(i), 0);
                break;
            }
        }
    }
    RebuildColumns();
    LayoutControls(kDesignWidth, kDesignHeight);

    // Reflect default column visibility in the View > Columns menu and the
    // persisted toggle states in their menu check marks.
    SyncColumnMenuChecks();
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_AUTOREFRESH, autoRefresh_);
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_RESOLVE, dnsEnabled_);
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TOPMOST, topMost_);
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAY, trayEnabled_);
    // defaults to ON, so the tick is set from the member rather than left
    // to whatever the resource compiled with - an unticked "Preserve
    // selection" that is actually on would be the reverse lie.
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_PRESERVE_SEL, preserveSelection_);
    // the tree mode starts off, so the tick is set from the member
    // for the same reason as the line above - a stale compiled-in check mark
    // is a lie either way.
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_PROCESSTREE, treeMode_);
    if (autoRefresh_)
        ::SetTimer(hwnd_, kRefreshTimerId, autoRefreshMs_, nullptr);
    // Drives the status bar's age / countdown pane. Runs even with
    // auto-refresh off so "3m old" stays truthful after a manual F5.
    ::SetTimer(hwnd_, kStatusTimerId, kStatusTickMs, nullptr);
    if (topMost_)
        ::SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
RefreshSystemColors();                // system theme / high contrast
SyncTray();

    // resume per-PID traffic counters if they were enabled while
    // elevated. A silent failure here (e.g. the user is no longer elevated)
    // just clears the flag; the menu toggle reports the reason on demand.
    if (settings_.trafficEnabled) {
        std::wstring etwError;
        if (!etw_->Start(etwError)) settings_.trafficEnabled = false;
        etwAutoAttempted_ = true;          // a start was already tried here
    }
    // Persisted traffic columns + no running session (e.g. the
    // app is no longer elevated) - make the same implicit attempt the
    // column-toggle path makes: ETW first, then the non-admin socket
    // fallback, so the state shown below is accurate at startup.
    if (!etw_->Running() && AnyTrafficColVisible()) EnsureTrafficCounters();
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAFFIC, etw_->Running());
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_CHARTS, charts_.IsVisible());

    // draw the UAC shield on the elevation-gated "Per-PID traffic
    // counters" item (shown when the user is an admin who is not currently
    // elevated; cleared if already elevated or under high contrast).
    ApplyTrafficShield(::GetMenu(hwnd_), HighContrastActive());

    StartWorker();
    StartDnsWorker();
    OpenLogFromSettings();                 // resume a saved log
}

void MainWindow::OnDestroy() {
    ::KillTimer(hwnd_, kRefreshTimerId);
    ::KillTimer(hwnd_, kStatusTimerId);
    ::KillTimer(hwnd_, kFilterTimerId);
    engine_.Stop();                      // no callbacks can be in flight after join
    enrich_.StopDnsWorker();
    etw_->Stop();                         // stop the kernel logger
    charts_.Close();                     // stop the 1 s sampler
    changeLog_.Close();                  // destroy before the owner goes
    {
        std::lock_guard<std::mutex> lk(Sink()->m);
        Sink()->shuttingDown = true;
        // Free payloads posted but not yet dispatched (their messages may
        // still surface; the handler checks registration before touching).
        for (RefreshResult* p : Sink()->pendingRefresh) delete p;
        Sink()->pendingRefresh.clear();
        for (DnsResolver::Result* p : Sink()->pendingDns) delete p;
        Sink()->pendingDns.clear();
    }
SaveSettings();                        // persist UI state
tray_.Remove();
    if (logFile_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(logFile_);
        logFile_ = INVALID_HANDLE_VALUE;
    }
    if (hwndBrushWindow_ != nullptr) {
        ::DeleteObject(hwndBrushWindow_);
        hwndBrushWindow_ = nullptr;
    }
    if (font_ != nullptr) {
        ::DeleteObject(font_);
        font_ = nullptr;
    }
    ::PostQuitMessage(0);
}

// ---------------------------------------------------------------------------
// worker plumbing ---------------------------------------------------

void MainWindow::StartWorker() {
    // Both lambdas capture shared state, never `this`: after Stop()
    // detaches the worker, a late pass still runs them, and anything they
    // touch must outlive the window. The sampler is leaked by design (never
    // freed); the flag and the sink are refcounted.
    const std::shared_ptr<WorkerSink> sink = Sink();
    sink->hwnd = hwnd_;
    const std::shared_ptr<std::atomic<bool>> flag = fallbackFlag_;
    SocketTrafficSampler* const sampler = socketTraffic_;
    // the worker also feeds the non-admin traffic fallback, using
    // the same PID set as the stats sampling. The lambda is a no-op unless
    // the UI armed the fallback (atomic check, no handle scan).
    engine_.SetTrafficSource(
        [flag, sampler](const std::vector<DWORD>& pids)
            -> std::map<DWORD, PidTraffic> {
            if (sampler == nullptr ||
                !flag->load(std::memory_order_relaxed))
                return std::map<DWORD, PidTraffic>();
            return sampler->Sample(pids);
        });
    // The same scan, per-socket. This is the only source that observes ONE
    // socket, so it is the only one allowed to mark rows perRowBytes - and
    // nothing did before, which is why the Speed column was a permanent
    // em-dash in the GUI while the CLI help advertised the column.
    engine_.SetSocketByteSource(
        [flag, sampler](const std::vector<DWORD>& pids)
            -> std::vector<SocketBytes> {
            if (sampler == nullptr ||
                !flag->load(std::memory_order_relaxed))
                return std::vector<SocketBytes>();
            return sampler->Bytes(pids);
        });
    // R8: seed the watchdog age. A fresh worker legitimately takes seconds
    // for its first pass, and the threshold floor covers it — but without a
    // seed the age would measure from boot and declare a brand-new worker
    // stale on its first tick.
    workerStartTick_ = ::GetTickCount64();
    watchdogRestarting_ = false;
    watchdogRestarts_ = 0;
    engine_.Start([sink](std::unique_ptr<RefreshResult> r) {
        RefreshResult* raw = r.release();
        bool registered = false;
        {
            std::lock_guard<std::mutex> lk(sink->m);
            if (!sink->shuttingDown) {
                sink->pendingRefresh.insert(raw);
                registered = true;
            }
        }
        if (registered) {
            const BOOL ok = ::PostMessageW(sink->hwnd, WM_APP_REFRESH_RESULT,
                                           0, reinterpret_cast<LPARAM>(raw));
            if (ok == FALSE) {
                std::lock_guard<std::mutex> lk(sink->m);
                if (sink->pendingRefresh.erase(raw) != 0) delete raw;
            }
        } else {
            delete raw;
        }
    });
    if (!engine_.Running()) {
        // The worker never came up. Everything downstream silently shows an
        // empty list, so make it loud rather than letting the window look
        // healthy while doing nothing.
        lastError_ = L"Refresh worker failed to start.";
    }
}

void MainWindow::StartDnsWorker() {
    enrich_.StartDnsWorker(hwnd_, Sink());
}

void MainWindow::OnDnsResult(DnsResolver::Result* payload) {
    // The effect the enrichment layer reports is mapped to this window's
    // controls here, and nowhere else: the layer cannot know a list view
    // exists, and a layer that asked the window to repaint would be a layer
    // with a window dependency.
    const RowEnrichment::Effect effect =
        enrich_.OnDnsResult(payload, store_, Sink(),
                            !filterProgram_.empty());
    switch (effect) {
        case RowEnrichment::Effect::kReapply:
            ApplyView();
            break;
        case RowEnrichment::Effect::kRepaint:
            if (list_.Handle() != nullptr)
                ::InvalidateRect(list_.Handle(), nullptr, FALSE);
            break;
        case RowEnrichment::Effect::kNone:
        default:
            break;
    }
}

void MainWindow::OfferDnsForAllRows() { enrich_.OfferAll(store_); }

// GeoIP and the ASN join: the engine half is RowEnrichment's (one local pass
// per database, both synchronous, both sharing the distinct-address memo
// rule). What is left here is the WHEN - after every refresh, and immediately
// after a database is loaded.
void MainWindow::OfferGeoIpForAllRows() { enrich_.OfferGeoIp(store_); }
void MainWindow::OfferAsnForAllRows() { enrich_.OfferAsn(store_); }


void MainWindow::OnRefreshResult(RefreshResult* payload) {
    if (payload == nullptr) return;
    {
        std::lock_guard<std::mutex> lk(Sink()->m);
        // 0 = we do not own this pointer (already freed during shutdown).
        if (Sink()->pendingRefresh.erase(payload) == 0) return;
    }
    const std::unique_ptr<RefreshResult> result(payload);

    // R8 liveness stamp: ANY posted result proves the worker alive, including
    // an error result (R2's containment posts those). The display age below
    // stays success-only; the watchdog reads this one.
    lastResultTick_ = ::GetTickCount64();
    // the in-flight request this result answers has landed, on every
    // path below (error, frozen, success) - cleared before any UpdateStatusBar
    // so the "Refreshing..." note never outlives the answer.
    refreshInFlight_ = false;
    if (!result->error.empty()) {
        lastError_ = result->error;
        if (reportErrorsNextResult_) {
            ::MessageBoxW(hwnd_, lastError_.c_str(), L"WinTCP - Refresh failed",
                          MB_OK | MB_ICONERROR);
        }
        reportErrorsNextResult_ = false;
        UpdateStatusBar(lastError_);
        return;
    }
    reportErrorsNextResult_ = false;
    lastError_.clear();
    lastRefreshTime_ = result->timeText;
    // a completed refresh clears the stale stall hint; the next
    // stalled lookup re-posts WM_APP_DNS_STALLED if it recurs.
    dnsStalledHint_.clear();
    // Monotonic stamp for the status bar's age / next-refresh countdown.
    lastRefreshTick_ = ::GetTickCount64();
    completedRefreshCount_.fetch_add(1, std::memory_order_relaxed);

    // Capture selection/scroll while the old view is still consistent,
    // swap in the new snapshot, then rebuild the view and restore.
    //
    // when preserveSelection_ is off, pass empty state so the rebuilt
    // view starts with nothing selected. Preserving the selection is the
    // better default for a live monitor - a row the user is inspecting
    // should not jump to the top of the list on every 2-second tick - but on
    // a busy machine the tracked row can be thousands of positions down, and
    // some workflows want a clean slate each cycle. Hence the toggle.
    std::vector<std::uint64_t> ids;
    std::uint64_t focusedId = 0;
    int topIdx = 0;
    if (preserveSelection_) {
        list_.CaptureSelection(ids, &focusedId, &topIdx);
    }
    // freeze. The sampler has already run and the new snapshot is in
    // hand, but the DISPLAY is left exactly as it was. Freezing the display
    // rather than the sampler is deliberate: counters keep accumulating, so
    // unfreezing shows what changed during the pause instead of a gap, and
    // the per-PID traffic does not arrive as one large lump.
    if (frozen_) {
        lastError_.clear();
        UpdateStatusBar(std::wstring());
        return;
    }
    store_.ReplaceSnapshot(std::move(result->rows));
    WriteChangeLog();                      // (no-op unless logging)
    if (etw_->Running()) {
        // re-apply the cumulative per-PID totals to the fresh
        // rows (ReplaceSnapshot rebuilt them with zeroed counters).
        const auto traffic = etw_->Snapshot();
        for (const auto& kv : traffic)
            store_.SetTraffic(kv.first, kv.second.rx, kv.second.tx);
        // Even on the ETW path the per-socket scan is consulted for RATES
        // only: ETW totals are per-PID and cannot be split across a process's
        // connections honestly, but the socket scan observes one socket, so it
        // is what makes the Speed column real in the common (elevated) case.
        // The totals themselves still come from ETW; ApplySocketBytes only
        // overwrites the rows it can attribute to a single socket, and marks
        // them perRowBytes.
        store_.ApplySocketBytes(result->socketBytes);
        (void)store_.ComputeRates();
    } else if (fallbackFlag_->load(std::memory_order_relaxed)) {
        // same join, sourced from the worker's socket scan. The
        // flag re-check drops data sampled just before the user turned
        // the counters off (ClearTraffic already ran).
        for (const auto& kv : result->traffic)
            store_.SetTraffic(kv.first, kv.second.rx, kv.second.tx);
        // Per-socket counters from that same scan, applied AFTER the per-PID
        // totals: a socket's own bytes are the more specific fact about the
        // same cell, and only this path may set perRowBytes, which is what
        // makes the Speed column real.
        store_.ApplySocketBytes(result->socketBytes);
        // Both readings in place now (previous sample carried by
        // ReplaceSnapshot, this tick's counters just written), so the Speed
        // column can be computed. See ConnectionStore::ComputeRates.
        (void)store_.ComputeRates();
    }
    // join the per-process live stats sampled on this worker
    // pass (manual refresh and every auto-refresh tick alike).
    for (const auto& kv : result->procStats) {
        const ProcStats& s = kv.second;
        store_.SetProcStats(kv.first, s.cpuKnown ? s.cpuPct : -1.0,
                            s.memKnown, s.memWs, s.memPrivate, s.ioKnown,
                            s.ioRead, s.ioWrite);
    }
    if (dnsEnabled_) OfferDnsForAllRows();
    OfferGeoIpForAllRows();
    RefreshBookmarkMarks();
    ApplyViewWith(ids, focusedId, topIdx);
    RefreshDetailsWindow();              // live stats stay fresh
    // AFTER the view is rebuilt, so a balloon names rows the user can
    // actually look at - evaluated earlier it would answer about a table
    // that is about to be replaced.
    RunAlerts();
}

void MainWindow::Refresh(bool reportErrors) {
    reportErrorsNextResult_ = reportErrors;
    // the request is in flight from here until OnRefreshResult runs,
    // so the status bar can say "Refreshing..." instead of looking idle
    // while a slow enum or a DNS stall holds the worker.
    refreshInFlight_ = true;
    engine_.Request();
    UpdateStatusBar(lastError_);
}

// ---------------------------------------------------------------------------
// controls ------------------------------------------------------------------

void MainWindow::CreateControls() {
    const DWORD btnStyle = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON;
    const DWORD chkStyle = WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX;
    const DWORD cboStyle = WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL;
    const DWORD editStyle = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;

    hwndRefreshBtn_ = ::CreateWindowExW(0, WC_BUTTONW, L"&Refresh",
                                        btnStyle, 0, 0, 0, 0, hwnd_,
                                        reinterpret_cast<HMENU>(IDC_BTN_REFRESH),
                                        hInstance_, nullptr);
    hwndExportBtn_ = ::CreateWindowExW(0, WC_BUTTONW, L"&Export CSV...",
                                       btnStyle, 0, 0, 0, 0, hwnd_,
                                       reinterpret_cast<HMENU>(IDC_BTN_EXPORT),
                                       hInstance_, nullptr);
    hwndAutoChk_ = ::CreateWindowExW(0, WC_BUTTONW, L"Auto-refresh",
                                     chkStyle, 0, 0, 0, 0, hwnd_,
                                     reinterpret_cast<HMENU>(IDC_CHK_AUTOREFRESH),
                                     hInstance_, nullptr);
    hwndIntervalCbo_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"", cboStyle, 0, 0, 0, S(200),
                                         hwnd_,
                                         reinterpret_cast<HMENU>(IDC_CBO_INTERVAL),
                                         hInstance_, nullptr);
    hwndProtoCbo_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"", cboStyle, 0, 0, 0, S(220),
                                      hwnd_,
                                      reinterpret_cast<HMENU>(IDC_CBO_PROTO),
                                      hInstance_, nullptr);
    hwndStateCbo_ = ::CreateWindowExW(0, WC_COMBOBOXW, L"", cboStyle, 0, 0, 0, S(240),
                                      hwnd_,
                                      reinterpret_cast<HMENU>(IDC_CBO_STATE),
                                      hInstance_, nullptr);
    HWND hwndFilterLabel = ::CreateWindowExW(0, WC_STATICW, L"Filter:",
                                             WS_CHILD | WS_VISIBLE | SS_LEFT,
                                             0, 0, 0, 0, hwnd_,
                                             reinterpret_cast<HMENU>(IDC_STATIC_FILTER),
                                             hInstance_, nullptr);
    (void)hwndFilterLabel;
    // The protocol and state filter combos are labelled like the
    // filter box, so a reader does not have to infer what each
    // drop-down narrows. Like the Filter: caption they are fetched
    // by id at layout time rather than kept as members.
    HWND hwndProtoLabel = ::CreateWindowExW(0, WC_STATICW, L"Protocol:",
                                             WS_CHILD | WS_VISIBLE | SS_LEFT,
                                             0, 0, 0, 0, hwnd_,
                                             reinterpret_cast<HMENU>(IDC_STATIC_PROTO),
                                             hInstance_, nullptr);
    HWND hwndStateLabel = ::CreateWindowExW(0, WC_STATICW, L"State:",
                                             WS_CHILD | WS_VISIBLE | SS_LEFT,
                                             0, 0, 0, 0, hwnd_,
                                             reinterpret_cast<HMENU>(IDC_STATIC_STATE),
                                             hInstance_, nullptr);
    (void)hwndProtoLabel;
    (void)hwndStateLabel;
    hwndSearchEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
                                        editStyle, 0, 0, 0, 0, hwnd_,
                                        reinterpret_cast<HMENU>(IDC_EDIT_SEARCH),
                                        hInstance_, nullptr);
    ::SendMessageW(hwndSearchEdit_, EM_SETCUEBANNER, TRUE,
                   reinterpret_cast<LPARAM>(
                       L"Filter: text, port:443, pid:1234, cpu:12, exclude:remote:tcp:80..."));
    // Bound what can be TYPED to what can be READ. A single-line EDIT
    // defaults to EM_LIMITTEXT 32767, while CurrentSearchText() reads into a
    // 512-wchar buffer - so a filter past 511 characters was silently truncated
    // on the way back in, and the user got results for a filter they had not
    // typed. Setting the control's own limit to the read buffer makes the
    // invariant "typeable == readable" true by construction: the control
    // refuses the extra characters at the keystroke, where they are visible,
    // instead of the read dropping them where they are not.
    ::SendMessageW(hwndSearchEdit_, EM_LIMITTEXT, kSearchTextMaxChars, 0);

// Virtual list view: rows are supplied by LVN_GETDISPINFO from the
// store, so refreshes never destroy/recreate items.
//
// The control itself is ConnectionsList's now; all that is left here is
// creating it and detaching the shell's shared image list onto it, which is
// a one-time shell32 call the window owns.
if (!list_.Create(hwnd_, hInstance_)) {
    // No list view: the window has nothing to show. Failing here rather than
    // carrying on makes the failure loud at startup instead of a blank
    // rectangle with a live table nobody can see.
    ::DestroyWindow(hwnd_);
    hwnd_ = nullptr;
    return;
}

// Per-row process icons. The shell's system
// small-icon list is attached once; each row then supplies
// its icon's index in that list from LVN_GETDISPINFO, so a
// connection shows the icon of the program that owns the
// socket, the way Task Manager and Process Explorer do.
// shell32.dll is delay-loaded, so it is checked before the
// first shell call; a machine without it shows no icons -
// the list is unchanged, not broken.
if (iconImageList_ == nullptr && DllAvailable("shell32.dll")) {
    SHFILEINFOW sfi = {};
    iconImageList_ = reinterpret_cast<HIMAGELIST>(
        ::SHGetFileInfoW(L"C:\\", 0, &sfi, sizeof(sfi),
                         SHGFI_SYSICONINDEX | SHGFI_SMALLICON));
if (iconImageList_ != nullptr)
    ::SendMessageW(list_.Handle(), LVM_SETIMAGELIST,
                   LVSIL_SMALL,
                   reinterpret_cast<LPARAM>(iconImageList_));
}

// the process-tree view mode. A tree control where the list
// view is, not another window answering the same question - Task
// Manager's Processes tab is the model. Created hidden beside the list
// and swapped in by ToggleTreeMode, so the mode costs nothing while it
// is off and the list state (selection, scroll, columns) survives the
// round trip untouched. Filled by ProcessTreeFill, the same
// implementation the detached viewer uses.
hwndTree_ = ::CreateWindowExW(
    WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
    WS_CHILD | WS_BORDER | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES |
        TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_DISABLEDRAGDROP,
    0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(IDC_PROCESS_TREE),
    hInstance_, nullptr);
::SendMessageW(hwndTree_, WM_SETFONT,
               reinterpret_cast<WPARAM>(font_), MAKELPARAM(TRUE, 0));
if (hwndTree_ != nullptr) ::ShowWindow(hwndTree_, SW_HIDE);

// per-row accessible names for screen readers. The subclass serves
// WM_GETOBJECT on the LIST itself (a query for the main window must keep
// answering the main window - serving the list's object there would hide
// the control bar from assistive tech). Everything else passes straight
// through, the way ChangeLogWindow's list subclass does.
::SetWindowSubclass(list_.Handle(), &MainWindow::ListSubclassProc, 2,
                    reinterpret_cast<DWORD_PTR>(this));

hwndStatus_ = ::CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
                                    WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                                    0, 0, 0, 0, hwnd_,
                                    reinterpret_cast<HMENU>(IDC_STATUS),
                                    hInstance_, nullptr);

    const HFONT font = static_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));
    SetChildFont(hwndRefreshBtn_, font);
    SetChildFont(hwndExportBtn_, font);
    SetChildFont(hwndAutoChk_, font);
    SetChildFont(hwndIntervalCbo_, font);
    SetChildFont(hwndProtoCbo_, font);
    SetChildFont(hwndStateCbo_, font);
    SetChildFont(hwndSearchEdit_, font);
    SetChildFont(list_.Handle(), font);
    SetChildFont(hwndStatus_, font);
    SetChildFont(hwndFilterLabel, font);
    SetChildFont(hwndProtoLabel, font);
    SetChildFont(hwndStateLabel, font);

    // tab order. Controls were created in a different order from the one a
    // user would expect to walk them in, and without an explicit order Tab
    // follows creation order - so Tab out of the filter box jumped to the
    // Refresh button.
    //
    // Set by rewriting the GW_HWNDNEXT chain, which is exactly what Tab walks.
    // The old BuildTabOrder macro is absent from every current Windows SDK
    // (an exhaustive search finds no declaration), and its CreateWindowEx
    // equivalent is documented as unreliable for WS_GROUP controls, so the
    // chain is linked directly instead.
    //
    // Relinking from the END backwards matters: each SetWindowPos(GW_HWNDPREV)
    // moves a child to sit immediately after its parent, so walking backwards
    // guarantees every child is still where it is needed to be linked next.
    // Walking forwards would work only by accident of the original order.
    //
    // The order matches the visual rows: the auto-refresh checkbox and
    // interval combo (row 1), then the search box and the protocol and
    // state combos (row 2), then the list, with the action buttons last
    // - the list is where the user's attention belongs after narrowing
    // the view, and Refresh/Export are acted on least often.
    const HWND order[] = {
        hwndAutoChk_, hwndIntervalCbo_, hwndSearchEdit_,
        hwndProtoCbo_, hwndStateCbo_,
        list_.Handle(), hwndRefreshBtn_, hwndExportBtn_,
    };
    const int n = static_cast<int>(sizeof(order) / sizeof(order[0]));
    for (int i = n - 1; i > 0; --i) {
        if (order[i] == nullptr || order[i - 1] == nullptr) continue;
        ::SetWindowPos(order[i], order[i - 1], 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                           SWP_NOACTIVATE);
    }
    InitTooltips();
}

// Index of the default cadence in the interval combo: the "2 seconds" row. A
// bare `1` here would silently select a different cadence the day someone
// reorders the AddComboString calls in InitFilterControls.
constexpr int kDefaultIntervalComboIndex = 1;

void MainWindow::InitFilterControls() {
    // The offered cadences. Labels carry the meaning; the default row is
    // kDefaultIntervalComboIndex, which must be the "2 seconds" row — see it.
    AddComboString(hwndIntervalCbo_, L"1 second", kMsPerSecond);
    AddComboString(hwndIntervalCbo_, L"2 seconds", kDefaultIntervalMs);
    AddComboString(hwndIntervalCbo_, L"5 seconds", 5000);
    AddComboString(hwndIntervalCbo_, L"10 seconds", 10000);
    ::SendMessageW(hwndIntervalCbo_, CB_SETCURSEL, kDefaultIntervalComboIndex,
                   0);
    autoRefreshMs_ = kDefaultIntervalMs;

    // Protocol filter: family and protocol bits combined.
    AddComboString(hwndProtoCbo_, L"All (TCP + UDP, IPv4 + IPv6)",
                   static_cast<LPARAM>(kProtoMaskAll));
    AddComboString(hwndProtoCbo_, L"TCP only",
                   static_cast<LPARAM>(kProtoMaskV4 | kProtoMaskV6 | kProtoMaskTCP));
    AddComboString(hwndProtoCbo_, L"UDP only",
                   static_cast<LPARAM>(kProtoMaskV4 | kProtoMaskV6 | kProtoMaskUDP));
    AddComboString(hwndProtoCbo_, L"IPv4 only",
                   static_cast<LPARAM>(kProtoMaskV4 | kProtoMaskTCP | kProtoMaskUDP));
    AddComboString(hwndProtoCbo_, L"IPv6 only",
                   static_cast<LPARAM>(kProtoMaskV6 | kProtoMaskTCP | kProtoMaskUDP));
    ::SendMessageW(hwndProtoCbo_, CB_SETCURSEL, 0, 0);

    for (const StateItem& si : kStateItems)
        AddComboString(hwndStateCbo_, si.label, static_cast<LPARAM>(si.state));
    ::SendMessageW(hwndStateCbo_, CB_SETCURSEL, 0, 0);
}

void MainWindow::HarvestColumnWidths() {
    // The window's half is nothing: the geometry object reads the control
    // back itself.
    cols_.HarvestWidths(list_.Handle(), static_cast<int>(dpi_));
}

void MainWindow::RebuildColumns() {
    if (list_.Handle() == nullptr) return;

    // Remember current widths (user may have dragged separators).
    HarvestColumnWidths();

    // Rebuilding the columns annihilates the sort arrow, so it is restored
    // here - one call, in the one place that deletes and re-inserts them.
    cols_.SyncColumns(list_.Handle(), static_cast<int>(dpi_));
    UpdateSortIndicator();
    SyncGroupHeader();
}

void MainWindow::SyncGroupHeader() {
    // in grouped mode the rows are per-process aggregates, and the
    // header of the column that carries the aggregation says so with the
    // live group count. A flat view keeps the plain title, so the label
    // is state rather than decoration.
    cols_.SetGroupTitle(list_.Handle(), groupByProcess_, store_.View().size());
}

int MainWindow::VisibleToCol(int visibleIndex) const {
    return cols_.VisibleToCol(visibleIndex);
}

int MainWindow::ColToVisible(int columnId) const {
    return cols_.ColToVisible(columnId);
}

void MainWindow::UpdateSortIndicator() {
    cols_.UpdateSortIndicator(list_.Handle(), store_.SortColumn(),
                              store_.SortAscending());
}

void MainWindow::SyncColumnMenuChecks() {
    cols_.SyncMenuChecks(::GetMenu(hwnd_));
}

// ---- the alert engine's only production caller ------------------------
// The engine has existed, pure and tested, with no caller at all. This is it.
//
// Three rules it must obey, and one it must NOT:
//
//   * The tray icon is OPTIONAL. Balloons need it; without one the alert still
//     fires, it just lands on the status bar rather than silently vanishing - an
//     alert that does nothing is worse than no alert at all.
//   * The engine latches. A condition already active is suppressed until it
//     clears, so a connection sitting above the threshold does not re-notify on
//     every refresh. That is the engine's job, not this function's.
//   * Settings are re-read FRESH each tick, because another process running
//     `wintcp.exe alert` can change them between two refreshes and the window
//     must not be the only thing that does not know.
//   * It must NOT hold a row pointer across the balloon call - a modal pumps
//     messages and a refresh can reallocate the store underneath. Everything
//     below is copied by value.
void MainWindow::RunAlerts() {
    Settings s;
    // portable defaults first, so the registry always wins. Silent on
    // a missing file; a file that exists but will not parse is reported once
    // on the status line, because a portable copy that quietly does nothing
    // is worse than one that says so.
    wchar_t exePath[MAX_PATH] = {0};
    const DWORD pn = ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring portableErr;
    if (pn != 0 && pn < MAX_PATH) {
        s.ApplyPortableDefaults(exePath, &portableErr);
    }
    if (!portableErr.empty()) {
        UpdateStatusBar(L"wintcp.ini: " + portableErr);
    }
    if (!s.Load()) return;              // no store, no alerting - say nothing

    // The rules are read here, per tick, for the same reason the settings are:
    // `alert rule add` from another process has to reach a running window without a
    // restart. One list, so the CLI and the window cannot disagree about what is
    // being watched.
    const std::vector<AlertRule> rules = AlertRuleStore::Load();

    // The hint is rebuilt from scratch every pass: the status line names what
    // fired on THIS tick, not an accumulation since the window opened. The
    // balloon path never touches it, so an empty hint means "no alerts fired
    // this tick" while the tray is up - which is the right answer to show.
    alertHint_.clear();

    // The pass itself is AlertMonitor's. The window's contribution is the
    // snapshot (copied by value: an emit pumps messages and can reallocate the
    // store) and the answer to "what does an alert look like here", which is
    // RaiseAlert - one balloon per alert when the tray icon is up, the status
    // line when it is not.
    const std::vector<Connection> rows = store_.Rows();   // a copy, on purpose
    alertMonitor_.Run(rows, s.alerts, rules,
                      [this](const Alert& a) { RaiseAlert(a); });
    suppressedAlerts_ = alertMonitor_.SuppressedCount();
    UpdateStatusBar(lastError_);
}

// One balloon per alert, whichever source it came from. Without an icon there
// is nowhere to put a balloon, so the alert lands in the status bar instead -
// which is why this branch exists rather than a silent drop.
void MainWindow::RaiseAlert(const Alert& a) {
    if (tray_.IsShown()) {
        tray_.Balloon(a.title, a.text, NIIF_WARNING);
        return;
    }
    // The monitor built the hint for this tick; the balloon path bypasses it,
    // so only the no-icon case needs the join.
    if (!alertHint_.empty()) alertHint_ += L"  \xB7  ";
    alertHint_ += a.title;
}

// ---- empty states -----------------------------------------------------
// A blank cell answers the wrong question. "No rows", "no country database
// loaded" and "traffic never ran" are three DIFFERENT reasons a column is empty,
// and on screen they are identical - so each gets one sentence that says what to
// do about it.
//
// Three deliberate choices:
//
// - It is recomputed, never stored. Nothing here is remembered between calls, so
//   no code path can leave a stale hint on screen. OnTimer already re-runs
//   UpdateStatusBar every second and ApplyViewWith calls this on every view
//   change, which is every path that can change any of the predicates.
// - Order is NO ROWS > DATABASE > TRAFFIC. With no rows at all the other two are
//   noise: telling someone their Country column is empty while the table is empty
//   is answering a question they did not ask.
// - Each message names the menu item that fixes it, because "add --db" is not
//   something a GUI user can act on and "pick one in View > GeoIP database" is.
void MainWindow::UpdateEmptyState() {
    emptyStateHint_.clear();

    if (store_.View().empty() && !store_.Rows().empty()) {
        // The table has traffic but the FILTER matches nothing - the case a user
        // reads as "the tool is broken". An empty table with no traffic at all is
        // normal and needs no banner.
        emptyStateHint_ = L"no rows match this filter - clear it to see everything";
        return;
    }

    // A country-bearing column with no database behind it. Both databases count,
    // because either fills the cell.
    const bool countryShown = cols_.IsVisible(COL_COUNTRY);
    if (countryShown && !enrich_.CountryLoaded() && !enrich_.AsnLoaded()) {
        emptyStateHint_ = L"no GeoIP database loaded - pick one in View > GeoIP "
                          L"database to fill Country";
        return;
    }

    // A traffic column with nothing measuring it. AnyTrafficColVisible already
    // answers "does the user care", and the two sources are exactly the two
    // states UpdateStatusBar distinguishes - so this adds no new predicate.
    if (AnyTrafficColVisible() && !etw_->Running() && !fallbackFlag_->load()) {
        emptyStateHint_ = L"traffic not being measured - View > Per-PID traffic "
                          L"counters (needs admin)";
        return;
    }
}

// ---- the buttons half ------------------------------------------------
// UpdateEmptyState says WHY the table is empty; this offers the fix as a
// click. The decision - which case, which buttons - is made by the pure
// DecideEmptyState (EmptyStateActions.cpp) so the window runs the same
// predicate the selftest pins, and there is no second copy here to drift.
void MainWindow::ShowEmptyStateActions() {
    const EmptyStateOffer offer = DecideEmptyState(
        store_.Rows().size(), store_.View().size(),
        cols_.IsVisible(COL_COUNTRY), enrich_.CountryLoaded(),
        enrich_.AsnLoaded(), AnyTrafficColVisible(), etw_->Running(),
        fallbackFlag_->load(), IsElevated());

    // Nothing to offer. The status-bar sentence UpdateEmptyState already sets
    // is the whole answer, and an empty-state message with no action is still
    // useful - a dialog with no buttons would just be an extra click.
    if (offer.ButtonCount() == 0) {
        // Reached only through the menu item, which is how a user asks "why is
        // my table empty?" directly. Saying there is nothing to fix is the
        // answer, and it is different from the dialog not appearing at all -
        // which would look like the menu item did nothing.
        ::MessageBoxW(hwnd_,
                      offer.message[0] != L'\0'
                          ? (std::wstring(offer.message) +
                             L", and there is nothing to fix.")
                                .c_str()
                          : L"The table is showing everything it has. "
                            L"There is nothing to fix right now.",
                      L"WinTCP", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Same delay-load guard ResolveMinimize uses, for the same reason: without
    // comctl32 the dialog cannot be shown at all, and the sentence on the
    // status bar must survive that.
    if (!DelayLoadGuard(hwnd_, "comctl32.dll")) return;

    TASKDIALOGCONFIG tc = {};
    tc.cbSize = sizeof(tc);
    tc.hwndParent = hwnd_;
    tc.dwFlags = TDF_USE_HICON_MAIN;
    tc.hMainIcon = ::LoadIconW(nullptr, IDI_INFORMATION);
    tc.pszWindowTitle = L"WinTCP";
    tc.pszMainInstruction = offer.message;
    tc.pszContent = L"WinTCP can put that right for you.";

    // Button ids start above 100 so they cannot collide with the standard
    // IDOK/IDCANCEL the dialog would otherwise return.
    enum {
        kBtnClear = 101, kBtnEdit, kBtnPickGeo, kBtnRunAdmin
    };
    TASKDIALOG_BUTTON btns[4] = {};
    size_t n = 0;
    // In the declarative order - the same order the bench asserts the offer
    // carries, so a test and the dialog cannot disagree.
    if (offer.offerClear) {
        btns[n].nButtonID = kBtnClear;
        btns[n].pszButtonText = kEmptyActionClear;
        ++n;
    }
    if (offer.offerEdit) {
        btns[n].nButtonID = kBtnEdit;
        btns[n].pszButtonText = kEmptyActionEdit;
        ++n;
    }
    if (offer.offerPickGeo) {
        btns[n].nButtonID = kBtnPickGeo;
        btns[n].pszButtonText = kEmptyActionPickGeo;
        ++n;
    }
    if (offer.offerRunAdmin) {
        btns[n].nButtonID = kBtnRunAdmin;
        btns[n].pszButtonText = kEmptyActionRunAdmin;
        ++n;
    }
    tc.pButtons = btns;
    tc.cButtons = static_cast<UINT>(n);
    tc.nDefaultButton = btns[0].nButtonID;   // the first is the safest action

    int which = 0;
    if (::TaskDialogIndirect(&tc, &which, nullptr, nullptr) != S_OK) return;

    switch (which) {
        case kBtnClear:
            // ClearFilterBox is the existing path: it empties the control AND
            // reapplies the view, so the table comes back with its filter gone
            // rather than just losing the text.
            ClearFilterBox();
            UpdateStatusBar(L"filter cleared");
            break;
        case kBtnEdit:
            // Focus the box with its text selected, so the expression can be
            // fixed rather than thrown away - a different intent from clearing,
            // and the reason both buttons are offered.
            FocusFilterBox();
            break;
        case kBtnPickGeo:
            LoadGeoIpDatabase();
            break;
        case kBtnRunAdmin:
            // Reelevate returns true only when it actually started a new
            // instance, and the contract is that the caller then exits
            // immediately - there is no path back here.
            if (Reelevate(L"Per-PID traffic counters")) {
                ::PostQuitMessage(0);
            }
            break;
        default:
            break;
    }
}
// ---- column profiles -------------------------------------------------
// A profile is a named COLUMN MASK, nothing else. That is a deliberate narrowing:
// a preset (File > Save view as preset) is a full ViewState - filter, sort,
// grouping, sources and mask - and these must not become a second, weaker preset
// that drifts from the real one. They also must not be persisted as preset
// entries; the visible mask is already persisted in settings_.colVisible.
//
// The masks are computed from the live ColumnId bits rather than hard-coded, so a
// future 33rd column cannot be silently missing from every profile.
UINT32 MainWindow::ColumnProfileMask(int profileId) const {
    switch (profileId) {
        case IDM_PROFILE_MINIMAL:
            return kMinimalProfileCols;
        case IDM_PROFILE_NETWORK:
            return kNetworkProfileCols;
        case IDM_PROFILE_SECURITY:
            return kSecurityProfileCols;
        case IDM_PROFILE_PERFORMANCE:
            return kPerformanceProfileCols;
        case IDM_PROFILE_DIAGNOSTICS:
            // Show diagnostics ORs the five readings onto whatever is
            // visible now, rather than replacing it: "show me the diagnostics
            // TOO" is the question, and a user who has hidden CPU would not
            // expect clicking this to bring it back.
            {
                const UINT32 diagnostics =
                    (1u << COL_RTT) | (1u << COL_MINRTT) | (1u << COL_CWND) |
                    (1u << COL_RETRANS) | (1u << COL_GROUPRATE);
                return cols_.VisibleMask() | diagnostics;
            }
        case IDM_PROFILE_DEFAULT:
        default:
            return kDefaultVisibleCols;
    }
}

void MainWindow::ApplyColumnProfile(int profileId) {
    RebuildColumns();                        // harvest widths before the swap
    cols_.SetVisibleMask(ClampVisibleCols(ColumnProfileMask(profileId)));
    RebuildColumns();
    SyncColumnMenuChecks();
    SyncColumnProfileChecks();
    ApplyView();
}

void MainWindow::SyncColumnProfileChecks() {
    const HMENU view = ::GetSubMenu(::GetMenu(hwnd_), 1);   // View popup
    if (view == nullptr) return;
    for (int id = IDM_PROFILE_DEFAULT; id <= IDM_PROFILE_DIAGNOSTICS; ++id) {
        // A profile is checked when the mask equals it EXACTLY. "Show diagnostics"
        // is the exception: it ors onto the current set, so it is checked when all
        // five of its bits are present, which survives the user hiding a column
        // afterwards without lying about what is on screen.
        const UINT32 mask = ColumnProfileMask(id);
        const UINT32 shown = cols_.VisibleMask();
        const bool on = (id == IDM_PROFILE_DIAGNOSTICS)
                            ? (shown & mask) == mask
                            : shown == mask;
        ::CheckMenuItem(view, id, MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED));
    }
}

// ---- quick filters ---------------------------------------------------
// One click writes an expression into the filter box and lets the existing
// debounce apply it, so the expression is VISIBLE and EDITABLE - the whole point
// of "one click builds the filter" rather than "one click filters".
void MainWindow::ApplyQuickFilter(int commandId) {
    const wchar_t* expr = L"";
    switch (commandId) {
        case IDM_QFILTER_TCP:    expr = L"proto:tcp";        break;
        case IDM_QFILTER_UDP:    expr = L"proto:udp";        break;
        case IDM_QFILTER_LISTEN: expr = L"state:listen";    break;
        case IDM_QFILTER_ESTAB:  expr = L"state:estab";     break;
        case IDM_QFILTER_MINE:
            // The ticket says "Mine" without defining it, and the filter grammar
            // cannot OR two terms - so "listening OR established" is not
            // expressible. What IS expressible, and what the name means:
            // connections whose LOCAL endpoint is on a non-routable range, i.e.
            // this machine talking to its own network rather than to the internet.
            expr = L"local:private";
            break;
        case IDM_QFILTER_ALL:
        default:                 expr = L"";                break;
    }
    if (hwndSearchEdit_ != nullptr && CurrentSearchText() != expr) {
        ::SetWindowTextW(hwndSearchEdit_, expr);
    }
    // Re-arm the debounce explicitly, exactly as ClearFilterBox does: a
    // programmatic SetWindowText does not guarantee EN_CHANGE, and without the
    // re-arm a box that already held the same text would not re-apply.
    ::KillTimer(hwnd_, kFilterTimerId);
    ::SetTimer(hwnd_, kFilterTimerId, kFilterDebounceMs, nullptr);
    SyncQuickFilterChecks();
}

void MainWindow::SyncQuickFilterChecks() {
    const HMENU bar = ::GetMenu(hwnd_);
    if (bar == nullptr) return;
    const wchar_t* want = nullptr;
    {
        const std::wstring cur = CurrentSearchText();
        if (cur == L"proto:tcp") want = L"proto:tcp";
        else if (cur == L"proto:udp") want = L"proto:udp";
        else if (cur == L"state:listen") want = L"state:listen";
        else if (cur == L"state:estab") want = L"state:estab";
        else if (cur == L"local:private") want = L"local:private";
        else if (cur.empty()) want = L"";
    }
    const int ids[] = {IDM_QFILTER_ALL,   IDM_QFILTER_TCP,    IDM_QFILTER_UDP,
                       IDM_QFILTER_LISTEN, IDM_QFILTER_ESTAB, IDM_QFILTER_MINE};
    for (int id : ids) {
        bool on = false;
        switch (id) {
            case IDM_QFILTER_ALL:     on = (want != nullptr && *want == L'\0'); break;
            case IDM_QFILTER_TCP:     on = (want != nullptr && ::wcscmp(want, L"proto:tcp") == 0); break;
            case IDM_QFILTER_UDP:     on = (want != nullptr && ::wcscmp(want, L"proto:udp") == 0); break;
            case IDM_QFILTER_LISTEN:  on = (want != nullptr && ::wcscmp(want, L"state:listen") == 0); break;
            case IDM_QFILTER_ESTAB:   on = (want != nullptr && ::wcscmp(want, L"state:estab") == 0); break;
            case IDM_QFILTER_MINE:    on = (want != nullptr && ::wcscmp(want, L"local:private") == 0); break;
            default: break;
        }
        ::CheckMenuItem(bar, id, MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED));
    }
}
void MainWindow::ToggleColumn(int columnId) {
    if (columnId < 0 || columnId >= COL_COUNT) return;
    RebuildColumns();                     // harvests current widths first
    // The geometry object refuses the case that would empty the set; the
    // window reports it, because a dialog is a window concern.
    if (!cols_.Toggle(columnId)) {
        ::MessageBoxW(hwnd_, L"At least one column must stay visible.",
                      L"Columns", MB_OK | MB_ICONINFORMATION);
        return;
    }
    SyncColumnMenuChecks();
    // Showing a traffic column with no source running would
    // leave it stuck on "—". Try the ETW counters once (elevated fills
    // immediately, UDP included) and fall back to the non-admin socket
    // totals otherwise; UpdateStatusBar explains whichever state applies.
    if (IsTrafficColumn(columnId)) {
        if (cols_.IsVisible(columnId)) {
            EnsureTrafficCounters();
        } else if (!AnyTrafficColVisible() && fallbackFlag_->load()) {
            // Last traffic column hidden: stop paying for socket scans.
            // Totals are retained in socketTraffic_, so re-showing the
            // column resumes without losing history.
            fallbackFlag_->store(false);
        }
    }
    RebuildColumns();
    ApplyView();
}

void MainWindow::EnsureTrafficCounters() {
    // whichever source can run fills the traffic columns.
    //  1) ETW kernel logger (elevated): full fidelity incl. UDP - tried
    //     silently at most once per session (this path was not requested
    //     by the user; the explicit menu toggle still reports why).
    //  2) otherwise the non-admin socket fallback (SIO_TCP_INFO) supplies
    //     per-PID TCP totals - also silently, because it succeeds: there
    //     is nothing to warn about.
    if (etw_->Running()) return;
    if (!etwAutoAttempted_) {
        etwAutoAttempted_ = true;
        std::wstring err;
        if (etw_->Start(err)) {
            settings_.trafficEnabled = true;
            fallbackFlag_->store(false);   // ETW is authoritative
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAFFIC, true);
            Refresh(false);               // re-apply counters to the rows
            return;
        }
    }
    if (!fallbackFlag_->load() && socketTraffic_->Supported()) {
        fallbackFlag_->store(true);
        Refresh(false);                   // one pass so cells fill now
    }
}

void MainWindow::RecreateFont() {
    // No handle is created or destroyed here any more. The cache owns every
    // font the process uses, so a DPI change is one call to OnDpiChanged and the
    // next Get() is correct by construction - instead of three windows each
    // releasing their own handles and one of them chasing a copy held elsewhere.
    FontCache::Get().OnDpiChanged();
    font_ = FontCache::Get().Get(kBodyPtSize, FW_NORMAL, dpi_);
    ApplyFontToChildren();
    // The details window borrows this handle for its buttons and re-resolves
    // its cache-owned faces at its own DPI; it must hear about the
    // replacement too, otherwise a monitor DPI change leaves it behind.
    details_.ApplyFont(font_);
    // the tree control is a child like any other, so it gets the
    // face through ApplyFontToChildren - the mode adds no font plumbing.
}

void MainWindow::ApplyFontToChildren() {
    HFONT f = font_;
    if (f == nullptr) f = static_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));
    for (HWND c = ::GetWindow(hwnd_, GW_CHILD); c != nullptr;
         c = ::GetWindow(c, GW_HWNDNEXT)) {
        SetChildFont(c, f);
    }
    if (list_.Handle() != nullptr) {
        if (HWND hdr = ListView_GetHeader(list_.Handle())) SetChildFont(hdr, f);
    }
}

void MainWindow::LayoutControls(int cx, int cy) {
    const int kMargin = S(8);
    const int kRow1Y = S(8);
    const int kRow1H = S(24);
    const int kRow2Y = S(38);
    const int kRow2H = S(22);
    const int kTopH = S(66);
    const int kStatusH = S(24);

    // Row 1 - actions. Refresh, Export and the auto-refresh
    // checkbox are fixed at the left, with the interval combo
    // after them at a fixed width. The protocol and state
    // filters moved down to row 2 with the search box, so this
    // row no longer carries the fixed x positions that used to
    // push the State combo past the client edge below ~760 px.
    if (hwndRefreshBtn_ != nullptr)
        ::MoveWindow(hwndRefreshBtn_, kMargin, kRow1Y, S(90), kRow1H, TRUE);
    if (hwndExportBtn_ != nullptr)
        ::MoveWindow(hwndExportBtn_, kMargin + S(96), kRow1Y, S(100), kRow1H, TRUE);
    if (hwndAutoChk_ != nullptr)
        ::MoveWindow(hwndAutoChk_, kMargin + S(202), kRow1Y, S(104), kRow1H, TRUE);
    if (hwndIntervalCbo_ != nullptr)
        ::MoveWindow(hwndIntervalCbo_, kMargin + S(310), kRow1Y, S(100), S(200), TRUE);

    // Row 2 - the view filters. The search box stretches to fill
    // the space before the right-anchored Protocol and State
    // combos, so those two track the right edge and never run
    // off a narrow window. Each is labelled like the Filter: box,
    // so a reader does not have to infer what a drop-down narrows.
    const int gap = S(6);
    const int stateW = S(110), stateLabelW = S(34);
    const int protoW = S(120), protoLabelW = S(52);
    const int stateComboX = cx - kMargin - stateW;
    const int stateLabelX = stateComboX - stateLabelW - gap;
    const int protoComboX = stateLabelX - gap - protoW;
    const int protoLabelX = protoComboX - protoLabelW - gap;

    HWND hwndLabel = ::GetDlgItem(hwnd_, IDC_STATIC_FILTER);
    if (hwndLabel != nullptr)
        ::MoveWindow(hwndLabel, kMargin, kRow2Y + S(3), S(40), kRow2H, TRUE);
    if (hwndSearchEdit_ != nullptr) {
        const int searchX = kMargin + S(44);
        int searchW = protoLabelX - gap - searchX;
        const int searchMin = S(60);
        if (searchW < searchMin) searchW = searchMin;
        ::MoveWindow(hwndSearchEdit_, searchX, kRow2Y, searchW, kRow2H, TRUE);
    }
    HWND hwndProtoLabel = ::GetDlgItem(hwnd_, IDC_STATIC_PROTO);
    if (hwndProtoLabel != nullptr)
        ::MoveWindow(hwndProtoLabel, protoLabelX, kRow2Y + S(3),
                         protoLabelW, kRow2H, TRUE);
    if (hwndProtoCbo_ != nullptr)
        ::MoveWindow(hwndProtoCbo_, protoComboX, kRow2Y, protoW, S(220), TRUE);
    HWND hwndStateLabel = ::GetDlgItem(hwnd_, IDC_STATIC_STATE);
    if (hwndStateLabel != nullptr)
        ::MoveWindow(hwndStateLabel, stateLabelX, kRow2Y + S(3),
                         stateLabelW, kRow2H, TRUE);
    if (hwndStateCbo_ != nullptr)
        ::MoveWindow(hwndStateCbo_, stateComboX, kRow2Y, stateW, S(240), TRUE);

if (hwndStatus_ != nullptr)
    ::MoveWindow(hwndStatus_, 0, cy - kStatusH, cx, kStatusH, TRUE);
if (list_.Handle() != nullptr) {
    int listH = cy - kTopH - kStatusH - kMargin;
    if (listH < S(40)) listH = S(40);
    ::MoveWindow(list_.Handle(), kMargin, kTopH, cx - 2 * kMargin, listH, TRUE);
}
// the tree occupies exactly the list's rectangle, and only one of
// the two is ever visible. The swap lives here - the single place every
// size, DPI change and toggle flows through - rather than in the toggle, so
// a resize while the mode is on cannot leave the tree at its old size.
if (hwndTree_ != nullptr) {
    int treeH = cy - kTopH - kStatusH - kMargin;
    if (treeH < S(40)) treeH = S(40);
    ::MoveWindow(hwndTree_, kMargin, kTopH, cx - 2 * kMargin, treeH, TRUE);
    ::ShowWindow(hwndTree_, treeMode_ ? SW_SHOW : SW_HIDE);
}
if (list_.Handle() != nullptr)
    ::ShowWindow(list_.Handle(), treeMode_ ? SW_HIDE : SW_SHOW);
}

void MainWindow::OnSize(int cx, int cy) {
    LayoutControls(cx, cy);
    if (hwndStatus_ != nullptr) {
        // Six parts: counts, live state breakdown, last refresh time,
        // selection, refresh age / next tick, and the traffic-source or
        // error state. The first two grow with the window; the rest are
        // fixed-width from the right, so a narrow window truncates the
        // informational panes first. All part coordinates are clamped so a
        // very small client area cannot produce a negative or inverted
        // split, and they are DPI-scaled.
        const int w = (cx < 100) ? 100 : cx;
        // Right-hand panes, measured from the right edge inwards.
        const int wRight  = S(170);   // traffic source / error
        const int wAge    = S(150);   // age + countdown
        const int wSel    = S(110);   // selected count
        const int wTime   = S(150);   // last refresh time
        const int minLeft = S(140);   // never squeeze the counts pane to nil

        int right = w;
        const auto place = [&](int width) {
            right -= width;
            if (right < minLeft) right = minLeft;
            return right;
        };
        const int p5 = place(wRight);
        const int p4 = place(wAge);
        const int p3 = place(wSel);
        int p2 = place(wTime);
        const int p1 = minLeft;
        if (p2 < p1) p2 = p1;

        const int parts[6] = {p1, p2, p3, p4, p5, -1};
        ::SendMessageW(hwndStatus_, SB_SETPARTS, 6,
                       reinterpret_cast<LPARAM>(parts));
    }
}

// ---------------------------------------------------------------------------
// view (filter + sort + repaint) -------------------------------

std::wstring MainWindow::CurrentSearchText() const {
    // Sized from kSearchTextMaxChars, which is also the control's EM_LIMITTEXT,
    // so this read can never truncate what the user typed. Deliberately NOT
    // _countof: the capacity that matters is the one the control was bounded
    // to, and spelling it as the constant makes the two impossible to drift.
    wchar_t buf[kSearchTextMaxChars] = {0};
    ::GetWindowTextW(hwndSearchEdit_, buf,
                     static_cast<int>(sizeof(buf) / sizeof(buf[0])));
    return std::wstring(buf);
}

unsigned MainWindow::CurrentProtoFilterMask() const {
    const LRESULT sel = ::SendMessageW(hwndProtoCbo_, CB_GETCURSEL, 0, 0);
    if (sel == CB_ERR) return kProtoMaskAll;
    const LRESULT data = ::SendMessageW(hwndProtoCbo_, CB_GETITEMDATA,
                                        static_cast<WPARAM>(sel), 0);
    if (data == CB_ERR || data == 0) return kProtoMaskAll;
    return static_cast<unsigned>(data);
}

DWORD MainWindow::CurrentStateFilter() const {
    const LRESULT sel = ::SendMessageW(hwndStateCbo_, CB_GETCURSEL, 0, 0);
    if (sel == CB_ERR) return kAllStates;
    const LRESULT data = ::SendMessageW(hwndStateCbo_, CB_GETITEMDATA,
                                        static_cast<WPARAM>(sel), 0);
    if (data == CB_ERR) return kAllStates;
    return static_cast<DWORD>(data);
}

void MainWindow::ApplyView() {
    std::vector<std::uint64_t> ids;
    std::uint64_t focusedId = 0;
    int topIdx = 0;
    list_.CaptureSelection(ids, &focusedId, &topIdx);
    ApplyViewWith(ids, focusedId, topIdx);
    UpdateCaption();
}

void MainWindow::ApplyViewWith(const std::vector<std::uint64_t>& ids,
                               std::uint64_t focusedId, int topIdx) {
    // Assemble the view and hand it to ViewState, which is the ONLY thing that
    // turns a description into a built view. This method used to do that work
    // itself - build a ViewQuery by hand, parse the filter, set the view - and
    // a CLI had no way to build the same view except by copying those lines,
    // which is how the two front ends drifted apart last time (the CLI carried
    // a private copy of the snapshot pipeline and had silently fallen behind
    // the GUI's). One builder, both callers.
    //
    // The GUI's contribution is reading the widgets into a ViewState; every
    // decision about what that state MEANS belongs to ViewState::ApplyTo.
    ViewState v;
    v.filter = CurrentSearchText();
    v.protoMask = CurrentProtoFilterMask();
    v.stateFilter = CurrentStateFilter();
    v.sortColumn = store_.SortColumn();
    v.sortAsc = store_.SortAscending();
    v.grouped = groupByProcess_;
    v.frozen = frozen_;
    v.frozenAtMs = frozenAt_;
    v.preserveSelection = preserveSelection_;
    v.colVisible = cols_.VisibleMask();
    // ApplyTo hands back the parsed program so the filter is parsed ONCE here
    // rather than again below; filterProgram_ is a derived cache of v.filter,
    // kept for the two callers that ask "is a text filter active?" without
    // re-reading the box.
    v.ApplyTo(&store_, &filterProgram_, &filterError_);

    // Recomputed here rather than only at startup because this is the
    // single funnel every path goes through: startup, a refresh result, a column
    // toggle, a preset, a GeoIP pick and a freeze all end here, and at this point
    // the row count, the column mask and both database states are simultaneously
    // valid.
    UpdateEmptyState();
    const size_t count = store_.View().size();
    ::SendMessageW(list_.Handle(), LVM_SETITEMCOUNT, static_cast<WPARAM>(count),
                   LVSICF_NOINVALIDATEALL);
    list_.RestoreSelection(ids, focusedId, topIdx);
    ::InvalidateRect(list_.Handle(), nullptr, TRUE);
    SyncGroupHeader();   // the group count moves every refresh
    // in tree mode the tree IS the view, so every path that lands
    // here - a refresh result, a column toggle, a preset, a GeoIP pick -
    // refills it. Filling from the unfiltered rows is the tree's rule, so
    // the filter box deliberately does not narrow the tree.
    if (treeMode_) RebuildTree();
    UpdateStatusBar(lastError_);
}

// does this row carry a wildcard bind - 0.0.0.0 or :: - rather than a
// resolvable specific address? The store prints the local address for most
// rows, so this is only the case for the fallback path that could not
// resolve one; the wildcard check itself lives in ExposureScore's predicates
// and the printable form is what the fallback actually carries.
static bool IsUnspecifiedAddress(const Connection& c) {
    // An empty or wildcard printable address is the same thing: the row does
    // not say where it is bound, and a caller that cannot say must not be
    // told "not exposed".
    return c.display.localAddress.empty() || c.display.localAddress == L"*" ||
           c.display.localAddress == L"0.0.0.0" || c.display.localAddress == L"::";
}

// the exposure badge's decision half, run per refresh.
//
// Walks the store once - not the view: an exposure finding is a property of
// the MACHINE, not of the current filter, so hiding a row with a filter must
// not hide the finding. The per-row predicate is wintcp::ScoreListener
// (ExposureScore.cpp), pure and pinned, so this is only the wiring.
void MainWindow::UpdateExposure() {
    exposureLine_.clear();
    exposureDetail_.clear();
    if (store_.Rows().empty()) return;

    std::vector<ExposureRow> rows;
    rows.reserve(store_.Rows().size());
    for (const Connection& c : store_.Rows()) {
        if (c.identity.pid == 0 && c.display.processName.empty()) continue;
        const bool isV6 = (c.identity.family == AF_INET6);
        ExposureRow row = ScoreListener(
            reinterpret_cast<const unsigned char*>(
                isV6 ? c.identity.local6.s6_addr : (const unsigned char*)&c.identity.local4),
            isV6 ? sizeof(c.identity.local6) : sizeof(c.identity.local4), isV6,
            static_cast<unsigned short>(c.identity.localPort), c.identity.protocol, c.identity.state,
            IsUnspecifiedAddress(c));
        // The two owner axes. A System process is a service, which can only
        // exist because something gave it the right; an unsigned image is the
        // one that has not been vouched for by anyone. The two together, on a
        // wildcard privileged port, is the recipe-24 red case.
        row.isSystem = (c.security.integrity == kIntegritySystem);
        row.isUnsigned = (c.security.signature == kSigUnsigned);
        if (row.level != ExposureLevel::kNone) {
            rows.push_back(row);
            if (row.level == ExposureLevel::kExposed && !row.reason.empty()) {
                if (exposureDetail_.size() < 200) {
                    exposureDetail_ += row.reason;
                    exposureDetail_ += L"\r\n";
                }
            }
        }
    }
    if (rows.empty()) return;
    const ExposureSummary sum = SummariseExposure(rows);
    exposureLine_ = sum.line;
}

void MainWindow::UpdateCaption() {
    // the caption carries the view state - grouped,
    // frozen, filtered - so the window is identifiable at
    // a glance and in Alt-Tab, not only from inside the
    // client area.
    std::wstring title = L"WinTCP - TCP/UDP Connections";
    if (groupByProcess_) title += L" [Grouped]";
    if (frozen_) title += L" [Frozen]";
    if (treeMode_) title += L" [Tree]";
    if (!CurrentSearchText().empty()) title += L" [Filtered]";
    ::SetWindowTextW(hwnd_, title.c_str());
}

void MainWindow::ToggleTreeMode() {
    // a tree control where the list view is. This is a MODE of the
    // main window rather than a window of its own, because the two would be
    // two answers to "show me the process hierarchy", and the list's own
    // state (selection, scroll, column widths) must be there when the mode
    // is switched off. The rows are re-read by value (ProcessTreeFill takes
    // a snapshot), so a refresh racing the render cannot reallocate the
    // store under it.
    treeMode_ = !treeMode_;
    if (::GetMenu(hwnd_) != nullptr)
        SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_PROCESSTREE, treeMode_);
    if (treeMode_) {
        // Leaving: remember the list's selection and scroll so switching
        // back restores what the reader had, rather than whatever row the
        // tree's last caret mapped to.
        list_.CaptureSelection(treeSavedIds_, &treeSavedFocus_, &treeSavedTop_);
    } else if (!treeSavedIds_.empty() || treeSavedFocus_ != 0 ||
               treeSavedTop_ >= 0) {
        list_.RestoreSelection(treeSavedIds_, treeSavedFocus_, treeSavedTop_);
        treeSavedIds_.clear();
        treeSavedFocus_ = 0;
        treeSavedTop_ = -1;
        ::SetFocus(list_.Handle());
    }
    if (hwndTree_ != nullptr) {
        ::ShowWindow(hwndTree_, treeMode_ ? SW_SHOW : SW_HIDE);
        ::InvalidateRect(hwndTree_, nullptr, TRUE);
    }
    if (list_.Handle() != nullptr) {
        ::ShowWindow(list_.Handle(), treeMode_ ? SW_HIDE : SW_SHOW);
        ::InvalidateRect(list_.Handle(), nullptr, TRUE);
    }
    if (treeMode_) RebuildTree();
    UpdateCaption();
    UpdateTrayTip();
    UpdateStatusBar(lastError_);
}

void MainWindow::RebuildTree() {
    if (hwndTree_ == nullptr) return;
    const ProcessTreeViewState previousTreeState =
        CaptureProcessTreeViewState(hwndTree_, treeProcs_);
    // Two sources, merged here and nowhere else. WHO the processes are comes
    // from one Toolhelp snapshot (EnumerateProcesses), so chrome.exe shows
    // its 32 renderers whether or not any of them holds a socket this
    // second; HOW MANY connections each owns comes from the store. The view
    // module takes the merged list and knows about neither source.
    //
    // This used to aggregate the store's rows instead, which meant the tree
    // held only processes that happened to own an endpoint. The user
    // reported the result: "it always shows firefox.exe with one child but
    // not chrome.exe's 32 processes" - every chrome renderer between
    // requests owns no socket and was simply absent.
    const std::vector<ProcessRecord> machine = EnumerateProcesses(true);
    std::unordered_map<DWORD, size_t> connByPid;
    connByPid.reserve(machine.size() * 2 + 1);
    size_t totalConnections = 0;
    for (const Connection& c : store_.Rows()) {
        if ((c.flags & kRowRemoved) != 0) continue;
        ++connByPid[c.identity.pid];
        ++totalConnections;
    }
    std::vector<ProcessTreeNode> procs;
    procs.reserve(machine.size());
    for (const ProcessRecord& r : machine) {
        ProcessTreeNode n;
        n.pid = r.pid;
        n.ppid = r.ppid;
        n.ppidKnown = true;   // Toolhelp carries the parent on the entry
        n.name = r.name.empty() ? std::wstring(L"(unknown)") : r.name;
        n.processCreate = r.processCreate;
        n.processCreateKnown = r.processCreateKnown;
        auto it = connByPid.find(r.pid);
        n.connections = (it != connByPid.end()) ? it->second : 0;
        procs.push_back(std::move(n));
    }
    // Keep the exact process snapshot alive: tree items store indices into
    // this copy, including processes that have no connection row.
    treeProcs_ = procs;

    bool depthExceeded = false;
    const size_t count = ProcessTreeFill(hwndTree_, procs, &depthExceeded);
    RestoreProcessTreeViewState(hwndTree_, procs, previousTreeState);
    if (previousTreeState.caret.has_value() &&
        FindProcessTreeInstance(procs, *previousTreeState.caret) == nullptr) {
        ::SendMessageW(hwndTree_, TVM_SELECTITEM, TVGN_CARET, 0);
        SelectViewRowForProcess(*previousTreeState.caret);
    }
    // What the fill actually drew, and how many processes it drew FROM. The
    // second number is what a check compares the tree with: enumerating
    // again would be a second, later snapshot of a machine that keeps
    // changing, so "the tree has one more item than the machine" was a
    // process that started between the two calls rather than a defect.
    treeItemsAtFill_ = count;
    treeEnumeratedAtFill_ = procs.size();
    // The fill preselects the first root; map that caret to a list SELECTION
    // here, so the mode opens with something selected - the status bar, the
    // context menu and every row command have a row to act on from the first
    // frame rather than after the user clicks. Mirrors what TVN_SELCHANGED
    // does for every later caret move.
    {
        const HTREEITEM caret = reinterpret_cast<HTREEITEM>(
            ::SendMessageW(hwndTree_, TVM_GETNEXTITEM, TVGN_CARET, 0));
        if (caret != nullptr) {
            TVITEMW it = {};
            it.mask = TVIF_PARAM | TVIF_HANDLE;
            it.hItem = caret;
            if (::SendMessageW(hwndTree_, TVM_GETITEMW, 0,
                               reinterpret_cast<LPARAM>(&it))) {
                const ProcessTreeNode* process =
                    TreeProcessForItemData(it.lParam);
                if (process != nullptr) SelectViewRowForProcess(*process);
            }
        }
    }
    std::wstring text = std::to_wstring(count) + L" processes, " +
                        std::to_wstring(totalConnections) + L" connections";
    if (depthExceeded)
        text += L"  \u2022  very deep chain: some nodes omitted";
    // an empty tree names its next action, like the other windows. The
    // machine reporting no processes is a snapshot failure, not an idle
    // machine, so the action is Refresh rather than "check the table".
    if (count == 0)
        text = L"No processes \u2014 the machine reports none. Press "
               L"Refresh, then try the tree again.";
    treeSummary_ = text;
    UpdateStatusBar(lastError_);
}

bool MainWindow::SelectViewRowForProcess(const ProcessTreeNode& process) {
    if (list_.Handle() == nullptr) return false;
    LVITEMW clear = {};
    clear.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE, static_cast<WPARAM>(-1),
                   reinterpret_cast<LPARAM>(&clear));
    if (process.pid == 0 || !process.processCreateKnown) return false;
    // The VIEW, not the rows: the command handlers read the selection through
    // store_.ViewRow(item), so a row outside a filtered view must not be
    // selected - it would make every command act on something the user
    // cannot see.
    const std::optional<size_t> viewIdx =
        FindProcessTreeViewRow(store_.Rows(), store_.View(), process);
    if (!viewIdx.has_value()) return false;
    LVITEMW st = {};
    st.mask = LVIF_STATE;
    st.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE, static_cast<WPARAM>(-1),
                   reinterpret_cast<LPARAM>(&st));
    LVITEMW sel = {};
    sel.mask = LVIF_STATE;
    sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    sel.state = LVIS_SELECTED | LVIS_FOCUSED;
    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE,
                   static_cast<WPARAM>(*viewIdx),
                   reinterpret_cast<LPARAM>(&sel));
    ::SendMessageW(list_.Handle(), LVM_ENSUREVISIBLE,
                   static_cast<WPARAM>(*viewIdx),
                   FALSE);
    return true;
}

const ProcessTreeNode* MainWindow::TreeProcessForItemData(LPARAM itemData) const {
    return ProcessTreeNodeForItemData(treeProcs_, itemData);
}

void MainWindow::ShowDetailsForTreeItemData(LPARAM itemData) {
    const ProcessTreeNode* process = TreeProcessForItemData(itemData);
    if (process == nullptr) return;
    if (SelectViewRowForProcess(*process)) {
        ShowDetailsOfSelectedRow();
        return;
    }
    Connection captured = {};
    captured.identity.pid = process->pid;
    captured.display.processName = process->name;
    captured.procMeta.processCreate = process->processCreate;
    captured.procMeta.processCreateKnown = process->processCreateKnown;
    detailsPid_ = captured.identity.pid;
    detailsProcessCreate_ = process->processCreate;
    detailsProcessCreateKnown_ = process->processCreateKnown;
    detailsExitedNoted_ = false;
    detailsModel_ = BuildDetails(captured);
    details_.SetDark(ThemeIsDark());
    details_.Show(hwnd_, font_, detailsModel_, std::wstring());
}

void MainWindow::UpdateTrayTip() {
    // the tray tip names what the window holds, so the icon is
    // identifiable without restoring it. Static text ("WinTCP - TCP/UDP
    // Connections") said nothing about rows, frozen/grouped modes or
    // alerts - the three states a user minimizes over and forgets.
    if (!tray_.IsShown() || hwnd_ == nullptr) return;
    if (!DllAvailable("shell32.dll")) return;
    const RowStats& st = store_.Stats();
    wchar_t tip[128] = {0};
    ::swprintf_s(tip, L"WinTCP - %zu shown / %zu", store_.View().size(),
                 st.total);
    std::wstring extra;
    if (groupByProcess_) extra += L", grouped";
    if (frozen_) extra += L", frozen";
    if (!alertHint_.empty()) extra += L", alert";
    if (!extra.empty()) {
        // Truncation-safe: swprintf_s truncates rather than overruns, and
        // szTip is 128 wchar_t, so the worst case is a shortened suffix.
        ::wcscat_s(tip, extra.c_str());
    }
    tray_.SetTip(tip);
}

void MainWindow::InitTooltips() {
    // the control bar had no tooltips and no accessible names - only
    // the filter edit's cue banner said anything. One tooltip control
    // serves the whole bar; each tool is a (control, text) pair added
    // once, because the bar's children live as long as the window.
    if (hwndTip_ != nullptr || hwnd_ == nullptr) return;
    hwndTip_ = ::CreateWindowExW(0, TOOLTIPS_CLASSW, nullptr,
                                 WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                 CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                                 CW_USEDEFAULT, hwnd_, nullptr, hInstance_,
                                 nullptr);
    if (hwndTip_ == nullptr) return;
    const struct {
        HWND* ctl;
        const wchar_t* text;
    } tools[] = {
        {&hwndRefreshBtn_, L"Refresh now (F5)"},
        {&hwndExportBtn_, L"Export the table to CSV/TSV/JSON (Ctrl+E)"},
        {&hwndAutoChk_, L"Refresh automatically on a timer"},
        {&hwndIntervalCbo_, L"Auto-refresh interval"},
        {&hwndProtoCbo_, L"Show only this protocol family"},
        {&hwndStateCbo_, L"Show only connections in this state"},
        {&hwndSearchEdit_,
         L"Filter the table: text, port:443, pid:1234 (Ctrl+F to focus)"},
    };
    for (const auto& t : tools) {
        if (t.ctl == nullptr || *t.ctl == nullptr) continue;
        TOOLINFOW ti = {};
        ti.cbSize = sizeof(ti);
        ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
        ti.hwnd = hwnd_;
        ti.uId = reinterpret_cast<UINT_PTR>(*t.ctl);
        ti.lpszText = const_cast<LPWSTR>(t.text);
        ::SendMessageW(hwndTip_, TTM_ADDTOOLW, 0,
                       reinterpret_cast<LPARAM>(&ti));
    }
    // A narrow bar clips its longest label first; a generous width keeps
    // the protocol/state explanations on one line.
    ::SendMessageW(hwndTip_, TTM_SETMAXTIPWIDTH, 0, 400);
}

void MainWindow::UpdateStatusTips() {
    // only pane 5 ever had a tooltip. Every pane now explains
    // itself; panes whose text already says everything get a short
    // label rather than an echo, so the tip adds rather than repeats.
    if (hwndStatus_ == nullptr) return;
    ::SendMessageW(hwndStatus_, SB_SETTIPTEXTW, 0,
                   reinterpret_cast<LPARAM>(L"Rows shown / total, by family"));
    ::SendMessageW(hwndStatus_, SB_SETTIPTEXTW, 1,
                   reinterpret_cast<LPARAM>(L"Connections by TCP state"));
    ::SendMessageW(hwndStatus_, SB_SETTIPTEXTW, 2,
                   reinterpret_cast<LPARAM>(
                       L"Last completed refresh (F5 refreshes now)"));
    ::SendMessageW(hwndStatus_, SB_SETTIPTEXTW, 3,
                   reinterpret_cast<LPARAM>(L"Selected rows"));
    ::SendMessageW(hwndStatus_, SB_SETTIPTEXTW, 4,
                   reinterpret_cast<LPARAM>(
                       L"View age; countdown to the next auto-refresh"));
}

void MainWindow::ResetLayout() {
    // the persisted layout (mask/order/widths/sort/filter) has no
    // recovery path short of the registry. Reset restores every default
    // the startup path uses, then persists through the same single write
    // path so the fix survives a restart.
    cols_.Reset();
    store_.SetSort(COL_PID, true);
    if (hwndSearchEdit_ != nullptr) ::SetWindowTextW(hwndSearchEdit_, L"");
    filterDebounceText_.clear();
    if (hwndProtoCbo_ != nullptr)
        ::SendMessageW(hwndProtoCbo_, CB_SETCURSEL, 0, 0);
    if (hwndStateCbo_ != nullptr)
        ::SendMessageW(hwndStateCbo_, CB_SETCURSEL, 0, 0);
    SyncColumnMenuChecks();
    RebuildColumns();
    ApplyView();
    UpdateCaption();
    // The geometry writes its own three settings keys, so the reset and the
    // save cannot disagree about which is the mask and which is the order.
    cols_.SaveToSettings(&settings_);
    settings_.colOrderValid = true;
    settings_.sortCol = COL_PID;
    settings_.sortAsc = true;
    settings_.filter[0] = L'\0';
    PersistSettings("reset-layout");
    UpdateStatusBar(L"Columns and layout reset to defaults.");
}

void MainWindow::UpdateStatusBar(const std::wstring& errorText) {
    // recompute the exposure badge here rather than at each
    // UpdateStatusBar call site. This function runs on every debounced
    // keystroke via ApplyView() and once a second from OnTimer, so the
    // badge stays current without a timer of its own - and no caller has to
    // remember to call it.
    UpdateExposure();
    // Counts come from the snapshot pass, not from rescanning every row -
    // this runs on every debounced keystroke via ApplyView().
    const RowStats& st = store_.Stats();
    wchar_t statusText[320] = {0};
    // A live state breakdown is what an analyst actually reads off the bar;
    // listing every state that happens to be non-zero keeps it quiet on an
    // idle machine and informative on a busy one.
    ::swprintf_s(statusText, L"%zu shown / %zu  ·  v4 %zu · v6 %zu · UDP %zu",
                 store_.View().size(), st.total, st.ipv4, st.ipv6, st.udp);
    std::wstring states;
    for (DWORD s : {static_cast<DWORD>(MIB_TCP_STATE_ESTAB),
                    static_cast<DWORD>(MIB_TCP_STATE_LISTEN),
                    static_cast<DWORD>(MIB_TCP_STATE_TIME_WAIT),
                    static_cast<DWORD>(MIB_TCP_STATE_CLOSE_WAIT),
                    static_cast<DWORD>(MIB_TCP_STATE_SYN_SENT)}) {
        const size_t n = st.StateCount(s);
        if (n == 0) continue;
        if (!states.empty()) states += L" · ";
        states += TcpStateToString(s);
        states += L" ";
        states += std::to_wstring(n);
    }
    if (!states.empty()) states += L"  ·  ";
    states += L"UDP ";
    states += std::to_wstring(st.udp);
    if (st.secure != 0) {
        states += L"  ·  TLS ";
        states += std::to_wstring(st.secure);
    }
    if (st.pinned != 0) {
        states += L"  ·  ★ ";
        states += std::to_wstring(st.pinned);
    }
    if (!filterError_.empty())
        states = L"Filter syntax: " + ToLowerW(filterError_) +
                 L" (literal fallback active)";
    // A visible traffic column with no source running renders
    // as a wall of "—". Say so instead of leaving the columns silently
    // empty; real errors keep priority. Three states:
    //   * ETW session running        -> "Ready" (full fidelity, UDP too)
    //   * socket fallback active     -> brief "TCP only" note + tooltip
    //   * nothing can run            -> the admin hint
    // Pane 2 is only ~170px wide (OnSize), so keep the labels short and
    // put the actionable detail in the pane's tooltip.
    const bool trafficColShown = AnyTrafficColVisible();
    const bool fallbackActive =
        trafficColShown && !etw_->Running() && fallbackFlag_->load();
    const bool trafficBlocked = trafficColShown && !etw_->Running() &&
                                !fallbackFlag_->load();
    // what the traffic scan could not measure, said where the traffic
    // columns are. A blank traffic cell means three different things and the
    // reader could previously not tell them apart - the connection moved no
    // bytes, the row was unmeasurable, or the SCAN FAILED. Only the third is
    // actionable, so it gets the pane.
    //
    // Both counters are 0 on a healthy machine, so this is silent until it is
    // not, which is the point of a status pane. Failure outranks staleness
    // because a failed pass measured nothing while a dropped pass kept the
    // previous totals - and "nothing" is the worse of the two to trust.
    const unsigned scanGaps =
        (socketTraffic_ != nullptr) ? socketTraffic_->ScanFailureCount() : 0u;
    const unsigned staleGaps =
        (socketTraffic_ != nullptr) ? socketTraffic_->TimeoutCount() : 0u;
    // name the traffic source in the status bar. "Ready" alone does not
    // distinguish a full ETW session (TCP+UDP, kernel-level) from a socket
    // fallback (TCP only, per-socket ioctl) - two very different fidelity levels
    // that the rest of the pane already distinguishes (see fallbackActive).
    std::wstring right =
        !errorText.empty()      ? (L"Error: " + errorText)
        : scanGaps != 0         ? L"Traffic FAILED"
        : staleGaps != 0        ? L"Traffic stale"
        : fallbackActive        ? L"TCP only - UDP needs admin"
        : trafficBlocked        ? L"Traffic off - needs admin"
                                 : etw_->Running()        ? L"Ready (ETW)"
                                : L"Ready";
    if (errorText.empty() && !copyFeedback_.empty() &&
        ::GetTickCount64() < copyFeedbackUntil_) {
        right += L"  ·  ";
        right += copyFeedback_;
    }
    // append the DNS-stall hint so a user knows some Host cells show
    // `pending` rather than `—`.
    // the empty-state strip. One sentence per case, and the sentence is the
    // ACTION rather than a description of a blank - "no country database loaded -
    // pick one in View > GeoIP database", not "Country: empty".
    //
    // Recomputed from live state every second by OnTimer through this same
    // function, so there is no timer to write and nothing to clean up. That is
    // the shape dnsStalledHint_ already uses and the only time-scoped message
    // channel the window has: there is no toolbar and no WM_PAINT hook in this
    // window, so a banner over the list would be new chrome rather than a reuse.
    // Same channel and same shape as the empty-state hint beside it, and
    // deliberately NOT stored: nothing about an alert survives a refresh, so a
    // cleared alert stops being reported without anyone removing it.
    if (!alertHint_.empty()) {
        if (!right.empty()) right += L"  ·  ";
        right += alertHint_;
    }
    if (!emptyStateHint_.empty()) {
        if (!right.empty()) right += L"  ";
        right += emptyStateHint_;
    }

    // the exposure badge. Recipe 24's red case - a listener on a
    // wildcard address and a privileged port - needs a surface that is not a
    // column, because COL_COUNT is exactly 32 and a 33rd requires the
    // eight-part UINT64 mask change the architecture note forbids arriving
    // as a side effect. The status bar costs nothing and cannot break the
    // mask, so the badge lives here, after the traffic and empty-state
    // messages that answer "is the tool working" and before anything that
    // would bury it.
    //
    // Silent on a healthy machine: loopback and RFC1918 listeners are the
    // default state of a Windows box, and a badge that fires on every
    // svchost teaches users to ignore the bar. Failure outranks everything
    // on this bar because a misreport is worse than a silence.
    if (exposureLine_.empty() == false) {
        if (!right.empty()) right += L"  ·  ";
        right += exposureLine_;
    }

    // while frozen, pane 2 must say so AND say how stale it is. Showing
    // the pre-freeze "Updated: 14:32:05" on its own would be a lie - it reads
    // as current, and the user has no way to tell the list is not updating.
    // FROZEN takes priority over the timestamp for exactly that reason.
    std::wstring mid;
    if (refreshInFlight_ && !frozen_) {
        // a request is outstanding and no result has arrived yet. A
        // slow enum or a DNS stall otherwise looks exactly like idle, so
        // the bar says what the worker is doing instead of its last age.
        mid = L"Refreshing...";
    } else if (frozen_) {
        // FrozenAgeMs returns MILLISECONDS; FormatDuration takes seconds.
        // Dividing is not enough on its own: a view frozen for 900 ms would
        // render "0s", indistinguishable from one frozen for 0 ms, so a
        // sub-second freeze reads as no freeze at all. Show "<1s" instead.
        const ULONGLONG age = FrozenAgeMs(frozenAt_, ::GetTickCount64());
        const std::wstring ageText =
            (age < kMsPerSecond) ? std::wstring(L"<1s")
                         : FormatDuration(age / kMsPerSecond);
        mid = L"FROZEN " + ageText + L" — F6 to resume";
    } else {
        mid = lastRefreshTime_.empty()
                  ? L"Not refreshed yet"
                  : (L"Updated: " + lastRefreshTime_);
    }
    ::SendMessageW(hwndStatus_, SB_SETTEXTW, 0,
                   reinterpret_cast<LPARAM>(statusText));
    ::SendMessageW(hwndStatus_, SB_SETTEXTW, 1,
                   reinterpret_cast<LPARAM>(states.c_str()));
    ::SendMessageW(hwndStatus_, SB_SETTEXTW, 2,
                   reinterpret_cast<LPARAM>(mid.c_str()));
    ::SendMessageW(hwndStatus_, SB_SETTEXTW, 3,
                   reinterpret_cast<LPARAM>(
                       treeMode_ ? TreeSummary().c_str()
                                 : SelectedSummary().c_str()));
    ::SendMessageW(hwndStatus_, SB_SETTEXTW, 4,
                   reinterpret_cast<LPARAM>(RefreshAgeText().c_str()));
    ::SendMessageW(hwndStatus_, SB_SETTEXTW, 5,
                   reinterpret_cast<LPARAM>(right.c_str()));
    // The tooltip is where the ACTIONABLE detail goes, because pane 5 is only
    // ~170px wide (OnSize). It puts the two gap explanations ahead of the
    // elevation ones: a machine that dropped a pass needs to know that before
    // it needs to know it should have been run elevated.
    std::wstring tip;
    if (scanGaps != 0) {
        tip = L"Traffic is UNMEASURED for this run: " + std::to_wstring(scanGaps) +
              L" scan(s) could not read the process handle table, so nothing was"
              L" merged and every traffic cell is blank rather than zero. This"
              L" is not an elevation problem and no switch fixes it - the handle"
              L" table was denied. Re-run; if it persists, something on this"
              L" machine is blocking handle enumeration.";
    } else if (staleGaps != 0) {
        tip = L"Traffic is STALE: " + std::to_wstring(staleGaps) +
              L" pass(es) were dropped because a socket's SIO_TCP_INFO never"
              L" returned. The counters shown are the last values that were"
              L" read, not current ones. Closing the owning connection usually"
              L" clears it - the sockets are remembered, so no later pass wastes"
              L" a worker on them again.";
    } else if (fallbackActive) {
        tip = L"TCP totals are read per-socket (SIO_TCP_INFO) - no elevation"
              L" needed. UDP rows stay \"-\": run WinTCP as administrator and"
              L" enable View > Per-PID traffic counters for the full ETW"
              L" session (TCP+UDP).";
    } else if (trafficBlocked) {
        tip = L"Per-PID traffic counters need elevation: run WinTCP as"
              L" administrator (View > Per-PID traffic counters).";
    }
    // Empty tip means "nothing to add", which is what the old ternary's 0
    // meant; setting an empty string instead would create an empty tooltip
    // balloon on every healthy refresh.
    ::SendMessageW(hwndStatus_, SB_SETTIPTEXTW, 5,
                    tip.empty() ? 0 : reinterpret_cast<LPARAM>(tip.c_str()));
    // every pane explains itself; the tray icon says what the
    // window holds. Both are refreshed with the bar so they never go stale.
    UpdateStatusTips();
    UpdateTrayTip();
}

std::wstring MainWindow::SelectedSummary() const {
    // Counted with one LVM_GETSELECTEDCOUNT rather than walking the
    // selection: a multi-row selection on a 50k virtual list must not cost
    // a round trip per selected row on every status-bar refresh.
    const LRESULT n = ::SendMessageW(list_.Handle(), LVM_GETSELECTEDCOUNT, 0, 0);
    if (n <= 0) return L"no selection";
    if (n == 1) return L"1 selected";
    wchar_t buf[48] = {0};
    ::swprintf_s(buf, L"%lld selected", static_cast<long long>(n));
    return buf;
}

std::wstring MainWindow::RefreshAgeText() const {
    if (lastRefreshTick_ == 0) return L"—";
    const ULONGLONG ageSec =
        (::GetTickCount64() - lastRefreshTick_) / kMsPerSecond;
    wchar_t buf[64] = {0};
    if (autoRefresh_) {
        // Countdown to the next tick, derived from the interval timer that
        // is already running - no second timer and no drift of its own.
        const ULONGLONG nextDue = lastRefreshTick_ + autoRefreshMs_;
        const ULONGLONG now = ::GetTickCount64();
        const ULONGLONG inSec = (nextDue > now) ? (nextDue - now) / kMsPerSecond : 0;
        ::swprintf_s(buf, L"%llus old · next in %llus",
                     ageSec, inSec);
    } else {
        ::swprintf_s(buf, L"%llus old", ageSec);
    }
    return buf;
}

// ---------------------------------------------------------------------------
// notifications ---------------------------------------------------------------

void MainWindow::OnCommand(WORD id, WORD notifyCode, HWND ctl) {
    switch (id) {
        case IDC_BTN_REFRESH:
            if (notifyCode == BN_CLICKED) Refresh(true);
            break;
        case IDM_FILE_REFRESH:
        case IDM_CTX_REFRESH:
            Refresh(true);
            break;
        case IDC_BTN_EXPORT:
            if (notifyCode == BN_CLICKED) ExportCsv();
            break;
        case IDM_FILE_EXPORT:
            ExportCsv();
            break;
        case IDC_CHK_AUTOREFRESH:
            if (notifyCode == BN_CLICKED) {
                autoRefresh_ = (::SendMessageW(hwndAutoChk_, BM_GETCHECK, 0, 0) ==
                                BST_CHECKED);
                SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_AUTOREFRESH, autoRefresh_);
                if (autoRefresh_) {
                    ::SetTimer(hwnd_, kRefreshTimerId, autoRefreshMs_, nullptr);
                    Refresh(false);
                } else {
                    ::KillTimer(hwnd_, kRefreshTimerId);
                }
            }
            break;
        case IDC_CBO_INTERVAL:
            if (notifyCode == CBN_SELCHANGE) {
                const LRESULT sel = ::SendMessageW(hwndIntervalCbo_, CB_GETCURSEL, 0, 0);
                LRESULT ms = static_cast<LRESULT>(kDefaultIntervalMs);
                if (sel != CB_ERR)
                    ms = ::SendMessageW(hwndIntervalCbo_, CB_GETITEMDATA,
                                        static_cast<WPARAM>(sel), 0);
                autoRefreshMs_ = (ms == CB_ERR || ms <= 0) ? kDefaultIntervalMs
                                                           : static_cast<UINT>(ms);
                if (autoRefresh_)
                    ::SetTimer(hwnd_, kRefreshTimerId, autoRefreshMs_, nullptr);
            }
            break;
        case IDC_CBO_PROTO:
        case IDC_CBO_STATE:
            if (notifyCode == CBN_SELCHANGE) ApplyView();
            break;
        case IDC_EDIT_SEARCH:
            if (notifyCode == EN_CHANGE) {
                // Debounce keystrokes.
                ::KillTimer(hwnd_, kFilterTimerId);
                ::SetTimer(hwnd_, kFilterTimerId, kFilterDebounceMs, nullptr);
            }
            break;
        case IDM_FILE_EXIT:
            ::DestroyWindow(hwnd_);
            break;
        case IDM_VIEW_AUTOREFRESH: {
            autoRefresh_ = !autoRefresh_;
            ::SendMessageW(hwndAutoChk_, BM_SETCHECK,
                           autoRefresh_ ? BST_CHECKED : BST_UNCHECKED, 0);
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_AUTOREFRESH, autoRefresh_);
            if (autoRefresh_) {
                ::SetTimer(hwnd_, kRefreshTimerId, autoRefreshMs_, nullptr);
                Refresh(false);
            } else {
                ::KillTimer(hwnd_, kRefreshTimerId);
            }
            break;
        }
        case IDM_FILE_CHANGELOG_WIN:
            // Toggle rather than always-open: a second click closes it, which
            // is what a menu item named after a window should do. Show() is
            // idempotent and re-raises an already-open window, so this only
            // has to decide between opening and closing.
            if (changeLog_.IsOpen()) {
                changeLog_.Close();
            } else {
                changeLog_.Show(hwnd_, font_);
            }
            break;
        case IDM_FILE_PRESET_SAVE:
            SavePreset();
            break;
        case IDM_FILE_PRESET_LOAD:
            LoadPreset();
            break;
        case IDM_FILE_PRESET_DELETE:
            DeletePreset();
            break;
        case IDM_FILE_BOOKMARKS:
            ShowBookmarksList();
            break;
        case IDM_CTX_BOOKMARK:
            BookmarkSelectedConnection();
            break;
        case IDM_CTX_NOTE:
            EditSelectedBookmarkNote();
            break;
        case IDM_HELP_ABOUT:
            ShowAboutBox();
            break;
        case IDM_HELP_SHORTCUTS:
            ShowShortcutsSheet();
            break;
        case IDM_CTX_COPY_SELECTED:
            CopySelectionToClipboard(false);
            break;
        case IDM_CTX_COPY_ALL:
            CopySelectionToClipboard(true);
            break;
        case IDM_CTX_COPY_REMOTE_IP:
            CopyFieldToClipboard(ConnectionsList::CopyField::RemoteIp);
            break;
        case IDM_CTX_COPY_HOSTNAME:
            CopyFieldToClipboard(ConnectionsList::CopyField::Hostname);
            break;
        case IDM_CTX_COPY_LOCAL_ENDPOINT:
            CopyFieldToClipboard(ConnectionsList::CopyField::LocalEndpoint);
            break;
        case IDM_CTX_COPY_REMOTE_ENDPOINT:
            CopyFieldToClipboard(ConnectionsList::CopyField::RemoteEndpoint);
            break;
        case IDM_CTX_COPY_LOCAL_PORT:
            CopyFieldToClipboard(ConnectionsList::CopyField::LocalPort);
            break;
        case IDM_CTX_COPY_REMOTE_PORT:
            CopyFieldToClipboard(ConnectionsList::CopyField::RemotePort);
            break;
        case IDM_CTX_COPY_PROCESS_PATH:
            CopyFieldToClipboard(ConnectionsList::CopyField::ProcessPath);
            break;
        case IDM_CTX_COPY_PROCESS_ID:
            CopyFieldToClipboard(ConnectionsList::CopyField::ProcessId);
            break;
        case IDM_CTX_DETAILS:
            ShowDetailsOfSelectedRow();
            break;
        case IDM_CTX_KILL_PROCESS:
            KillSelectedProcess();
            break;
        case IDM_CTX_CLOSE_CONNECTION:
            CloseSelectedConnection();
            break;
        case IDM_FOLLOW_STREAM:
            // REMOVED 2026-10-05: this case is unreachable - the menu entry
            // that sent IDM_FOLLOW_STREAM is gone (see OnContextMenu). Kept as
            // a comment rather than deleted so the removal is reversible and so
            // anyone re-adding the entry finds this note. The capability itself
            // was NOT lost: it is the `capture` verb, which now prints the
            // reassembled stream to stdout (--text) and can write the capture
            // out as pcapng (--out). The GUI form
            // was not salvageable: it re-elevated the whole application, then
            // blocked modally on a sampling capture that can legitimately come
            // back empty.
            // FollowSelectedStream();
            break;
        case IDM_OPEN_FILE_LOCATION:
            OpenSelectedFileLocation();
            break;
        // REMOVED 2026-10-05: IDM_PROCESS_PROPERTIES / ShowSelectedProcessProperties.
        // See the note in OnContextMenu for why the verb was removed rather than
        // repaired.
        // case IDM_PROCESS_PROPERTIES:
        //     ShowSelectedProcessProperties();
        //     break;
        case IDM_BLOCK_CONNECTION:
            // BlockSelectedConnection() writes firewall rules, which need
            // an elevated token. If the user is an admin who is not elevated,
            // hand off to Reelevate() (this call exits the old process) - now a
            // live caller. If the account cannot elevate at all, show why and
            // do not attempt the block (it would fail inside BlockConn anyway).
            if (!IsElevated()) {
                if (IsAdminMember() && Reelevate(L"Block connection")) return;
                const std::wstring reason = ElevationUnavailableReason();
                ::MessageBoxW(hwnd_, reason.c_str(), L"WinTCP - Blocked requires elevation",
                              MB_OK | MB_ICONINFORMATION);
                return;
            }
            BlockSelectedConnection();
            break;
        case IDM_TRAY_UNBLOCK_ALL:
            RemoveAllWinTcpBlocks();
            break;
        case IDM_VIEW_RESOLVE: {
            dnsEnabled_ = !dnsEnabled_;
            enrich_.SetDnsEnabled(dnsEnabled_);
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_RESOLVE, dnsEnabled_);
            if (dnsEnabled_) OfferDnsForAllRows();
            break;
        }
        case IDM_VIEW_PRESERVE_SEL:
            preserveSelection_ = !preserveSelection_;
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_PRESERVE_SEL,
                         preserveSelection_);
            break;
        case IDM_VIEW_ASNIP:
            LoadAsnDatabase();
            break;
        // The quick filters write the box and let the debounce do the
        // work, so there is exactly one code path from a click to a filtered
        // view - the same one typing uses. Going straight to ApplyView here
        // would skip the EN_CHANGE path and leave the two able to disagree.
        case IDM_QFILTER_ALL:
        case IDM_QFILTER_TCP:
        case IDM_QFILTER_UDP:
        case IDM_QFILTER_LISTEN:
        case IDM_QFILTER_ESTAB:
        case IDM_QFILTER_MINE:
            ApplyQuickFilter(static_cast<int>(id));
            break;
        case IDM_QFILTER_CLEAR:
            FocusFilterBox();
            break;
        // .
        case IDM_PROFILE_DEFAULT:
        case IDM_PROFILE_MINIMAL:
        case IDM_PROFILE_NETWORK:
        case IDM_PROFILE_SECURITY:
        case IDM_PROFILE_PERFORMANCE:
        case IDM_PROFILE_DIAGNOSTICS:
            ApplyColumnProfile(static_cast<int>(id));
            break;
        case IDM_VIEW_GEOIP:
            LoadGeoIpDatabase();
            break;
        case IDM_VIEW_BLOCKED: {
            // Read-only unless the user edits, so it does not
            // touch the view's state: a list that could change the rows would
            // have to say so, and the whole point of this dialog is that it
            // only affects the firewall. It stays open across edits now, so
            // the caller hears once, at the end, about what changed.
            std::wstring failure;
            const BlockedPeersChoice choice =
                ShowBlockedPeersDialog(hwnd_, &failure);
            if (choice == BlockedPeersChoice::kRefused) {
                UpdateStatusBar(failure.empty() ? L"could not list the firewall rules."
                                                : failure);
                ::MessageBoxW(hwnd_, failure.c_str(), L"WinTCP",
                              MB_OK | MB_ICONERROR);
                break;
            }
            // kChanged means at least one rule was deleted, enabled or
            // disabled. The dialog already re-read the firewall, so the count
            // on the status bar is only approximate; say what happened rather
            // than restating a number that may now be stale.
            if (choice == BlockedPeersChoice::kChanged) {
                UpdateStatusBar(L"Firewall rules changed. `blocks` re-counts them.");
            }
            break;
        }
        case IDM_VIEW_FIX_EMPTY:
            // DecideEmptyState answers both halves: whether there is
            // anything to fix, and what the buttons are. "Nothing to fix" is a
            // real answer here, not a failure - it is what "why is my table
            // empty" deserves when the table is empty for a legitimate reason.
            ShowEmptyStateActions();
            break;
        case IDM_VIEW_RESET_LAYOUT:
            // persisted layout, one click back to defaults.
            ResetLayout();
            break;
        case IDM_VIEW_FREEZE:
            frozen_ = !frozen_;
            // Stamped from GetTickCount64 (a monotonic counter), not from
            // wall-clock time, so a clock change cannot make the frozen age
            // jump or run backwards.
            frozenAt_ = frozen_ ? ::GetTickCount64() : 0;
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_FREEZE, frozen_);
            UpdateStatusBar(std::wstring());
            UpdateCaption();
            break;
        case IDM_VIEW_GROUP:
            groupByProcess_ = !groupByProcess_;
            store_.SetGrouped(groupByProcess_);
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_GROUP, groupByProcess_);
            // The view is rebuilt from the same rows either way, so this is
            // safe to do mid-selection: the row ids are unchanged and
            // RestoreSelection puts the user's row back.
            ApplyView();
            break;
        case IDM_FILE_CHANGELOG:
            ToggleChangeLog();
            break;
        case IDM_CTX_EXPORT_SELECTION:
            DoExport(true);
            break;
        case IDM_EDIT_SELECTALL:
            list_.SelectAll();
            break;
        case IDM_EDIT_FOCUSFILTER:
            FocusFilterBox();
            break;
        case IDM_EDIT_CLEARFILTER:
            ClearFilterBox();
            break;
        case IDM_VIEW_TOPMOST:
            topMost_ = !topMost_;
            settings_.topMost = topMost_;
            SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TOPMOST, topMost_);
            ::SetWindowPos(hwnd_, topMost_ ? HWND_TOPMOST : HWND_NOTOPMOST,
                           0, 0, 0, 0,
                           SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            break;
case IDM_VIEW_TRAY:
    trayEnabled_ = !trayEnabled_;
    settings_.trayEnabled = trayEnabled_;
    settings_.trayMinimizeChoice = trayMinimizeChoice_;
    // SyncTray does the add/remove and the check mark in one place, so the
    // menu tick and the icon cannot disagree.
    SyncTray();
    break;
        case IDM_TRAY_RESTORE:
            ::ShowWindow(hwnd_, SW_RESTORE);
            ::SetForegroundWindow(hwnd_);
            break;
        case IDM_VIEW_TRAFFIC: {
            // Toggle the ETW per-PID traffic counters.
            if (etw_->Running()) {
                etw_->Stop();
                settings_.trafficEnabled = false;
                // The user asked to stop counting: the non-admin fallback
                // must not silently keep feeding the columns either.
                fallbackFlag_->store(false);
                SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAFFIC, false);
                store_.ClearTraffic();
                ApplyView();
            } else {
                // starting a full ETW session needs elevation. If the user
                // is an admin who is not currently elevated, hand off to Reelevate()
                // (this call exits the old process - the new, elevated one resumes
                // here from settings_.trafficEnabled) rather than letting Start()
                // fail noisily below. A standard account shows the reason instead.
                if (!IsElevated()) {
                    if (IsAdminMember() && Reelevate(L"Traffic counters")) return;
                    const std::wstring reason = ElevationUnavailableReason();
                    ::MessageBoxW(hwnd_, reason.c_str(),
                                  L"WinTCP - Traffic counters require elevation",
                                  MB_OK | MB_ICONINFORMATION);
                    return;
                }
                std::wstring etwError;
                if (etw_->Start(etwError)) {
                    settings_.trafficEnabled = true;
                    fallbackFlag_->store(false);   // ETW authoritative
                    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAFFIC, true);
                    Refresh(false);        // pick counters up promptly
                } else {
                    // Graceful fallback: explain, keep the app running.
                    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAFFIC, false);
                    if (fallbackFlag_->load()) {
                        etwError +=
                            L"\r\n\r\nNote: per-socket TCP totals are already "
                            L"being collected\r\nwithout administrator rights "
                            L"- only UDP (and the\r\nfull-fidelity session) "
                            L"need elevation.";
                    }
                    ::MessageBoxW(hwnd_, etwError.c_str(),
                                  L"WinTCP - Traffic counters",
                                  MB_OK | MB_ICONWARNING);
                }
            }
            break;
        }
        case IDM_VIEW_CHARTS: {
            // toggle the performance graphs window.
            if (charts_.IsVisible()) {
                charts_.Close();
                SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_CHARTS, false);
            } else {
                charts_.Show(hwnd_, ThemeIsDark());
                SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_CHARTS, true);
            }
            break;
        }
        case IDM_VIEW_PROCESSTREE: {
            // the process-tree view mode. A tree control where the
            // list view is - Task Manager's Processes tab - rather than a
            // second window holding the same information. Toggle, like
            // group-by-process, with its own check mark on the menu.
            ToggleTreeMode();
            break;
        }
        default:
            if (id >= IDM_COL_BASE && id < IDM_COL_BASE + IDM_COL_COUNT)
                ToggleColumn(static_cast<int>(id - IDM_COL_BASE));
            break;
    }
    (void)ctl;
}

void MainWindow::OnNotify(NMHDR* hdr, LPARAM /*lParam*/) {
    if (hdr == nullptr) return;
    // in tree mode the tree is the surface, so its notifications
    // route here too. Everything the tree needs resolves to a list selection
    // first (SelectViewRowForProcess), which is what keeps the command handlers
    // free of tree knowledge.
    if (hdr->hwndFrom == hwndTree_) {
        if (!treeMode_) return;
        switch (hdr->code) {
            case NM_DBLCLK:
            case NM_RETURN: {
                HTREEITEM item = reinterpret_cast<HTREEITEM>(
                    ::SendMessageW(hwndTree_, TVM_GETNEXTITEM, TVGN_CARET, 0));
                if (item == nullptr) break;
                TVITEMW it = {};
                it.mask = TVIF_PARAM | TVIF_HANDLE;
                it.hItem = item;
                if (::SendMessageW(hwndTree_, TVM_GETITEMW, 0,
                                   reinterpret_cast<LPARAM>(&it)))
                    ShowDetailsForTreeItemData(it.lParam);
                break;
            }
            case NM_RCLICK: {
                // Select under the cursor first, so the menu acts on the
                // node that was clicked - the same rule the list applies at
                // LVM_HITTEST below.
                POINT cp;
                ::GetCursorPos(&cp);
                POINT local = cp;
                ::ScreenToClient(hwndTree_, &local);
                TVHITTESTINFO hti = {};
                hti.pt = local;
                HTREEITEM hit = reinterpret_cast<HTREEITEM>(
                    ::SendMessageW(hwndTree_, TVM_HITTEST, 0,
                                   reinterpret_cast<LPARAM>(&hti)));
                if (hit != nullptr &&
                    (hti.flags & (TVHT_ONITEM | TVHT_ONITEMRIGHT |
                                  TVHT_ONITEMBUTTON)) != 0) {
                    ::SendMessageW(hwndTree_, TVM_SELECTITEM, TVGN_CARET,
                                   reinterpret_cast<LPARAM>(hit));
                    TVITEMW it = {};
                    it.mask = TVIF_PARAM | TVIF_HANDLE;
                    it.hItem = hit;
                    if (::SendMessageW(hwndTree_, TVM_GETITEMW, 0,
                                       reinterpret_cast<LPARAM>(&it))) {
                        const ProcessTreeNode* process =
                            TreeProcessForItemData(it.lParam);
                        if (process != nullptr)
                            SelectViewRowForProcess(*process);
                    }
                }
                break;
            }
            case TVN_SELCHANGEDW: {
                // Every caret move - arrow keys or click - maps to a list
                // selection, which is what keeps the status bar's summary and
                // every row command pointed at the node the reader is on.
                // Without this the tree's own caret and the row the commands
                // act on would be two different things after the first
                // keypress.
                const auto* nm = reinterpret_cast<NMTREEVIEWW*>(hdr);
                if (nm->itemNew.mask & TVIF_PARAM) {
                    const ProcessTreeNode* process =
                        TreeProcessForItemData(nm->itemNew.lParam);
                    if (process != nullptr)
                        SelectViewRowForProcess(*process);
                }
                break;
            }
            default:
                break;
        }
        return;
    }
    // The list's notifications were answered by ConnectionsList (in
    // WM_NOTIFY, before this is reached), so this handler now serves only the
    // surface the window owns: the tree.
}

void MainWindow::SyncColumnOrderFromHeader() {
    // The geometry object folds the drag back into the permutation and says
    // whether it actually changed. Everything else here is the window's job:
    // persist the order, and re-apply so the visible order matches.
    if (!cols_.SyncOrderFromHeader(list_.Handle())) return;

    // Persist immediately. A reorder is an explicit user action, and losing it
    // because the app was killed afterwards would look like the feature is
    // broken. Widths are harvested first so the rebuild does not clobber the
    // layout the user just made with pre-drag widths.
    HarvestColumnWidths();
    settings_.colOrderValid = true;
    const std::vector<int>& order = cols_.Order();
    for (size_t i = 0; i < order.size() && i < COL_COUNT; ++i)
        settings_.colOrder[i] = order[i];
    PersistSettings("column reorder");
    RebuildColumns();
    ApplyView();
}

// Type-to-jump. Returns true when the keystroke was consumed.
//
// The candidate list is built from the VISIBLE rows, and the label matched
// against is the process name where there is one and the local address
// otherwise - those are the two things a user can actually see and type. A
// jump therefore lands on a row that is genuinely on screen; matching against
// a hidden column could select something the user cannot see.
bool MainWindow::OnTypeJumpChar(wchar_t ch) {
    if (list_.Handle() == nullptr) return false;
    const size_t count = store_.View().size();
    if (count == 0) return false;

    // Build candidates. Rebuilt on every keystroke rather than cached: a cache
    // would need the store's generation counter to stay in step with the
    // view, and getting that wrong would jump to a stale row. A few hundred
    // short string copies at human typing speed is not a cost worth
    // engineering around.
    std::vector<JumpCandidate> rows;
    rows.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const Connection* c = store_.ViewRow(i);
        if (c == nullptr) continue;
        JumpCandidate jc;
        jc.id = c->id;
        jc.label = !c->display.processName.empty() ? c->display.processName : c->display.localAddress;
        rows.push_back(jc);
    }
    if (rows.empty()) return false;

    const int hit = typeToJump_.Feed(ch, ::GetTickCount64(), rows);
    if (hit < 0 || hit >= static_cast<int>(rows.size())) {
        // No match: leave the selection exactly where it was. Jumping to the
        // top would be a surprising way to say "nothing matched".
        return true;   // still consumed: this keystroke is a search, not a beep
    }

    // Select and scroll, anchored on the row so it ends up visible rather than
    // just selected. LVM_ENSUREVISIBLE is enough; scrolling it to the middle
    // would fight the user's own scrolling.
    LVITEMW st = {};
    st.mask = LVIF_STATE;
    st.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE, static_cast<WPARAM>(-1),
                   reinterpret_cast<LPARAM>(&st));
    LVITEMW sel = {};
    sel.mask = LVIF_STATE;
    sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    sel.state = LVIS_SELECTED | LVIS_FOCUSED;
    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE, static_cast<WPARAM>(hit),
                   reinterpret_cast<LPARAM>(&sel));
    ::SendMessageW(list_.Handle(), LVM_ENSUREVISIBLE, static_cast<WPARAM>(hit), 0);
    ::SetFocus(list_.Handle());
    return true;
}

void MainWindow::OnTimer(UINT_PTR timerId) {
    if (timerId == kRefreshTimerId) {
        if (autoRefresh_) engine_.Request();
    } else if (timerId == kFilterTimerId) {
        ::KillTimer(hwnd_, kFilterTimerId);
        ApplyView();
    } else if (timerId == kStatusTimerId) {
        CheckRefreshWatchdog();
        // Only the age/countdown pane changes on its own, so refresh the
        // whole bar rather than tracking which panes are time-dependent.
        UpdateStatusBar(lastError_);
    }
}

// R8: refresh watchdog. Runs on the 1 s status tick; the policy (thresholds,
// verdicts) is RefreshWatchdogNext in RefreshEngine.h — this only executes.
//
// State machine: Healthy clears history (a recovered worker is forgiven).
// StaleRestart asks the worker to exit WITHOUT waiting (RequestStop — Stop()
// would block this same UI thread up to 8 s) and completes the restart over
// later ticks once the old thread is reaped. StaleGiveUp switches
// auto-refresh off loudly instead of looping restarts forever. Every branch
// preserves the invariant that the status bar never shows a live view over a
// dead worker.
void MainWindow::CheckRefreshWatchdog() {
    if (!autoRefresh_) {
        // The watchdog judges the automatic cadence only: manual refreshes
        // are user-paced by definition, and nagging about them would train
        // the user to ignore the message when it matters.
        watchdogRestarting_ = false;
        watchdogRestarts_ = 0;
        return;
    }
    const ULONGLONG now = ::GetTickCount64();
    const ULONGLONG base =
        (lastResultTick_ != 0) ? lastResultTick_ : workerStartTick_;
    if (base == 0) return;   // worker never started; nothing to judge yet
    const WatchdogAction action =
        RefreshWatchdogNext(now, base, autoRefreshMs_, watchdogRestarts_);
    if (action == WatchdogAction::Healthy) {
        if (watchdogRestarting_) {
            // A result arrived after the stop was asked: the worker was slow,
            // not dead. Cancel the stop rather than killing a live worker —
            // killing it here would inflict the frozen list this exists to
            // prevent. CancelStop runs one pass immediately, proving liveness.
            engine_.CancelStop();
        }
        watchdogRestarting_ = false;
        watchdogRestarts_ = 0;
        return;
    }
    if (action == WatchdogAction::StaleGiveUp) {
        // Terminal: restarts changed nothing. Mirror the toggle-off path
        // exactly (member, checkbox, menu, timer) so no half-state survives:
        // a dead cadence still firing Request() is the frozen list that
        // looks alive.
        watchdogRestarting_ = false;
        autoRefresh_ = false;
        ::SendMessageW(hwndAutoChk_, BM_SETCHECK, BST_UNCHECKED, 0);
        SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_AUTOREFRESH, false);
        ::KillTimer(hwnd_, kRefreshTimerId);
        wchar_t msg[kWatchdogMsgChars] = {0};
        ::swprintf_s(msg,
                     L"Auto-refresh stopped: no refresh for %llus despite %d "
                     L"worker restarts. Press Refresh to try again.",
                     (now - base) / kMsPerSecond, watchdogRestarts_);
        lastError_ = msg;
        UpdateStatusBar(lastError_);
        return;
    }
    // StaleRestart.
    if (!watchdogRestarting_) {
        watchdogRestarting_ = true;
        watchdogRestartTick_ = now;
        engine_.RequestStop();
        wchar_t msg[kWatchdogMsgChars] = {0};
        ::swprintf_s(msg,
                     L"View stale: no refresh for %llus — restarting refresh "
                     L"worker…",
                     (now - base) / kMsPerSecond);
        lastError_ = msg;
        UpdateStatusBar(lastError_);
        return;
    }
    if (engine_.ReapIfExited()) {
        // Old worker gone: start a fresh one through StartWorker wholesale
        // (sources, sink, seed), so a restarted worker is identical to a
        // first-started one — including a fresh watchdog seed, which grants
        // the full threshold before anything is judged again.
        StartWorker();
        ++watchdogRestarts_;
        return;
    }
    // Restart asked but the old worker still lives. Past another full
    // threshold the stop itself has failed (thread in kernel): spend one
    // restart from the cap and re-arm, so the cap still converges instead of
    // waiting on a thread that will never exit.
    if (RefreshWatchdogNext(now, watchdogRestartTick_, autoRefreshMs_, 0) !=
        WatchdogAction::Healthy) {
        ++watchdogRestarts_;
        watchdogRestarting_ = false;
    }
}

void MainWindow::OnContextMenu(HWND target, int x, int y) {
    // the tree is a valid target in tree mode - NM_RCLICK above
    // already selected its node, so nothing on the list needs hit-testing.
    if (target != list_.Handle() && target != hwndTree_) return;
    POINT pt = {x, y};

    if (x != -1 || y != -1) {
        if (target == hwndTree_) {
            // Keyboard-free path: the node was selected on NM_RCLICK, and
            // the menu is built from the list selection that selection made.
            // Keyboard invocation on the tree comes through the branch below
            // with (-1, -1), so there is nothing to anchor here.
        } else {
            // Mouse invocation: select the row under the cursor first,
            // otherwise Details/Copy/Close would act on an unrelated selection.
            POINT cp = pt;
            ::ScreenToClient(list_.Handle(), &cp);
            LVHITTESTINFO hti = {};
            hti.pt = cp;
            const int hit = static_cast<int>(::SendMessageW(
                list_.Handle(), LVM_HITTEST, 0, reinterpret_cast<LPARAM>(&hti)));
            if (hit >= 0) {
                const UINT selected = static_cast<UINT>(::SendMessageW(
                    list_.Handle(), LVM_GETITEMSTATE, static_cast<WPARAM>(hit),
                    LVIS_SELECTED));
                if ((selected & LVIS_SELECTED) == 0) {
                    LVITEMW st = {};
                    st.mask = LVIF_STATE;
                    st.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE,
                                   static_cast<WPARAM>(-1),
                                   reinterpret_cast<LPARAM>(&st));
                    LVITEMW sel = {};
                    sel.mask = LVIF_STATE;
                    sel.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
                    sel.state = LVIS_SELECTED | LVIS_FOCUSED;
                    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE,
                                   static_cast<WPARAM>(hit),
                                   reinterpret_cast<LPARAM>(&sel));
                } else {
                    LVITEMW focus = {};
                    focus.stateMask = LVIS_FOCUSED;
                    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE,
                                   static_cast<WPARAM>(-1),
                                   reinterpret_cast<LPARAM>(&focus));
                    focus.state = LVIS_FOCUSED;
                    ::SendMessageW(list_.Handle(), LVM_SETITEMSTATE,
                                   static_cast<WPARAM>(hit),
                                   reinterpret_cast<LPARAM>(&focus));
                }
            }
        }
    } else {
        // Keyboard invocation (Shift+F10 / menu key): anchor at focus.
        const int focus = static_cast<int>(::SendMessageW(
            list_.Handle(), LVM_GETNEXTITEM, static_cast<WPARAM>(-1),
            MAKELPARAM(LVNI_FOCUSED, 0)));
        RECT rc = {};
        if (focus >= 0 &&
            ::SendMessageW(list_.Handle(), LVM_GETITEMRECT,
                           static_cast<WPARAM>(focus),
                           reinterpret_cast<LPARAM>(&rc))) {
            pt.x = rc.left + 16;
            pt.y = rc.top + 8;
        } else {
            pt.x = 0;
            pt.y = 0;
        }
        ::ClientToScreen(list_.Handle(), &pt);
    }

    HMENU menu = ::CreatePopupMenu();
    if (menu == nullptr) return;
    const int selected = static_cast<int>(::SendMessageW(
        list_.Handle(), LVM_GETSELECTEDCOUNT, 0, 0));
    const UINT gray = (selected > 0) ? MF_ENABLED : MF_GRAYED;
    // The one remaining user of the POINTER form, and deliberately so:
    // every read of `row` below happens BEFORE TrackPopupMenu runs its modal
    // loop, and only to compute a grey/enabled flag. Nothing here dereferences
    // the row after the menu returns, so there is no window in which a refresh
    // could free it. A copy would also be harmless but would copy a row whose
    // only use is four boolean reads.
    const Connection* row = list_.FirstSelectedRow();
    const std::optional<Connection> process = SelectedProcessCopy();
    const Connection* processRow = process.has_value() ? &*process : nullptr;
    const bool liveRow = !treeMode_ && !groupByProcess_ && row != nullptr &&
                         (row->flags & kRowRemoved) == 0;
    // "Close connection" only works for IPv4 - SetTcpEntry has no IPv6
    // variant (TcpTable.cpp:262 refuses it with a clear error). Disable the item
    // for IPv6 rows rather than letting the user invoke it and read the error,
    // and call the reason in the label the same way "End process..." does, so a
    // greyed item is not a silent mystery (see the note above). The Block
    // item stays enabled: firewall rules are family-agnostic and stop the
    // connection from coming back, which is the right outcome for IPv6.
    const bool isV4Tcp = (liveRow && row->identity.protocol == IPPROTO_TCP &&
                          row->identity.family == AF_INET &&
                          row->identity.state != MIB_TCP_STATE_LISTEN &&
                          row->identity.state != 0);
    const bool isV6Tcp = (liveRow && row->identity.protocol == IPPROTO_TCP &&
                          row->identity.family != AF_INET &&
                          row->identity.state != MIB_TCP_STATE_LISTEN &&
                          row->identity.state != 0);
    const bool closable = isV4Tcp;
    ::AppendMenuW(menu, MF_STRING | (processRow != nullptr ? MF_ENABLED : MF_GRAYED),
                   IDM_CTX_DETAILS, L"&Details...");
    ::AppendMenuW(menu, MF_STRING | gray, IDM_CTX_COPY_SELECTED, L"&Copy selected");
    ::AppendMenuW(menu, MF_STRING, IDM_CTX_COPY_ALL, L"Copy &all");
    const std::vector<Connection> copyRows = SelectedCopyRows();
    HMENU copyFields = ::CreatePopupMenu();
    if (copyFields != nullptr) {
        const auto appendCopyField = [&](ConnectionsList::CopyField field,
                                         UINT id, const wchar_t* label) {
            const bool available =
                !ConnectionsList::CopyFieldText(copyRows, field).empty();
            ::AppendMenuW(copyFields, MF_STRING |
                          (available ? MF_ENABLED : MF_GRAYED), id, label);
        };
        appendCopyField(ConnectionsList::CopyField::RemoteIp,
                        IDM_CTX_COPY_REMOTE_IP, L"Remote &IP");
        appendCopyField(ConnectionsList::CopyField::Hostname,
                        IDM_CTX_COPY_HOSTNAME, L"Remote &hostname");
        appendCopyField(ConnectionsList::CopyField::LocalEndpoint,
                        IDM_CTX_COPY_LOCAL_ENDPOINT, L"&Local endpoint");
        appendCopyField(ConnectionsList::CopyField::RemoteEndpoint,
                        IDM_CTX_COPY_REMOTE_ENDPOINT, L"&Remote endpoint");
        appendCopyField(ConnectionsList::CopyField::LocalPort,
                        IDM_CTX_COPY_LOCAL_PORT, L"Local &port");
        appendCopyField(ConnectionsList::CopyField::RemotePort,
                        IDM_CTX_COPY_REMOTE_PORT, L"Remote p&ort");
        ::AppendMenuW(copyFields, MF_SEPARATOR, 0, nullptr);
        appendCopyField(ConnectionsList::CopyField::ProcessPath,
                        IDM_CTX_COPY_PROCESS_PATH, L"Executable &path");
        appendCopyField(ConnectionsList::CopyField::ProcessId,
                        IDM_CTX_COPY_PROCESS_ID, L"Process &PID");
        ::AppendMenuW(menu, MF_POPUP | MF_STRING,
                      reinterpret_cast<UINT_PTR>(copyFields), L"Copy &value");
    }
    ::AppendMenuW(menu, MF_STRING | gray, IDM_CTX_EXPORT_SELECTION,
                   L"&Export selection...");
    // REMOVED 2026-10-05. Both menu entries that used to live here
    // are gone; the capability was moved to the CLI rather than dropped.
    //
    // REMOVED: "Follow TCP &stream..." (IDM_FOLLOW_STREAM). It re-elevated the
    // whole application to get at pktmon - losing the window, the filter and the
    // column layout to read hex bytes - and then blocked modally on a sampling
    // capture that returns nothing unless the connection is still carrying data
    // after the filter is armed. See `FollowSelectedStream` below for the full
    // chain, and `capture --text` / `capture --out` in cli.md for what replaced
    // it.
    //
    // const bool canFollow = closable && CaptureAvailable(nullptr);
    // ::AppendMenuW(menu, MF_STRING | (canFollow ? MF_ENABLED : MF_GRAYED),
    //               IDM_FOLLOW_STREAM, L"Follow TCP &stream...");

    // Shell navigation. Both need a real path, which a row does not
    // always have: PID 4 and some service processes report a name but no
    // image path. Offering the item and then failing is worse than greying
    // it, so the predicate is the same condition the action depends on.
    const bool hasPath = (processRow != nullptr && !processRow->display.processPath.empty() &&
                          processRow->display.processPath != L"System");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasPath ? MF_ENABLED : MF_GRAYED),
                  IDM_OPEN_FILE_LOCATION, L"Open file &location");
    // REMOVED 2026-10-05: "Process &properties..." (IDM_PROCESS_PROPERTIES).
    // The user reported it does not work, and the cause is structural rather
    // than a bug to repair: `properties` is a shell VERB, registered against
    // shell object types, and calling it directly with a bare path is the case
    // where it fails - silently, since ShellExecuteW returns <= 32 instead of
    // raising. The old handler collapsed that, a missing path, and PID 4's
    // placeholder "System" path into one identical message box.
    //
    // Removed rather than fixed on purpose. A menu entry offering an action the
    // app cannot perform teaches the reader to distrust the rest of the menu,
    // which costs more than the feature is worth. "Open file location" above
    // still reaches the same file through Explorer, where the verb does exist,
    // so nothing that ever worked is lost.
    //
    // ::AppendMenuW(menu, MF_STRING | (hasPath ? MF_ENABLED : MF_GRAYED),
    //               IDM_PROCESS_PROPERTIES, L"Process &properties...");
    ::AppendMenuW(menu, MF_STRING | (liveRow && row->identity.protocol == IPPROTO_TCP &&
                                         row->identity.state != MIB_TCP_STATE_LISTEN
                                         ? MF_ENABLED : MF_GRAYED),
                   IDM_BLOCK_CONNECTION, L"&Block this connection...");
    // "Block this connection..." adds Windows Firewall rules, which need
    // an elevated token. Show the UAC shield when the user is an admin who is
    // not currently elevated (ElevationPossibleForUser). A standard account gets
    // no shield: the glyph means "can be elevated", and a click on that item
    // instead shows ElevationUnavailableReason() from the OnCommand handler.
    if (!HighContrastActive() && ElevationPossibleForUser())
        SetMenuItemShield(menu, IDM_BLOCK_CONNECTION, true);
    // Note on "Close connection": SetTcpEntry on a connection the current user
    // owns does NOT require elevation, so it deliberately takes no shield -
    // showing one would mislead users into thinking the action is privileged.

    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (isV6Tcp ? MF_GRAYED : (closable ? MF_ENABLED : MF_GRAYED)),
                   IDM_CTX_CLOSE_CONNECTION,
                   isV6Tcp ? L"&Close connection (IPv6 - use Block instead...)"
                           : L"&Close connection...");
    // "End process..." was unconditionally enabled, so it was clickable on
    // a wintcp.exe row - and wintcp.exe is a network tool, so it has its own
    // rows. Clicking it ended WinTCP. The item is now greyed when the row's PID
    // cannot be ended, and says WHY in the label rather than greying silently,
    // because a greyed item with no explanation is the thing users report as a
    // bug. The rule comes from Commands.cpp so the CLI applies the same one.
    const PidVerdict killVerdict =
        PidKillVerdict(processRow != nullptr ? processRow->identity.pid : 0,
                       ::GetCurrentProcessId(), processRow != nullptr);
    const bool canEnd = killVerdict == PidVerdict::Ok &&
                        processRow->procMeta.processCreateKnown;
    ::AppendMenuW(menu, MF_STRING | (canEnd ? MF_ENABLED : MF_GRAYED),
                  IDM_CTX_KILL_PROCESS,
                  canEnd ? L"&End process..."
                         : L"&End process... (not available for this row)");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, IDM_CTX_REFRESH, L"&Refresh");
    ::TrackPopupMenu(menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd_,
                     nullptr);
    ::DestroyMenu(menu);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
void MainWindow::ExportCsv() {
    DoExport(false);
}

void MainWindow::DoExport(bool selectionOnly) {
    if (store_.View().empty()) {
        ::MessageBoxW(hwnd_, L"There are no rows to export.", L"WinTCP",
                      MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (selectionOnly) {
        const int n = static_cast<int>(
            ::SendMessageW(list_.Handle(), LVM_GETSELECTEDCOUNT, 0, 0));
        if (n <= 0) {
            ::MessageBoxW(hwnd_, L"No rows are selected.", L"WinTCP",
                          MB_OK | MB_ICONINFORMATION);
            return;
        }
    }
    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFile = path;
    ofn.nMaxFile = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
    ofn.lpstrFilter = L"CSV files (*.csv)\0*.csv\0"
                      L"TSV files (*.tsv)\0*.tsv\0"
                      L"JSON files (*.json)\0*.json\0"
                      L"All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (settings_.lastExportDir[0] != 0)
        ofn.lpstrInitialDir = settings_.lastExportDir;    // remember
    // comdlg32.dll is delay-loaded; DelayLoadGuard reports its absence, where a
    // bare `return` here would be indistinguishable from the user cancelling.
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return;
    if (!::GetSaveFileNameW(&ofn)) return;

    // Format: a typed extension wins, otherwise the dropdown decides and
    // the matching extension is appended when the name has none.
    std::wstring p(path);
    const size_t slash = p.find_last_of(L"\\/");
    const size_t dot = p.find_last_of(L'.');
    const bool hasExt = (dot != std::wstring::npos) &&
                        (slash == std::wstring::npos || dot > slash);
    int format = (ofn.nFilterIndex >= 1 && ofn.nFilterIndex <= 3)
                     ? static_cast<int>(ofn.nFilterIndex)
                     : 1;                                  // 1=csv 2=tsv 3=json
    if (hasExt) {
        const std::wstring ext = ToLowerW(p.substr(dot));
        if (ext == L".csv") format = 1;
        else if (ext == L".tsv" || ext == L".tab") format = 2;
        else if (ext == L".json") format = 3;
    } else {
        p += (format == 2) ? L".tsv" : (format == 3 ? L".json" : L".csv");
    }

    // Rows are collected first (copies, not pointers): the serializers in
    // Commands take values, so the GUI and the CLI export byte-identical
    // content from the same code.
    std::vector<Connection> rows;
    if (selectionOnly) {
        std::vector<int> sel;
        if (list_.SelectedRowIndices(sel)) {
            for (int item : sel) {
                const Connection* c =
                    store_.ViewRow(static_cast<size_t>(item));
                if (c != nullptr) rows.push_back(*c);
            }
        }
    } else {
        for (size_t v = 0; v < store_.View().size(); ++v) {
            const Connection* c = store_.ViewRow(v);
            if (c != nullptr) rows.push_back(*c);
        }
    }
    const std::string content = (format == 3)
        ? RenderJsonRows(rows, DefaultExportColumns(),
                         /*extraHostname=*/true)
        : RenderDelimitedRows(rows, cols_.VisToCol(), (format == 2) ? '\t' : ',',
                              /*rfcCsv=*/format != 2);
    // JSON must not carry a BOM (strict parsers reject it); CSV/TSV keep
    // the Excel-friendly BOM.
    const std::wstring err = WriteUtf8FileWithBom(p, content, format != 3);
    if (!err.empty()) {
        const std::wstring msg = L"Failed to write file:\n" + err;
        ::MessageBoxW(hwnd_, msg.c_str(), L"WinTCP - Export failed",
                      MB_OK | MB_ICONERROR);
        return;
    }
    // Remember the directory for the next export.
    const size_t lastSep = p.find_last_of(L"\\/");
    if (lastSep != std::wstring::npos && lastSep < MAX_PATH)
        ::wcsncpy_s(settings_.lastExportDir, p.substr(0, lastSep).c_str(),
                    _TRUNCATE);
    // surface the row count the export actually wrote, so a user
    // exporting a 3000-row snapshot gets a confirmation that names the volume
    // rather than a bare "Export completed." The count is authoritative: it
    // is the number of rows fed to the serializer, which is exactly what
    // landed in the file.
    std::wstring msg = L"Exported " + std::to_wstring(rows.size()) +
                       L" rows to " + p + L".";
    ::MessageBoxW(hwnd_, msg.c_str(), L"WinTCP",
                  MB_OK | MB_ICONINFORMATION);
}

void MainWindow::CopySelectionToClipboard(bool copyAll) {
    if (!copyAll) {
        const int n = static_cast<int>(::SendMessageW(
            list_.Handle(), LVM_GETSELECTEDCOUNT, 0, 0));
        if (n <= 0) return;
    }
    const std::wstring text = list_.SelectedRowsText(copyAll, groupByProcess_, frozen_, frozenAt_, cols_);
    CopyTextToClipboard(text, copyAll ? L"Copied all rows." : L"Copied selected rows.");
}

std::vector<Connection> MainWindow::SelectedCopyRows() const {
    if (!treeMode_) return list_.SelectedRowsCopy();
    std::vector<Connection> rows;
    const std::optional<Connection> process = SelectedProcessCopy();
    if (process.has_value()) rows.push_back(*process);
    return rows;
}

void MainWindow::CopyFieldToClipboard(ConnectionsList::CopyField field) {
    const std::vector<Connection> rows = SelectedCopyRows();
    const std::wstring text = ConnectionsList::CopyFieldText(rows, field);
    if (text.empty()) {
        copyFeedback_ = L"No selected row has a known value for that field.";
        copyFeedbackUntil_ = ::GetTickCount64() + 4000;
        UpdateStatusBar(lastError_);
        return;
    }
    const wchar_t* label = L"selected values";
    switch (field) {
        case ConnectionsList::CopyField::RemoteIp: label = L"remote IP addresses"; break;
        case ConnectionsList::CopyField::Hostname: label = L"hostnames"; break;
        case ConnectionsList::CopyField::LocalEndpoint: label = L"local endpoints"; break;
        case ConnectionsList::CopyField::RemoteEndpoint: label = L"remote endpoints"; break;
        case ConnectionsList::CopyField::LocalPort: label = L"local ports"; break;
        case ConnectionsList::CopyField::RemotePort: label = L"remote ports"; break;
        case ConnectionsList::CopyField::ProcessPath: label = L"executable paths"; break;
        case ConnectionsList::CopyField::ProcessId: label = L"process IDs"; break;
    }
    CopyTextToClipboard(text, L"Copied " + std::wstring(label) + L".");
}

void MainWindow::CopyTextToClipboard(const std::wstring& text,
                                     const std::wstring& successMessage,
                                     const ClipboardApi* clipboardApi) {
    const auto showFeedback = [this](const std::wstring& message) {
        copyFeedback_ = message;
        copyFeedbackUntil_ = ::GetTickCount64() + 4000;
        UpdateStatusBar(lastError_);
    };
    const ClipboardApi nativeClipboard = NativeClipboardApi();
    const ClipboardWriteStatus result = WriteClipboardText(
        hwnd_, text, clipboardApi != nullptr ? *clipboardApi : nativeClipboard);
    switch (result) {
        case ClipboardWriteStatus::Copied:
            showFeedback(successMessage);
            break;
        case ClipboardWriteStatus::EmptyText:
            break;
        case ClipboardWriteStatus::InvalidApi:
            showFeedback(L"Copy failed: clipboard access is unavailable.");
            break;
        case ClipboardWriteStatus::AllocationFailed:
            showFeedback(L"Copy failed: could not allocate clipboard memory.");
            break;
        case ClipboardWriteStatus::LockFailed:
            showFeedback(L"Copy failed: could not lock clipboard memory.");
            break;
        case ClipboardWriteStatus::OpenFailed:
            showFeedback(L"Copy failed: the clipboard is busy or unavailable.");
            break;
        case ClipboardWriteStatus::EmptyFailed:
            showFeedback(L"Copy failed: Windows could not open the clipboard for replacement.");
            break;
        case ClipboardWriteStatus::SetDataFailed:
            showFeedback(L"Copy failed: Windows rejected clipboard data; prior contents may have been cleared.");
            break;
    }
    if (ClipboardNeedsManualFallback(result)) {
        ShowTextSheet(hwnd_, L"Clipboard unavailable — select text and press Ctrl+C",
                      text, nullptr, true);
    }
}

std::optional<Connection> MainWindow::SelectedProcessCopy() const {
    if (!treeMode_) return list_.SelectedCopy();
    const HTREEITEM item = reinterpret_cast<HTREEITEM>(
        ::SendMessageW(hwndTree_, TVM_GETNEXTITEM, TVGN_CARET, 0));
    if (item == nullptr) return std::nullopt;
    TVITEMW selected = {};
    selected.mask = TVIF_PARAM | TVIF_HANDLE;
    selected.hItem = item;
    if (::SendMessageW(hwndTree_, TVM_GETITEMW, 0,
                       reinterpret_cast<LPARAM>(&selected)) == 0)
        return std::nullopt;
    const ProcessTreeNode* node = TreeProcessForItemData(selected.lParam);
    if (node == nullptr) return std::nullopt;
    Connection processCopy;
    if (MakeProcessTreeActionCopy(*node, store_.Rows(), nullptr, processCopy))
        return processCopy;
    Connection row;
    row.identity.pid = node->pid;
    row.display.processName = node->name;
    row.procMeta.processCreate = node->processCreate;
    row.procMeta.processCreateKnown = node->processCreateKnown;
    if (!node->processCreateKnown) return row;
    std::vector<Connection> rows{row};
    ProcessResolver resolver;
    resolver.ResolveBatch(rows);
    if (!MakeProcessTreeActionCopy(*node, store_.Rows(), &rows[0],
                                   processCopy))
        return std::nullopt;
    return processCopy;
}

void MainWindow::KillSelectedProcess() {
    const std::optional<Connection> sel = SelectedProcessCopy();
    if (!sel.has_value()) return;
    const Connection& c = *sel;

    if (!c.procMeta.processCreateKnown) {
        ::MessageBoxW(hwnd_, L"The captured process lifetime is unavailable. "
                      L"Refresh the view before trying to end this process.",
                      L"WinTCP - End process", MB_OK | MB_ICONWARNING);
        return;
    }

    // THE ROW IS ALREADY A COPY — `sel` above, not `rows_[n]`.
    //
    // This handler used to read `c->identity.pid` and friends *after* the confirm
    // MessageBox returned, and the comment above those reads explained why
    // that was wrong without doing anything about it: a modal dialog runs its
    // own message loop, so the refresh timer fires underneath it,
    // `ReplaceSnapshot` reallocates `rows_`, and `c` - a pointer INTO that
    // vector - dangles. Reading `pid` out of freed memory and handing it to
    // `KillPid` ends a process nobody selected. The report that started this
    // was wintcp.exe closing itself after "End process" on AnyDesk.exe, which
    // is exactly what a garbage PID that happened to be our own produces.
    //
    // The copy this handler relied on is no longer a local `const Connection
    // row = c;` that a future edit could move below the dialog: it is
    // `list_.SelectedCopy()` at the top of every handler, so there is no way to write
    // this handler wrong. It costs one Connection on a path the user just
    // opened a dialog for, and the whole row is copied rather than the few
    // fields this dialog happens to use, because a partial copy is a copy that
    // can be extended wrongly later.

    // second half: refuse our own process BEFORE the dialog, so the user
    // is not asked to approve something that will be refused afterwards. The
    // rule itself lives in Commands.cpp (PidKillVerdict) because the CLI can
    // reach it too; this is only the GUI asking early.
    const PidVerdict verdict =
        PidKillVerdict(c.identity.pid, ::GetCurrentProcessId(), true);
    if (verdict != PidVerdict::Ok) {
        ::MessageBoxW(hwnd_, PidKillRefusal(verdict), L"WinTCP - End process",
                      MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Refuse pseudo-pids and verify the PID still maps to the same process
    // instance we captured (PID-reuse protection).
    std::wstring verifyErr;
    if (!ProcessResolver::VerifyProcess(c.identity.pid, c.procMeta.processCreate,
                                        c.procMeta.processCreateKnown, verifyErr)) {
        ::MessageBoxW(hwnd_, verifyErr.c_str(), L"WinTCP",
                      MB_OK | MB_ICONWARNING);
        return;
    }

    // Confirm with enough identity detail that the user is agreeing to end
    // the process they think they are ending. Name plus PID alone is not
    // enough: PIDs get recycled, and "chrome.exe (PID 1234)" is ambiguous
    // when two instances are running. Full path and start time disambiguate
    // completely, because the start time is what the verification above just
    // confirmed.
    std::wstring path;
    if (c.display.processPath.empty())
        path = L"(path unavailable)";
    else if (c.display.processPath == L"System")
        // PID 4 (System) is the kernel - there is no image to show, so
        // describe it instead of echoing the internal "System" sentinel.
        path = L"Windows kernel process (no executable image)";
    else
        path = c.display.processPath;
    const std::wstring started = FormatFileTimeLocal(c.procMeta.processCreate,
                                                      c.procMeta.processCreateKnown);
    const std::wstring cmdLine = QueryProcessCommandLine(c.identity.pid);
    wchar_t prompt[kKillPromptChars] = {0};
    if (cmdLine.empty() || cmdLine.size() > kKillPromptCmdChars) {
        ::swprintf_s(prompt,
                     L"End this process?\n\n  Name:  %ls\n  PID:   %lu\n"
                     L"  Path:  %ls\n  Start: %ls\n\n"
                     L"WinTCP will ask the process to close normally first, "
                     L"and only end it forcibly if it does not exit within a "
                     L"few seconds.\n\nUnsaved data may still be lost."
                     L"\n\nScriptable: wintcp.exe kill --pid %lu --yes",
                     c.display.processName.c_str(),
                     static_cast<unsigned long>(c.identity.pid), path.c_str(),
                     started.c_str(), static_cast<unsigned long>(c.identity.pid));
    } else {
        ::swprintf_s(prompt,
                     L"End this process?\n\n  Name:  %ls\n  PID:   %lu\n"
                     L"  Path:  %ls\n  Start: %ls\n  Cmd:   %ls\n\n"
                     L"WinTCP will ask the process to close normally first, "
                     L"and only end it forcibly if it does not exit within a "
                     L"few seconds.\n\nUnsaved data may still be lost."
                     L"\n\nScriptable: wintcp.exe kill --pid %lu --yes",
                     c.display.processName.c_str(),
                     static_cast<unsigned long>(c.identity.pid), path.c_str(),
                     started.c_str(), cmdLine.c_str(),
                     static_cast<unsigned long>(c.identity.pid));
    }
    if (::MessageBoxW(hwnd_, prompt, L"WinTCP - End process",
                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
        return;

    // From here nothing reads a Connection. The row is gone as far as this
    // function is concerned; only the by-value copy above is live, and
    // KillPid re-verifies the PID against its start time in case it was
    // recycled while the dialog was up.
    //
    // Execution lives in the abstract layer (Commands::KillPid): graceful
    // close first, then terminate.
    MutateOptions mo;
    mo.yes = true;
    const CommandResult kr =
        KillPid(c.identity.pid, c.procMeta.processCreate, c.procMeta.processCreateKnown,
                c.display.processName, mo);
    if (kr.exitCode != kExitOk) {
        ::MessageBoxW(hwnd_, Utf8ToWide(kr.err.c_str()).c_str(), L"WinTCP",
                      MB_OK | MB_ICONERROR);
        return;
    }
    Refresh(false);
}

void MainWindow::OpenSelectedFileLocation() {
    const std::optional<Connection> sel = SelectedProcessCopy();
    if (!sel.has_value()) return;
    const Connection& c = *sel;
    if (c.display.processPath.empty() || c.display.processPath == L"System") {
        ::MessageBoxW(hwnd_,
                      L"This row has no process path, so there is no file to "
                      L"open.\n\nSystem-owned processes and rows whose owning "
                      L"process has already exited do not have one.",
                      L"Open file location", MB_OK | MB_ICONINFORMATION);
        return;
    }
    // One implementation with the Details button (Utils::ShowFileInExplorer):
    // "explorer.exe /select,". The old "explore" verb is a folder verb and
    // fails on file paths, which is why this menu item failed while the
    // button worked.
    std::wstring error;
    if (!ShowFileInExplorer(c.display.processPath, &error)) {
        ::MessageBoxW(hwnd_, error.c_str(), L"Open file location",
                      MB_OK | MB_ICONWARNING);
    }
}

// REMOVED 2026-10-05. Kept, and kept as an explanation rather than as
// commented-out code, for the same reason as the menu entry: the reasoning is
// the valuable part and deleting it would lose the answer to "why doesn't
// Process properties work?".
//
// What was wrong with it, having read it rather than guessed: `properties` is
// a shell verb, and the way to invoke one is through a shell item
// (ShellExecuteEx on an IShellItem, or "explorer /select,"), not by handing
// ShellExecuteW a raw path. Given a path it returns <= 32, which the three boxes
// above collapsed into a single indistinguishable message - so a user could not
// tell a genuinely missing file from a verb the shell declined to run, which is
// exactly the "it does not work" report. There was also no working version of
// the idea to fall back on: "Open file location" opens Explorer on the same
// file, and Explorer does have the verb.

void MainWindow::BlockSelectedConnection() {
    if (treeMode_ || groupByProcess_) {
        UpdateStatusBar(L"Select an individual connection in the table to block it.");
        return;
    }
    const std::optional<Connection> sel = list_.SelectedCopy();
    if (!sel.has_value()) return;
    const Connection& c = *sel;

    // Row -> request mapping lives in the abstract layer
    // (Commands::ConnectionToBlockRequest), so the GUI and the `block` CLI
    // verb refuse the same rows for the same reason.
    BlockRequest req;
    std::wstring whyNot;
    if (!ConnectionToBlockRequest(c, &req, &whyNot)) {
        ::MessageBoxW(hwnd_,
                      (whyNot +
                       L"\n\nA listening socket has no peer yet, and a UDP row "
                       L"has no connection to stop.")
                          .c_str(),
                      L"Block connection", MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Say plainly what will and will not happen, because the two layers have
    // different reach: the firewall rule always works, but Windows exposes no
    // public way to tear down a single live IPv6 connection, so on IPv6 only
    // future connections are stopped.
    wchar_t prompt[kBlockPromptChars] = {0};
    if (req.ipv6) {
        ::swprintf_s(prompt,
                     L"Block %ls?\n\nWindows Firewall rules will be added so this "
                     L"peer cannot be reached again.\n\nThe currently open "
                     L"connection will NOT be dropped: Windows provides no "
                     L"supported way to close a single live IPv6 connection. "
                     L"It will end on its own when the application closes it."
                     L"\n\nScriptable: wintcp.exe block --select "
                     L"\"pid:%lu remote:%ls\" --yes",
                     req.label.c_str(), static_cast<unsigned long>(c.identity.pid),
                     c.display.remoteAddress.c_str());
    } else {
        ::swprintf_s(prompt,
                     L"Block %ls?\n\nThe connection will be closed now, and "
                     L"Windows Firewall rules will be added so this peer cannot "
                     L"be reached again.\n\nTo undo, use Remove All WinTCP "
                     L"Blocks from the tray menu."
                     L"\n\nScriptable: wintcp.exe block --select "
                     L"\"pid:%lu remote:%ls\" --yes",
                     req.label.c_str(), static_cast<unsigned long>(c.identity.pid),
                     c.display.remoteAddress.c_str());
    }
    if (::MessageBoxW(hwnd_, prompt, L"WinTCP - Block connection",
                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
        return;

    // Execution lives in the abstract layer (Commands::BlockNow); this only
    // confirms and renders the result.
    MutateOptions mo;
    mo.yes = true;
    const CommandResult br = BlockNow(req, mo);
    if (br.exitCode == kExitOk) {
        // the block succeeded, so the result goes to the
        // status bar rather than a modal that interrupts the
        // flow - the user can keep watching the table. A
        // partial failure is still a failure and stays a
        // modal: it must not be missed.
        // The confirm above cites the CLI verb, verified on the
        // real machine: `block --select "pid:<pid> remote:<addr>"
        // --dry-run` resolved to the same row the GUI had.
        UpdateStatusBar(L"Blocked " + req.label);
    } else {
        // Partial success is reported as partial. Saying "done" when only
        // one of the two layers applied would leave the user believing
        // the connection is gone when it is still open.
        ::MessageBoxW(hwnd_, Utf8ToWide((br.out + br.err).c_str()).c_str(),
                      L"Block connection - partial",
                      MB_OK | MB_ICONWARNING);
    }
    Refresh(false);
}

void MainWindow::CloseSelectedConnection() {
    if (treeMode_ || groupByProcess_) {
        UpdateStatusBar(L"Select an individual connection in the table to close it.");
        return;
    }
    const std::optional<Connection> sel = list_.SelectedCopy();
    if (!sel.has_value()) return;
    const Connection& c = *sel;
    const std::string closeReason = ConnectionCloseCapabilityReason(c, IsElevated());
    if (!closeReason.empty()) {
        UpdateStatusBar(Utf8ToWide(closeReason.c_str()));
        return;
    }

    // `c` is a copy (SelectedCopy): the confirm below runs a modal loop, and
    // a refresh arriving in that window reallocates rows_.

    wchar_t prompt[768] = {0};
    ::swprintf_s(prompt,
                 L"Close this TCP connection?\n\n  %ls  ->  %ls\n  [%ls]  PID %lu"
                 L"\n\nScriptable: wintcp.exe close --select "
                 L"\"pid:%lu remote:%ls\" --yes",
                 c.display.localEndpoint.c_str(), c.display.remoteEndpoint.c_str(),
                 c.keys.stateLabel.c_str(), static_cast<unsigned long>(c.identity.pid),
                 static_cast<unsigned long>(c.identity.pid), c.display.remoteAddress.c_str());
    if (::MessageBoxW(hwnd_, prompt, L"WinTCP - Close connection",
                      MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
        return;

    // Execution lives in the abstract layer (Commands::CloseRow); this only
    // confirms and renders the result.
    MutateOptions mo;
    mo.yes = true;
    const CommandResult cr = CloseRow(c, mo);
    if (cr.exitCode != kExitOk) {
        ::MessageBoxW(hwnd_, Utf8ToWide(cr.err.c_str()).c_str(),
                      L"WinTCP - Close failed", MB_OK | MB_ICONWARNING);
        return;
    }
    Refresh(false);   // the row vanishes, flashes red, then lingers as a grey ghost
}

void MainWindow::RemoveAllWinTcpBlocks() {
    // remove every WinTCP block rule the ledger remembers - i.e., every
    // rule that `block` created. The ledger, not a full enumeration, is the
    // source of truth, so this removes exactly what this application added
    // and nothing else.
    const int count = CountWinTcpRules();

    if (count == 0) {
        // count == 0 also means "firewall API not accessible" (not
        // elevated); a removal attempt surfaces that before we say
        // "nothing to remove".
        std::wstring error;
        (void)RemoveAllWinTcpRules(&error);
        if (!error.empty()) {
            ::MessageBoxW(hwnd_, error.c_str(),
                          L"Remove All WinTCP Blocks", MB_OK | MB_ICONERROR);
            return;
        }
        ::MessageBoxW(hwnd_,
                      L"No WinTCP firewall rules are currently present. "
                      L"Nothing to remove.",
                      L"WinTCP - Remove all blocks",
                      MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Confirm before tearing down every rule at once - one wrong click
    // must not leave a whole range of peers suddenly open.
    wchar_t prompt[640] = {0};
    ::swprintf_s(prompt,
                 L"Remove ALL WinTCP firewall blocks?\n\n"
                 L"This removes %d rule(s) and unblocks every peer that was "
                 L"previously blocked with `block`. Rules can always be "
                 L"recreated by blocking the peer again.",
                 count);
    if (::MessageBoxW(hwnd_, prompt, L"WinTCP - Remove all blocks",
                       MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        return;
    }

    std::wstring error;
    const bool removed = RemoveAllWinTcpRules(&error);
    if (!removed) {
        ::MessageBoxW(hwnd_, error.c_str(),
                      L"Remove All WinTCP Blocks", MB_OK | MB_ICONERROR);
        return;
    }

::MessageBoxW(hwnd_,
             (L"Removed " + std::to_wstring(count) +
              L" WinTCP firewall rule(s).").c_str(),
             L"WinTCP - Remove all blocks",
             MB_OK | MB_ICONINFORMATION);
}

DetailModel MainWindow::BuildDetails(const Connection& c) const {
    // The GUI and the `details` CLI verb share this model.
    return BuildDetailModel(c, store_);
}

void MainWindow::RefreshDetailsWindow() {
    // Silent live-update after every refresh: rebuild the text for the
    // tracked PID without showing, focusing or foregrounding anything.
    // A hidden or never-opened window is left alone.
    if (!details_.IsVisible() || detailsPid_ == 0) return;
    const Connection* found = FindProcessInstance(
        store_.Rows(), detailsPid_, detailsProcessCreate_,
        detailsProcessCreateKnown_);
    if (found == nullptr) {
        // Process exited (or every connection closed): keep the last
        // sample but say so once instead of silently going stale
        //
        if (!detailsExitedNoted_ && !detailsModel_.sections.empty()) {
            detailsExitedNoted_ = true;
            // Appended to the model's own note, not to a string: the
            // renderer shows it in place without re-parsing anything.
            DetailModel stale = detailsModel_;
            if (!stale.sections.empty())
                stale.sections.back().note =
                    L"no matching live connection — showing the last sample";
            details_.UpdateModel(std::move(stale));
        }
        return;
    }
    detailsExitedNoted_ = false;
    detailsModel_ = BuildDetails(*found);
    details_.UpdateModel(detailsModel_);
}

void MainWindow::ShowDetailsOfSelectedRow() {
    const std::optional<Connection> sel = SelectedProcessCopy();
    if (!sel.has_value()) return;
    const Connection& c = *sel;

    detailsPid_ = c.identity.pid;
    detailsProcessCreate_ = c.procMeta.processCreate;
    detailsProcessCreateKnown_ = c.procMeta.processCreateKnown;
    detailsExitedNoted_ = false;
    detailsModel_ = BuildDetails(c);
    details_.SetDark(ThemeIsDark());
    details_.Show(hwnd_, font_, detailsModel_,
                  c.display.processPath.empty() ? std::wstring() : c.display.processPath);
}

/* REMOVED 2026-10-05 - the modal "capturing..." countdown
   window, and the whole of FollowSelectedStream's wait step.

   This existed for one caller: the GUI's Follow TCP stream action, which is
   gone. It could not simply be left in place, because an unreferenced function
   with internal linkage is C4505 - a warning, and /WX makes every warning an
   error. So it is commented rather than deleted: the timer handling and the
   countdown arithmetic are worth keeping a record of, and a future caller that
   wants a non-modal capture window should start from this instead of from
   nothing.

   Reinstating it means unwrapping this block, re-enabling IDM_FOLLOW_STREAM in
   wintcp.rc and OnContextMenu, and answering the question this window never
   did: how the user knows when to generate traffic. Better answered on the
   command line, which is where the feature went.
namespace {

// A small modal "capturing" window with a live countdown. Written here
// rather than reusing a .rc dialog so the whole feature stays in one place
// and needs no new resource ids.
//
// It is a plain window, not a dialog: no template, one STATIC, one BUTTON,
// one 1 Hz timer. The main window stays enabled underneath so the user can
// watch the connection they are capturing and generate traffic on it.
constexpr wchar_t kCaptureWaitClass[] = L"WinTcpCaptureWait";
constexpr UINT_PTR kCaptureWaitTimer = 1;
constexpr UINT IDM_WAIT_STOP = 2001;
constexpr UINT IDC_WAIT_TEXT = 2002;

// Seconds offered. Long enough to catch a page load, short enough that an
// impatient user is not trapped.
constexpr int kCaptureSeconds = 15;

// The wait dialog's countdown tick. 250 ms refreshes the displayed countdown
// promptly without repainting constantly; both creation sites share it so the
// rate is stated once.
constexpr UINT kCapturePollMs = 250;

LRESULT CALLBACK CaptureWaitProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l);
bool g_captureWaitRegistered = false;
int g_captureWaitDeadline = 0;   // GetTickCount at which to auto-close

INT_PTR ShowCaptureWait(HWND owner, const std::wstring& what) {
    if (!g_captureWaitRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &CaptureWaitProc;
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        wc.lpszClassName = kCaptureWaitClass;
        if (::RegisterClassExW(&wc) == 0 &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            return 0;
        g_captureWaitRegistered = true;
    }

    HWND dlg = ::CreateWindowExW(
        WS_EX_DLGMODALFRAME, kCaptureWaitClass, L"Capturing TCP stream",
        WS_POPUPWINDOW | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT,
        CW_USEDEFAULT, 460, 190, owner, nullptr, ::GetModuleHandleW(nullptr),
        nullptr);
    if (dlg == nullptr) return 0;

    ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                      16, 16, 410, 90, dlg,
                      reinterpret_cast<HMENU>(static_cast<UINT_PTR>(
                          IDC_WAIT_TEXT)),
                      ::GetModuleHandleW(nullptr), nullptr);
    ::CreateWindowExW(0, L"BUTTON", L"&Stop and view",
                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                      330, 118, 110, 28, dlg,
                      reinterpret_cast<HMENU>(static_cast<UINT_PTR>(
                          IDM_WAIT_STOP)),
                      ::GetModuleHandleW(nullptr), nullptr);

    ::SetWindowTextW(
        dlg, (L"Capture: " + what).c_str());

    g_captureWaitDeadline =
        static_cast<int>(::GetTickCount()) + kCaptureSeconds * kMsPerSecond;
    ::SetTimer(dlg, kCaptureWaitTimer, kCapturePollMs, nullptr);

    // Modal loop: own message pump so the main list keeps refreshing and the
    // user can interact with it while the capture runs.
    ::EnableWindow(owner, FALSE);
    MSG msg;
    for (;;) {
        if (::IsWindow(dlg) == FALSE) break;
        if (::GetMessageW(&msg, nullptr, 0, 0) <= 0) break;
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            ::DestroyWindow(dlg);
            break;
        }
        if (::IsDialogMessageW(dlg, &msg) == 0) ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }
    ::EnableWindow(owner, TRUE);
    ::SetForegroundWindow(owner);
    return 1;
}

LRESULT CALLBACK CaptureWaitProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_CREATE: {
            g_captureWaitDeadline =
                static_cast<int>(::GetTickCount()) + kCaptureSeconds * kMsPerSecond;
            ::SetTimer(hwnd, kCaptureWaitTimer, kCapturePollMs, nullptr);
            return 0;
        }
        case WM_TIMER: {
            const int left = (g_captureWaitDeadline -
                              static_cast<int>(::GetTickCount()) + kMsPerSecond - 1) / kMsPerSecond;
            HWND text = ::GetDlgItem(hwnd, IDC_WAIT_TEXT);
            if (left <= 0) {
                ::DestroyWindow(hwnd);
                return 0;
            }
            wchar_t buf[512] = {0};
            ::swprintf_s(buf, L"Capturing this connection for %d more "
                              L"second(s).\n\nBrowse or sync something that uses "
                              L"it now.\n\nFor an encrypted (TLS) connection the "
                              L"handshake and certificate will be shown in "
                              L"cleartext; the application data itself cannot "
                              L"be read.",
                         left);
            ::SetWindowTextW(text, buf);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDM_WAIT_STOP &&
                HIWORD(w) == BN_CLICKED) {
                ::DestroyWindow(hwnd);
                return 0;
            }
            break;
        case WM_CLOSE:
        case WM_DESTROY:
            ::KillTimer(hwnd, kCaptureWaitTimer);
            return 0;
        default:
            break;
    }
    return ::DefWindowProcW(hwnd, msg, w, l);
}


*/


// REMOVED 2026-10-05: FollowSelectedStream, the GUI half of
// "Follow TCP stream". Commented, not deleted, because the chain of reasons it
// failed IS the argument for moving the feature to the CLI:
//
//  1. It re-elevated the ENTIRE application to reach pktmon. Reelevate replaces
//     the process, so the window, the filter box, the column layout and the
//     scroll position are all gone - to look at hex bytes. The original comment
//     claimed the state "is still there on the other side"; the command line is,
//     the user's working state is not.
//  2. Even elevated it is modal: arm the filter, show a wait dialog, sleep, and
//     only THEN show the bytes. pktmon is a sampling driver, not a tap, so
//     anything before `pktmon filter add` is simply not recorded - and a
//     connection that goes quiet in the meantime yields an empty window that the
//     user cannot distinguish from a bug.
//  3. The bytes then land in a hand-rolled hex window. The hex window is the
//     right tool for the job; the flow around it is what made the feature read
//     as broken even when it worked.
//
// The capability was NOT dropped. `capture` already ran this exact pipeline
// (StartCapture -> StopCapture -> Pcapng -> TcpReasm) and then printed one line
// of counters, throwing the payload away. It now has `--text`, which writes the
// reassembled direction to stdout the way `tcpflow -A` does, and `--out FILE`,
// which keeps the pcapng for Wireshark or tshark. On the command line the
// blocking is the point rather than the defect.
//

// ---- presets + bookmarks -----------------------------------------

// Snapshot the current view into a PresetView.
//
// The traffic-source toggles are included deliberately: a preset that
// captured the columns and filter but not whether GeoIP/DNS/traffic were
// running would restore a view that looks identical on screen but silently
// behaves differently, which is worse than not having presets at all.
PresetView MainWindow::CurrentPresetView() const {
    unsigned sources = 0;
    if (dnsEnabled_) sources |= kPresetSourceHosts;
    if (etw_->Running() || fallbackFlag_->load(std::memory_order_relaxed))
        sources |= kPresetSourceEtw;
    // the ASN database shares the GeoIP bit rather than taking a new one.
    // It is the same enrichment applied from a second file, and kPresetSourceAll
    // is a four-bit mask - adding a fifth bit would be a schema change to a
    // persisted value for no distinction a user can act on.
    if (enrich_.CountryLoaded() || enrich_.AsnLoaded()) sources |= kPresetSourceGeoIp;
    // Widget reads stay here (search box, column mask, sort); the ViewState
    // assembly lives in the abstract layer so the CLI builds the same type.
    return CurrentPresetViewFor(CurrentSearchText(), cols_.VisibleMask(),
                                store_.SortColumn(), store_.SortAscending(),
                                sources);
}

void MainWindow::ApplyPresetView(const PresetView& v) {
    // Filter first: ParseFilter runs on the text, and doing it before the
    // column rebuild means the filter box and the column mask change together
    // in one repaint rather than showing an intermediate state.
    ::SetWindowTextW(hwndSearchEdit_, v.filter.c_str());
    filterDebounceText_ = v.filter;
    cols_.SetVisibleMask(ClampVisibleCols(v.colVisible));
    store_.SetSort(v.sortColumn, v.sortAsc);

    // Apply the source toggles. Turning one ON may start a counter source,
    // which is exactly what the preset asked for, so this is not a no-op.
    const bool wantDns = (v.sources & kPresetSourceHosts) != 0;
    if (wantDns != dnsEnabled_) {
        dnsEnabled_ = wantDns;
        enrich_.SetDnsEnabled(wantDns);
    }
    const bool wantTraffic = (v.sources & kPresetSourceEtw) != 0;
    if (wantTraffic) EnsureTrafficCounters();

    SyncColumnMenuChecks();
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_RESOLVE, dnsEnabled_);
    RebuildColumns();
    ApplyView();
}


void MainWindow::SavePreset() {
    // The dialogs are ViewPresetDialogs' now; the window supplies what it
    // always did - the current view and how to apply one - through the
    // lambdas below.
    presetDialogs_.Save();
}

void MainWindow::LoadPreset() { presetDialogs_.Load(); }
void MainWindow::DeletePreset() { presetDialogs_.Delete(); }

// The bookmark store is joined once per refresh and the actions are
// BookmarkActions'. The window's half is the two functions it always supplied:
// which row is selected, and what "the bookmark set changed" means here - the
// rows are re-joined and the view is re-applied, because a pin and a note both
// live on the row.
void MainWindow::RefreshBookmarkMarks() { bookmarks_.JoinInto(store_); }
void MainWindow::ShowBookmarksList() { bookmarks_.ShowList(); }
void MainWindow::BookmarkSelectedConnection() { bookmarks_.ToggleSelected(); }
void MainWindow::EditSelectedBookmarkNote() { bookmarks_.EditSelectedNote(); }


// ---------------------------------------------------------------------------
// About box / shortcuts sheet
// Both used to be a bare MessageBoxW. The About summary runs to a
// dozen lines and the shortcut list is laid out in columns: a message
// box wraps them, cannot be monospaced, and does not scroll. A small
// modal sheet with a read-only, scrolling edit does all three, and the
// shortcut sheet is given a fixed-pitch font so its columns line up.
namespace {

struct TextSheetState {
    std::wstring text;
    HFONT font = nullptr;   // a stock object when set; never owned here
    bool selectAll = false;
    bool initialized = false;
};

INT_PTR CALLBACK TextSheetProc(HWND dlg, UINT msg,
                                    WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG: {
            auto* st = reinterpret_cast<TextSheetState*>(lParam);
            ::SetWindowLongPtrW(dlg, DWLP_USER,
                                  reinterpret_cast<LONG_PTR>(st));
            if (st != nullptr) st->initialized = true;
            HWND edit = ::GetDlgItem(dlg, kTextSheetEditId);
            if (edit != nullptr && st != nullptr) {
                ::SetWindowTextW(edit, st->text.c_str());
                if (st->font != nullptr)
                    ::SendMessageW(edit, WM_SETFONT,
                                     reinterpret_cast<WPARAM>(st->font),
                                     TRUE);
                ::SendMessageW(edit, EM_SETSEL, 0, st->selectAll ? -1 : 0);
                if (st->selectAll) {
                    ::SetFocus(edit);
                    return FALSE;
                }
            }
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
                ::EndDialog(dlg, LOWORD(wParam));
                return TRUE;
            }
            break;
        case WM_CLOSE:
            ::EndDialog(dlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

// 4-DLU alignment, local to this translation unit: PromptDialog and
// BlockedPeersDialog each carry their own Pad4 in their anonymous
// namespaces, so this one does too rather than reaching into another.
size_t Pad4Local(size_t n) {
    return (n + 3) & ~static_cast<size_t>(3);
}

// A bounds-checked DLGITEMTEMPLATE writer, the same shape PromptDialog
// and BlockedPeersDialog use, so a partial template is never handed to
// the dialog manager (cdit says how many controls it will read).
bool WriteSheetItem(BYTE** p, BYTE* end, DWORD style, short x,
                        short y, short cx, short cy, int id,
                        WORD cls, const wchar_t* caption) {
    const uintptr_t address = reinterpret_cast<uintptr_t>(*p);
    const uintptr_t alignedAddress = (address + 3u) & ~static_cast<uintptr_t>(3u);
    if (alignedAddress < address ||
        alignedAddress - address > static_cast<uintptr_t>(end - *p))
        return false;
    *p = reinterpret_cast<BYTE*>(alignedAddress);
    const size_t capChars =
        (caption != nullptr) ? wcslen(caption) + 1 : 1;
    const size_t capBytes = Pad4Local(capChars * sizeof(wchar_t));
    const size_t need = sizeof(DLGITEMTEMPLATE) + 4 + capBytes + 2;
    if (static_cast<size_t>(end - *p) < need) return false;
    auto* it = reinterpret_cast<DLGITEMTEMPLATE*>(*p);
    it->style = style;
    it->dwExtendedStyle = 0;
    it->x = x; it->y = y; it->cx = cx; it->cy = cy;
    it->id = static_cast<WORD>(id);
    *p += sizeof(DLGITEMTEMPLATE);
    // Extended window class: a 0xFFFF marker followed by the ordinal.
    *reinterpret_cast<WORD*>(*p) = 0xFFFF;
    *reinterpret_cast<WORD*>(*p + 2) = cls;
    *p += 4;
    if (caption != nullptr)
        memcpy(*p, caption, capChars * sizeof(wchar_t));
    else
        memset(*p, 0, sizeof(wchar_t));
    *p += capBytes;
    *reinterpret_cast<WORD*>(*p) = 0;   // no extra data
    *p += 2;
    return true;
}

// The sheet template: a scrolling read-only edit over an OK button.
// Coordinates are dialog units, as in every in-memory template here.
std::vector<BYTE> MakeTextSheetTemplate(const wchar_t* title) {
    if (title == nullptr) return std::vector<BYTE>();
    const size_t titleBytes =
        Pad4Local((wcslen(title) + 1) * sizeof(wchar_t));
    constexpr wchar_t kFont[] = L"Segoe UI";
    const size_t fontBytes =
        Pad4Local((sizeof(kFont) / sizeof(wchar_t)) * sizeof(wchar_t));

    // Two controls. The capacity is deliberately generous - the writer
    // bounds-checks every byte and the buffer is trimmed to the true
    // length at the end - so an over-estimate here is harmless and an
    // under-estimate is caught by the writer, not by the dialog manager.
    const size_t capacity =
        sizeof(DLGTEMPLATE) + 4 + titleBytes + 2 + fontBytes +
        2 * (sizeof(DLGITEMTEMPLATE) + 4 +
             Pad4Local(16 * sizeof(wchar_t)) + 2) +
        4096;
    std::vector<BYTE> buf(capacity, 0);
    BYTE* p = buf.data();
    BYTE* const begin = p;
    BYTE* const end = buf.data() + buf.size();

    if (static_cast<size_t>(end - p) < sizeof(DLGTEMPLATE))
        return std::vector<BYTE>();
    auto* dlg = reinterpret_cast<DLGTEMPLATE*>(p);
    dlg->style = DS_CENTER | WS_POPUP | WS_CAPTION | WS_SYSMENU |
                 DS_MODALFRAME | DS_SETFONT;
    dlg->dwExtendedStyle = 0;
    dlg->cdit = 2;
    dlg->x = 0; dlg->y = 0; dlg->cx = 440; dlg->cy = 300;
    p += sizeof(DLGTEMPLATE);

    if (static_cast<size_t>(end - p) < 4)
        return std::vector<BYTE>();
    memset(p, 0, 4);   // no menu, default window class
    p += 4;

    const size_t tChars = wcslen(title) + 1;
    if (static_cast<size_t>(end - p) < titleBytes)
        return std::vector<BYTE>();
    memcpy(p, title, tChars * sizeof(wchar_t));
    p += titleBytes;

    if (static_cast<size_t>(end - p) < 2)
        return std::vector<BYTE>();
    *reinterpret_cast<WORD*>(p) = 9;   // 9pt, matching the app
    p += 2;

    if (static_cast<size_t>(end - p) < fontBytes)
        return std::vector<BYTE>();
    memcpy(p, kFont, (sizeof(kFont) / sizeof(wchar_t)) * sizeof(wchar_t));
    p += fontBytes;

    // The scrolling text edit, then the OK button.
    if (!WriteSheetItem(&p, end,
                        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER |
                        WS_TABSTOP | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                        8, 8, 424, 258, kTextSheetEditId, 0x81, nullptr) ||
        !WriteSheetItem(&p, end,
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                            BS_DEFPUSHBUTTON,
                        376, 274, 56, 16, IDOK, 0x80, L"OK")) {
        return std::vector<BYTE>();
    }

    buf.resize(static_cast<size_t>(p - begin));
    return buf;
}

}  // namespace

bool ShowTextSheet(HWND owner, const wchar_t* title,
                   const std::wstring& text, HFONT font, bool selectAll) {
    TextSheetState st;
    st.text = text;
    st.font = font;
    st.selectAll = selectAll;
    std::vector<BYTE> tpl = MakeTextSheetTemplate(title);
    if (tpl.empty()) {
        // The template could not be built. Fall back to a message box
        // so the information still reaches the user rather than
        // silently showing nothing.
        ::MessageBoxW(owner, text.c_str(), title,
                          MB_OK | MB_ICONINFORMATION);
        return false;
    }
    const INT_PTR result = ::DialogBoxIndirectParamW(::GetModuleHandleW(nullptr),
                                  reinterpret_cast<LPCDLGTEMPLATEW>(tpl.data()),
                                  owner, TextSheetProc,
                                  reinterpret_cast<LPARAM>(&st));
    if (result == -1 || !st.initialized) {
        ::MessageBoxW(owner, text.c_str(), title,
                      MB_OK | MB_ICONINFORMATION);
        return false;
    }
    return true;
}

void MainWindow::ShowAboutBox() {
    // Every line of the capability block is read from live state, not
    // hard-coded: a summary that always said "Administrator: no" would be
    // wrong for exactly the user most likely to be reading it.
    BuildSummary s;
    // IsElevated(), not IsElevatedInstance(): the marker only says "this
    // process was relaunched by WinTCP". A user who launched an already-
    // elevated console has no marker and was told "Administrator no" while
    // every elevated feature worked.
    s.elevated = IsElevated();
    s.etwRunning = etw_->Running();
    s.trafficFallback = fallbackFlag_->load(std::memory_order_relaxed);
    // the same two counters the status bar shows, so the About box and
    // the pane cannot disagree. Reported only when the sampler exists at all:
    // a window with traffic off has no opinion, and printing a confident 0
    // there would claim a check nobody ran.
    if (socketTraffic_ != nullptr) {
        s.trafficScanRan = true;
        s.trafficTimeouts = socketTraffic_->TimeoutCount();
        s.trafficScanFailures = socketTraffic_->ScanFailureCount();
    }
    s.geoIpLoaded = enrich_.CountryLoaded();
    s.presetsAvailable = true;   // the store is in-process; always available
    for (int i = 0; i < COL_COUNT; ++i)
        if ((cols_.VisibleMask() & (1u << i)) != 0) ++s.visibleColumnCount;
    s.totalColumnCount = COL_COUNT;
    s.rowCount = store_.View().size();
    s.rowCountKnown = true;
    s.columnCountKnown = true;
    ShowTextSheet(hwnd_, L"About WinTCP", AboutText(s), nullptr);
}

// The sheet is rendered from the same list the selftest checks, so a
// shortcut that exists but is undocumented (or documented but absent) is a
// test failure rather than something a user discovers.
void MainWindow::ShowShortcutsSheet() {
    // A fixed-pitch font so the shortcut columns line up,
    // which the proportional message-box font could not do.
    ShowTextSheet(hwnd_, L"WinTCP — Keyboard shortcuts",
                      ShortcutsText(),
                      static_cast<HFONT>(
                          ::GetStockObject(OEM_FIXED_FONT)));
}

// Pick a user-supplied MaxMind .mmdb and start filling the Country
// column.
//
// The database is NEVER downloaded. This is a deliberate constraint, not an
// omission: an auto-fetch would mean the app silently pulls tens of megabytes
// from a third party, and a privacy-sensitive network tool that phones home
// is a different product. The user supplies the file.
//
// A load failure reports the parser's own message rather than a generic
// "could not open": GeoIpDatabase::Load distinguishes a missing file from a
// truncated one from a file that is not an MMDB at all, and those need
// different things from the user.
void MainWindow::LoadGeoIpDatabase() {
    wchar_t file[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"MaxMind databases (*.mmdb)\0*.mmdb\0"
                      L"All files (*.*)\0*.*\0\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open a MaxMind .mmdb database";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    // comdlg32.dll is delay-loaded; see the export-dialog guard above.
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return;
    if (!::GetOpenFileNameW(&ofn)) return;   // cancelled: not an error

    std::wstring error;
    if (!enrich_.LoadCountry(file, &error)) {
        ::MessageBoxW(hwnd_, error.c_str(), L"GeoIP database not loaded",
                      MB_OK | MB_ICONERROR);
        return;
    }

    // persist the path the user picked, so it survives a relaunch.
    // Only reached on a successful load: a cancelled picker returned above,
    // and a load that failed returned with the parser's reason.
    ::wcsncpy_s(settings_.geoIpPath, file, _TRUNCATE);
    // Routed through PersistSettings like the other two, and this is the one
    // where the discarded bool hurt most: the user has just clicked a file in a
    // dialog, so a write that fails loses exactly the thing they chose to do,
    // and they find out at the next launch with no message in between. This was
    // the third discarding call site; the two the change names were not the
    // only ones.
    PersistSettings("geoip path picked");

    // Fill immediately rather than waiting for the next tick, so the Country
    // column appears at once. The user chose a file precisely to see results.
    // Only the database that was loaded: the ASN pass has its own loader and
    // its own settings key, and offering the other one here would make this
    // command do twice what it says.
    OfferGeoIpForAllRows();
    ApplyView();
    UpdateStatusBar(std::wstring());
}

// The ASN picker. A near-copy of LoadGeoIpDatabase, and deliberately so:
// the two differ only in which member they load, which settings key they write
// and the words in the message boxes. Factoring the shared half would mean
// threading a "which database" enum through the error strings for no gain, and
// the two will diverge anyway - this one names ASN in every message so a user
// who picked the wrong file can tell which half is unhappy.
void MainWindow::LoadAsnDatabase() {
    wchar_t file[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"MaxMind ASN databases (*.mmdb)\0*.mmdb\0"
                      L"All files (*.*)\0*.*\0\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    // Naming the expected product in the title: GeoLite2-Country is the file
    // most people already have, and picking it here produces an ASN column that
    // is always empty for a reason no message would otherwise explain.
    ofn.lpstrTitle = L"Open a GeoLite2-ASN .mmdb database";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return;
    if (!::GetOpenFileNameW(&ofn)) return;   // cancelled: not an error

    std::wstring error;
    if (!enrich_.LoadAsn(file, &error)) {
        ::MessageBoxW(hwnd_, error.c_str(),
                      L"ASN database not loaded (expected GeoLite2-ASN)",
                      MB_OK | MB_ICONERROR);
        return;
    }

    ::wcsncpy_s(settings_.asnIpPath, file, _TRUNCATE);
    PersistSettings("asn path picked");

    OfferAsnForAllRows();
    ApplyView();
    UpdateStatusBar(std::wstring());
}

// ---- settings ---------------------------------------------------

void MainWindow::SaveSettings() {
    RECT rc = {};
    if (hwnd_ != nullptr && ::GetWindowRect(hwnd_, &rc) != FALSE) {
        settings_.winX = rc.left;
        settings_.winY = rc.top;
        settings_.winW = rc.right - rc.left;
        settings_.winH = rc.bottom - rc.top;
        settings_.winPlaced = settings_.winW > 0 && settings_.winH > 0;
        settings_.showCmd = ::IsZoomed(hwnd_) ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;
    }
    HarvestColumnWidths();                 // physical -> logical widths
    cols_.SaveToSettings(&settings_);
    settings_.colWidthsValid = true;
    settings_.colWidthsValid = true;
    settings_.sortCol = store_.SortColumn();
    settings_.sortAsc = store_.SortAscending();
    settings_.autoRefresh = autoRefresh_;
    settings_.intervalMs = autoRefreshMs_;
    settings_.resolveHosts = dnsEnabled_;
    settings_.topMost = topMost_;
    settings_.trayEnabled = trayEnabled_;
    settings_.trayMinimizeChoice = trayMinimizeChoice_;
    settings_.trafficEnabled = etw_->Running();
    const std::wstring filter = CurrentSearchText();
    ::wcsncpy_s(settings_.filter, filter.c_str(), _TRUNCATE);
    // the GeoIP path is part of the view, not just the data - it has
    // to leave here with everything else the user chose.
    //
    // Set BEFORE the single write below. It used to be set BETWEEN two calls to
    // settings_.Save(), so the first write could never have carried it and was
    // pure waste: two full registry writes on every exit, and the second
    // overwrote the first regardless.
    ::wcsncpy_s(settings_.geoIpPath,
                enrich_.CountryLoaded() ? enrich_.CountrySourcePath().c_str() : L"",
                _TRUNCATE);
    // the ASN path is remembered on the same terms - whatever is actually
    // loaded - so a database the user cleared does not come back on the next
    // launch. Same single PersistSettings call below; do not add another.
    ::wcsncpy_s(settings_.asnIpPath,
                enrich_.AsnLoaded() ? enrich_.AsnSourcePath().c_str() : L"",
                _TRUNCATE);
    PersistSettings("shutdown");
}

// The one place this class writes settings. Every caller goes through here, and
// the reason is not tidiness: the two sites this replaced each called
// Settings::Save() directly and each DISCARDED the bool, so a write that failed
// was indistinguishable from one that succeeded and the user's column layout,
// window position, filter and GeoIP path were simply gone on the next launch.
//
// `why` names the caller. It costs one argument and buys the ability to answer
// "which of these lost my settings?" from a counter instead of a memory.
void MainWindow::PersistSettings(const char* why) {
    ++settingsSaveAttempts_;
    if (!settings_.Save()) {
        ++settingsSaveFailures_;
        // Deliberately NOT a MessageBox. One of the two callers runs from
        // ~MainWindow, where popping a dialog up during teardown is worse than
        // saying nothing; the other runs on a live window, where a box on every
        // drag would be intolerable. So the count is recorded and read through
        // the op table, and no attempt is made to interrupt the user for it.
        (void)why;
    }
}

// ---- change log -------------------------------------------------

namespace {

// Open 'path' in append mode, writing the CSV header when the file is
// new or empty. Returns INVALID_HANDLE_VALUE on failure.
HANDLE OpenLogAppend(const wchar_t* path, DWORD& error) {
    HANDLE h = ::CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = ::GetLastError();
        return h;
    }
    // OPEN_ALWAYS starts at offset 0; move to the end so we append.
    // SetFilePointerEx, not SetFilePointer: a file position of 0xFFFFFFFF
    // is a legal 4 GiB offset, so it cannot be distinguished from the
    // INVALID_SET_FILE_POINTER failure sentinel.
    LARGE_INTEGER end = {};
    end.QuadPart = 0;
    if (::SetFilePointerEx(h, end, nullptr, FILE_END) == FALSE) {
        error = ::GetLastError();
        ::CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    LARGE_INTEGER size = {};
    if (::GetFileSizeEx(h, &size) != FALSE && size.QuadPart == 0) {
        const char* header =
            "time,event,proto,local,remote,state,oldstate,pid,process\r\n";
        DWORD written = 0;
        ::WriteFile(h, header, static_cast<DWORD>(strlen(header)), &written,
                    nullptr);
    }
    error = NO_ERROR;
    return h;
}

}  // namespace

bool MainWindow::OpenLogFromSettings() {
    if (!settings_.logEnabled || settings_.logPath[0] == 0) return false;
    DWORD err = NO_ERROR;
    logFile_ = OpenLogAppend(settings_.logPath, err);
    if (logFile_ == INVALID_HANDLE_VALUE) {
        // The saved path is gone or unwritable: drop logging quietly and
        // keep the app usable (the user can pick a new file anytime).
        settings_.logEnabled = false;
        settings_.logPath[0] = 0;
        logPath_.clear();
        return false;
    }
    logPath_ = settings_.logPath;
    SetMenuCheck(::GetMenu(hwnd_), IDM_FILE_CHANGELOG, true);
    return true;
}

void MainWindow::ToggleChangeLog() {
    if (logFile_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(logFile_);
        logFile_ = INVALID_HANDLE_VALUE;
        logPath_.clear();
        settings_.logEnabled = false;
        settings_.logPath[0] = 0;
        SetMenuCheck(::GetMenu(hwnd_), IDM_FILE_CHANGELOG, false);
        return;
    }

    wchar_t path[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFile = path;
    ofn.nMaxFile = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
    ofn.lpstrFilter = L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrDefExt = L"csv";
    ofn.lpstrTitle = L"WinTCP - Select change log file";
    // Append semantics: no overwrite prompt (existing content is kept).
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    // comdlg32.dll is delay-loaded; see the export-dialog guard above.
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return;
    if (!::GetSaveFileNameW(&ofn)) return;

    DWORD err = NO_ERROR;
    HANDLE h = OpenLogAppend(path, err);
    if (h == INVALID_HANDLE_VALUE) {
        const std::wstring msg =
            L"Could not open the log file:\n" + FormatSystemError(err);
        ::MessageBoxW(hwnd_, msg.c_str(), L"WinTCP - Change log",
                      MB_OK | MB_ICONERROR);
        return;
    }
    logFile_ = h;
    logPath_ = path;
    settings_.logEnabled = true;
    ::wcsncpy_s(settings_.logPath, path, _TRUNCATE);
    SetMenuCheck(::GetMenu(hwnd_), IDM_FILE_CHANGELOG, true);
}

void MainWindow::WriteChangeLog() {
    // Always drain: events must not pile up while logging is off.
    //
    // TakeChangeEvents is DESTRUCTIVE - the first caller gets the events and
    // everyone after gets nothing. The file writer and the change-log window
    // are two independent consumers of the same stream, so the drain happens
    // ONCE here and the batch is handed to both. Draining inside the
    // "logging is off" early-return would starve the window of every event
    // on a machine where the file writer is not enabled, which is the default
    // and therefore the common case.
    const std::vector<RowChange> changes = store_.TakeChangeEvents();
    if (logFile_ == INVALID_HANDLE_VALUE || changes.empty()) {
        // The window is fed even when the file writer is off, and even when
        // there is nothing to write, so the two can never disagree about
        // which events exist.
        if (changeLog_.IsOpen()) changeLog_.AppendEvents(changes);
        return;
    }

    std::string out;
    for (const RowChange& ch : changes) {
        const char* event =
            (ch.kind == kChangeAppear)     ? "APPEAR"
            : (ch.kind == kChangeDisappear) ? "DISAPPEAR"
                                            : "STATE";
        std::string oldState;
        if (ch.kind == kChangeState) {
            Connection tmp = ch.row;
            tmp.identity.state = ch.oldState;
            ConnectionStore::FinalizeRow(tmp);   // idempotent label refresh
            oldState = WideToUtf8(tmp.keys.stateLabel);
        }
        out += WideToUtf8(FormatCurrentTime());
        out += ',';
        out += event;
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(ch.row.keys.protoLabel));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(ch.row.display.localEndpoint));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(ch.row.display.remoteEndpoint));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(ch.row.keys.stateLabel));
        out += ',';
        out += CsvEscapeUtf8(oldState);
        out += ',';
        out += std::to_string(ch.row.identity.pid);
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(ch.row.display.processName));
        out += "\r\n";
    }
    DWORD written = 0;
    ::WriteFile(logFile_, out.data(), static_cast<DWORD>(out.size()), &written,
                nullptr);
    // The window sees the same batch the file just got, from the same
    // drain. Appending here rather than at the drain means the file writer
    // cannot skip it on a write error.
    if (changeLog_.IsOpen()) changeLog_.AppendEvents(changes);
}

void MainWindow::FocusFilterBox() {
    if (hwndSearchEdit_ == nullptr) return;
    ::SetFocus(hwndSearchEdit_);
    ::SendMessageW(hwndSearchEdit_, EM_SETSEL, 0, -1);
}

void MainWindow::ClearFilterBox() {
    if (hwndSearchEdit_ != nullptr && !CurrentSearchText().empty())
        ::SetWindowTextW(hwndSearchEdit_, L"");
    // Re-arm the debounce timer explicitly: EN_CHANGE is not guaranteed
    // for a programmatic SetWindowText when the box was already empty,
    // and ApplyView is cheap and idempotent either way.
    ::KillTimer(hwnd_, kFilterTimerId);
    ::SetTimer(hwnd_, kFilterTimerId, kFilterDebounceMs, nullptr);
}

// ---- system colors / high contrast -----------------------------------------
// The app has no theme of its own: it uses the system window colors, so it
// follows the user's light/dark preference automatically. When high
// contrast is active (WO_HC_ACTIVE) those colors are the accessibility
// palette, which is exactly what we want - so this is one code path, not a
// special case.

bool MainWindow::HighContrastActive() const {
    // one probe for the whole app (Theme.h); the body used to repeat
    // the SystemParametersInfoW call DetailsDialog carried line for line.
    return wintcp::HighContrastActive();
}

// True when the system theme is dark, so highlight colors can be picked to
// stay legible. Derived from COLOR_WINDOW rather than a setting: the app
// has no theme of its own, it simply follows the system one. High contrast
// always counts as "light" for this purpose - its palette is chosen for
// maximum contrast, not for darkness.
bool MainWindow::ThemeIsDark() const {
    if (HighContrastActive()) return false;
    const COLORREF bg = ::GetSysColor(COLOR_WINDOW);
    const BYTE r = static_cast<BYTE>(bg & 0xFF);
    const BYTE g = static_cast<BYTE>((bg >> 8) & 0xFF);
    const BYTE b = static_cast<BYTE>((bg >> 16) & 0xFF);
    // Rec. 601 luma; below 128 counts as a dark background.
    return (299 * r + 587 * g + 114 * b) / 1000 < 128;
}

void MainWindow::RefreshSystemColors() {
    // the change-log window is a top-level window, so it does not get
    // WM_SYSCOLORCHANGE from the main window. Forward it explicitly or the
    // log window keeps stale colours after a theme change while the rest of
    // the app has already repainted.
    if (changeLog_.IsOpen()) {
        ::SendMessageW(changeLog_.Handle(), WM_SYSCOLORCHANGE, 0, 0);
        ::RedrawWindow(changeLog_.Handle(), nullptr, nullptr,
                       RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
    }
    const COLORREF bg = ::GetSysColor(COLOR_WINDOW);
    const COLORREF tx = ::GetSysColor(COLOR_WINDOWTEXT);

    if (hwndBrushWindow_ != nullptr) ::DeleteObject(hwndBrushWindow_);
    hwndBrushWindow_ = ::CreateSolidBrush(bg);

    if (list_.Handle() != nullptr) {
        ::SendMessageW(list_.Handle(), LVM_SETTEXTCOLOR, 0, tx);
        ::SendMessageW(list_.Handle(), LVM_SETTEXTBKCOLOR, 0, bg);
        ::SendMessageW(list_.Handle(), LVM_SETBKCOLOR, 0, bg);
    }
    if (hwndStatus_ != nullptr)
        ::SendMessageW(hwndStatus_, SB_SETBKCOLOR, 0,
                       static_cast<LPARAM>(::GetSysColor(COLOR_3DFACE)));
    ::RedrawWindow(hwnd_, nullptr, nullptr,
                   RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

// ---- tray icon / minimize-to-tray -------------------------------
//
// The tray's plumbing (add/remove/tip/balloon/menu) belongs to TrayIcon;
// what is left here is WHEN. One call covers both directions so the icon
// and the menu check cannot disagree - the old code carried a
// trayEnabled_/trayIconShown_ pair for exactly that reason, and a second
// truth is the thing it was avoiding.
void MainWindow::SyncTray() {
    if (hwnd_ == nullptr) return;
    if (trayEnabled_) {
        if (tray_.Add(hwnd_, hInstance_)) UpdateTrayTip();
    } else {
        tray_.Remove();
    }
    SetMenuCheck(::GetMenu(hwnd_), IDM_VIEW_TRAY, trayEnabled_);
}

MainWindow::MinimizeTarget MainWindow::ResolveMinimize() {
    // the prompt only fires when the tray icon is OFF. With the tray on,
    // the existing SC_MINIMIZE handler hides the window to the tray directly.
    if (trayEnabled_) return MinimizeTarget::kTray;

    // kTrayMinimizeChoice: 0 = never asked, 1 = remembered tray, 2 = remembered exit.
    if (trayMinimizeChoice_ == 1) return MinimizeTarget::kTray;
    if (trayMinimizeChoice_ == 2) return MinimizeTarget::kExit;

    // First minimize without a remembered choice: prompt. A TaskDialog gives us a
    // checkbox for "don't ask again" with no template to maintain, and is
    // available on every Windows version this tool supports (Vista+).
    //
    // comdlg32.dll (TaskDialogIndirect) is delay-loaded; if it is absent the
    // prompt cannot be shown, so fall back to the plain taskbar minimize the
    // user asked for.
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return MinimizeTarget::kTaskbar;

    TASKDIALOGCONFIG tc = {};
    tc.cbSize = sizeof(tc);
    tc.hwndParent = hwnd_;
    tc.dwFlags = TDF_USE_HICON_MAIN | TDF_ALLOW_DIALOG_CANCELLATION;
    tc.hMainIcon = ::LoadIconW(nullptr, IDI_QUESTION);
    tc.pszWindowTitle = L"WinTCP";
    tc.pszMainInstruction =
        L"Minimize to tray hides WinTCP in the notification area instead of "
        L"keeping a taskbar button, and adds a tray icon you can right-click.";
    tc.pszContent =
        L"How do you want WinTCP to behave when you minimize it?";
    tc.pszVerificationText = L"&Don't ask me again (applies to both options)";

    enum { kBtnTray = 100, kBtnExit };
    TASKDIALOG_BUTTON btns[2] = {
        { kBtnTray, L"&Minimize to tray" },
        { kBtnExit, L"C&lose WinTCP (exit)" },
    };
    tc.pButtons = btns;
    tc.cButtons = 2;
    tc.nDefaultButton = kBtnTray;          // tray is the safer, more useful default

    int which = 0;
    int radio = 0;
    BOOL checked = FALSE;
    HRESULT hr = ::TaskDialogIndirect(&tc, &which, &radio, &checked);
    if (hr != S_OK || which == IDCANCEL) {
        // A cancel / close (X) exits this minimize without enabling the tray
        // or remembering a permanent choice. The prompt returns next time.
        return MinimizeTarget::kExit;
    }
    if (which == kBtnExit) {
        // Explicit exit: remember it only when "don't ask again" is checked.
        if (checked) {
            trayMinimizeChoice_ = 2;
            settings_.trayMinimizeChoice = 2;
            settings_.Save();
        }
        return MinimizeTarget::kExit;
    }

    // "Don't ask again" checkbox. When set, remember the chosen target so the
    // prompt never returns. When not set, leave choice = 0 and the dialog will
    // fire again next time - the user has not consented to a permanent decision.
    if (checked) {
        trayMinimizeChoice_ = 1;           // remember: tray
        settings_.trayMinimizeChoice = 1;
    }
// Enable the tray icon so the chosen behaviour takes effect on the next
// minimize and the icon survives this session.
trayEnabled_ = true;
settings_.trayEnabled = true;
settings_.Save();
SyncTray();
return MinimizeTarget::kTray;
}

}  // namespace wintcp

// ChangeLogWindow.cpp
// SPDX-License-Identifier: Apache-2.0
// See ChangeLogWindow.h. A virtual ListView over a capped ring of
// pre-formatted entries, a follow-the-tail scroll rule, and a button row.
// No dialog template, matching the rest of the codebase's zero-dependency
// style.

#include "ChangeLogWindow.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <commctrl.h>    // ListView_*, LVM_*, SetWindowSubclass
#include <commdlg.h>     // GetSaveFileNameW, OPENFILENAMEW
#include <windowsx.h>    // GET_X_LPARAM / GET_Y_LPARAM
#include <windows.h>

#include <algorithm>
#include <cstring>

#include "Utils.h"
#include "ConnectionsList.h"  // WriteClipboardText / NativeClipboardApi
#include "TextSheetDialog.h"  // manual clipboard fallback
#include "WinCaps.h"   // DelayLoadGuard: comdlg32.dll is delay-loaded

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
// GetSaveFileNameW lives in comdlg32, which the project already links (the
// main window's change-log dialog uses it). Repeating it here means this
// file builds against the same set whether or not it is the first one
// compiled.
#pragma comment(lib, "comdlg32.lib")

namespace wintcp {
namespace {

// Control ids are local to this window, so they cannot collide with the main
// window's control ids.
const UINT IDC_LOG_PAUSE = 1;
const UINT IDC_LOG_CLEAR = 2;
const UINT IDC_LOG_SAVE  = 3;
const UINT IDC_LOG_COPY  = 4;
const UINT IDC_LOG_CLOSE = 5;
const UINT IDC_LOG_LIST  = 6;   // the list's child id, for WM_NOTIFY routing
// The three kind checkboxes - the GUI's `--event appear,disappear,state`.
const UINT IDC_LOG_EV_APPEAR     = 7;
const UINT IDC_LOG_EV_DISAPPEAR  = 8;
const UINT IDC_LOG_EV_STATE      = 9;

// Logical (96 dpi) layout metrics.
constexpr int kMargin = 8;
constexpr int kBtnH = 26;
constexpr int kBtnWPause = 80;
constexpr int kBtnWClear = 80;
constexpr int kBtnWSave = 110;
constexpr int kBtnWCopy = 90;
constexpr int kBtnWClose = 70;
constexpr int kBtnGap = 6;
constexpr int kStatusH = 22;
// The kind-checkbox row. A checkbox wants its own height - the default
// button height clips the box and the label - and the widths are generous
// because "Disappear" is the longest of the three labels with its accelerator.
constexpr int kChkH = 20;
constexpr int kChkWAppear = 90;
constexpr int kChkWDisappear = 110;
constexpr int kChkWState = 80;

// Logical column widths. Time and state are fixed - the first needs ~19
// characters, the second ~25 for "SYN_SENT -> ESTABLISHED" - while process
// and the two endpoints share the slack, because that is where resizing the
// window buys the user something.
constexpr int kColTimeW = 150;
constexpr int kColEventW = 88;
constexpr int kColProtoW = 56;
constexpr int kColStateW = 250;

// Most rows one clipboard copy will take. A guard, not a limit on what the user
// may select: it exists so a future select-all cannot build a kMaxEvents-sized
// buffer behind the user's back, and it sits below the event cap on purpose —
// a copy that silently dropped rows would be worse than one that stopped.
constexpr size_t kMaxClipboardRows = 8192;
constexpr int kMinTotalW = 900;   // below this the fixed columns do not fit

// The DPI every MulDiv in this file scales FROM: USER_DEFAULT_SCREEN_DPI (96),
// the grid the layout metrics above were authored on. Same number as the
// kDefaultScreenDpi fallback in Utils.cpp and FontCache.cpp, but a different
// role, so it keeps its own name.
constexpr int kMetricsDpi = 96;

// Default window size, in that grid. Wide enough that the four fixed columns
// plus a usable process and endpoint column all fit at once.
constexpr int kDefaultWidth96 = 860;
constexpr int kDefaultHeight96 = 480;

// Smallest the window will track. The width is kMinTotalW; the height is the
// point at which the list stops reading as a list and starts as a slot.
constexpr int kMinTrackHeight96 = 200;

// Narrowest the process and endpoint columns will share between them. A
// narrower split clips every endpoint, so the split is floored rather than
// letting it shrink with the window.
constexpr int kMinElasticW96 = 80;

// Debug-output buffers for the two CreateWindowExW / RegisterClassExW failure
// paths. One line plus an error number, so this is slack; swprintf_s truncates
// rather than overruns in any case.
constexpr size_t kWindowErrChars = 128;

void SetChildFont(HWND hwnd, HFONT font) {
    if (font != nullptr && hwnd != nullptr) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font),
                       MAKELPARAM(TRUE, 0));
    }
}

// The codebase's placeholder for a value nobody could read, so an empty
// endpoint reads the same here as it does in the main list.
std::wstring DashIfEmpty(const std::wstring& s) {
    return s.empty() ? std::wstring(L"—") : s;
}

}  // namespace

const wchar_t* ChangeLogWindow::kClassName = L"WinTcpChangeLogWnd";

constexpr size_t ChangeLogWindow::kMaxEvents;

ChangeLogWindow::~ChangeLogWindow() {
    // Nothing GDI-owned: the UI font is borrowed from MainWindow and the
    // ListView owns its own. So closing the window releases everything this
    // class touches, and repeated open/close cycles cannot accumulate.
    Close();
}

int ChangeLogWindow::S(int px96) const {
    const UINT dpi = QueryDpiForWindow(hwnd_);
    return ::MulDiv(px96, static_cast<int>(dpi), kMetricsDpi);
}

void ChangeLogWindow::CenterOnOwner(HWND owner) {
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

void ChangeLogWindow::Show(HWND owner, HFONT font) {
    if (font_ != font) ApplyFont(font);

    if (hwnd_ == nullptr) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = &ChangeLogWindow::WindowProc;
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wc.lpszClassName = kClassName;
        // Idempotent registration (ERROR_CLASS_ALREADY_EXISTS is fine) - and
        // the window CLASS carries a background brush, which nothing else here
        // does. Without one the window paints whatever was on the screen, and a
        // log opened over the list came up looking like a hole rather than a
        // window.
        if (::RegisterClassExW(&wc) == 0 &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            // Registration failed for a reason other than "already there".
            // Returning silently leaves the caller with a ChangeLogWindow whose
            // hwnd_ is still null and no idea why - which is exactly the state
            // the UI harness reported as "the command opens the window: FAIL,
            // created=no". Report the error to the debug output so the next
            // occurrence is diagnosable without a debugger attached.
            wchar_t msg[kWindowErrChars] = {0};
            ::swprintf_s(msg, L"[changelog] RegisterClassExW failed: %lu\n",
                         ::GetLastError());
            ::OutputDebugStringW(msg);
            return;
        }

        const UINT dpi = QueryDpiForWindow(owner);   // owner's monitor DPI
        hwnd_ = ::CreateWindowExW(
            0, kClassName, L"WinTCP - Connection change log",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT,
            CW_USEDEFAULT,
            ::MulDiv(kDefaultWidth96, static_cast<int>(dpi), kMetricsDpi),
            ::MulDiv(kDefaultHeight96, static_cast<int>(dpi), kMetricsDpi),
            owner, nullptr,
            ::GetModuleHandleW(nullptr), this);
        if (hwnd_ == nullptr) {
            // CreateWindowExW failed. Same reasoning as the registration branch
            // above: an unexplained null window is the failure mode that cost the
            // most time to diagnose, so it says what happened instead of
            // returning quietly.
            wchar_t msg[kWindowErrChars] = {0};
            ::swprintf_s(msg, L"[changelog] CreateWindowExW failed: %lu\n",
                         ::GetLastError());
            ::OutputDebugStringW(msg);
            return;
        }
        CenterOnOwner(owner);
    }

    // Re-showing means "I want the live view". The buffer is kept (the main
    // window keeps feeding it) but the view goes back to the tail.
    follow_ = true;
    MaybeFollow();

    if (::IsWindowVisible(hwnd_) == FALSE) ::ShowWindow(hwnd_, SW_SHOW);
    ::SetForegroundWindow(hwnd_);
    // Diagnostic: WM_CREATE reached? Logged to the debugger only, so it costs
    // nothing in normal use. Kept while the work is being verified, because
    // "the window did not appear" has three possible causes (not created,
    // created but WM_CREATE skipped, created and hidden) and guessing between
    // them from the outside is slow.
    ::OutputDebugStringW(hwndEvAppear_ != nullptr
                             ? L"[changelog] WM_CREATE built the controls\n"
                             : L"[changelog] WM_CREATE did NOT build controls\n");
    UpdateStatus();
    UpdatePauseButton();
}

void ChangeLogWindow::Close() {
    if (hwnd_ != nullptr && ::IsWindow(hwnd_)) ::DestroyWindow(hwnd_);
}

bool ChangeLogWindow::IsVisible() const {
    return hwnd_ != nullptr && ::IsWindowVisible(hwnd_) == TRUE;
}

void ChangeLogWindow::ApplyFont(HFONT font) {
    font_ = font;   // borrowed from MainWindow; never deleted here
    if (font_ == nullptr) return;
    SetChildFont(hwndList_, font_);
    SetChildFont(hwndPause_, font_);
    SetChildFont(hwndClear_, font_);
    SetChildFont(hwndSave_, font_);
    SetChildFont(hwndCopy_, font_);
    SetChildFont(hwndClose_, font_);
    SetChildFont(hwndStatus_, font_);
    // The kind checkboxes are children too, and leaving them on the
    // dialog's default font would make them a different size from every other
    // control in the window - the kind of inconsistency a user reads as a bug
    // even when they cannot say what is wrong.
    SetChildFont(hwndEvAppear_, font_);
    SetChildFont(hwndEvDisappear_, font_);
    SetChildFont(hwndEvState_, font_);
}

// ---- buffering -------------------------------------------------------------

// The GUI's `--event`. Applied HERE, at the point events enter the
// buffer, rather than in the renderer - so the buffer, the count, the CSV
// export and the Copy all agree with what is on screen. Filtering at render
// time instead would leave "312 events" in the status bar while showing four,
// which is the kind of small lie that makes a tool untrustworthy.
//
// Mirrors the CLI's ordering: the kind mask is applied BEFORE anything else
// looks at the events, exactly as --event is applied before the row filter.
void ChangeLogWindow::SetEventMask(bool appear, bool disappear, bool state) {
    evAppear_ = appear;
    evDisappear_ = disappear;
    evState_ = state;
    // The CHECKBOXES follow the mask, not the other way round. Setting the
    // member without ticking the box would leave the control showing the wrong
    // state, and the next click would toggle from the wrong baseline - so any
    // code path that sets the mask (this one, the harness, a future restore)
    // gets the visible state right for free.
    const auto setBox = [](HWND h, bool v) {
        if (h != nullptr)
            ::CheckDlgButton(::GetParent(h),
                             ::GetDlgCtrlID(h),
                             v ? BST_CHECKED : BST_UNCHECKED);
    };
    setBox(hwndEvAppear_, evAppear_);
    setBox(hwndEvDisappear_, evDisappear_);
    setBox(hwndEvState_, evState_);
}

namespace {

// One kind's visibility. A free function rather than three lines at each call
// site, because getting one of the three wrong is the entire failure mode.
bool KindEnabled(const ChangeLogWindow& w, int kind) {
    // 'int', not RowChangeKind: RowChange's field is declared `int`, and taking
    // the enum by value here needs a conversion that /W4 rejects at every call
    // site. The switch below covers all three enumerators, so a new kind added
    // to RowChangeKind falls into `default` and is SHOWN rather than silently
    // dropped - the safe direction for a log.
    switch (kind) {
        case kChangeAppear:     return w.EventAppear();
        case kChangeDisappear: return w.EventDisappear();
        case kChangeState:     return w.EventState();
        default:                return true;
    }
}

}  // namespace

void ChangeLogWindow::AppendEvents(const std::vector<RowChange>& events) {
    if (events.empty()) return;

    std::vector<RowChange> kept;
    kept.reserve(events.size());
    for (const RowChange& e : events) {
        if (KindEnabled(*this, e.kind)) kept.push_back(e);
    }
    // Nothing matched the mask. Return WITHOUT clearing or touching the cap -
    // an empty batch must be a no-op, not a reset, or a log whose kinds are
    // all switched off would silently discard its history.
    if (kept.empty()) return;
    const std::vector<RowChange>& events2 = kept;

    // One stamp per batch, not per event: every row in a batch comes from
    // one refresh, so the values are identical anyway, and a burst of
    // thousands of rows costs one GetLocalTime instead of thousands.
    const std::wstring stamp = FormatCurrentTime();

    const size_t before = events_.size();
    size_t evicted = 0;

    if (before + events2.size() > kMaxEvents) {
        // Drop from the front *before* appending, so an oversized batch
        // never transiently allocates more than the cap. The oldest rows
        // go: a log that kept the head and cut the tail would show the
        // user events from an hour ago and silently discard the one that
        // just happened.
        evicted = (std::min)(before, before + events2.size() - kMaxEvents);
        if (evicted >= before) {
            // The batch alone overflows the cap: keep only its tail. The
            // tail is the part a live log is for - the head is already
            // older than anything on screen.
            const size_t skip = events2.size() - kMaxEvents;
            dropped_ += static_cast<unsigned long long>(skip + before);
            const std::vector<RowChange> tail(
                events2.begin() + static_cast<std::ptrdiff_t>(skip),
                events2.end());
            events_.clear();
            AppendFormatted(tail, stamp);
            FinishAppend(skip + before);
            return;
        }
        // erase(begin, begin + n) - the half-open range starts at the
        // FRONT. Erasing from begin()+n to end() would drop the newest rows
        // and keep the oldest, which is the one thing a log must not do.
        const auto first = events_.begin();
        const auto last = first + static_cast<std::ptrdiff_t>(evicted);
        events_.erase(first, last);
        dropped_ += static_cast<unsigned long long>(evicted);
    }

    AppendFormatted(events2, stamp);
    FinishAppend(evicted);
}

void ChangeLogWindow::AppendFormatted(const std::vector<RowChange>& events,
                                      const std::wstring& stamp) {
    events_.reserve(kMaxEvents);   // grow to the cap, never shrink back
    copyNote_.clear();   // fresh data replaces the copy receipt
    for (const RowChange& ch : events) {
        Entry e;
        e.time = stamp;
        e.kind = (ch.kind == kChangeAppear)     ? L"APPEAR"
                 : (ch.kind == kChangeDisappear) ? L"DISAPPEAR"
                                                 : L"STATE";
        e.proto = DashIfEmpty(ch.row.keys.protoLabel);
        e.process = ch.row.display.processName;
        if (e.process.empty()) e.process = L"(unknown)";
        e.process += L" (";
        // pidText is filled by FinalizeRow; fall back to the raw pid so a
        // hand-built row (the self-test) still shows a number.
        e.process += ch.row.keys.pidText.empty() ? std::to_wstring(ch.row.identity.pid)
                                             : ch.row.keys.pidText;
        e.process += L")";
        e.local = DashIfEmpty(ch.row.display.localEndpoint);
        e.remote = DashIfEmpty(ch.row.display.remoteEndpoint);
        e.newState = DashIfEmpty(ch.row.keys.stateLabel);
        if (ch.kind == kChangeState) {
            // FinalizeRow is idempotent and labels a copy of the row with
            // its old state - the same trick the CSV writer uses, so the
            // window and the log file show identical text.
            Connection tmp = ch.row;
            tmp.identity.state = ch.oldState;
            ConnectionStore::FinalizeRow(tmp);
            e.oldState = DashIfEmpty(tmp.keys.stateLabel);
            e.stateText = e.oldState + L" \u2192 " + e.newState;
        } else {
            e.oldState.clear();
            e.stateText = e.newState;
        }
        e.pidText = std::to_wstring(ch.row.identity.pid);
        events_.push_back(std::move(e));
    }
}

void ChangeLogWindow::FinishAppend(size_t evicted) {
    // Fed while closed: the buffer is the only thing that changes, and the
    // next Show() picks the view up again.
    if (hwnd_ == nullptr) return;
    SyncList(evicted);
}

// ---- view / scroll ---------------------------------------------------------

void ChangeLogWindow::SyncCount() {
    if (hwndList_ == nullptr) return;
    ::SendMessageW(hwndList_, LVM_SETITEMCOUNT,
                   static_cast<WPARAM>(events_.size()), 0);
}

int ChangeLogWindow::ListCount() const {
    return static_cast<int>(events_.size());
}

int ChangeLogWindow::ListTop() const {
    if (hwndList_ == nullptr) return 0;
    // GetScrollInfo, not LVM_GETTOPINDEX. The list message reports the top
    // index of the *cached page* and is left at 0 by a plain
    // LVM_ENSUREVISIBLE in a virtual list (measured: the scrollbar sat at
    // 2975 while LVM_GETTOPINDEX reported 0), which would make every
    // follow decision wrong. The scrollbar position is what the control
    // actually shows.
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_POS;
    if (!::GetScrollInfo(hwndList_, SB_VERT, &si)) return 0;
    return si.nPos;
}

int ChangeLogWindow::ListPage() const {
    if (hwndList_ == nullptr) return 0;
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_PAGE;
    if (!::GetScrollInfo(hwndList_, SB_VERT, &si)) return 0;
    return si.nPage;
}

bool ChangeLogWindow::AtBottom() const {
    if (hwndList_ == nullptr) return true;
    const int perPage = ListPage();
    if (perPage <= 0) return true;   // everything fits: nowhere to scroll
    // Exact, with no tolerance band. The scroll position is a whole number
    // of rows, so there is no "the last row is only half visible" case to
    // forgive here - and a band would mean a one-line scroll up still counted
    // as "at the bottom", so the follow would not actually stop.
    return ListTop() + perPage >= ListCount();
}

void ChangeLogWindow::ScrollToBottom() {
    if (hwndList_ == nullptr) return;
    const WPARAM last = static_cast<WPARAM>(ListCount() > 0 ? ListCount() - 1
                                                             : 0);
    suppressFollow_ = true;
    // Twice: a ListView clamps its scroll position lazily, and after a batch
    // that changed the item count one EnsureVisible is not always enough to
    // reach the new end.
    ::SendMessageW(hwndList_, LVM_ENSUREVISIBLE, last, FALSE);
    ::SendMessageW(hwndList_, LVM_ENSUREVISIBLE, last, FALSE);
    suppressFollow_ = false;
    ::UpdateWindow(hwndList_);
}

void ChangeLogWindow::ScrollToTop(int index) {
    if (hwndList_ == nullptr) return;
    if (index < 0) index = 0;
    // SetScrollPos, and nothing else.
    //
    // LVM_ENSUREVISIBLE is not a positioning call: it only promises that the
    // row ends up somewhere on screen, and the control picks the nearest
    // such position. Measured with 5000 rows, EnsureVisible(2980) from top
    // 2980 settled on 2780 - the reader was dragged 200 rows up on an
    // append that had evicted nothing at all. It cannot restore a position.
    //
    // The repaint is forced because a virtual list caches its page and
    // re-derives a position on the next paint; without it the scroll can be
    // undone by the control itself.
    suppressFollow_ = true;
    ::SetScrollPos(hwndList_, SB_VERT, index, TRUE);
    ::RedrawWindow(hwndList_, nullptr, nullptr,
                   RDW_INVALIDATE | RDW_UPDATENOW | RDW_NOERASE);
    suppressFollow_ = false;
}

void ChangeLogWindow::OnUserScrolled() {
    if (suppressFollow_) return;   // our own scroll, not the user's
    if (paused_) return;           // frozen anyway; do not fight the user
    follow_ = AtBottom();
}

void ChangeLogWindow::MaybeFollow() {
    if (hwndList_ == nullptr) return;
    follow_ = true;
    ScrollToBottom();
}

void ChangeLogWindow::SyncList(size_t evicted) {
    if (hwndList_ == nullptr) return;

    if (paused_) {
        // Remember where the user is, counting the rows that fell off the
        // front, so the resume restores the same content rather than the
        // same line number. The list itself is not touched at all.
        pausedTop_ = static_cast<int>(evicted) + ListTop();
        return;
    }

    if (follow_) {
        SyncCount();
        ScrollToBottom();
    } else {
        // Not following: the user is reading somewhere in the middle. Rows
        // were dropped from the front and appended at the back, so the same
        // content has shifted up by 'evicted' and the top index has to move
        // with it - otherwise a fast log scrolls the text out from under the
        // reader one batch at a time.
        const int keep = (std::max)(0, ListTop() - static_cast<int>(evicted));
        SyncCount();
        ScrollToTop(keep);
    }
    UpdateStatus();
}

void ChangeLogWindow::Clear() {
    events_.clear();
    dropped_ = 0;
    copyNote_.clear();
    follow_ = true;
    pausedTop_ = 0;
    if (hwndList_ == nullptr) return;
    SyncCount();
    ScrollToBottom();
    UpdateStatus();
}

void ChangeLogWindow::SetPaused(bool paused) {
    if (paused_ == paused) return;
    paused_ = paused;
    if (paused_) {
        // Freeze where the user is; nothing appended after this point can
        // touch the list.
        pausedTop_ = ListTop();
    } else {
        // Catch up on everything buffered while paused, then re-pin the
        // tail: the user asked to resume, not to keep reading.
        follow_ = true;
        SyncList(0);
    }
    UpdatePauseButton();
    UpdateStatus();
}

// ---- list content ----------------------------------------------------------

void ChangeLogWindow::OnGetDispInfo(NMLVDISPINFOW* info) {
    if (info == nullptr || (info->item.mask & LVIF_TEXT) == 0) return;
    const int index = info->item.iItem;
    if (index < 0 || static_cast<size_t>(index) >= events_.size()) return;
    const Entry& e = events_[static_cast<size_t>(index)];

    const std::wstring* text = nullptr;
    switch (info->item.iSubItem) {
        case kColTime:    text = &e.time;      break;
        case kColEvent:   text = &e.kind;      break;
        case kColProto:   text = &e.proto;     break;
        case kColProcess: text = &e.process;   break;
        case kColLocal:   text = &e.local;     break;
        case kColRemote:  text = &e.remote;    break;
        case kColState:   text = &e.stateText; break;
        default: return;
    }

    // LVS_DISPINFO: pszText must stay valid until the control has finished
    // with it, i.e. until the next message is processed. A string in our
    // own buffer has exactly that lifetime, which is why the rows are
    // stored pre-formatted.
    info->item.pszText = const_cast<LPWSTR>(text->c_str());
    info->item.cchTextMax = static_cast<int>(text->size());
}

std::wstring ChangeLogWindow::ColumnText(size_t index, int column) const {
    if (index >= events_.size()) return std::wstring();
    const Entry& e = events_[index];
    switch (column) {
        case kColTime:    return e.time;
        case kColEvent:   return e.kind;
        case kColProto:   return e.proto;
        case kColProcess: return e.process;
        case kColLocal:   return e.local;
        case kColRemote:  return e.remote;
        case kColState:   return e.stateText;
        default: return std::wstring();
    }
}

std::string ChangeLogWindow::ToCsv() const {
    // Same field order as MainWindow::WriteChangeLog(), so a saved buffer
    // and the change log file are interchangeable.
    std::string out;
    for (const Entry& e : events_) {
        out += WideToUtf8(e.time);
        out += ',';
        out += WideToUtf8(e.kind);
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(e.proto));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(e.local));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(e.remote));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(e.newState));
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(e.oldState));
        out += ',';
        out += WideToUtf8(e.pidText);
        out += ',';
        out += CsvEscapeUtf8(WideToUtf8(e.process));
        out += "\r\n";
    }
    return out;
}

void ChangeLogWindow::CopySelection() {
    if (hwndList_ == nullptr) return;
    int i = ListView_GetNextItem(hwndList_, -1, LVNI_SELECTED);
    // Copying with no selection used to fail silently. Fall back to
    // the whole buffer (capped like any copy) and say the count, so the
    // clipboard always gets what the button promises and the user knows
    // it was everything, not the row they thought was selected.
    bool fellBackToAll = false;
    std::vector<int> sel;
    if (i < 0) {
        fellBackToAll = true;
        const int n = ListCount();
        for (int k = 0; k < n && sel.size() < kMaxClipboardRows; ++k)
            sel.push_back(k);
    } else {
        // Selected rows, top to bottom. The cap is a guard: a future select-all
        // must not be able to build a 5000-row clipboard buffer behind the
        // user's back.
        while (i >= 0 && sel.size() < kMaxClipboardRows) {
            sel.push_back(i);
            i = ListView_GetNextItem(hwndList_, i, LVNI_SELECTED);
        }
    }
    if (sel.empty()) return;

    std::wstring text;
    for (const int index : sel) {
        for (int c = 0; c < kColumnCount; ++c) {
            if (c != 0) text += L'\t';
            text += ColumnText(static_cast<size_t>(index), c);
        }
        text += L"\r\n";
    }

    const ClipboardWriteStatus result =
        WriteClipboardText(hwnd_, text, NativeClipboardApi());
    if (ClipboardNeedsManualFallback(result)) {
        ShowTextSheet(hwnd_, L"Clipboard unavailable - select text and press Ctrl+C",
                      text, nullptr, true);
    }
    // The count is the fallback's receipt: without it a whole-log copy
    // is indistinguishable from a one-row copy.
    if (fellBackToAll) {
        copyNote_ = L"copied all " + std::to_wstring(sel.size()) +
                    L" rows (no selection)";
        UpdateStatus();
    }
}

void ChangeLogWindow::SaveToFile() {
    if (events_.empty()) {
        ::MessageBoxW(hwnd_, L"There is nothing in the buffer to save yet.",
                      L"WinTCP - Change log", MB_OK | MB_ICONINFORMATION);
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
    ofn.lpstrTitle = L"WinTCP - Save change log buffer";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    // comdlg32.dll is delay-loaded; DelayLoadGuard reports its absence, where a
    // bare `return` would look exactly like the user cancelling.
    if (!DelayLoadGuard(hwnd_, "comdlg32.dll")) return;
    if (::GetSaveFileNameW(&ofn) == FALSE) return;

    // WriteUtf8FileWithBom opens, writes and closes in one call, so no
    // handle survives on any of its return paths.
    const std::wstring err = WriteUtf8FileWithBom(path, ToCsv(), true);
    if (!err.empty()) {
        ::MessageBoxW(hwnd_,
                      (L"Could not write the change log:\n" + err).c_str(),
                      L"WinTCP - Change log", MB_OK | MB_ICONERROR);
    }
}

// ---- layout and chrome -----------------------------------------------------

void ChangeLogWindow::SetColumnWidths() {
    if (hwndList_ == nullptr) return;
    RECT rc = {};
    ::GetClientRect(hwndList_, &rc);
    const int total = rc.right - rc.left;
    int elastic = total - S(kColTimeW + kColEventW + kColProtoW + kColStateW);
    if (elastic < S(kMinElasticW96)) elastic = S(kMinElasticW96);
    const int wProcess = elastic / 3;
    const int wEndpoint = (elastic - wProcess) / 2;

    const auto set = [this](int col, int width) {
        ListView_SetColumnWidth(hwndList_, col, S(width));
    };
    set(kColTime, kColTimeW);
    set(kColEvent, kColEventW);
    set(kColProto, kColProtoW);
    set(kColProcess, wProcess);
    set(kColLocal, wEndpoint);
    set(kColRemote, wEndpoint);
    set(kColState, kColStateW);
}

void ChangeLogWindow::Layout(int cx, int cy) {
    if (hwnd_ == nullptr) return;
    const int m = S(kMargin);
    const int btnH = S(kBtnH);
    const int btnY = cy - m - btnH;

    // Buttons are laid out from the right so the row stays intact when the
    // window is narrow; the log is what shrinks, not the controls.
    int x = cx - m - S(kBtnWClose);
    const auto place = [this, &x, btnY, btnH](HWND h, int w) {
        if (h != nullptr) ::MoveWindow(h, x, btnY, S(w), btnH, TRUE);
        x -= S(w) + S(kBtnGap);
    };
    place(hwndClose_, kBtnWClose);
    place(hwndCopy_, kBtnWCopy);
    place(hwndSave_, kBtnWSave);
    place(hwndClear_, kBtnWClear);
    place(hwndPause_, kBtnWPause);
    // The kind checkboxes go on a SECOND row under the buttons, on the
    // LEFT. They are not part of the right-aligned button cluster because they
    // are a different kind of control - a persistent view filter, not an action -
    // and mixing the two would suggest they all do the same thing.
    //
    // The list therefore ends above the checkbox row rather than above the
    // status line, so the checkboxes never overlap it. Laid out left to right
    // from the margin so the group reads as one control.
    const int chkH = S(kChkH);
    const int chkY = btnY - S(kBtnGap) - chkH;
    int cx2 = m;
    const auto placeChk = [this, &cx2, chkY, chkH](HWND h, int w) {
        if (h != nullptr) ::MoveWindow(h, cx2, chkY, S(w), chkH, TRUE);
        cx2 += S(w) + S(kBtnGap);
    };
    placeChk(hwndEvAppear_, kChkWAppear);
    placeChk(hwndEvDisappear_, kChkWDisappear);
    placeChk(hwndEvState_, kChkWState);

    // The list runs from the top margin down to just above the status line; the
    // status line itself sits on the button row's line, to its left. The
    // checkbox row is below that, so the list stops above it.
    const int statusH = S(kStatusH);
    const int statusY = btnY + (btnH - statusH) / 2;
    if (hwndStatus_ != nullptr) {
        const int statusX = m;
        const int statusW = (std::max)(0, x - statusX);
        ::MoveWindow(hwndStatus_, statusX, statusY, statusW, statusH, TRUE);
    }
    if (hwndList_ != nullptr) {
        const int listH = (std::max)(0, chkY - m - m);
        ::MoveWindow(hwndList_, m, m, (std::max)(0, cx - 2 * m), listH,
                     TRUE);
    }

    // MoveWindow does not re-send WM_SIZE to the list when the size is
    // unchanged, so the column widths are re-applied here instead of from
    // WM_SIZE.
    SetColumnWidths();
    // A resize changes the page size, so a view that was following has to
    // re-pin the new bottom - otherwise the last line ends up half a screen
    // up the list.
    MaybeFollow();
}

void ChangeLogWindow::UpdateStatus() {
    if (hwndStatus_ == nullptr) return;
    std::wstring text = L"Showing ";
    text += std::to_wstring(events_.size());
    text += L" of the last ";
    text += std::to_wstring(kMaxEvents);
    text += L" events";
    // When the mask is narrowed, SAY SO and say when it takes effect. A
    // status line reading "Showing 40 of the last 2000 events" beside unticked
    // boxes is ambiguous - the user cannot tell whether the mask is already
    // applied or whether the 40 are simply all that happened. This closes that
    // gap in one line, and the "from now on" is the part that matters: the mask
    // is not retroactive.
    if (!EventMaskIsFull()) {
        std::wstring on;
        const auto add = [&on](const wchar_t* n, bool v) {
            if (!v) return;
            if (!on.empty()) on += L" ";
            on += n;
        };
        add(L"appear", evAppear_);
        add(L"disappear", evDisappear_);
        add(L"state", evState_);
        text += L"  \u2022  showing only: ";
        text += on;
        text += L" (from now on)";
    }
    if (dropped_ > 0) {
        text += L"  \u2022  ";
        text += std::to_wstring(dropped_);
        text += L" older events dropped";
    }
    // The fallback copy's receipt, until fresh data replaces it.
    if (!copyNote_.empty()) {
        text += L"  \u2022  ";
        text += copyNote_;
    }
    // An empty log names its next action instead of sitting blank.
    // The buffer fills only while the main window logs to a file, so the
    // hint points at the switch that starts the feed.
    if (events_.empty())
        text += L"  \u2022  no events yet - File > Log changes to file... "
                L"starts the feed";
    if (paused_)
        text += L"  \u2022  PAUSED";
    else if (!follow_)
        text += L"  \u2022  scrolled up (not following)";
    ::SetWindowTextW(hwndStatus_, text.c_str());
}

void ChangeLogWindow::UpdatePauseButton() {
    if (hwndPause_ == nullptr) return;
    ::SetWindowTextW(hwndPause_, paused_ ? L"&Resume" : L"&Pause");
}

void ChangeLogWindow::OnCommand(WORD id, LPARAM lParam) {
    switch (id) {
        case IDC_LOG_PAUSE:
            SetPaused(!paused_);
            break;
        // Toggling a kind filters the kinds that will be APPENDED from now
        // on. It deliberately does NOT retro-filter what is already buffered:
        // the log is a record of what happened, and rewriting history because
        // someone unticked a box would make it a lie. The status line says so
        // explicitly (see UpdateStatus).
        case IDC_LOG_EV_APPEAR:
        case IDC_LOG_EV_DISAPPEAR:
        case IDC_LOG_EV_STATE: {
            const UINT which = static_cast<UINT>(LOWORD(lParam));
            const bool a = IsDlgButtonChecked(hwnd_, IDC_LOG_EV_APPEAR) != 0;
            const bool d =
                IsDlgButtonChecked(hwnd_, IDC_LOG_EV_DISAPPEAR) != 0;
            const bool st = IsDlgButtonChecked(hwnd_, IDC_LOG_EV_STATE) != 0;
            // All three off would silently freeze the log with no
            // explanation, so it is refused: the last one on cannot be
            // turned off. Same reasoning as a GUI that will not let you hide
            // every column - an empty view with no way back is a trap.
            if (!a && !d && !st) {
                // Put back the box the user actually clicked, and NOTHING
                // else. The first version re-checked whichever control it
                // considered current, and the UI harness caught the
                // consequence immediately: clicking Appear turned off
                // disappear AND state, because those two had never been
                // ticked - SetEventMask then synced the checkboxes to that
                // wrong mask, and the log went on showing a mixture nobody
                // asked for. which is the only control this click touched.
                ::CheckDlgButton(hwnd_, which, BST_CHECKED);
                ::MessageBeep(MB_ICONWARNING);
                break;
            }
            SetEventMask(a, d, st);
            UpdateStatus();
            break;
        }
        case IDC_LOG_CLEAR:
            // Clearing discards every recorded event, so it is
            // confirmed when there is something to lose.
            if (!events_.empty() &&
                ::MessageBoxW(hwnd_,
                              L"Clear the change log?\r\n\r\n"
                              L"Every recorded event will be discarded.",
                              L"WinTCP - Clear change log",
                              MB_YESNO | MB_ICONWARNING |
                                  MB_DEFBUTTON2) != IDYES)
                break;
            Clear();
            break;
        case IDC_LOG_SAVE:
            SaveToFile();
            break;
        case IDC_LOG_COPY:
            CopySelection();
            break;
        case IDC_LOG_CLOSE:
            ::ShowWindow(hwnd_, SW_HIDE);
            break;
        default:
            break;
    }
}

// ---- window procedure -------------------------------------------------------

LRESULT CALLBACK ChangeLogWindow::WindowProc(HWND hwnd, UINT msg,
                                             WPARAM wParam, LPARAM lParam) {
    // 'this' rides in CREATESTRUCT's lpCreateParams, which is the only place a
    // window procedure can be handed its owner before the object exists - so
    // nothing here dereferences it before WM_NCCREATE has been through.
    if (msg == WM_NCCREATE) {
        const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        auto* owner = reinterpret_cast<ChangeLogWindow*>(cs->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                            reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        // Publish hwnd_ NOW. Show() cannot do it, because
        // CreateWindowExW does not return until WM_CREATE has been dispatched -
        // so for the whole of WM_CREATE the member still holds whatever was
        // there before (null on the first open, a DESTROYED handle on a reopen).
        // Every control created in WM_CREATE passes hwnd_ as its parent, so
        // without this they were all parented to null and every one of the ten
        // CreateWindowExW calls failed with ERROR_TLW_WITH_WSCHILD (1406).
        //
        // The window appeared, the list was empty, and no button existed - which
        // is why IsVisible() reported success throughout.
        if (owner != nullptr) owner->hwnd_ = hwnd;
        // Must return TRUE or the window is destroyed immediately after
        // WM_NCCREATE and nothing else - not even WM_CREATE - ever runs.
        return TRUE;
    }
    auto* self = reinterpret_cast<ChangeLogWindow*>(
        ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (self != nullptr) return self->HandleMessage(msg, wParam, lParam);
    // `this` is not attached yet. Only WM_NCCREATE / WM_CREATE can arrive
    // before it is, and both are handled above / in HandleMessage, so reaching
    // here with a null owner means something sent an unexpected message during
    // creation - and calling DefWindowProc would silently drop WM_CREATE's
    // result. Report it instead of hiding it.
    if (msg == WM_NCCREATE || msg == WM_CREATE) {
        ::OutputDebugStringW(
            L"[changelog] WM_CREATE arrived with no owner attached - controls "
            L"were not built.\n");
        return (msg == WM_NCCREATE) ? TRUE : 0;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// The list's proc. Scroll and keyboard input never reach the parent window, so
// the "is the user still at the bottom" rule can only be evaluated here. Only
// the messages that can change that answer are intercepted; everything else is
// passed straight through, because a subclass that inspects more than it must
// is how a list view starts dropping keystrokes.
LRESULT CALLBACK ChangeLogWindow::SubclassProc(HWND hwnd, UINT msg,
                                               WPARAM wParam, LPARAM lParam,
                                               UINT_PTR, DWORD_PTR refData) {
    auto* self = reinterpret_cast<ChangeLogWindow*>(refData);
    if (self == nullptr) return ::DefSubclassProc(hwnd, msg, wParam, lParam);
    // Ctrl+A selects the whole buffer. The main window's accelerator
    // table does not reach this owned window's focused list, so the list
    // handles it itself rather than relying on a menu id that never fires.
    if (msg == WM_KEYDOWN && wParam == L'A' &&
        (::GetKeyState(VK_CONTROL) & 0x8000) != 0) {
        const int n = self->ListCount();
        for (int k = 0; k < n; ++k) {
            ListView_SetItemState(hwnd, k, LVIS_SELECTED, LVIS_SELECTED);
        }
        return 0;
    }
    // Esc hides even when the list owns the focus. Keys go to the
    // focused child, so the parent's own WM_KEYDOWN never fires for them.
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        if (self->Handle() != nullptr) ::ShowWindow(self->Handle(), SW_HIDE);
        return 0;
    }
    if (msg == WM_VSCROLL || msg == WM_MOUSEWHEEL || msg == WM_KEYDOWN ||
        msg == WM_LBUTTONUP) {
        const LRESULT r = ::DefSubclassProc(hwnd, msg, wParam, lParam);
        self->OnUserScrolled();
        return r;
    }
    return ::DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT ChangeLogWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            ++createCount_;
            // The window may be RECREATED after a previous one was destroyed
            // (the menu item is a toggle, so close-then-open is the normal
            // path). Any stale child handle from the destroyed instance must be
            // cleared first: this is a NEW window, so re-assigning every handle
            // below is correct, but a field left pointing at the old window's
            // dead HWND would be written over only if that particular control is
            // created successfully - and a partially-built window is exactly the
            // state that is hard to diagnose.
            hwndList_ = nullptr;
            hwndPause_ = nullptr;
            hwndClear_ = nullptr;
            hwndSave_ = nullptr;
            hwndCopy_ = nullptr;
            hwndClose_ = nullptr;
            hwndStatus_ = nullptr;
            hwndEvAppear_ = nullptr;
            hwndEvDisappear_ = nullptr;
            hwndEvState_ = nullptr;
            // The controls are built ONCE, at the one moment the window is
            // created - not on every Show(). WM_CREATE fires exactly once per
            // window instance, whereas Show() runs every time the log is
            // re-opened, and building the controls there was what made the
            // window come back EMPTY: the harness toggled the log closed and
            // open again and found no buttons at all, because the second Show()
            // created a fresh set only if the handles were null, and the first
            // set had been destroyed with the old window. WM_CREATE is the only
            // correct place; everything Show() needs on re-open is covered by
            // the WM_SIZE that follows it.
            const HINSTANCE inst = ::GetModuleHandleW(nullptr);
            // Virtual list view: rows arrive as LVN_GETDISPINFO from the
            // buffer, so appending an event never recreates items and a
            // 5000-row window costs the same to paint as a 50-row one.
            const DWORD listStyle = WS_CHILD | WS_VISIBLE | WS_BORDER |
                                    LVS_REPORT | LVS_OWNERDATA |
                                    LVS_SHOWSELALWAYS;
            hwndList_ = ::CreateWindowExW(
                WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", listStyle, 0, 0, 0, 0,
                hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_LIST)),
                inst, nullptr);
            if (hwndList_ != nullptr) {
                // The list's GWLP_USERDATA belongs to the subclass chain, so
                // 'this' travels as the subclass refdata.
                ::SetWindowSubclass(hwndList_, &ChangeLogWindow::SubclassProc,
                                    1, reinterpret_cast<DWORD_PTR>(this));
                // Read-only and copyable: the extended styles are the whole
                // of the "this is a log, you may read it and copy from it"
                // behaviour - no editing, no drag-drop, full-row selection.
                ::SendMessageW(hwndList_, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                               LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                   LVS_EX_DOUBLEBUFFER);
                const wchar_t* titles[kColumnCount] = {
                    L"Time",     L"Event", L"Proto", L"Process",
                    L"Local",    L"Remote", L"State"};
                for (int c = 0; c < kColumnCount; ++c) {
                    LVCOLUMNW col = {};
                    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
                    col.pszText = const_cast<LPWSTR>(titles[c]);
                    col.cx = 0;
                    col.iSubItem = c;
                    ListView_InsertColumn(hwndList_, c, &col);
                }
                SetColumnWidths();
                ::SendMessageW(hwndList_, LVM_SETITEMCOUNT, 0, 0);
            }

            hwndPause_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Pause", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_PAUSE)),
                inst, nullptr);
            hwndClear_ = ::CreateWindowExW(
                0, L"BUTTON", L"C&lear", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_CLEAR)),
                inst, nullptr);
            hwndSave_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Save\u2026",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_SAVE)),
                inst, nullptr);
            hwndCopy_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Copy", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_COPY)),
                inst, nullptr);
            hwndClose_ = ::CreateWindowExW(
                0, L"BUTTON", L"C&lose",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_CLOSE)),
                inst, nullptr);
            // The three kind checkboxes. AUTOCHECKBOX rather than a menu,
            // because they are a live VIEW control over a stream that keeps
            // arriving - toggling one takes effect on the next event with no
            // confirmation, which is what you want from a filter and not what
            // you want from a command. BS_AUTOCHECKBOX also means BM_CLICK
            // applies the new state and then notifies the parent, so the
            // handler reads settled values.
            hwndEvAppear_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Appear",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_EV_APPEAR)),
                inst, nullptr);
            hwndEvDisappear_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Disappear",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(
                    static_cast<UINT_PTR>(IDC_LOG_EV_DISAPPEAR)),
                inst, nullptr);
            hwndEvState_ = ::CreateWindowExW(
                0, L"BUTTON", L"&State",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_LOG_EV_STATE)),
                inst, nullptr);
            hwndStatus_ = ::CreateWindowExW(
                0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0,
                hwnd_, nullptr, inst, nullptr);
            // Report every child this handler tried to create and did not get.
            // The harness could see "the window is up, but it has no children"
            // and nothing else - which does not distinguish a CreateWindowExW
            // that failed from one that was never called, and those have very
            // different causes.
            {
                const struct { const wchar_t* name; HWND h; } made[] = {
                    {L"list", hwndList_}, {L"pause", hwndPause_},
                    {L"clear", hwndClear_}, {L"save", hwndSave_},
                    {L"copy", hwndCopy_},   {L"close", hwndClose_},
                    {L"status", hwndStatus_},
                    {L"evAppear", hwndEvAppear_},
                    {L"evDisappear", hwndEvDisappear_},
                    {L"evState", hwndEvState_},
                };
                // Last-resort diagnostic: record the FIRST failure's GetLastError
                // so the harness can report it. OutputDebugString is useless
                // here - there is no debugger attached, so the message goes
                // nowhere and the failure has to be explained by the NEXT run.
                lastChildError_ = 0;
                for (const auto& m : made) {
                    if (m.h != nullptr) continue;
                    lastChildError_ = ::GetLastError();
                    break;
                }
            }

            ApplyFont(font_);   // borrowed font to every child
            SetColumnWidths();
            SyncCount();
            ScrollToBottom();
            UpdatePauseButton();
            UpdateStatus();
            // Tick the boxes from the current mask. CreateWindowEx leaves
            // an AUTOCHECKBOX unchecked, so without this a log whose mask was
            // set programmatically before opening would show three unticked
            // boxes and filter nothing - the control lying about the state.
            if (hwndEvAppear_ != nullptr) {
                ::CheckDlgButton(hwnd_, IDC_LOG_EV_APPEAR,
                                 evAppear_ ? BST_CHECKED : BST_UNCHECKED);
                ::CheckDlgButton(hwnd_, IDC_LOG_EV_DISAPPEAR,
                                 evDisappear_ ? BST_CHECKED : BST_UNCHECKED);
                ::CheckDlgButton(hwnd_, IDC_LOG_EV_STATE,
                                 evState_ ? BST_CHECKED : BST_UNCHECKED);
            }
            return 0;
        }

        case WM_SIZE:
            Layout(LOWORD(lParam), HIWORD(lParam));
            return 0;

        case WM_SYSCOLORCHANGE:
            // Every colour here is live (COLOR_WINDOW brush, default
            // list colours), so a theme or high-contrast switch needs no
            // re-derivation - only a repaint to pick the new scheme up.
            ::InvalidateRect(hwnd_, nullptr, TRUE);
            return 0;

        case WM_GETMINMAXINFO: {
            // Wide enough for the fixed columns at 96 dpi, and tall enough
            // to be a list rather than a slot.
            const UINT dpi = QueryDpiForWindow(hwnd_);
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x =
                ::MulDiv(kMinTotalW, static_cast<int>(dpi), kMetricsDpi);
            mmi->ptMinTrackSize.y =
                ::MulDiv(kMinTrackHeight96, static_cast<int>(dpi), kMetricsDpi);
            return 0;
        }

        case WM_DPICHANGED: {
            const auto* suggested = reinterpret_cast<const RECT*>(lParam);
            ::SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                           suggested->right - suggested->left,
                           suggested->bottom - suggested->top,
                           SWP_NOZORDER | SWP_NOACTIVATE);
            // Re-derive every width and size from the new DPI. SetWindowPos
            // sends WM_SIZE, so Layout runs, but the font has to be re-applied
            // first or the controls keep the old face at the new metrics.
            ApplyFont(font_);
            Layout(LOWORD(lParam) == 0 ? 0 : LOWORD(lParam), 0);
            return 0;
        }

        case WM_GETFONT:
            return reinterpret_cast<LRESULT>(font_);

        case WM_NOTIFY:
            if (reinterpret_cast<NMHDR*>(lParam)->idFrom ==
                static_cast<UINT_PTR>(IDC_LOG_LIST)) {
                if (reinterpret_cast<NMHDR*>(lParam)->code == LVN_GETDISPINFO) {
                    OnGetDispInfo(
                        reinterpret_cast<NMLVDISPINFOW*>(lParam));
                    return 0;
                }
            }
            break;

        case WM_COMMAND:
            // BN_CLICKED only: without the notification check an
            // enable/disable notification would also trigger the command.
            if (HIWORD(wParam) == BN_CLICKED)
                OnCommand(LOWORD(wParam), lParam);
            return 0;

        case WM_KEYDOWN:
            // Esc hides (never destroys - the buffer survives, and
            // hiding is what every other secondary window does), matching
            // the Close button and the Details window.
            if (wParam == VK_ESCAPE) {
                ::ShowWindow(hwnd_, SW_HIDE);
                return 0;
            }
            break;

        case WM_CLOSE:
            // Hide, keep the buffer: the main window keeps feeding it while
            // the window is closed, and reopening should show recent
            // history. Close() (shutdown) destroys it.
            ::ShowWindow(hwnd_, SW_HIDE);
            return 0;

        case WM_DESTROY:
            // Clear every child handle before anything else: the object may
            // outlive the window and a stale child HWND would be a dangling
            // value in a window that can be reopened.
            hwndList_ = nullptr;
            hwndPause_ = nullptr;
            hwndClear_ = nullptr;
            hwndSave_ = nullptr;
            hwndCopy_ = nullptr;
            hwndClose_ = nullptr;
            // The same for the checkboxes.
            hwndEvAppear_ = nullptr;
            hwndEvDisappear_ = nullptr;
            hwndEvState_ = nullptr;
            hwndStatus_ = nullptr;
            hwnd_ = nullptr;
            return 0;

        default:
            break;
    }
    return ::DefWindowProcW(hwnd_, msg, wParam, lParam);
}

}  // namespace wintcp
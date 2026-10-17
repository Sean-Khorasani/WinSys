// MainWindowInternal.h
// SPDX-License-Identifier: Apache-2.0
//
// The shared plumbing of the main window: constants the window and its
// helpers agree on, and the free functions that are not about the window's
// state at all.
//
// This used to be an anonymous namespace inside MainWindow.cpp. It has to be
// a header now that the window is split across several translation units:
// an anonymous namespace in a header gives every unit its OWN copy, which is
// how one window ends up with two shield icons (one cached per .cpp) and a
// SetMenuCheck that checks a menu in a unit that does not own it. Everything
// here is `inline`, so there is exactly one definition and no per-unit
// duplication.
//
// The functions here deliberately take no MainWindow - they are the layer
// that does not know a window exists, which is what keeps them testable and
// what stops the split from becoming a shared-god-object split.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tcpmib.h>

#include <cstddef>

#include "Columns.h"
#include "ConnectionStore.h"
#include "Elevate.h"       // IsElevated, IsAdminMember
#include "resource.h"    // IDM_COL_*, IDM_VIEW_TRAFFIC
#include "WinCaps.h"     // DllAvailable: shell32 is delay-loaded

namespace wintcp {
namespace mw {

inline constexpr UINT_PTR kRefreshTimerId = 1;   // auto-refresh -> worker request
inline constexpr UINT_PTR kFilterTimerId = 2;    // filter debounce
inline constexpr UINT_PTR kStatusTimerId = 3;    // 1 s tick for the clock
inline constexpr UINT kFilterDebounceMs = 250;   // one keystroke-delay on any machine
inline constexpr UINT kStatusTickMs = 1000;

// Unit conversions. Six sites spelled 1000 as "milliseconds per second" and
// three as 96 = "DPI at which the design pixel sizes are unscaled". Named
// because the failure mode of getting them wrong is a factor-of-1000 age or a
// window a third the intended size at 200% scaling, and neither looks like a
// bug where it is shown.
inline constexpr ULONGLONG kMsPerSecond = 1000;
inline constexpr int kDpiUnscaled = 96;

// The layout is authored at an unscaled 1080x640 and multiplied by the system
// DPI ratio (MainWindow::S() does that). Named because the pair appeared
// TWICE - once as the MulDiv fallback in Create() and once in the WM_CREATE
// handler calling LayoutControls - and the two must agree or the first painted
// frame has a different geometry from every later one.
inline constexpr int kDesignWidth = 1080;
inline constexpr int kDesignHeight = 640;

// What the filter box holds. One constant for BOTH ends of the round trip: the
// control's EM_LIMITTEXT (what the user may type) and the buffer
// CurrentSearchText() reads into. See the create site for why they must agree.
inline constexpr int kSearchTextMaxChars = 512;

// Smallest window geometry worth restoring from the saved settings. Below it a
// toolbar row and the list cannot both be laid out, so the saved rect is
// ignored in favour of CW_USEDEFAULT rather than restored into something the
// app cannot draw.
inline constexpr int kMinRestorableW = 200;
inline constexpr int kMinRestorableH = 140;

// The visible set is a 32-bit mask, one bit per column (Columns.h), so the
// persisted order can name at most 32 columns - the same freeze the mask
// encodes, and the UiProbe that reports the order walks no further.
inline constexpr size_t kMaxColOrderSlots = 32;

// Longest command line the kill-confirmation prompt will quote in full. A
// longer one is cut rather than filling a modal dialog with several screenfuls
// of arguments the user has to dismiss; the name, PID, path and start time
// below it are the parts that identify the process.
inline constexpr size_t kKillPromptCmdChars = 300;

// Text buffers. Each holds a fixed sentence around a value, and every
// swprintf_s truncates rather than overruns, so these are slack sized for the
// longest wording each site uses rather than a shared maximum.
inline constexpr size_t kWatchdogMsgChars = 192;
inline constexpr size_t kProbeBufChars = 1024;
inline constexpr size_t kMissingColListChars = 512;
inline constexpr size_t kCommaColChars = 16;
inline constexpr size_t kKillPromptChars = 1536;
inline constexpr size_t kBlockPromptChars = 1024;

// Themed colors: the app follows the system theme. High-contrast mode
// wins over everything - see RefreshSystemColors().
struct ColDef { int id; const wchar_t* title; int width; int fmt; };
inline const ColDef kColumns[COL_COUNT] = {
    // Header text comes from ConnectionStore::ColumnTitle so the GUI, CSV
    // export and CLI cannot drift apart; only width/format live here.
    { COL_PROTO,   ConnectionStore::ColumnTitle(COL_PROTO),   70, LVCFMT_LEFT  },
    { COL_LOCAL,   ConnectionStore::ColumnTitle(COL_LOCAL),  150, LVCFMT_LEFT  },
    { COL_LPORT,   ConnectionStore::ColumnTitle(COL_LPORT),   65, LVCFMT_RIGHT },
    { COL_REMOTE,  ConnectionStore::ColumnTitle(COL_REMOTE), 150, LVCFMT_LEFT  },
    { COL_RPORT,   ConnectionStore::ColumnTitle(COL_RPORT),   65, LVCFMT_RIGHT },
    { COL_STATE,   ConnectionStore::ColumnTitle(COL_STATE),  110, LVCFMT_LEFT  },
    { COL_PID,     ConnectionStore::ColumnTitle(COL_PID),     65, LVCFMT_RIGHT },
    { COL_PROCESS, ConnectionStore::ColumnTitle(COL_PROCESS),150, LVCFMT_LEFT  },
    { COL_SERVICE, ConnectionStore::ColumnTitle(COL_SERVICE),130, LVCFMT_LEFT  },
    { COL_HOST,    ConnectionStore::ColumnTitle(COL_HOST),   180, LVCFMT_LEFT  },
    { COL_PATH,    ConnectionStore::ColumnTitle(COL_PATH),   300, LVCFMT_LEFT  },
    { COL_TRAFFIC, ConnectionStore::ColumnTitle(COL_TRAFFIC),130, LVCFMT_LEFT  },
    { COL_RX,      ConnectionStore::ColumnTitle(COL_RX),      88, LVCFMT_RIGHT },
    { COL_TX,      ConnectionStore::ColumnTitle(COL_TX),      88, LVCFMT_RIGHT },
    { COL_NETTOTAL, ConnectionStore::ColumnTitle(COL_NETTOTAL),100, LVCFMT_RIGHT },
    { COL_CPU,     ConnectionStore::ColumnTitle(COL_CPU),     70, LVCFMT_RIGHT },
    { COL_MEM,     ConnectionStore::ColumnTitle(COL_MEM),    100, LVCFMT_RIGHT },
    { COL_DISK,    ConnectionStore::ColumnTitle(COL_DISK),   110, LVCFMT_RIGHT },
    { COL_DURATION, ConnectionStore::ColumnTitle(COL_DURATION), 80, LVCFMT_RIGHT },
    { COL_BANDWIDTH, ConnectionStore::ColumnTitle(COL_BANDWIDTH),140, LVCFMT_LEFT  },
    // Present but not displayed. kColumns is indexed by ColumnId (and the
    // static_assert below pins its length to COL_COUNT), so a missing entry
    // would renumber every column after it. What keeps this column off the
    // screen is its absence from kDisplayOrder - see the note there.
    { COL_TLS,     L"\x2014 reserved \x2014",          190, LVCFMT_LEFT  },
    { COL_COUNTRY, ConnectionStore::ColumnTitle(COL_COUNTRY), 90, LVCFMT_LEFT  },
    { COL_PINNED,  ConnectionStore::ColumnTitle(COL_PINNED),  90, LVCFMT_LEFT  },
    // the `ss -i` columns. Widths are the GUI's own budget rather than
    // Columns.h's cap: the list view scrolls horizontally and each column is
    // independently resizable, so there is no table to keep aligned here.
    // Right aligned, because every one of these is a number.
    { COL_RTT,     ConnectionStore::ColumnTitle(COL_RTT),     80, LVCFMT_RIGHT },
    { COL_MINRTT,  ConnectionStore::ColumnTitle(COL_MINRTT),  90, LVCFMT_RIGHT },
    { COL_CWND,    ConnectionStore::ColumnTitle(COL_CWND),   100, LVCFMT_RIGHT },
    { COL_RETRANS, ConnectionStore::ColumnTitle(COL_RETRANS),100, LVCFMT_RIGHT },
    // Wider than COL_BANDWIDTH because the value is a process total and so
    // carries more digits - the same shape, a larger number.
    { COL_GROUPRATE, ConnectionStore::ColumnTitle(COL_GROUPRATE),160, LVCFMT_LEFT },
    // The bookmark note. Wider than most because the value is prose the user
    // typed, not a code or a number; anything longer elides and the tooltip
    // shows it whole.
    { COL_NOTE,    ConnectionStore::ColumnTitle(COL_NOTE),  180, LVCFMT_LEFT  },
  // 150 is generous for "<pid> <name>" because the name is an unbounded
  // process name; it elides with a tooltip beyond that.
  { COL_PPID,    ConnectionStore::ColumnTitle(COL_PPID),   150, LVCFMT_LEFT  },
  // Both are short words, sized from their longest possible cell
  // ("Protected+AC" and "BAD SIG") rather than from a typical row, so enabling
  // either never shows a truncated header.
  { COL_INTEGRITY, ConnectionStore::ColumnTitle(COL_INTEGRITY), 90, LVCFMT_LEFT },
  { COL_SIGNATURE, ConnectionStore::ColumnTitle(COL_SIGNATURE), 90, LVCFMT_LEFT },
};

// Every column needs exactly one IDM_COL_* command (View > Columns) and one
// entry in kColumns; a mismatch shows up here instead of as a column that
// cannot be toggled.
static_assert(COL_COUNT == IDM_COL_COUNT,
              "resource.h IDM_COL_COUNT is out of step with Columns.h COL_COUNT");
static_assert(sizeof(kColumns) / sizeof(kColumns[0]) == COL_COUNT,
              "kColumns must describe every ColumnId");

// DEDUCED size, deliberately. Declaring this `[COL_COUNT]` and then removing
// an entry zero-fills the tail instead of shrinking, which every iterating
// caller would read as COL_PROTO a second time - a duplicate column in the
// header and a permutation that claims 32 slots. The length is now whatever
// is listed, and the count of offered columns is a real number.
//
// This list is ALSO the column filter: a ColumnId that is not here is not
// inserted into the header, not offered in View > Columns and not saved into a
// preset. It is the one place all three read from, which is why excluding a
// column is a single deletion here rather than edits in four files.
//
// COL_TLS is the one exclusion. It is not a mistake and it is commented out
// rather than deleted: no socket-level TLS source exists (see the note on the
// enum in Columns.h), so the column answers "unknown" on every row, and a
// header of unresolvable columns teaches the user to ignore headers. The
// ColumnId, its mask bit and its width stay defined and unused.
inline const int kDisplayOrder[] = {
    COL_PROCESS, COL_CPU, COL_TRAFFIC, COL_PROTO,
    COL_LOCAL, COL_LPORT, COL_REMOTE, COL_RPORT, COL_STATE, COL_PID,
    COL_SERVICE, COL_HOST, COL_PATH,
    // The two rate columns sit together, then the connection-health columns:
    // RTT next to Min RTT next to Cwnd next to Retrans is the order `ss -i`
    // prints, and keeping them adjacent means the relationship between a
    // current RTT and its best-ever value is visible at a glance.
    COL_DURATION, COL_BANDWIDTH, COL_GROUPRATE,
    COL_RTT, COL_MINRTT, COL_CWND, COL_RETRANS,
    // COL_TLS deliberately absent - reserved, never populated. See above.
    COL_COUNTRY, COL_PINNED, COL_NOTE,
    // join the other per-process identity and trust columns: after the
    // bookmark fields, before the raw stat columns.
    COL_PPID, COL_INTEGRITY, COL_SIGNATURE,
    COL_MEM, COL_DISK, COL_RX, COL_TX, COL_NETTOTAL,
};

struct StateItem { const wchar_t* label; DWORD state; };
inline const StateItem kStateItems[] = {
    { L"All states",       kAllStates },
    { L"ESTABLISHED",      MIB_TCP_STATE_ESTAB },
    { L"LISTENING",        MIB_TCP_STATE_LISTEN },
    { L"TIME_WAIT",        MIB_TCP_STATE_TIME_WAIT },
    { L"SYN_SENT",         MIB_TCP_STATE_SYN_SENT },
    { L"SYN_RECEIVED",     MIB_TCP_STATE_SYN_RCVD },
    { L"FIN_WAIT_1",       MIB_TCP_STATE_FIN_WAIT1 },
    { L"FIN_WAIT_2",       MIB_TCP_STATE_FIN_WAIT2 },
    { L"CLOSE_WAIT",       MIB_TCP_STATE_CLOSE_WAIT },
    { L"CLOSING",          MIB_TCP_STATE_CLOSING },
    { L"LAST_ACK",         MIB_TCP_STATE_LAST_ACK },
    { L"CLOSED",           MIB_TCP_STATE_CLOSED },
    { L"DELETE_TCB",       MIB_TCP_STATE_DELETE_TCB },
    { L"— (none / UDP)", 0 },
};

inline void SetChildFont(HWND hwnd, HFONT font) {
    if (font != nullptr && hwnd != nullptr) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font),
                       MAKELPARAM(TRUE, 0));
    }
}

inline void AddComboString(HWND cbo, const wchar_t* text, LPARAM itemData = 0) {
    const LRESULT idx = ::SendMessageW(cbo, CB_ADDSTRING, 0,
                                       reinterpret_cast<LPARAM>(text));
    if (idx != CB_ERR)
        ::SendMessageW(cbo, CB_SETITEMDATA, static_cast<WPARAM>(idx), itemData);
}

// Check/uncheck a menu item that lives in one of the top-level submenus:
// CheckMenuItem only inspects the given menu handle, and the item IDs
// live inside the File/View/Edit popups, not on the menu bar itself.
inline void SetMenuCheck(HMENU menu, UINT id, bool on) {
    if (menu == nullptr) return;
    const UINT flags = MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED);
    const int count = ::GetMenuItemCount(menu);
    for (int i = 0; i < count; ++i) {
        if (::GetMenuItemID(menu, i) == static_cast<UINT>(-1)) {
            HMENU sub = ::GetSubMenu(menu, i);
            if (sub != nullptr &&
                ::GetMenuState(sub, id, MF_BYCOMMAND) != 0xFFFFFFFF) {
                ::CheckMenuItem(sub, id, flags);
                return;
            }
        }
    }
    ::CheckMenuItem(menu, id, flags);
}

// Locate the View > Columns popup by scanning for one of its command IDs
// instead of by hard-coded submenu index. New items have been inserted above
// "Columns", so any fixed index silently pointed at the wrong entry and left
// colsMenu NULL - which meant no column check mark was ever shown.
inline HMENU FindColumnsMenu(HMENU mainMenu) {
    if (mainMenu == nullptr) return nullptr;
    const int topCount = ::GetMenuItemCount(mainMenu);
    for (int t = 0; t < topCount; ++t) {
        HMENU top = ::GetSubMenu(mainMenu, t);
        if (top == nullptr) continue;
        const int subCount = ::GetMenuItemCount(top);
        for (int i = 0; i < subCount; ++i) {
            HMENU sub = ::GetSubMenu(top, i);
            if (sub == nullptr) continue;
            const int n = ::GetMenuItemCount(sub);
            for (int j = 0; j < n; ++j) {
                if (::GetMenuItemID(sub, j) == IDM_COL_PROTO) return sub;
            }
        }
    }
    return nullptr;
}

// True for the four columns fed by the ETW per-PID counters.
// They all render "—" until a traffic session is running, so showing any
// of them is what triggers the implicit start + status-bar hint below.
inline bool IsTrafficColumn(int col) {
    return col == COL_TRAFFIC || col == COL_RX || col == COL_TX ||
           col == COL_NETTOTAL;
}

// the admin-required actions (Block connection, ETW traffic counters)
// get the standard UAC shield glyph so a click reads as "this needs elevation"
// before the consent dialog appears. The icon is loaded once from the system
// via SHGetStockIconInfo (SIID_SHIELD); like every other shell32 call it is
// skipped when shell32 is delay-load unavailable, and skipped under
// high contrast - HC already provides its own high-contrast palette and a
// custom bitmap there would be drawn over it illegibly.
//
// The shield is shown only when the action is actually elevation-gated AND the
// current process is not already elevated. A standard account that cannot
// elevate at all gets NO shield: there is nothing the glyph could promise, so
// clicking the item shows the elevation-unavailable reason instead.
inline HICON g_shieldIcon = nullptr;   // owned; never destroyed (leak == exit)
inline bool  g_shieldTried = false;    // attempted load once

inline HICON LoadShieldIcon() {
    // shell32.dll is delay-loaded (WinCaps.cpp); gate before touching it so
    // the absence is a clean no-shield rather than an import crash.
    if (!DllAvailable("shell32.dll")) return nullptr;
    SHSTOCKICONINFO sii = {};
    sii.cbSize = sizeof(sii);
    if (::SHGetStockIconInfo(SIID_SHIELD, SHGFI_ICON | SHGFI_SMALLICON, &sii)
            != S_OK || sii.hIcon == nullptr)
        return nullptr;
    return sii.hIcon;
}

inline HICON ShieldIcon() {
    if (!g_shieldTried) {
        g_shieldTried = true;
        g_shieldIcon = LoadShieldIcon();
    }
    return g_shieldIcon;
}

// A process may have no icon to show: its image path could not be resolved
// (a protected / System / dead process), or the shell returned no icon for a
// path it did resolve. Rather than a blank row, fall back to one of the
// shell's stock icons (SIID_APPLICATION - the "generic application, no
// custom icon" glyph the shell uses as its own default).
//
// The index is into the shell's shared system image list - the same list
// MainWindow attaches to the connection view - so ProcessIconIndex can
// consume it without touching that list. Cached: the index is stable for
// the life of the shell image list.
inline int g_stockAppIconIndex = -2;   // -2 untried, -1 unavailable, >=0 index
inline int StockAppIconIndex() {
    if (!DllAvailable("shell32.dll")) return -1;
    if (g_stockAppIconIndex != -2) return g_stockAppIconIndex;
    SHSTOCKICONINFO sii = {};
    sii.cbSize = sizeof(sii);
    g_stockAppIconIndex = (::SHGetStockIconInfo(SIID_APPLICATION,
        SHGFI_SYSICONINDEX | SHGFI_SMALLICON, &sii) == S_OK)
        ? sii.iSysImageIndex : -1;
    return g_stockAppIconIndex;
}

// True when the current process lacks an elevated token but its user still has
// a linked Administrators token - i.e. elevation is possible via UAC and the
// shield glyph is meaningful.
inline bool ElevationPossibleForUser() {
    return !IsElevated() && IsAdminMember();
}

// Put/take the shield glyph on a single menu item. `on == false` clears it.
// Draws (or clears) the UAC shield glyph on one menu item. `on` already folds
// in every precondition - the caller's HighContrastActive() result, and
// ElevationPossibleForUser() - so this function just owns the bitmap plumbing.
// No-op when there is no shield icon to draw (shell32 delay-loaded away, or
// the stock-icon query failed).
inline void SetMenuItemShield(HMENU menu, UINT id, bool on) {
    if (menu == nullptr) return;
    const HICON icon = ShieldIcon();
    if (icon == nullptr) return;               // no shell / icon unavailable
    MENUITEMINFO mii = {};
    mii.cbSize   = sizeof(mii);
    mii.fMask    = MIIM_BITMAP;
    mii.dwTypeData = nullptr;                  // not used with MIIM_BITMAP
    mii.hbmpItem = on ? reinterpret_cast<HBITMAP>(icon) : nullptr;
    ::SetMenuItemInfoW(menu, id, FALSE, &mii);
}

// the bar-menu ETW item (View > Per-PID traffic counters). Its submenu
// is found by scanning for the item, so this fails closed if the menu layout
// changes rather than asserting a wrong submenu index. `highContrast` is
// supplied by the caller because this is a free function and cannot inspect
// the window's own high-contrast state.
inline void ApplyTrafficShield(HMENU bar, bool highContrast) {
    if (bar == nullptr) return;
    const bool showShield = !highContrast && ElevationPossibleForUser();
    const int pops = ::GetMenuItemCount(bar);
    for (int i = 0; i < pops; ++i) {
        HMENU sub = ::GetSubMenu(bar, i);
        if (sub == nullptr) continue;
        const int subCount = ::GetMenuItemCount(sub);
        for (int j = 0; j < subCount; ++j) {
            MENUITEMINFO sm = {};
            sm.cbSize = sizeof(sm);
            sm.fMask = MIIM_ID;
            if (::GetMenuItemInfoW(sub, static_cast<UINT>(j), TRUE, &sm) &&
                sm.wID == IDM_VIEW_TRAFFIC) {
                SetMenuItemShield(sub, IDM_VIEW_TRAFFIC, showShield);
            }
        }
    }
}

}  // namespace mw
}  // namespace wintcp

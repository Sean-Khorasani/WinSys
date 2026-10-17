// Settings.h
// SPDX-License-Identifier: Apache-2.0
// Persisted user settings in HKCU\Software\WinTCP: window
// placement, refresh interval, toggles, sort/visibility/widths, filter
// text, change-log path and last export directory. All loads/saves are
// best effort - a missing value or access failure keeps the default.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>   // RegReadBoundedString's std::wstring
#include <vector>

#include "Alerts.h"   // AlertSettings
#include "ColumnsWin.h"   // COL_COUNT, kDefaultVisibleCols, ClampVisibleCols

namespace wintcp {

// Read one REG_SZ / REG_EXPAND_SZ value and return it only if it is PROVABLY a
// terminated string no longer than 'maxChars'. False on any doubt - missing,
// wrong type, not a multiple of sizeof(wchar_t), unterminated, or longer than
// the bound - and on false *out is left untouched, so a caller keeps whatever
// default it had.
//
// 'maxChars' EXCLUDES the terminator: a value of exactly maxChars is legal,
// maxChars + 1 is not. Pass 0 only for a value that must be empty.
//
// This is the ONE validator. Bookmarks and Presets each carried their own
// byte-identical copy of this trust logic - same size-mod-wchar_t check, same
// maxChars+2 slack for the query's double-counted terminator, same NUL check.
// Two copies of a security check is one more than the codebase should have:
// the day one was tightened (say, to reject embedded NULs) the other would have
// kept accepting them, and the difference would have been invisible.
//
// Written to std::wstring rather than a caller buffer because that is what
// forced the duplication: a buffer-filling signature needs the caller to supply
// the capacity, so each store invented its own.
bool RegReadBoundedString(HKEY key, const wchar_t* name, size_t maxChars,
                          std::wstring* out);

// Load-time validation bounds. A persisted value outside these is
// discarded in favour of the compiled-in default — never repaired, never
// believed. Named here (not at the use sites) so Load, Save and any future
// validator share one definition of "sane".
constexpr UINT kMinIntervalMs = 250;        // 0.25 s: below this the UI livelocks
constexpr UINT kMaxIntervalMs = 3600000;    // 1 h: above this "auto" is meaningless
constexpr int kMaxColWidth = 4000;          // wider than any monitor: corrupt data

// Compiled-in defaults. Every non-obvious default below has a name so
// the registry, the GUI fallback and the help text cannot disagree about it.
// Trivially self-evident initializers (false, 0, empty strings, COL_PID,
// SW_SHOWNORMAL, kDefaultVisibleCols) deliberately have none — a name for
// "false" is clutter, not clarity, and the struct initializer already says it.
constexpr UINT kDefaultRefreshSec = 2;       // the product's cadence, in seconds
constexpr UINT kDefaultIntervalMs =
    kDefaultRefreshSec * 1000;              // ...and in ms (unifies all three)
constexpr UINT kCurrentColVersion = 5;       // schema Save() writes; see Load
constexpr size_t kMaxFilterChars = 512;     // filter box + persisted Filter

struct Settings {
    // Window placement
    bool winPlaced = false;
    int winX = 0;
    int winY = 0;
    int winW = 0;
    int winH = 0;
    int showCmd = SW_SHOWNORMAL;

    // Behavior
    UINT intervalMs = kDefaultIntervalMs;
    bool autoRefresh = false;
    bool resolveHosts = false;

    // Modern Windows
    bool topMost = false;
    bool trayEnabled = false;

    // First-run minimization choice. Persisted as a single DWORD so the
    // "Minimize to tray or exit?" prompt appears at most once:
    //   0  never asked          -> prompt the first minimize when tray is off
    //   1  remembered: tray     -> minimize-to-tray, no prompt
    //   2  remembered: exit     -> exit on minimize, no prompt
    DWORD trayMinimizeChoice = 0;

    // Traffic counters. Only ever persisted as true when the
    // ETW kernel logger actually started (i.e. the process was elevated).
    bool trafficEnabled = false;

    // View state
    int sortCol = COL_PID;
    bool sortAsc = true;
    UINT32 colVisible = kDefaultVisibleCols;
    UINT colVersion = 0;   // schema of the persisted column mask (0 = never saved)
    int colWidths[COL_COUNT] = {};
    bool colWidthsValid = false;

    // User's column drag-reorder. Persisted as a permutation of
    // ColumnId over ALL columns, not just the visible ones, so that hiding and
    // re-showing a column does not silently lose where the user put it.
    // colOrderValid is false until a reorder has actually been saved, which is
    // what distinguishes "user never dragged" from "user dragged and the
    // stored order happens to equal the default".
    int colOrder[COL_COUNT] = {};
    bool colOrderValid = false;
    // Same capacity as the preset filter (kMaxPresetFilterChars, Presets.h):
    // a saved filter must survive a round trip through either store.
    wchar_t filter[kMaxFilterChars] = {0};

    // Change log
    bool logEnabled = false;
    wchar_t logPath[MAX_PATH] = {0};

    // Export
    wchar_t lastExportDir[MAX_PATH] = {0};

    // GeoIP: the GUI's picked .mmdb path, persisted. Empty = never
    // picked (or the file moved - a stale path is retried silently on the
    // next launch and Country stays "—" until one loads). Deliberately NOT
    // a ColVersion bump: the column schema does not change, this is one new
    // REG_SZ that older keys simply lack.
    wchar_t geoIpPath[MAX_PATH] = {0};
    // The GeoLite2-ASN path, persisted on the same terms as geoIpPath and
    // for the same reason - the window should not have to be told again at every
    // launch. Also deliberately NOT a ColVersion bump: it is not a column.
    wchar_t asnIpPath[MAX_PATH] = {0};

    // Alerts. The engine itself is pure and tested; it had no persistence
    // and no caller, so nothing could ever fire. Persisted on the same terms as the
    // paths above - one value per setting, absent keys fall back to the engine's own
    // defaults, and no ColVersion bump because none of this is a column.
    //
    // MUTED BY DEFAULT is the design rule, not a missing feature: a network viewer
    // that pops a balloon every refresh is one the user switches off, and then it is
    // useless for the one event that mattered.
    //
    // This is the ENGINE'S OWN struct, not a parallel shape of it. The first
    // attempt kept eight separate fields here and converted on the way to the
    // evaluator, which is the duplication this codebase's own rule is about: two
    // representations of one configuration can drift, and the one that drifts is
    // always the one nobody displays. Persisting the struct the engine reads is
    // what makes the CLI, the registry and the evaluator unable to disagree.
    //
    // MUTED BY DEFAULT, by design rather than by omission.
    AlertSettings alerts;

    // Read from HKCU; never fails hard (defaults stay on missing values).
    bool Load();
    bool Save() const;         // best effort; returns false on write failure

    // Apply the portable `wintcp.ini` that sits beside the executable.
    //
    // MUST be called BEFORE Load(). It supplies DEFAULTS only, so an existing
    // user's saved settings always win - the alternative (the ini overriding
    // the registry) means a setting changed in the GUI silently reverts on the
    // next launch. With this ordering the ini is exactly "what to use on a
    // machine I have never run this on".
    //
    // Only the BEHAVIOUR preferences are in scope. Window placement, column
    // widths and the column order are per-monitor, per-machine facts whose
    // values mean nothing elsewhere - see IniFile.h for why.
    //
    // Returns true and sets 'error' when the file EXISTS but cannot be read or
    // parsed, which is a user-visible fault worth reporting; returns false with
    // an empty error when there is no ini at all, which is the ordinary case.
    bool ApplyPortableDefaults(const std::wstring& exePath,
                               std::wstring* error);
};

// Is the first 'count' entries of 'order' a permutation of 0..count-1?
//
// 'count' is a parameter rather than being pinned to COL_COUNT because the
// real check has to run over a whole-column-count array that may be a
// different size than the one in memory - a 6-element scratch buffer checked
// as 23 columns reads off the end, which is undefined behaviour and would
// have silently "worked" in a test. Passing the count makes the two agree by
// construction.
//
// A duplicate would render one column twice while another vanished, and a
// half-written or hand-edited registry value is entirely possible, so this is
// checked on load as well as before saving.
bool IsColumnPermutation(const int* order, size_t count);

// Fold a reordered VISIBLE column sequence back into a full-order permutation.
//
// 'visibleMask' is the bitmask of which ColumnIds are currently shown.
// 'newVisible' is those same visible columns in the order the user just chose.
// Returns the new full order, or 'fullOrder' unchanged if anything about the
// inputs is inconsistent.
//
// This is the non-obvious half of that. The header only ever sees the visible
// subset, but the persisted order covers every column. Writing the visible
// subset straight back would renumber the hidden ones and scramble the layout
// the next time a column is enabled.
//
// The algorithm fills the EXISTING visible slots in place rather than
// repositioning columns. That distinction is the whole point: moving the
// visible columns to the front and appending the hidden ones also satisfies
// "the visible subsequence is in this order", but it relocates every hidden
// column on every drag, and - worse - it is not the identity when the user
// has not dragged at all. Filling the slots in place makes the no-drag case
// exactly a no-op, which is what lets the caller trust it unconditionally.
//
// Exposed for testing because getting it wrong is silent: nothing crashes,
// the layout is just quietly wrong after a drag.
std::vector<int> FoldVisibleOrder(const std::vector<int>& fullOrder,
                                  UINT32 visibleMask,
                                  const std::vector<int>& newVisible);

}  // namespace wintcp

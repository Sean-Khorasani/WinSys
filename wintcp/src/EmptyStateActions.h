// EmptyStateActions.h
// SPDX-License-Identifier: Apache-2.0
// The buttons half of empty states.
//
// MainWindow::UpdateEmptyState already says the reason (one actionable
// sentence per case, NO ROWS > DATABASE > TRAFFIC). The empty state also
// BUTTONS alongside it: [Run as admin], [Clear], [Edit], [Pick .mmdb].
//
// This is the decision half, pure and tested, so the wiring in MainWindow is a
// thin hook. Same split as every other module here (FilterClause is the
// precedent): the predicate the window runs is the predicate the selftest
// pins, and there is no second copy in the window to drift from it.
//
// TWO RULES the button set follows, both learned from the window:
//
//   1. [Run as admin] only ever appears when the process is NOT already
//      elevated. Offering "restart with more rights" to a process that already
//      has them is a button that does nothing - and a user who clicks it and
//      sees nothing happen has been lied to. `doctor` reports elevation, and
//      the empty-state message already says "(needs admin)", so the honest
//      thing is to show the button only in the case where the click works.
//
//   2. The precedence is the one UpdateEmptyState already uses: NO ROWS
//      first, then DATABASE, then TRAFFIC. Keeping the order is what stops the
//      two from disagreeing about which case the window is in.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cwchar>

namespace wintcp {

// Which case the window is in. kNone means "not an empty state at all" - the
// ordinary full table, or a genuinely empty machine.
enum class EmptyStateCase {
    kNone,
    kNoFilterMatch,   // rows exist, the filter excludes all of them
    kNoGeoIp,         // a country column is shown with no database
    kNoTraffic,       // a traffic column is shown with nothing measuring it
};

// The button labels, in one place, so the dialog and the tests agree on the
// exact text. The existing infobar text already names the menu item that fixes
// each case; these are the same fixes offered as a click.
constexpr const wchar_t* kEmptyActionClear = L"&Clear filter";
constexpr const wchar_t* kEmptyActionEdit = L"&Edit filter";
constexpr const wchar_t* kEmptyActionPickGeo = L"&Pick .mmdb file";
constexpr const wchar_t* kEmptyActionRunAdmin = L"Re&start as administrator";

struct EmptyStateOffer {
    EmptyStateCase caze = EmptyStateCase::kNone;

    // The sentence UpdateEmptyState already produces. Recomputed here rather
    // than passed in so a caller cannot offer buttons for a case the predicate
    // did not actually select - the two halves cannot disagree.
    const wchar_t* message = L"";

    // Which buttons to offer, each in the order the dialog will show them.
    bool offerClear = false;
    bool offerEdit = false;
    bool offerPickGeo = false;
    bool offerRunAdmin = false;

    // How many buttons that is. Zero means "nothing to offer": the message
    // stays on the status bar exactly as it is today, and no dialog appears.
    // That matters because an empty-state message with no action is still
    // useful (it says why the table is empty); a dialog with no buttons is
    // just an extra click.
    size_t ButtonCount() const {
        return (offerClear ? 1u : 0u) + (offerEdit ? 1u : 0u) +
               (offerPickGeo ? 1u : 0u) + (offerRunAdmin ? 1u : 0u);
    }
};

// Decide the case and its buttons from the live facts.
//
// 'rowsTotal' is every row the store holds, 'viewCount' what passes the
// filter, and the four flags are the same live values UpdateEmptyState reads.
// The precedence and the individual facts mirror that function exactly, so if
// one changes the other must, and the selftest pins both.
EmptyStateOffer DecideEmptyState(size_t rowsTotal, size_t viewCount,
                                 bool countryColumnVisible, bool geoLoaded,
                                 bool asnLoaded, bool trafficColumnVisible,
                                 bool etwRunning, bool socketFallback,
                                 bool processElevated);

}  // namespace wintcp

// BuildInfo.cpp
// SPDX-License-Identifier: Apache-2.0
// See BuildInfo.h.

#include "BuildInfo.h"
#include "Version.h"

#include "WinCaps.h"   // the optional-capability block in AboutText

namespace wintcp {
namespace {

// Pad 'keys' out to a fixed column so the descriptions line up. A fixed
// column rather than the longest key seen, because the longest key is a
// data-dependent value and a sheet whose indentation changes every time a
// longer shortcut is added looks broken.
constexpr size_t kKeyColumn = 18;

std::wstring PadKeys(const std::wstring& keys) {
    std::wstring line = keys;
    if (line.size() < kKeyColumn)
        line.append(kKeyColumn - line.size(), L' ');
    else
        line.push_back(L'\t');
    return line;
}

}  // namespace

const std::vector<Shortcut>& AllShortcuts() {
    // Order is the order the sheet groups them, not alphabetical: keys a user
    // is likely to reach for come first, and the sheet reads better grouped
    // by what they DO than sorted by letter.
    static const std::vector<Shortcut> kList = {
        {L"F1",         L"Keyboard shortcuts (this sheet)"},
        {L"F5",         L"Refresh now"},
        {L"F6",         L"Freeze / unfreeze the view (5.5)"},
        {L"F7",         L"Group rows by process on / off (5.1)"},
        {L"Ctrl+C",     L"Copy selected connections"},
        {L"Ctrl+A",     L"Select all rows"},
        {L"Ctrl+F",     L"Focus the filter box"},
        {L"Ctrl+S",     L"Save view as preset"},
        {L"Ctrl+E",     L"Export to CSV"},
        {L"Esc",        L"Clear the filter"},
        {L"Del",        L"Close the selected connection"},
        {L"Ctrl+Del",   L"End the selected process (graceful close first)"},
        {L"A-Z",        L"Type to jump to a row by process name"},
        {L"Backspace",  L"Back out of a type-to-jump prefix"},
        {L"Alt",        L"Underline a letter to walk the menus (Ctrl+key)"},
        {L"Ctrl+click", L"Extend the selection"},
        {L"Shift+click",L"Select a range"},
        {L"Double-click", L"Open the details pane for the row"},
        {L"Shift+F10",  L"Open the context menu for the selected row"},
        {L"Drag header",L"Reorder a column (the order is remembered)"},
        {L"Tab",        L"Move between the filter controls and the list"},
    };
    return kList;
}

std::wstring ShortcutsText() {
    std::wstring out;
    out += L"Keyboard shortcuts\n\n";
    // A trailing \r\n because MessageBox renders \n only inconsistently
    // across the Windows versions this app still runs on.
    for (const Shortcut& s : AllShortcuts()) {
        out += PadKeys(s.keys);
        out += s.description;
        out += L"\r\n";
    }
    out += L"\r\nType-to-jump: press a letter to jump to the first row "
           L"beginning with it. Press the SAME letter again to step through "
           L"rows sharing that prefix. Wait a second and the next keystroke "
           L"starts a new search.\r\n";
    return out;
}

std::wstring AboutText(const BuildSummary& s, bool verbose) {
    std::wstring out;
    out += L"WinTCP ";
    out += std::to_wstring(WINTCP_VERSION_MAJOR) + L"." +
           std::to_wstring(WINTCP_VERSION_MINOR) + L"." +
           std::to_wstring(WINTCP_VERSION_PATCH) + L"\r\n\r\n";
    out += L"A live view of every TCP and UDP endpoint on this machine "
           L"(IPv4 + IPv6), with the process that owns it, read through the "
           L"IP Helper API (GetExtendedTcpTable / GetExtendedUdpTable).\r\n";
    out += L"Plain Win32 API and the common controls. No MFC, ATL or Qt.\r\n";
    out += L"\r\n";

    // The --verbose switch adds diagnostic detail for troubleshooting. The base
    // output is the capability summary; verbose adds the internal state that
    // explains WHY a capability is missing or a counter is zero.
    if (verbose) {
        out += L"Verbose diagnostics\r\n";
        out += PadKeys(L"ETW running") +
               (s.etwRunning ? L"yes" : L"no") + L"\r\n";
        out += PadKeys(L"Socket fallback") +
               (s.trafficFallback ? L"yes" : L"no") + L"\r\n";
        out += PadKeys(L"GeoIP loaded") +
               (s.geoIpLoaded ? L"yes" : L"no") + L"\r\n";
        out += PadKeys(L"Presets") +
               (s.presetsAvailable ? L"available" : L"unavailable") + L"\r\n";
        out += PadKeys(L"Column count") +
               std::to_wstring(s.totalColumnCount) + L"\r\n";
        if (s.trafficScanRan) {
            out += PadKeys(L"Traffic timeouts") +
                   std::to_wstring(s.trafficTimeouts) + L"\r\n";
            out += PadKeys(L"Traffic failures") +
                   std::to_wstring(s.trafficScanFailures) + L"\r\n";
        }
        out += L"\r\n";
    }

    // The capability block. This is what it is actually for: a user
    // wondering why a column is empty should be able to find the answer
    // here rather than guessing from a blank cell.
    out += L"This run\r\n";
    out += PadKeys(L"Administrator") +
           (s.elevated
                ? std::wstring(L"yes — traffic counters and connection "
                               L"closing are available")
                : std::wstring(L"no — per-PID traffic counters and "
                               L"per-connection close are unavailable")) +
           L"\r\n";
    out += PadKeys(L"Traffic source") +
           std::wstring(s.etwRunning
                            ? L"ETW kernel logger (full, including UDP)"
                            : (s.trafficFallback
                                   ? L"socket fallback (TCP only)"
                                   // Elevated with no collector running is
                                   // its own state, and it is NOT "needs
                                   // administrator": the CLI runs no session
                                   // at all, and an elevated GUI with traffic
                                   // off has rights to spare. Printing the
                                   // unelevated reason here put
                                   // "none (needs administrator)" two lines
                                   // under "Administrator yes".
                                   : (s.elevated
                                          ? L"none (no collector is running)"
                                          : L"none (needs administrator)"))) +
           L"\r\n";
    // What the traffic scan could not measure. Printed only when a scan
    // actually ran, and only the non-zero ones - a healthy machine gains
    // nothing here, which is the point. See BuildSummary for why the two
    // counters are separate fields.
    if (s.trafficScanRan && (s.trafficTimeouts != 0 || s.trafficScanFailures != 0)) {
        std::wstring lost;
        if (s.trafficScanFailures != 0) {
            lost += L"failed ";
            lost += std::to_wstring(s.trafficScanFailures);
            lost += L" time(s) - traffic UNMEASURED";
        }
        if (s.trafficTimeouts != 0) {
            if (!lost.empty()) lost += L";";
            lost += L"dropped ";
            lost += std::to_wstring(s.trafficTimeouts);
            lost += L" pass(es) - traffic STALE";
        }
        out += PadKeys(L"Traffic gaps") + lost + L"\r\n";
    }
    // "empty", not "—": the cell is filled with an empty string when no database
    // is loaded, so that is what a user sees. The em-dash here was a documented
    // lie - it described a rendering the code never produced, and a reader who
    // went looking for a dash in their table would not find one.
    out += PadKeys(L"GeoIP database") +
           std::wstring(s.geoIpLoaded
                            ? L"loaded"
                            : L"not loaded (Country column is empty)") +
           L"\r\n";
    out += PadKeys(L"Saved presets") +
           std::wstring(s.presetsAvailable ? L"available" : L"unavailable") +
           L"\r\n";

    // The optional-capability block (WinCaps.h). Its purpose is the one the
    // GeoIP line above sets out and cannot deliver alone: a user staring at an
    // empty Disk column deserves to be told WHY, and told what would fix it.
    // Every line is omitted when the capability is present, so on a normal
    // machine this block contributes nothing and the About box reads exactly as
    // it did before it existed.
    {
        int unavailable = 0;
        for (const Capability& cap : WinCapabilities()) {
            if (cap.state == CapState::Available) continue;
            ++unavailable;
            out += PadKeys(cap.what) + cap.detail;
            if (!cap.install.empty()) out += L" (install: " + cap.install + L")";
            out += L"\r\n";
        }
        // THE SUMMARY LINE IS ALWAYS PRINTED. The first version used
        // `else if (unavailable > 1)`, so with exactly ONE unavailable
        // capability the report printed the detail line and then went silent -
        // no summary at all. That is the worst possible case: the single
        // degraded feature is the one a user most wants a headline for, and it
        // was the one case the block said nothing about. Found by running the
        // binary with a stub pdh.dll, which the machine this was written on
        // cannot otherwise produce.
        //
        // Every case therefore ends in a line: 0 says "all available", n says
        // how many. A count the reader can trust is the whole value of the
        // block.
        if (unavailable == 0) {
            out += PadKeys(L"Optional features") + L"all available\r\n";
        } else {
            out += PadKeys(L"Optional features") +
                   std::to_wstring(unavailable) +
                   L" unavailable (listed above)\r\n";
        }
    }
    // A count nobody measured must not be printed. The CLI has no
    // persisted GUI view mask and (before the fix) took no snapshot either, and
    // both used to print a confident-looking "0 of 23" / "Connections 0" that
    // reads as a fact about the machine. Omit the line instead: an absent
    // number is honest, a wrong one is not.
    if (s.columnCountKnown) {
        out += PadKeys(L"Columns shown") +
               std::to_wstring(s.visibleColumnCount) + L" of " +
               std::to_wstring(s.totalColumnCount) + L"\r\n";
    }
    if (s.rowCountKnown)
        out += PadKeys(L"Connections") + std::to_wstring(s.rowCount) + L"\r\n";
    // Handle and GDI counts, so a user reporting "it gets slow after a
    // day" can report a number instead. These are the counters that grow when
    // something leaks, and they are the only evidence that distinguishes a
    // leak from "this machine is just busy" - so printing them makes the
    // difference checkable rather than arguable.
    //
    // USER objects are reported alongside GDI because they are the same leak
    // with a different budget: the default per-process GDI limit is 10,000 and
    // the USER limit is 10,000 too, and a tool that draws icons and cursors
    // can hit either. Reported separately because they fail differently and a
    // single combined number would hide which one is at the ceiling.
    // Each line is gated on its OWN answer, because they are read by different
    // calls with different failure reporting: the handle count knows whether
    // it succeeded, the two GDI budgets do not. See BuildSummary in
    // BuildInfo.h for the measured reason 0 is a real answer here.
    if (s.resourceCountsKnown)
        out += PadKeys(L"Handles") + std::to_wstring(s.handleCount) + L"\r\n";
    out += PadKeys(L"GDI objects") + std::to_wstring(s.gdiCount) + L"\r\n";
    out += PadKeys(L"USER objects") + std::to_wstring(s.userCount) + L"\r\n";
    return out;
}

}  // namespace wintcp

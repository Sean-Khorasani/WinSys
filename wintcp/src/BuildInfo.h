// BuildInfo.h
// SPDX-License-Identifier: Apache-2.0
// Build summary and the keyboard-shortcut sheet.
//
// Both are text assembled from live state rather than hard-coded strings,
// which is the whole point: a shortcut sheet that is written out by hand goes
// stale the moment someone adds F7, and a build summary that hard-codes
// "elevation: no" is wrong for the one user who cares - the one running as
// administrator. Both read the same source of truth the rest of the app uses
// (Version.h, the resource ids, the live capability probes), so they cannot
// drift from what the program actually does.
//
// The shortcut list is DATA, not text. ShortcutsText() renders it, and the
// selftest renders the same list, so adding a shortcut without documenting it
// - or documenting one that does not exist - is caught by a test rather than
// discovered by a user.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>
#include <vector>

namespace wintcp {

struct Shortcut {
    std::wstring keys;         // "F5", "Ctrl+C"
    std::wstring description;  // "Refresh now"
};

// Every keyboard shortcut the app binds, in the order the sheet lists them.
// Sourced from the same IDs the accelerator table and the menu use, so this
// cannot claim a shortcut the accelerator table does not contain.
const std::vector<Shortcut>& AllShortcuts();

// The rendered sheet, grouped by category with a tab-aligned column so the
// keys line up in a proportional font.
std::wstring ShortcutsText();

// The About box body: version, build configuration, and the capability
// state of THIS run. 'elevated' and each capability flag are passed in rather
// than probed here, so the caller decides what counts as "this run" and the
// function stays free of side effects.
struct BuildSummary {
    // The SECURITY TOKEN's elevation, not "did this process get the relaunch
    // marker". The two differ for anyone who launched an already-elevated
    // console, and reporting "Administrator no" there - while `close --yes`
    // goes on to succeed - is the single most damaging thing this box can say.
    bool elevated = false;
    bool etwRunning = false;
    bool trafficFallback = false;
    bool geoIpLoaded = false;
    bool presetsAvailable = false;
    int visibleColumnCount = 0;
    int totalColumnCount = 0;
    size_t rowCount = 0;
    // This process's own handle and GDI counts.
    //
    // 'resourceCountsKnown' gates ONLY the handle count, because that is the
    // only one of the three whose success the API can report - GetProcess-
    // HandleCount returns a BOOL, while GetGuiResources returns the count with
    // no way to distinguish a failure from a true zero. A console-subsystem
    // process really does hold 0 GDI objects, so 0 is printed rather than
    // treated as a missing answer.
    DWORD handleCount = 0;
    DWORD gdiCount = 0;
    DWORD userCount = 0;
    bool resourceCountsKnown = true;
    // True when rowCount was actually measured. False means the caller could
    // not take a snapshot, and the line is then omitted rather than printed as
    // a confident "Connections 0" - which is what the CLI used to claim, and
    // which reads as "this machine has no connections" instead of "nobody
    // looked".
    bool rowCountKnown = true;
    // True when visibleColumnCount is a real count. The CLI has no persisted
    // GUI view mask, so it has nothing to count; the line is omitted there
    // rather than printed as "0 of 23".
    bool columnCountKnown = true;

    // What the traffic scan could not measure, counted. Both are 0 on
    // a healthy machine and both mean the traffic columns are incomplete for a
    // REASON, which is the point: a blank traffic cell is otherwise
    // indistinguishable from a connection that genuinely moved no bytes.
    //
    //   trafficTimeouts     - passes dropped because a worker stopped making
    //                         progress (a socket whose SIO_TCP_INFO never
    //                         returns). Previous totals are kept, so the
    //                         numbers are STALE rather than absent.
    //   trafficScanFailures - passes that could not read the process handle
    //                         table at all, so nothing was merged and every
    //                         traffic cell is UNMEASURED.
    //
    // The two are separate fields because the remedies differ: a timeout says
    // "this machine has an unreadable socket", a failure says "the scan itself
    // did not run". One number wearing two names would be useless.
    unsigned trafficTimeouts = 0;
    unsigned trafficScanFailures = 0;
    // False when nothing was sampled in this process, so the lines are omitted
    // rather than printed as a confident "0" - the same rule as the counters
    // above. A CLI run that never asked for --traffic has no opinion.
    bool trafficScanRan = false;
};

std::wstring AboutText(const BuildSummary& s, bool verbose = false);

}  // namespace wintcp

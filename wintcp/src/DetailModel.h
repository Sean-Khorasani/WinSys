// DetailModel.h
// SPDX-License-Identifier: Apache-2.0
// The structured content of the Details window.
//
// The window used to be a single flat wstring built by string concatenation
// and dropped into one read-only EDIT control with ES_AUTOVSCROLL. That
// forced a fixed 640 px window, could not wrap a value, and re-parsed the
// whole body on every auto-refresh tick. This model replaces the string with
// typed data so the window can lay it out, wrap long values, collapse
// sections and repaint cheaply.
//
// Kept in its own header, and free of any window code, so the builder in
// MainWindow and the renderer in DetailsDialog agree on one structure and so
// --selftest can exercise the builder without a window.

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

// One "label : value" pair. 'label' is a short, stable key ("PID",
// "Remote port"); 'value' is the display text, already formatted and already
// carrying the em-dash placeholder when the reading is unavailable.
struct DetailField {
    std::wstring label;
    std::wstring value;
    // A monospaced hint for values where alignment matters (hex, byte
    // counts, timestamps). The renderer uses a monospace face for these so
    // digits line up; everything else uses the UI font.
    bool monospace = false;
};

// The Details window's tab set is derived from the model's sections: each tab
// that has at least one section is shown, in tab-ordinal order, so a row with
// no TLS session simply has no Security tab instead of an empty one.
enum DetailTab : unsigned {
    kTabProcess = 0,     // Process, Threads, Live stats
    kTabConnection,      // Selected connection
    kTabSockets,         // Sibling connections (Sockets-of-PID)
    kTabSecurity,        // TLS + integrity/signature
    kTabNotes,           // Bookmarks, pins, user note
    kTabCount
};

// Display label for a tab, used by the renderer and pinned by selftests so the
// vocabulary cannot drift silently.
const wchar_t* TabLabel(DetailTab t);

// A titled group of fields. Sections are collapsible; the collapsed state is
// the user's, not the data's, and is never persisted.
//
// `tab` classifies the section into one of the Details window's tabs (see
// DetailTab), so the renderer can show only the active tab's sections - which
// is how a row with no TLS session simply drops the Security tab instead of
// showing an empty one.
struct DetailSection {
    std::wstring title;
    std::vector<DetailField> fields;
    // Rendered under the section title in a dimmer face - used for the
    // hint lines ("enable View > Per-PID traffic counters") and for the
    // connection list, which the renderer lays out as its own block.
    std::wstring note;
    DetailTab tab = kTabProcess;
};

// Everything the Details window shows. Building this is pure; rendering it
// is not.
struct DetailModel {
    // Header line above the content, e.g. "chrome.exe (PID 42)".
    std::wstring title;
    std::wstring subtitle;      // smaller second line, e.g. the endpoint
    std::vector<DetailSection> sections;
    // Endpoint lines for the "Connections" section. Kept separate from
    // fields because the renderer gives them a monospace, wrapped layout
    // rather than a label/value row.
    std::vector<std::wstring> connectionLines;
    size_t connectionTotal = 0;   // may exceed connectionLines.size()
    // The tab currently shown by the window. Defaults to Process so a
    // freshly opened Details lands on the process identity first - the thing
    // a reader usually wants to confirm before the endpoints.
    DetailTab activeTab = kTabProcess;

    // Plain-text rendering, used by the Copy button. Produces the same
    // content the window shows, in a form that pastes cleanly anywhere.
    std::wstring ToPlainText() const;
};

// Process creation time as a local "YYYY-MM-DD HH:MM:SS", or empty when the
// time is unknown. Split out of MainWindow so both the details builder and
// the tests use one formatter.
std::wstring FormatFileTimeLocal(const FILETIME& ft, bool known);

}  // namespace wintcp

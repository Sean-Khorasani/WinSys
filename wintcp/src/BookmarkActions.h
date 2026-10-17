// BookmarkActions.h
// SPDX-License-Identifier: Apache-2.0
//
// The bookmark surface: the list dialog, the registry join, and the three row
// actions (toggle, edit note, remove).
//
// Extracted from MainWindow because the bookmark STORE (Bookmarks.h) was
// always a separate, tested module and the window was the only thing holding
// the dialogs, the selection read, and the "the bookmark set changed"
// bookkeeping in one place. The coupling that remains is exactly the two
// things the window owns: which row is selected, and what a change looks like
// (a re-join and a repaint).
//
// One hazard the window had and this class keeps, stated once instead of once
// per method: every prompt below runs a MODAL message loop, during which a
// queued refresh can reallocate the store and dangle a row pointer. So the
// endpoint is copied before the first prompt, in every method, without
// exception.
//
// Storage goes through the abstract layer (CmdBookmark*) so the GUI and the
// `bookmark` CLI verb share one path and cannot drift.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <functional>
#include <optional>
#include <string>

#include "Bookmarks.h"
#include "Connection.h"

namespace wintcp {

class ConnectionStore;

class BookmarkActions {
public:
    // The window's two contributions: which row is selected, and what to do
    // after the bookmark set changes (re-join the rows and repaint).
    using SelectedRow = std::function<std::optional<Connection>()>;
    using Changed = std::function<void()>;

    BookmarkActions(HWND owner, SelectedRow selected, Changed changed)
        : owner_(owner), selected_(std::move(selected)),
          changed_(std::move(changed)) {}

    // View > Bookmarks: everything in the store, with the unreadable count
    // stated rather than quietly dropped.
    void ShowList();

    // Read the store once and push it into the row model. Once per refresh,
    // into a plain vector the store can walk without touching the registry -
    // asking per row would mean a registry query per connection per tick.
    //
    // Address, PORT and note are all carried: the port is part of a bookmark's
    // identity (matching on the address alone flagged the wrong conversation),
    // and the note is what makes it visible in the table and reachable by a
    // `note:` filter.
    void JoinInto(ConnectionStore& store);

    // Toggle the selected row's endpoint: remove it when it is already
    // bookmarked, add it (and ask for a note) when it is not. One checkable
    // action rather than a separate remove command, which is what a user
    // expects from a menu item with a tick.
    void ToggleSelected();

    // Prompt for the note on the selected row's endpoint. The prompt comes
    // pre-filled with the existing note, so it edits rather than re-enters.
    void EditSelectedNote();

private:
    // The selected row's endpoint, already checked and copied. Returns false
    // with 'why' set when there is nothing to act on.
    bool SelectedEndpoint(std::wstring* address, UINT* port,
                          std::wstring* why);

    HWND owner_;
    SelectedRow selected_;
    Changed changed_;
};

}  // namespace wintcp

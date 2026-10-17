// BookmarkActions.cpp
// SPDX-License-Identifier: Apache-2.0
// See BookmarkActions.h.

#include "BookmarkActions.h"

#include "Commands.h"      // the abstract layer: CmdBookmark*
#include "ConnectionStore.h"
#include "PromptDialog.h"  // PromptForText
#include "Utils.h"         // Utf8ToWide

namespace wintcp {

void BookmarkActions::ShowList() {
    size_t unreadable = 0;
    const std::vector<Bookmark> all = Bookmarks::List(&unreadable);
    if (all.empty()) {
        std::wstring msg = L"No bookmarks yet.\r\n\r\n"
                           L"Right-click a connection and choose "
                           L"\"Bookmark this connection\".";
        if (unreadable != 0)
            msg = L"No readable bookmarks.\r\n\r\n" +
                  std::to_wstring(unreadable) +
                  L" stored bookmark(s) could not be read and are being "
                  L"ignored.";
        ::MessageBoxW(owner_, msg.c_str(), L"Bookmarks", MB_OK);
        return;
    }
    std::wstring text;
    for (const Bookmark& b : all) {
        text += b.Key();
        if (b.tag != kBookmarkTagNone) {
            text += L"  [";
            text += BookmarkTagLabel(b.tag);
            text += L"]";
        }
        if (!b.note.empty()) {
            text += L"\r\n    ";
            text += b.note;
        }
        text += L"\r\n\r\n";
    }
    if (unreadable != 0) {
        // Never claim "you have N bookmarks" when some were skipped: a count
        // that quietly drops entries is how a user loses track of one.
        text += std::to_wstring(unreadable) +
                L" further bookmark(s) could not be read and are not shown.\r\n";
    }
    ::MessageBoxW(owner_, text.c_str(), L"Bookmarks", MB_OK);
}

void BookmarkActions::JoinInto(ConnectionStore& store) {
    std::vector<BookmarkMark> known;
    const std::vector<Bookmark> all = Bookmarks::List();
    known.reserve(all.size());
    for (const Bookmark& b : all) {
        BookmarkMark m;
        m.address = b.address;
        m.port = b.port;
        m.tag = b.tag;
        m.note = b.note;
        known.push_back(std::move(m));
    }
    store.JoinBookmarks(known);
}

bool BookmarkActions::SelectedEndpoint(std::wstring* address, UINT* port,
                                      std::wstring* why) {
    if (address == nullptr || port == nullptr || why == nullptr) return false;
    const std::optional<Connection> sel = selected_();
    if (!sel.has_value()) {
        *why = L"Select a row first.";
        return false;
    }
    if (sel->display.remoteAddress.empty()) {
        *why = L"This row has no remote address to bookmark.";
        return false;
    }
    // COPY the endpoint before anything can pump messages. See the header:
    // every prompt below runs a modal loop, during which a queued refresh can
    // reallocate the store and dangle a pointer into it. That defect
    // reproduced roughly one run in three, always right after the note prompt.
    *address = sel->display.remoteAddress;
    *port = sel->identity.remotePort;
    return true;
}

void BookmarkActions::ToggleSelected() {
    std::wstring address;
    UINT port = 0;
    std::wstring why;
    if (!SelectedEndpoint(&address, &port, &why)) {
        // An empty 'why' means nothing was selected, which is a no-op rather
        // than an error: the menu item is enabled on the chance of a selection.
        if (!why.empty())
            ::MessageBoxW(owner_, why.c_str(), L"Bookmark", MB_OK | MB_ICONERROR);
        return;
    }

    const bool exists = Bookmarks::IsBookmarked(address, port);
    if (exists) {
        const CommandResult rr = CmdBookmarkRemove(address, port);
        if (rr.exitCode != kExitOk) {
            ::MessageBoxW(owner_, Utf8ToWide(rr.err.c_str()).c_str(),
                          L"Bookmark", MB_OK | MB_ICONERROR);
            return;
        }
        // Re-join rather than just repaint: the pin lives on the row, not in
        // the list view, so a repaint alone would show a bookmark that no
        // longer exists.
        changed_();
        return;
    }
    {
        const CommandResult ar = CmdBookmarkAdd(address, port, 0, L"");
        if (ar.exitCode != kExitOk) {
            ::MessageBoxW(owner_, Utf8ToWide(ar.err.c_str()).c_str(),
                          L"Bookmark", MB_OK | MB_ICONERROR);
            return;
        }
    }
    // Ask for the note straight away: the user is looking at the connection
    // now and this is the moment they know why it is interesting. An empty
    // answer is a perfectly good answer.
    std::wstring note;
    if (PromptForText(owner_, L"Bookmark note", L"Note (optional):", L"",
                      Bookmarks::kMaxNoteChars, &note))
        (void)CmdBookmarkNote(address, port, note);
    changed_();
}

void BookmarkActions::EditSelectedNote() {
    std::wstring address;
    UINT port = 0;
    std::wstring why;
    if (!SelectedEndpoint(&address, &port, &why)) {
        if (!why.empty())
            ::MessageBoxW(owner_, why.c_str(), L"Bookmark note",
                          MB_OK | MB_ICONERROR);
        return;
    }
    Bookmark b;
    if (!Bookmarks::Get(address, port, &b)) {
        ::MessageBoxW(owner_, L"This connection is not bookmarked.",
                      L"Bookmark note", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring note;
    if (!PromptForText(owner_, L"Bookmark note", L"Note:", b.note.c_str(),
                       Bookmarks::kMaxNoteChars, &note))
        return;
    const CommandResult nr = CmdBookmarkNote(address, port, note);
    if (nr.exitCode != kExitOk) {
        ::MessageBoxW(owner_, Utf8ToWide(nr.err.c_str()).c_str(),
                      L"Bookmark note", MB_OK | MB_ICONERROR);
    }
    // The note is part of the row model (it is what the table shows and what a
    // `note:` filter matches on), so a note edit changes rows too - not just
    // the bookmark store.
    changed_();
}

}  // namespace wintcp

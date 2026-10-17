// BookmarkFile.h
// SPDX-License-Identifier: Apache-2.0
// bookmark export and import.
//
// Bookmarks live in HKCU, which is the wrong shape for the three things a
// user actually wants to do with them: move them to another machine, keep
// them in a dotfiles repo, and edit them as text. This module is the file
// format that does those things - a JSON document with an explicit schema
// version, plus a strict reader for it.
//
// WHY A STRICT READER AND NOT A GENERAL JSON PARSER. The reader accepts
// exactly the Version=1 bookmark schema and nothing else. That is deliberate:
// a parser that accepts anything accepts a malformed file, and importing half
// a bookmark file is worse than importing none - a user who thinks their
// bookmarks moved and finds three of forty is the failure this is designed to
// make impossible. A partial import is refused in full rather than in part.
//
// The reader also refuses the whole document when a record is missing a
// required field or carries one of the wrong type. That mirrors the
// all-or-nothing rule Bookmarks::Load already applies per entry, extended to
// the file as a whole, and it is what makes an import safe to run unattended.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Bookmarks.h"

namespace wintcp {

// Schema version. Bumping it is the only sanctioned way to change what the
// file means; a reader that saw a future version would otherwise guess, and a
// guess about bookmark semantics is a wrong bookmark.
constexpr int kBookmarkFileVersion = 1;

// Bounds for the READ path. A real bookmark file is one short record per
// pinned peer, so these are generous while still giving the reader something
// to refuse the way ParseLedgerBytes refuses. Over either, the file is
// refused in full rather than parsed in part - the same R3 rule `blocks`
// follows, because "unknown" and "you have no bookmarks" must never look the
// same from the outside.
constexpr size_t kBookmarkFileMaxBytes = 4u * 1024u * 1024u;
constexpr size_t kBookmarkFileMaxRecords = 100000u;

// Write 'items' as a Version=1 JSON document. Pure: it touches no registry
// and no file, so the writer is pinned by a round-trip test.
//
// The output is deterministic - records in the order given, keys in a fixed
// order - so a file exported twice from the same input is byte-identical.
// That matters for the dotfiles case, where an export that reordered itself
// would produce a diff on every run.
void SerialiseBookmarks(const std::vector<Bookmark>& items, std::string* out);

// Read a Version=1 JSON document. All-or-nothing: on success '*out' holds
// every record in the document; on failure '*out' is left untouched and
// 'error' (optional) says why.
//
// Refuses, with a reason, for: a document that is not valid JSON; a schema
// version that is missing, not a number, or not 1; a record that is not an
// object; a record missing any required field or carrying one of the wrong
// type; a note over Bookmarks::kMaxNoteChars; an address that does not
// normalise or is unspecified; a port over 65535 or an unknown tag; and either
// size bound above.
bool ParseBookmarks(const std::string& text, std::vector<Bookmark>* out,
                    std::wstring* error);

}  // namespace wintcp

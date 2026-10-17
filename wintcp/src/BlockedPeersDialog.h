// BlockedPeersDialog.h
// SPDX-License-Identifier: Apache-2.0
// View > Blocked peers...
//
// A modal that lists the firewall rules `blocks` counts, with per-rule delete
// and "remove all". The rules come from ListBlockedRules (BlockConn.h), which
// reports what the firewall actually holds rather than what the ledger
// remembers, so a rule the user disabled or flipped to allow shows up as
// disabled rather than as protection.
//
// The LAYOUT is built in memory, the same as PromptDialog, and the bounds are
// pinned by a selftest in the same way: the writer refuses rather than
// overrunning, and the test drives it with deliberately small buffers. See the
// long note in PromptDialog.cpp for why a dialog template writer needs that
// treatment - the failure mode is an out-of-bounds read inside the dialog
// manager, which presents as an intermittent access violation rather than as a
// crash at the site that caused it.
//
// No HWND crosses this interface: MainWindow passes an owner and gets back
// what the user did, so nothing below this header depends on the window.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>

#include "BlockConn.h"

namespace wintcp {

// What happened before the dialog closed.
//
// kChanged covers every successful edit - delete, enable, disable or remove
// all - and is distinct from kClosed, which means "looked and left". The
// distinction exists because the caller sets a status message about what
// actually happened, and "I changed something" and "I read something" are not
// the same report.
enum class BlockedPeersChoice {
    kClosed,    // read and dismissed without changing anything
    kChanged,   // at least one rule was deleted, enabled or disabled
    kRefused,   // the dialog could not be shown, or the rules could not be read
};

// Show the viewer. 'owner' may be null. Returns what happened; 'failure' is
// set with a human-readable reason on kRefused and is never set on success.
// Never throws.
BlockedPeersChoice ShowBlockedPeersDialog(HWND owner, std::wstring* failure);

// The two pieces the selftest pins, exposed for the same reason
// PromptDialog's TemplateFits is: the one place the layout runs is a modal
// the UI harness cannot dismiss, so every capacity rule in it would otherwise
// go unverified. What is tested is what ships, because these are the
// definitions the product links against too.
//
// The row text for one rule. A rule that is disabled or is no longer a block
// is labelled, never shown as though it were protection.
std::wstring BlockedPeersRowText(const BlockedRule& rule);

// Columns of the report view: the rule name, the remote scope it
// blocks, and its state. The state column replaces the old "[disabled]" /
// "[not a block]" text suffixes, so state is a sortable column instead of
// a substring embedded in a string.
enum BlockedPeersColumn {
    kBlockedColRule = 0,
    kBlockedColRemote = 1,
    kBlockedColStatus = 2,
    kBlockedColCount = 3,
};

// Cell text for one rule in one column. Pure, so the selftest pins every
// column the dialog renders - the same reason BlockedPeersRowText exists.
std::wstring BlockedPeersCellText(const BlockedRule& rule, int column);

// How many controls the template declares. Exported so the selftest can pin
// it against the capacity arithmetic: cdit and the buffer size are two
// spellings of the same fact, and a mismatch is an out-of-bounds read inside
// the dialog manager rather than a compile error.
int BlockedPeersControlCount();

// Bytes the dialog template needs for a title of 'titleChars' characters.
// Exported for the same reason: it is the arithmetic cdit must agree with.
size_t BlockedPeersTemplateCapacity(size_t titleChars);

// Build the template into 'buf' if it fits. REFUSES (false, buf untouched)
// rather than writing past the end - see PromptDialog.cpp for why that
// property is the whole point.
bool BlockedPeersTemplateFits(const wchar_t* title, std::vector<BYTE>* buf);

}  // namespace wintcp

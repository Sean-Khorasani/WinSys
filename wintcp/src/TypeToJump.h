// TypeToJump.h
// SPDX-License-Identifier: Apache-2.0
// Keyboard "type a few letters, land on the matching row" navigation (7.2).
//
// Split out of MainWindow because the interesting part - which row a prefix
// matches, and what happens when two rows share that prefix - is pure logic
// with no window in it, and therefore testable. The window only supplies the
// keystrokes and performs the scroll.
//
// The matching rule is the same one Explorer and every other list uses, and
// deviating from it would feel wrong:
//
//   * A single character jumps to the first row starting with it.
//   * Subsequent characters EXTEND the prefix and jump to the first row
//     starting with it. There is no fallback to a substring match: a user who
//     types "svch" wants rows beginning "svch", not the first row containing
//     "svch" somewhere.
//   * Typing the same character again cycles through the rows sharing that
//     prefix - so "s s" walks through every service rather than getting
//     stuck on the first match.
//   * Space is treated as a separator, not a character, because in
//     "<something>.exe" the dot is the separator and a user typing it means
//     "next segment".
//   * A pause longer than the timeout restarts the sequence, so returning to
//     the window half a minute later and typing "s" does not try to extend a
//     stale "svchost" prefix.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstddef>
#include <string>
#include <vector>

namespace wintcp {

// How long a pause breaks the sequence. ~1s matches Explorer.
constexpr DWORD kTypeToJumpTimeoutMs = 1000;

// One row's searchable text. The window builds these from the visible text
// columns, so a jump lands on what the user can actually see rather than on
// something from a hidden column.
struct JumpCandidate {
    std::uint64_t id = 0;      // stable row id, for restoring a selection
    std::wstring label;        // the text the prefix is matched against
};

class TypeToJump {
public:
    void Reset();

    // Feed one keystroke. Returns the index of the row to select, or -1 when
    // nothing matched (in which case the caller leaves the selection alone -
    // silently moving the selection to row 0 on a failed jump is worse than
    // doing nothing).
    //
    // 'now' is passed in rather than read from the clock so the timeout is
    // testable; the window passes GetTickCount64().
    int Feed(wchar_t ch, ULONGLONG now, const std::vector<JumpCandidate>& rows);

    // The prefix typed so far, for the status-bar hint.
    const std::wstring& Prefix() const { return prefix_; }

private:
    // First row whose label starts with the current prefix, or -1. Not const:
    // a hit records the index so a repeated keystroke can cycle from there,
    // and that bookkeeping is the whole point of the "type the same letter
    // again" behaviour.
    int FindFirst(const std::vector<JumpCandidate>& rows);

    std::wstring prefix_;
    int lastIndex_ = -1;   // row matched by the previous keystroke
    ULONGLONG lastStamp_ = 0;
    bool active_ = false;
};

// Does 'label' begin with 'prefix', ignoring case? Windows-1252 and ASCII
// both lower-case correctly through towlower; a full Unicode case fold is not
// needed because the comparison is a prefix test, not a collation.
bool LabelStartsWith(const std::wstring& label, const std::wstring& prefix);

}  // namespace wintcp

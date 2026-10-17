// TypeToJump.cpp
// SPDX-License-Identifier: Apache-2.0
// See TypeToJump.h.

#include "TypeToJump.h"

#include <cwctype>   // towlower

namespace wintcp {

bool LabelStartsWith(const std::wstring& label, const std::wstring& prefix) {
    if (prefix.empty()) return true;
    if (label.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (::towlower(static_cast<unsigned short>(label[i])) !=
            ::towlower(static_cast<unsigned short>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

void TypeToJump::Reset() {
    prefix_.clear();
    lastIndex_ = -1;
    lastStamp_ = 0;
    active_ = false;
}

int TypeToJump::Feed(wchar_t ch, ULONGLONG now,
                      const std::vector<JumpCandidate>& rows) {
    if (rows.empty()) return -1;

    // A pause breaks the sequence. Checked BEFORE handling the character so
    // the first keystroke after a pause always starts a fresh search rather
    // than being appended to a prefix the user can no longer see.
    if (active_ && now > lastStamp_ &&
        (now - lastStamp_) > kTypeToJumpTimeoutMs) {
        Reset();
    }

    // Backspace removes one character - the natural way to back out of a
    // mistyped prefix, and cheap to support while the state is here.
    if (ch == L'\b') {
        if (!prefix_.empty()) {
            prefix_.pop_back();
            lastIndex_ = -1;   // start the search over for the new prefix
        }
        return prefix_.empty() ? -1 : FindFirst(rows);
    }

    // Space separates segments rather than matching one: "svchost.exe" is
    // reached by "svchost" then "." and a space in the middle of a process
    // name is never something the user wants to type into a search.
    if (ch == L' ') {
        if (prefix_.empty()) return -1;
        lastIndex_ = -1;
        return FindFirst(rows);
    }

    // Printable only. Control characters, and anything multi-byte (an IME
    // commit arriving as WM_CHAR 0), must not be accumulated: a stray
    // surrogate would make every subsequent comparison fail and the feature
    // would look permanently broken.
    if (ch < 0x20 || ch == 0x7F) return -1;

    const bool repeat = (prefix_.size() == 1 && prefix_[0] == ch);
    if (!repeat) {
        prefix_.push_back(ch);
    }
    // A REPEATED character is deliberately NOT appended. Pressing "s" twice
    // must mean "the next row starting with s", not "a prefix of ss" - the
    // second press is a navigation step, not a letter. Appending it made the
    // prefix "ss", which matches almost nothing, so a second press appeared
    // to do nothing at all.
    lastStamp_ = now;
    active_ = true;

    if (!repeat) {
        lastIndex_ = -1;
        return FindFirst(rows);
    }

    // Typing the same character again cycles. Without this, a prefix shared
    // by many rows (a dozen svchost.exe rows) would make the second 's'
    // appear to do nothing, which reads as a broken key.
    //
    // The starting point must be the PREVIOUS match, captured before
    // FindFirst runs: FindFirst records its own hit in lastIndex_, so
    // reading lastIndex_ afterwards would always start the cycle from the
    // first match and appear to do nothing at all. That was the first
    // implementation's bug, and it showed up as "pressing s twice always
    // selects the same row".
    const int previous = lastIndex_;
    if (previous < 0) {
        return FindFirst(rows);
    }
    const size_t n = rows.size();
    for (size_t step = 1; step <= n; ++step) {
        const int candidate = static_cast<int>((static_cast<size_t>(previous) + step) % n);
        if (LabelStartsWith(rows[static_cast<size_t>(candidate)].label, prefix_)) {
            lastIndex_ = candidate;
            return candidate;
        }
    }
    // Only one row matches: stay put rather than moving the selection away.
    lastIndex_ = previous;
    return previous;
}

int TypeToJump::FindFirst(const std::vector<JumpCandidate>& rows) {
    for (size_t i = 0; i < rows.size(); ++i) {
        if (LabelStartsWith(rows[i].label, prefix_)) {
            lastIndex_ = static_cast<int>(i);
            return lastIndex_;
        }
    }
    return -1;
}

}  // namespace wintcp

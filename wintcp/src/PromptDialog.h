// PromptDialog.h
// SPDX-License-Identifier: Apache-2.0
// A one-line text prompt (name a preset, type a bookmark note).
//
// WHY IT EXISTS. Three separate features need the same thing - "ask the user
// for a short string, then act on it": saving a preset, naming a bookmark, and
// editing a note. Writing that as three near-identical dialog procs is how
// they drift apart (one forgets to strip whitespace, one forgets the
// length cap, one forgets the message loop), and it is why this is one
// function rather than three.
//
// It is a dialog, not a MessageBox, for one concrete reason: MessageBox has no
// text input, and the three near-misses people reach for instead are all
// worse. SHGetFilePath gets the wrong answer, a custom MessageBox subclass
// cannot host an edit control reliably, and reusing a stray GetOpenFileName
// for a name is a user-hostile joke.
//
// No dependency on DetailsDialog: this is a modal utility, and borrowing the
// details window's lifetime and model plumbing would couple two things that
// have nothing to do with each other.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>
#include <vector>   // TemplateFits hands back the built bytes

namespace wintcp {

// Show a modal single-line prompt. Returns true when the user confirmed,
// with the typed text in '*out'. Returns false on Cancel or on failure, in
// which case '*out' is untouched - so a caller cannot act on a stale value
// from a previous prompt.
//
// 'initial' is pre-filled and selected, so typing replaces it (the common
// case when re-naming) rather than appending to it.
//
// 'maxChars' bounds the edit control AND the returned string. It is a
// parameter rather than a constant because the three callers have genuinely
// different limits (preset names, notes) and silently sharing one number
// would either truncate a legitimate note or allow a preset name that the
// preset store will later reject.
bool PromptForText(HWND owner, const wchar_t* title, const wchar_t* label,
                   const wchar_t* initial, size_t maxChars,
                   std::wstring* out);

// Build the DLGTEMPLATE that PromptForText would use, into the buffer the
// caller supplies, IN PLACE. Returns true when the template was built.
//
// Exposed for one reason: this layout is the part of the module most likely to
// be wrong. A DLGTEMPLATE is padded to a 4-byte boundary at four points and
// every DLGITEMTEMPLATE must start on a DWORD, so a miscount makes the dialog
// manager read past the end of the buffer. PromptForText is a MODAL dialog,
// which no headless harness can drive, so while this stayed private none of
// that arithmetic could be checked at all - including the bounds this change
// adds.
//
// IN PLACE, and NOT returning a copy, is load-bearing rather than style. Each
// control is aligned by rounding its ADDRESS up to a DWORD, so the result is
// only valid at the address the caller supplied. An earlier version returned
// `std::vector<BYTE>` by value; that copy was allocated wherever the allocator
// liked, and the alignment was silently lost on the way out - so the caller
// would have handed DialogBoxIndirectParamW a template whose controls were not
// DWORD-aligned, which is the exact misread the padding exists to prevent.
// Writing into the caller's own buffer means the bytes are read back from the
// address they were laid out for.
//
// Any starting size is accepted, including one too small: every write is
// bounds-checked and a title or caption past the limits below is REFUSED, so a
// false return is a real answer meaning "no template fits" and the caller shows
// no prompt. On success the buffer is truncated to the template's true length,
// so its contents are exactly the bytes the dialog manager reads.
bool TemplateFits(DWORD style, DWORD exStyle, short x, short y, short cx,
                  short cy, const wchar_t* title, std::vector<BYTE>* buf,
                  const wchar_t* label = nullptr);

// The capacities TemplateFits checks against, in wchar_t. Named so the test
// asserts the boundary instead of restating the number.
constexpr size_t kTemplateMaxChars = 128;   // a prompt title
constexpr size_t kCaptionMaxChars = 32;     // "OK" / "Cancel"
// The instruction line above the edit (e.g. the numbered preset list a
// Load/Delete prompt shows). Longer than a button caption by design, still
// bounded so one prompt cannot size the template without limit.
constexpr size_t kLabelMaxChars = 512;

}  // namespace wintcp

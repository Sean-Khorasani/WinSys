// ViewPresets.h
// SPDX-License-Identifier: Apache-2.0
//
// The preset file dialogs: save, load, delete, list.
//
// Extracted from MainWindow because the window's half is small and the
// dialog half is not: the window supplies the current view and applies a
// loaded one, and everything else - the prompt text, the strict number
// parsing, the overwrite confirm, the delete confirm - is dialog plumbing
// that lived inside a window class.
//
// One duplication removed on the way: Load and Delete each carried their own
// copy of the numbered-list prompt text and their own copy of the strict
// index parser. Two copies of a parsing rule is two chances for "2abc" to
// resolve to preset 2, and only one of them would have been found.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

#include "Presets.h"

namespace wintcp {

class ViewPresetDialogs {
public:
    // The window's two contributions: what the current view is, and how to
    // apply one. Both stay on the window because both read window state; the
    // dialogs only move them around.
    using CurrentView = std::function<PresetView()>;
    using ApplyView = std::function<void(const PresetView&)>;

    ViewPresetDialogs(HWND owner, CurrentView current, ApplyView apply)
        : owner_(owner), current_(std::move(current)),
          apply_(std::move(apply)) {}

    void Save();
    void Load();
    void Delete();

    // The numbered-list prompt body, shared by Load and Delete. A numbered
    // list rather than a combo: with more than a handful of presets a list box
    // scrolls, and the numbers double as a way to refer to one in the message
    // box. The list is the prompt's LABEL rather than a discarded local - the
    // prompt used to build this text and then ask with an empty label, so the
    // numbers meant nothing. Capped with a count so a long library cannot
    // blow the dialog's caption bound: a truncated list still reads, a missing
    // one does not.
    static std::wstring NumberedList(const std::vector<std::wstring>& names,
                                     const wchar_t* question);

    // Strict index parse: 1..names.size(), or 0 for anything that is not a
    // plain number. "2abc" and "-1" must not resolve to 2, and an index past
    // the end must not wrap.
    static size_t ParseIndex(const std::wstring& answer, size_t count);

private:
    // The shared "choose a preset by number" front half of Load and Delete.
    // Returns the chosen name, or empty when the user cancelled. Reports its
    // own errors.
    std::wstring Choose(const wchar_t* title, const wchar_t* question);

    HWND owner_;
    CurrentView current_;
    ApplyView apply_;
};

}  // namespace wintcp

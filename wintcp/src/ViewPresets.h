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

private:
    // The shared named-choice dialog for Load and Delete.
    std::wstring Choose(const wchar_t* title, const wchar_t* question);

    HWND owner_;
    CurrentView current_;
    ApplyView apply_;
};

}  // namespace wintcp

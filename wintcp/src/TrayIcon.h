// TrayIcon.h
// SPDX-License-Identifier: Apache-2.0
//
// The notification-area icon: adding it, removing it, its tooltip, its
// balloons and its right-click menu.
//
// Extracted from MainWindow because the icon is a self-contained piece of
// shell32 state with exactly one owner - and because the MainWindow half of
// the tray was scattered across five methods that each reached into the same
// NOTIFYICONDATAW (TrayAdd, the first-hide balloon, the alert balloon, the
// tip). One class means one place that knows the structure exists.
//
// What deliberately did NOT move: the decision of WHEN to minimize to the
// tray (MainWindow::ResolveMinimize). That is window policy - it reads the
// remembered choice, prompts with a TaskDialog, writes settings and syncs a
// menu check - and only the icon plumbing below is the tray's business. A
// "minimize policy" living inside the icon class is how the two get confused
// the first time either changes.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <shellapi.h>

#include <string>

#include "WorkerSink.h"   // WM_APP_TRAY: the app's private message space

namespace wintcp {

class TrayIcon {
public:
    // Add the icon for 'owner' if it is not already there. Returns false when
    // it could not be added, which the caller reports rather than guesses at.
    //
    // shell32.dll is delay-loaded (kDelayedDlls in WinCaps.cpp) and
    // Shell_NotifyIconW would RAISE on a machine without it. The gate is in
    // WinCaps.h - `DllAvailable` - and it is checked here so that "minimize
    // to tray" degrades to no icon rather than an import crash.
    bool Add(HWND owner, HINSTANCE instance);

    // Remove the icon. No-op when it was never added, which is the normal
    // state on a machine where Add() found no shell32.
    void Remove();

    bool IsShown() const { return shown_; }

    // The tooltip: what the window holds right now (rows, frozen, grouped,
    // alert states) rather than a fixed title.
    void SetTip(const std::wstring& tip);

    // One balloon. 'title' is the bold line, 'text' the body, 'flags' one of
    // the NIIF_* values the caller judges appropriate (NIIF_INFO for the
    // first-hide explanation, NIIF_WARNING for an alert).
    void Balloon(const std::wstring& title, const std::wstring& text,
                 DWORD flags);

    // The right-click menu, tracked and dispatched. 'topMost' decides the
    // Always-on-top check mark. The chosen command is posted back to 'owner'
    // as a WM_COMMAND, so the tray menu and the main menu have exactly one
    // handler and cannot drift.
    void ShowMenu(HWND owner, bool topMost) const;

private:
    NOTIFYICONDATAW nid_ = {};
    bool shown_ = false;
    bool ownsIcon_ = false;
};

}  // namespace wintcp

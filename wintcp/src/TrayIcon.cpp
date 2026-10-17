// TrayIcon.cpp
// SPDX-License-Identifier: Apache-2.0
// See TrayIcon.h.

#include "TrayIcon.h"

#include "resource.h"
#include "WinCaps.h"   // DllAvailable: shell32 is delay-loaded

namespace wintcp {

namespace {

// The icon's identity within the notification area: one icon, this window.
constexpr UINT_PTR kTrayIconId = 1;

// How long a balloon stays. Long enough to read two sentences, short enough
// that it is not still on screen after the user has looked away.
constexpr UINT kBalloonTimeoutMs = 5000;

}  // namespace

bool TrayIcon::Add(HWND owner, HINSTANCE instance) {
    if (owner == nullptr || shown_) return shown_;
    if (!DllAvailable("shell32.dll")) return false;

    nid_ = {};
    nid_.cbSize = sizeof(nid_);
    nid_.hWnd = owner;
    nid_.uID = kTrayIconId;
    nid_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid_.uCallbackMessage = WM_APP_TRAY;
    nid_.hIcon = static_cast<HICON>(::LoadImageW(
        instance, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON, 16, 16, 0));
    if (nid_.hIcon == nullptr)
        nid_.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
    ::wcscpy_s(nid_.szTip, L"WinTCP - TCP/UDP Connections");
    shown_ = ::Shell_NotifyIconW(NIM_ADD, &nid_) != FALSE;
    return shown_;
}

void TrayIcon::Remove() {
    if (!shown_) return;
    // shell32.dll is delay-loaded. This gate is load-bearing even though
    // shown_ looks like it already implies the library is there: it does NOT,
    // because on a machine without shell32 Add() would have raised and left
    // the flag false - so the invariant holds, and this guard makes that
    // dependency explicit rather than incidental.
    if (!DllAvailable("shell32.dll")) return;
    ::Shell_NotifyIconW(NIM_DELETE, &nid_);
    shown_ = false;
}

void TrayIcon::SetTip(const std::wstring& tip) {
    if (!shown_) return;
    if (tip.size() >= _countof(nid_.szTip)) {
        // Shell32 rejects a tip longer than the field - the call fails and
        // the tooltip silently keeps the old text. Truncating here means the
        // tip is slightly shorter rather than stale.
        ::wcsncpy_s(nid_.szTip, tip.c_str(), _TRUNCATE);
    } else {
        ::wcscpy_s(nid_.szTip, tip.c_str());
    }
    nid_.uFlags = NIF_TIP;
    ::Shell_NotifyIconW(NIM_MODIFY, &nid_);
}

void TrayIcon::Balloon(const std::wstring& title, const std::wstring& text,
                       DWORD flags) {
    if (!shown_) return;
    ::ZeroMemory(&nid_.szInfo, sizeof(nid_.szInfo));
    ::ZeroMemory(&nid_.szInfoTitle, sizeof(nid_.szInfoTitle));
    ::wcsncpy_s(nid_.szInfo, text.c_str(), _TRUNCATE);
    ::wcsncpy_s(nid_.szInfoTitle, title.c_str(), _TRUNCATE);
    nid_.uFlags = NIF_INFO;
    nid_.dwInfoFlags = flags;
    nid_.uTimeout = kBalloonTimeoutMs;
    ::Shell_NotifyIconW(NIM_MODIFY, &nid_);
    // Clear NIF_INFO so the next tip update does not re-send a balloon: the
    // mask is what tells shell32 which field the modify is about, and leaving
    // it set turns every later tooltip change into a balloon.
    nid_.uFlags = 0;
}

void TrayIcon::ShowMenu(HWND owner, bool topMost) const {
    HMENU menu = ::CreatePopupMenu();
    if (menu == nullptr) return;
    ::AppendMenuW(menu, MF_STRING, IDM_TRAY_RESTORE, L"&Open WinTCP");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (topMost ? MF_CHECKED : 0),
                  IDM_VIEW_TOPMOST, L"Always on top");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    // This is the item the Block confirmation has always pointed at
    // ("use Remove All WinTCP Blocks from the tray menu"). It did not exist
    // until now, so the documented removal path has a handler; the handler
    // reports "no rules" / "needs elevation" honestly. Always shown - built
    // directly from the menu, no COM-query gymnastics required.
    ::AppendMenuW(menu, MF_STRING, IDM_TRAY_UNBLOCK_ALL,
                  L"Remove All WinTCP Blocks");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, IDM_FILE_EXIT, L"E&xit");

    POINT pt = {};
    ::GetCursorPos(&pt);
    // Required so the menu dismisses correctly when the window is hidden.
    ::SetForegroundWindow(owner);
    const UINT cmd = ::TrackPopupMenu(
        menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0,
        owner, nullptr);
    ::DestroyMenu(menu);
    ::PostMessageW(owner, WM_NULL, 0, 0);
    if (cmd != 0)
        ::SendMessageW(owner, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
}

}  // namespace wintcp

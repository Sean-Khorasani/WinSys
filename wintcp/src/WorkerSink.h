// WorkerSink.h
// SPDX-License-Identifier: Apache-2.0
//
// The mailbox the worker threads post their results into.
//
// Extracted from MainWindow's private section because both workers use it -
// the refresh worker and the DNS worker - and an enrichment subsystem that
// cannot name the mailbox it posts into is not an extracted subsystem.
//
// The lifetime rule is the reason this exists as a shared block rather than
// as window state: if Stop() detaches a worker, its late pass still holds a
// shared_ptr to the sink, so the callback can run to completion against
// freed-window-safe state (a PostMessage to the dead hwnd simply fails and
// the payload is deleted). That is what makes the bounded-join detach
// provably harmless rather than hopefully so.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <mutex>
#include <set>

#include "DnsResolver.h"
#include "RefreshEngine.h"   // RefreshResult

namespace wintcp {

// Private messages posted by worker threads, plus the one the shell posts.
// They live here, with the mailbox they deliver into, because both the
// refresh worker and the DNS worker post them - a message that only one
// module knew about is a message the other module cannot receive. WM_APP_TRAY
// is in the same enum because the tray icon's callback is part of the same
// small private message space, and splitting the space across two headers is
// how two ids collide.
enum : UINT {
    WM_APP_REFRESH_RESULT = WM_APP + 1,   // RefreshResult*
    WM_APP_DNS_RESULT     = WM_APP + 2,   // DnsResolver::Result*
    WM_APP_TRAY           = WM_APP + 3,   // tray icon callback
    WM_APP_DNS_STALLED    = WM_APP + 6,   // wParam = stalled count
};

struct WorkerSink {
    std::mutex m;
    std::set<RefreshResult*> pendingRefresh;
    std::set<DnsResolver::Result*> pendingDns;
    bool shuttingDown = false;
    HWND hwnd = nullptr;
};

}  // namespace wintcp

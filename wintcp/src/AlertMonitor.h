// AlertMonitor.h
// SPDX-License-Identifier: Apache-2.0
//
// The alert engine's wiring: one pass per refresh that evaluates the current
// snapshot against the settings and the rules, and reports what fired.
//
// Extracted from MainWindow because the ENGINE (Alerts.cpp) was already pure
// and tested and this was its only production caller - which meant the one
// thing standing between a tested engine and a shipped feature lived inside a
// window class alongside the tray, the menus and the presets. The three rules
// the wiring must obey moved with it, so they are now stated once instead of
// being a comment on a method:
//
//   * The tray icon is OPTIONAL. A balloon needs one; without it the alert
//     still happens, it just lands in the hint the caller shows. An alert that
//     does nothing is worse than no alert at all.
//   * The engine LATCHES. A condition already active is suppressed until it
//     clears, so a connection sitting above the threshold does not re-notify on
//     every refresh. That is the engine's job, not this class's.
//   * State is read FRESH each call, because another process running
//     `wintcp.exe alert rule add` can change the rules between two refreshes
//     and a monitor with its own copy would be the only thing that did not
//     know.
//   * A row pointer is never held across the emit callback: a balloon pumps
//     messages and a refresh can reallocate the store underneath.

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

#include "Alerts.h"
#include "Connection.h"

namespace wintcp {

class AlertMonitor {
public:
    // Called once per fired alert, in the order the engine produced them.
    // The window's implementation decides tray balloon or status hint - this
    // layer reports and does not know which.
    using Emit = std::function<void(const Alert&)>;

    // One pass over the current snapshot. 'settings' and 'rules' are the
    // freshly-read values (see the rules above); 'emit' is the caller's
    // answer per alert.
    //
    // Returns false when alerting is off or there is nothing to evaluate, and
    // true when the pass actually ran. The caller uses that to know whether
    // the hint and the suppressed count on this object are from this tick.
    bool Run(const std::vector<Connection>& rows, const AlertSettings& settings,
             const std::vector<AlertRule>& rules, const Emit& emit);

    // How many alerts the latch is currently suppressing. Surfaced rather than
    // hidden: "nothing appeared" and "it is all already on fire" are different
    // answers and only one of them is fine.
    size_t SuppressedCount() const { return suppressed_; }

    // Clear the latch. Called when alerting is switched off, so a stale latch
    // does not fire the instant it is switched back on for a condition the user
    // never saw happen.
    void Reset() { engine_.Reset(); }

private:
    AlertEngine engine_;
    size_t suppressed_ = 0;
};

}  // namespace wintcp

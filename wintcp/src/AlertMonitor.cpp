// AlertMonitor.cpp
// SPDX-License-Identifier: Apache-2.0
// See AlertMonitor.h.

#include "AlertMonitor.h"

namespace wintcp {

bool AlertMonitor::Run(const std::vector<Connection>& rows,
                       const AlertSettings& settings,
                       const std::vector<AlertRule>& rules,
                       const Emit& emit) {
    suppressed_ = 0;
    if (!settings.enabled) {
        // Reset on disable for the reason in the header: a stale latch would
        // fire the instant alerting is turned back on.
        Reset();
        return false;
    }
    // Two lists, one pass each: the threshold rules come from the settings,
    // the per-rule matches from the rule store. Both are evaluated before
    // ANY emit, because an emit pumps messages (a balloon is modal) and a
    // pointer into 'rows' must not survive that.
    const std::vector<Alert> fired = engine_.Evaluate(rows, settings);
    const std::vector<Alert> ruleFired =
        engine_.EvaluateRules(rows, rules, settings);
    for (const Alert& a : fired) emit(a);
    for (const Alert& a : ruleFired) emit(a);
    // Surfaced, not hidden - see the header.
    suppressed_ = engine_.SuppressedCount();
    return true;
}

}  // namespace wintcp

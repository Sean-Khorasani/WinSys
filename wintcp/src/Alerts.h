// Alerts.h
// SPDX-License-Identifier: Apache-2.0
// Threshold alerting and change notifications.
//
// DESIGN RULE, and the reason this is a separate file: a network viewer that
// pops up a balloon every time a connection crosses a line becomes something
// the user switches off, and then it is useless for the one event that
// mattered. So:
//   * Alerting is MUTED BY DEFAULT. Nothing is ever shown until the user
//     turns it on.
//   * Each distinct condition fires ONCE and then goes quiet until it
//     clears. A connection sitting above the threshold does not re-notify
//     every refresh - that is a notification storm, and it is the single
//     most common way this kind of feature becomes noise.
//   * Balloons require the tray icon. If the user has tray disabled, alerts
//     fall back to the status bar rather than silently doing nothing.
//
// The evaluator is a pure function of the current row stats plus the previous
// state, so it is testable without a window and without a network.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <shellapi.h>   // NOTIFYICONDATAW, Shell_NotifyIconW, NIF_INFO

#include <cstdint>
#include <string>
#include <vector>
#include <set>

#include "ConnectionStore.h"

namespace wintcp {

// Thresholds for the alert engine below. Zero disables a given alert.
//
// These ARE user-configurable: the values persist in the settings store, the
// `wintcp.exe alert` CLI verb reads and writes them, and the window evaluates
// them on every refresh and raises a tray balloon per alert. The seam the
// evaluation core exposes is what that loop is built on - the core itself
// stays pure, so it is directly testable and the loop over it stays thin.
struct AlertSettings {
    bool enabled = false;                 // master switch, off by default
    double bpsWarn = 0.0;                 // per-connection bytes/sec
    double bpsCritical = 0.0;
    size_t connectionWarn = 0;            // total connection count
    // "Quiet mode": do not alert on new listening sockets, only on data.
    // Off by default is wrong here - a new listener is the interesting event
    // for a network tool - but it is exposed because some users find a
    // reconnect loop unbearable.
    bool alertOnNewListener = true;
    bool alertOnNewConnection = true;
    bool alertOnRst = true;
    bool alertOnClosed = false;
};

// What changed since the last evaluation.
enum class AlertKind : unsigned {
    kBpsWarn = 1u << 0,
    kBpsCritical = 1u << 1,
    kConnectionCount = 1u << 2,
    kNewListener = 1u << 3,
    kNewConnection = 1u << 4,
    kRst = 1u << 5,
    kClosed = 1u << 6,
};

struct Alert {
    AlertKind kind = AlertKind::kBpsWarn;
    std::wstring title;
    std::wstring text;
    // True if this is the first time the condition has been seen, i.e. the
    // transition, not the steady state.
    bool rising = false;

};
// A rule about ONE connection rather than about the whole table.
//
// Empty means "any": a rule with no address and no process watches every row,
// which is what the whole-table threshold already does. The interesting case is
// a rule with an address - "tell me when anything talks to 203.0.113.9".
//
// Matching is deliberately SUBSTRING and case-insensitive on the process image:
// that is how people write it, and a rule that silently matches nothing is worse
// than one that matches slightly more than intended.
struct AlertRule {
    std::wstring name;          // the identity: latches and registry keys use it
    std::wstring address;       // remote address substring; empty = any
    std::wstring process;       // process image substring; empty = any
    bool onNew = true;          // a matching row appeared
    bool onClose = false;        // it went away
    bool onThreshold = false;   // it crossed the rate threshold in AlertSettings

    // Does this rule match this row? Pure, so the CLI and the GUI agree and both
    // can be tested without a window.
    bool Matches(const Connection& c) const;
};

class AlertEngine {
public:
    // Evaluate the current snapshot. Returns the alerts that fired on THIS
    // call. Any condition that was already active last time is suppressed
    // until it clears, so a caller can relay these directly without
    // deduplicating.
    std::vector<Alert> Evaluate(const std::vector<Connection>& rows,
                                const AlertSettings& s);

    // Per-connection rules. A whole-table threshold answers "the machine is
    // busy"; this answers "the one thing I asked about changed".
    //
    // The latch is PER RULE, keyed by NAME rather than by address: two rules
    // watching the same address are two independent watches, and keying by address
    // would make the second a silent no-op.
    std::vector<Alert> EvaluateRules(const std::vector<Connection>& rows,
                                    const std::vector<AlertRule>& rules,
                                    const AlertSettings& s);

    void Reset();

    // Number of alerts currently suppressed because they were already
    // active. Surfaced in the UI so "nothing appeared" is distinguishable
    // from "it is all already on fire".
    size_t SuppressedCount() const { return suppressed_; }

private:
    // Latched condition bits: set while the condition holds, cleared when it
    // stops holding.
    unsigned latched_ = 0;
    bool sawListener_ = false;
    bool sawConnection_ = false;
    size_t lastCount_ = 0;
    size_t suppressed_ = 0;
    // rule name -> true while that rule is matching.
    std::set<std::wstring> ruleLatched_;
};

// Show a balloon on the tray icon. Returns false if the shell refused it.
// There is no owner parameter: the nid already carries the window handle, and
// a second one would be a second thing to get wrong. The caller owns the nid
// and must keep it alive for the call.
bool ShowTrayBalloon(NOTIFYICONDATAW* nid, const std::wstring& title,
                     const std::wstring& text, DWORD iconFlags);

// Human-readable byte-rate, shared with the status bar.
std::wstring FormatBps(double bytesPerSecond);

// Where rules live. The engine reads a vector; something has to fill it, and
// the answer cannot be a member of the window or of the CLI - both would be a place
// the other one does not see.
//
// Rules are stored as one registry value PER RULE under
// HKCU\Software\WinTCP\AlertRules, whose value name is the rule name. Not one packed
// blob: the registry is already the store, enumerating it is how you list, and
// deleting one rule must not require rewriting all of them.
class AlertRuleStore {
public:
    // Read every rule. Returns an empty vector when nothing has been saved, which is
    // a valid and expected state rather than an error.
    static std::vector<AlertRule> Load();

    // Add or replace a rule by name. Returns false on a write failure.
    static bool Save(const AlertRule& rule);

    // Remove by name. Returns false when the rule does not exist, so a caller can
    // tell "removed" from "never was there".
    static bool Remove(const std::wstring& name);

private:
    static constexpr const wchar_t* kSubKey = L"WinTCP\\AlertRules";
};

// Parse/serialise one rule. Pipe-separated because neither an address nor a process
// name contains one, and because a rule a human wrote by hand in the registry is a
// rule that has to be readable.
std::wstring AlertRuleToValue(const AlertRule& rule);
bool AlertRuleFromValue(const std::wstring& name, const std::wstring& value,
                        AlertRule* out);
}  // namespace wintcp

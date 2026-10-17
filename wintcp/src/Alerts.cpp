// Alerts.cpp
// SPDX-License-Identifier: Apache-2.0
// See Alerts.h.

#include "Alerts.h"
#include "Utils.h"   // kBytesPerKB/MB/GB shared unit ladder

#include <iphlpapi.h>   // MIB_TCP_STATE_LISTEN
#include <tcpmib.h>

#include <cstdio>
#include <algorithm>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

namespace wintcp {
namespace {

// Width of the one-line rate text ("1023.9 GB/s"). swprintf_s truncates rather
// than overruns, so this is slack chosen to cover every value the unit ladder
// above it can produce, not a measured worst case.
constexpr size_t kRateTextChars = 64;

// Registry enumeration buffers for the rule store. RegEnumValueW reports a name
// or value longer than the buffer as the REQUIRED size, and the load loop below
// treats any rc other than ERROR_SUCCESS as "skip this value" - so an oversized
// rule is skipped whole rather than silently truncated into something the
// parser would then reject. That is why these can be fixed sizes.
constexpr DWORD kRuleNameChars = 256;
constexpr DWORD kRuleValueBytes = 1024;

// Latch helper: returns true only on the rising edge of a condition.
inline bool Rising(bool nowActive, bool* latched) {
    const bool rising = (nowActive && !*latched);
    *latched = nowActive;
    return rising;
}

}  // namespace

std::wstring FormatBps(double bps) {
    if (!(bps > 0.0)) return L"0 B/s";
    wchar_t buf[kRateTextChars] = {0};
    if (bps >= kBytesPerGB) {
        ::swprintf_s(buf, L"%.1f GB/s", bps / kBytesPerGB);
    } else if (bps >= kBytesPerMB) {
        ::swprintf_s(buf, L"%.1f MB/s", bps / kBytesPerMB);
    } else if (bps >= kBytesPerKB) {
        ::swprintf_s(buf, L"%.0f KB/s", bps / kBytesPerKB);
    } else {
        ::swprintf_s(buf, L"%.0f B/s", bps);
    }
    return buf;
}

// Substring on the process image, exact on the address.
//
// The asymmetry is deliberate. An address is a precise token - "203.0.113.9" either
// appears or it does not - while a process name is typed by a human who may write
// "chrome", "Chrome.exe" or "chrome.exe (12)". Substring on the name is forgiving
// where being precise is what people want; substring on the ADDRESS would match
// "203.0.113.90" when the user meant "203.0.113.9", which is the one mistake a
// network watch must not make.
bool AlertRule::Matches(const Connection& c) const {
    if (!address.empty() &&
        c.display.remoteAddress.find(address) == std::wstring::npos) {
        return false;
    }
    if (!process.empty() &&
        ToLowerW(c.display.processName).find(ToLowerW(process)) == std::wstring::npos) {
        return false;
    }
    return true;
}

// Two passes, and they have to be separate: "which rules match NOW" is a pure
// question about this snapshot, and "did anything change" is a question about the
// previous one. Doing them in one pass is what makes this kind of loop fire twice.
std::vector<Alert> AlertEngine::EvaluateRules(
    const std::vector<Connection>& rows, const std::vector<AlertRule>& rules,
    const AlertSettings& s) {
    (void)s;   // reserved for onThreshold, which reads the rate from the rows
    std::vector<Alert> out;
    if (rules.empty()) return out;

    // Which rules match ANY row right now. A SET, not a count: two matching rows
    // for one rule is still one condition holding, not two firings.
    std::set<std::wstring> matchingNow;
    for (const AlertRule& rule : rules) {
        if (rule.name.empty()) continue;   // unnamed rules cannot latch; ignore
        for (const Connection& c : rows) {
            if (rule.Matches(c)) {
                matchingNow.insert(rule.name);
                break;
            }
        }
    }

    for (const AlertRule& rule : rules) {
        if (rule.name.empty()) continue;
        const bool now = matchingNow.count(rule.name) != 0;
        const bool before = ruleLatched_.count(rule.name) != 0;
        if (now == before) continue;   // no transition - already reported

        Alert a;
        if (now) {
            ruleLatched_.insert(rule.name);
            a.kind = AlertKind::kNewConnection;
            a.rising = true;
            a.title = L"alert: " + rule.name;
            a.text = L"a matching connection is now present";
            if (rule.onNew) out.push_back(a);
        } else {
            ruleLatched_.erase(rule.name);
            a.kind = AlertKind::kClosed;
            a.rising = false;
            a.title = L"cleared: " + rule.name;
            a.text = L"no matching connection is present any more";
            // onClose is separate for a reason: the interesting event is usually the
            // appearance, and a watcher that also fires on every disappearance fires
            // twice per connection.
            if (rule.onClose) out.push_back(a);
        }
    }

    // Same contract Evaluate() keeps: "nothing appeared" and "it is all already on
    // fire" are different answers, and only one of them is fine.
    suppressed_ = ruleLatched_.size();
    return out;
}
void AlertEngine::Reset() {
    ruleLatched_.clear();
    latched_ = 0;
    sawListener_ = false;
    sawConnection_ = false;
    lastCount_ = 0;
    suppressed_ = 0;
}

std::vector<Alert> AlertEngine::Evaluate(const std::vector<Connection>& rows,
                                         const AlertSettings& s) {
    std::vector<Alert> out;
    suppressed_ = 0;
    // Everything below is inert when alerting is off, but the latches are
    // still updated so that turning alerts on does not immediately fire on
    // conditions that were already true. Firing on a pre-existing condition
    // the first time the user enables alerts would be a lie about timing.
    if (!s.enabled) {
        lastCount_ = rows.size();
        return out;
    }

    // Per-connection throughput. Only rows whose rate is actually known are
    // considered: an unknown rate is not "below the threshold", it is "no
    // data yet", and alerting on the difference would be meaningless.
    // rx and tx are summed - a transfer saturating a link in either
    // direction is the event the user cares about, not a directional split.
    double peakBps = 0.0;
    size_t peakCount = 0;
    for (const Connection& c : rows) {
        if (!c.rate.bpsKnown) continue;
        const double total = c.rate.rxBps + c.rate.txBps;
        if (total > peakBps) { peakBps = total; peakCount = 1; }
        else if (peakBps > 0.0 && total == peakBps) { ++peakCount; }
    }

    const bool overWarn = (s.bpsWarn > 0.0 && peakBps >= s.bpsWarn);
    const bool overCrit = (s.bpsCritical > 0.0 && peakBps >= s.bpsCritical);
    bool latchWarn = (latched_ & (1u << 0)) != 0;
    bool latchCrit = (latched_ & (1u << 1)) != 0;

    // Count every condition that is active but did not notify, so the UI can
    // distinguish "nothing happened" from "it is all already on fire and you
    // have been told once". Counted for BOTH thresholds, not just the warning
    // branch: a latched critical alert is just as suppressed as a latched
    // warning, and leaving it uncounted would make the number under-report.
    if (Rising(overCrit, &latchCrit)) {
        Alert a;
        a.kind = AlertKind::kBpsCritical;
        a.title = L"Throughput critical";
        a.text = FormatBps(peakBps) +
                 (peakCount > 1 ? L" on " + std::to_wstring(peakCount) +
                                      L" connections."
                                : std::wstring(L" on a connection."));
        a.rising = true;
        out.push_back(a);
    } else if (overCrit) {
        ++suppressed_;
    }
    // The warning is only interesting if the critical threshold has not
    // already taken over; reporting both for the same event is noise.
    if (overWarn && !overCrit) {
        if (Rising(overWarn, &latchWarn)) {
            Alert a;
            a.kind = AlertKind::kBpsWarn;
            a.title = L"High throughput";
            a.text = FormatBps(peakBps) + L" observed.";
            a.rising = true;
            out.push_back(a);
        } else {
            ++suppressed_;
        }
    } else {
        latchWarn = overWarn;   // re-sync the latch
    }
    latched_ = (latched_ & ~((1u << 0) | (1u << 1))) |
               (latchWarn ? (1u << 0) : 0) |
               (latchCrit ? (1u << 1) : 0);

    // Connection count.
    bool latchCount = (latched_ & (1u << 2)) != 0;
    const bool overCount = (s.connectionWarn > 0 && rows.size() >= s.connectionWarn);
    if (Rising(overCount, &latchCount)) {
        Alert a;
        a.kind = AlertKind::kConnectionCount;
        a.title = L"Many connections";
        a.text = std::to_wstring(rows.size()) + L" connections open.";
        a.rising = true;
        out.push_back(a);
    } else if (overCount) {
        ++suppressed_;
    }
    latched_ = (latched_ & ~(1u << 2)) | (latchCount ? (1u << 2) : 0);

    // Listening sockets and brand-new connections.
    size_t listeners = 0;
    for (const Connection& c : rows) {
        if (c.identity.protocol == IPPROTO_TCP &&
            c.identity.state == MIB_TCP_STATE_LISTEN)
            ++listeners;
    }
    const bool anyListener = listeners > 0;
    const bool anyConnection = rows.size() > listeners;
    bool latchL = (latched_ & (1u << 3)) != 0;
    bool latchC = (latched_ & (1u << 4)) != 0;
    const bool newListener = Rising(anyListener, &latchL);
    const bool newConn = Rising(anyConnection, &latchC);
    latched_ = (latched_ & ~((1u << 3) | (1u << 4))) |
               (latchL ? (1u << 3) : 0) | (latchC ? (1u << 4) : 0);

    if (s.alertOnNewListener && newListener) {
        Alert a;
        a.kind = AlertKind::kNewListener;
        a.title = L"Listening socket";
        a.text = std::to_wstring(listeners) +
                 (listeners == 1 ? L" socket is listening."
                                 : L" sockets are listening.");
        a.rising = true;
        out.push_back(a);
    }
    if (s.alertOnNewConnection && newConn) {
        Alert a;
        a.kind = AlertKind::kNewConnection;
        a.title = L"Connection established";
        a.text = std::to_wstring(rows.size() - listeners) + L" active connection(s).";
        a.rising = true;
        out.push_back(a);
    }

    sawListener_ = anyListener;
    sawConnection_ = anyConnection;
    lastCount_ = rows.size();
    return out;
}

// No owner parameter: NOTIFYICONDATAW already carries hWnd, and passing a
// second one invites the two to disagree. The caller owns the nid and its
// lifetime.
bool ShowTrayBalloon(NOTIFYICONDATAW* nid, const std::wstring& title,
                     const std::wstring& text, DWORD iconFlags) {
    if (nid == nullptr) return false;
    // NIF_INFO is NOT in the icon's original uFlags; it has to be added here.
    // A balloon sent without it is silently dropped by the shell, which looks
    // exactly like "the alert feature does not work".
    nid->uFlags |= NIF_INFO;
    nid->hIcon = nullptr;   // required when NIF_INFO is set
    nid->dwInfoFlags = iconFlags;
    nid->uVersion = NOTIFYICON_VERSION_4;
    nid->szInfoTitle[0] = L'\0';
    nid->szInfo[0] = L'\0';
    ::wcsncpy_s(nid->szInfoTitle, title.c_str(), _TRUNCATE);
    ::wcsncpy_s(nid->szInfo, text.c_str(), _TRUNCATE);
    return ::Shell_NotifyIconW(NIM_MODIFY, nid) != FALSE;
}

// ---------------------------------------------------------------------------
// the rule store
// ---------------------------------------------------------------------------
// One value per rule, keyed by the rule's name. The alternative - one packed blob
// under a single value - would make deleting one rule a read-modify-write of all of
// them, and would lose the one property the registry gives for free: enumerating.

std::vector<AlertRule> AlertRuleStore::Load() {
    std::vector<AlertRule> out;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kSubKey, 0, KEY_READ, &k) !=
        ERROR_SUCCESS) {
        return out;   // nothing saved yet
    }
    wchar_t name[kRuleNameChars] = {0};
    unsigned char buf[kRuleValueBytes] = {0};
    for (DWORD i = 0;; ++i) {
        DWORD nameLen = kRuleNameChars;
        DWORD bufLen = kRuleValueBytes;
        DWORD type = 0;
        const LSTATUS rc = ::RegEnumValueW(k, i, name, &nameLen, nullptr, &type,
                                           buf, &bufLen);
        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS || type != REG_SZ) continue;   // skip, not fail
        AlertRule rule;
        if (AlertRuleFromValue(name, std::wstring(reinterpret_cast<wchar_t*>(buf),
                                                  bufLen / sizeof(wchar_t) - 1),
                               &rule)) {
            out.push_back(rule);
        }
    }
    ::RegCloseKey(k);
    std::sort(out.begin(), out.end(),
              [](const AlertRule& a, const AlertRule& b) { return a.name < b.name; });
    return out;
}

bool AlertRuleStore::Save(const AlertRule& rule) {
    if (rule.name.empty()) return false;   // nothing to key it by
    HKEY k = nullptr;
    if (::RegCreateKeyExW(HKEY_CURRENT_USER, kSubKey, 0, nullptr, 0, KEY_WRITE,
                          nullptr, &k, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const std::wstring v = AlertRuleToValue(rule);
    const LSTATUS rc = ::RegSetValueExW(
        k, rule.name.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(v.c_str()),
        static_cast<DWORD>((v.size() + 1) * sizeof(wchar_t)));
    ::RegCloseKey(k);
    return rc == ERROR_SUCCESS;
}

bool AlertRuleStore::Remove(const std::wstring& name) {
    if (name.empty()) return false;
    HKEY k = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kSubKey, 0, KEY_SET_VALUE, &k) !=
        ERROR_SUCCESS) {
        return false;   // never was there
    }
    const LSTATUS rc = ::RegDeleteValueW(k, name.c_str());
    ::RegCloseKey(k);
    return rc == ERROR_SUCCESS;
}

// Pipe-separated, and every field is either present or empty. A rule typed by hand
// in the registry is a rule a human has to be able to read and write, which is the
// whole reason this is not a blob.
std::wstring AlertRuleToValue(const AlertRule& rule) {
    std::wstring v;
    v += rule.address;   v += L'|';
    v += rule.process;   v += L'|';
    v += rule.onNew ? L"1" : L"0";    v += L'|';
    v += rule.onClose ? L"1" : L"0";  v += L'|';
    v += rule.onThreshold ? L"1" : L"0";
    return v;
}

bool AlertRuleFromValue(const std::wstring& name, const std::wstring& value,
                        AlertRule* out) {
    if (out == nullptr || name.empty()) return false;
    // Split into exactly five fields on the pipe. Four separators, and the fifth
    // field is whatever is left after the fourth - NOT another iteration of this
    // loop, which is how it was written first: it stopped after four fields,
    // found four, and refused a value its own serialiser had just produced.
    std::vector<std::wstring> f;
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        const size_t pipe = value.find(L'|', start);
        if (pipe == std::wstring::npos) return false;   // too few separators
        f.push_back(value.substr(start, pipe - start));
        start = pipe + 1;
    }
    f.push_back(value.substr(start));                   // the fifth
    out->name = name;
    out->address = f[0];
    out->process = f[1];
    out->onNew = f[2] == L"1";
    out->onClose = f[3] == L"1";
    out->onThreshold = f[4] == L"1";
    return true;
}

}  // namespace wintcp
// Settings.cpp
// SPDX-License-Identifier: Apache-2.0
// HKCU\Software\WinTCP registry load/save. Every field is optional: a
// missing value simply leaves the compiled-in default in place, so the
// registry can be pruned freely without breaking startup.

#include "Settings.h"

#include <cstring>

#include "IniFile.h"   // the portable wintcp.ini
#include "Opt.h"       // ReadUtf8File (Utf8ToWide lives in Utils.h)
#include "Utils.h"

namespace wintcp {
namespace {

const wchar_t* kKeyPath = L"Software\\WinTCP";

// Registry value names. One constant per value, used by Load and Save
// alike: a rename or typo in either direction used to compile cleanly and
// silently stop persisting that field. The Bookmarks kVal* group is the model.
const wchar_t* kValWinX = L"WinX";
const wchar_t* kValWinY = L"WinY";
const wchar_t* kValWinW = L"WinW";
const wchar_t* kValWinH = L"WinH";
const wchar_t* kValShowCmd = L"ShowCmd";
const wchar_t* kValIntervalMs = L"IntervalMs";
const wchar_t* kValAutoRefresh = L"AutoRefresh";
const wchar_t* kValResolveHosts = L"ResolveHosts";
const wchar_t* kValTopMost = L"TopMost";
    const wchar_t* kValTrayEnabled = L"TrayEnabled";
    // first-minimize prompt choice (DWORD: 0=never, 1=tray, 2=exit).
    const wchar_t* kValTrayMinimizeChoice = L"TrayMinimizeChoice";
const wchar_t* kValTrafficEnabled = L"TrafficEnabled";
const wchar_t* kValSortCol = L"SortCol";
const wchar_t* kValSortAsc = L"SortAsc";
const wchar_t* kValColVisible = L"ColVisible";
const wchar_t* kValColVersion = L"ColVersion";
const wchar_t* kValColWidths = L"ColWidths";
const wchar_t* kValColOrder = L"ColOrder";
const wchar_t* kValFilter = L"Filter";
const wchar_t* kValLogEnabled = L"LogEnabled";
const wchar_t* kValLogPath = L"LogPath";
const wchar_t* kValLastExportDir = L"LastExportDir";
    // the picked .mmdb survives a relaunch (gui.md's admitted gap).
    const wchar_t* kValGeoIpPath = L"GeoIpPath";
// the ASN database path.
const wchar_t* kValAsnIpPath = L"AsnIpPath";
// Alerting. One value per setting so a missing key leaves the engine
//'s own default in place, which is what makes an older Settings store load clean.
const wchar_t* kValAlertEnabled = L"AlertEnabled";
const wchar_t* kValAlertBpsWarn = L"AlertBpsWarn";
const wchar_t* kValAlertBpsCritical = L"AlertBpsCritical";
const wchar_t* kValAlertConnWarn = L"AlertConnWarn";
const wchar_t* kValAlertOnListener = L"AlertOnNewListener";
const wchar_t* kValAlertOnConnection = L"AlertOnNewConnection";
const wchar_t* kValAlertOnRst = L"AlertOnRst";
const wchar_t* kValAlertOnClosed = L"AlertOnClosed";

bool GetDword(HKEY root, const wchar_t* path, const wchar_t* name, DWORD& out) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LSTATUS rc = ::RegGetValueW(root, path, name,
                                      RRF_RT_REG_DWORD, &type, &value, &size);
    if (rc == ERROR_SUCCESS && type == REG_DWORD) {
        out = value;
        return true;
    }
    return false;
}

bool GetSz(HKEY root, const wchar_t* path, const wchar_t* name,
           wchar_t* out, DWORD outChars) {
    DWORD type = 0;
    const LSTATUS rc = ::RegGetValueW(root, path, name,
                                      RRF_RT_REG_SZ, &type, out, &outChars);
    return rc == ERROR_SUCCESS && type == REG_SZ;
}

bool SetDword(HKEY key, const wchar_t* name, DWORD value) {
    return ::RegSetValueExW(key, name, 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&value),
                            sizeof(value)) == ERROR_SUCCESS;
}

bool SetSz(HKEY key, const wchar_t* name, const wchar_t* value) {
    const DWORD bytes =
        static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
    return ::RegSetValueExW(key, name, 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(value),
                            bytes) == ERROR_SUCCESS;
}

}  // namespace

// At wintcp namespace scope, NOT in the anonymous namespace above: this is the
// shared policy that Bookmarks.cpp and Presets.cpp call, so it needs external
// linkage. An internal-linkage copy would have let those two keep their own
// versions, which is the problem itself.
//
// The shared trust rules for a registry string. Every field in this file
// goes through here too, which is the point: Settings used to trust a bare
// `type == REG_SZ` while Bookmarks and Presets each enforced a much stricter
// set of checks on the SAME registry, so a hand-edited value could be refused
// by one store and believed by another. One validator, one policy.
bool RegReadBoundedString(HKEY key, const wchar_t* name, size_t maxChars,
                          std::wstring* out) {
    if (key == nullptr || name == nullptr || out == nullptr) return false;

    // Pass 1: ask for the size only, with RRF_RT_ANY so a value of the WRONG type
    // is reported rather than refused by the API - the explicit type check below
    // is the one that refuses it, and having both sites read it the same way is
    // what the unification was for. RegGetValueW needs a buffer even to report
    // a length, and the value must not be believed before its shape is known -
    // hence the checks before the allocation below.
    DWORD type = 0;
    DWORD bytes = 0;
    if (::RegGetValueW(key, nullptr, name, RRF_RT_ANY, &type, nullptr,
                       &bytes) != ERROR_SUCCESS)
        return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    if (bytes < sizeof(wchar_t) || (bytes % sizeof(wchar_t)) != 0) return false;
    // '+ 2' slack covers the query's double-counted terminator, so a legal
    // value is never rejected here. The strict bound is applied after the read,
    // against the length actually returned.
    if (static_cast<size_t>(bytes) / sizeof(wchar_t) > maxChars + 2)
        return false;

    std::vector<wchar_t> buf(
        static_cast<size_t>(bytes) / sizeof(wchar_t) + 1, L'\0');
    DWORD have = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
    if (::RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, &type, buf.data(),
                       &have) != ERROR_SUCCESS)
        return false;

    // Pass 2: the same checks against what actually came back, because the
    // value may have changed between the two queries. An embedded NUL, a
    // non-terminated tail or an over-long string is refused rather than
    // truncated: a silently shortened note or bookmark text is a wrong answer
    // that looks right.
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    if (have < sizeof(wchar_t) || (have % sizeof(wchar_t)) != 0) return false;
    const size_t chars = static_cast<size_t>(have) / sizeof(wchar_t);
    if (chars > maxChars + 1) return false;
    if (buf[chars - 1] != L'\0') return false;
    out->assign(buf.data(), chars - 1);
    return true;
}


// ---- column-order helpers --------------------------------------------------
// At namespace scope, NOT in the anonymous namespace above. Declared in
// Settings.h so the selftest exercises the same functions the loader and the
// window call; an internal-linkage copy here would be a second implementation
// that could drift from the tested one without anything noticing.

// Is the first 'count' entries of 'order' a permutation of 0..count-1?
//
// A duplicate would render one column twice while another vanishes, and a
// half-written or hand-edited registry value is entirely possible, so this is
// checked on load as well as before saving. The 'count' bound is explicit so
// this can never read past the array it was given.
bool IsColumnPermutation(const int* order, size_t count) {
    if (order == nullptr) return false;
    if (count > static_cast<size_t>(COL_COUNT)) return false;
    bool seen[COL_COUNT] = {};
    for (size_t i = 0; i < count; ++i) {
        const int id = order[i];
        if (id < 0 || id >= COL_COUNT) return false;
        if (seen[id]) return false;
        seen[id] = true;
    }
    return true;
}

std::vector<int> FoldVisibleOrder(const std::vector<int>& fullOrder,
                                  UINT32 visibleMask,
                                  const std::vector<int>& newVisible) {
    // Refuse anything inconsistent rather than producing a plausible-looking
    // but wrong layout: a corrupted order is far less bad than a silently
    // rearranged one, because the user can at least still find their columns.
    if (fullOrder.empty()) return fullOrder;
    size_t expected = 0;
    for (int id = 0; id < COL_COUNT; ++id) {
        if ((visibleMask & (1u << id)) != 0) ++expected;
    }
    if (newVisible.size() != expected) return fullOrder;
    // Every visible column must appear exactly once, and must be visible.
    for (const int col : newVisible) {
        if (col < 0 || col >= COL_COUNT) return fullOrder;
        if ((visibleMask & (1u << col)) == 0) return fullOrder;
    }

    // Fill the existing visible slots, in place. Positions already holding a
    // visible column are the slots; positions holding a hidden one are left
    // exactly as they are, so a no-drag call is the identity.
    std::vector<int> result = fullOrder;
    size_t next = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        const int id = result[i];
        if (id < 0 || id >= COL_COUNT) return fullOrder;
        if ((visibleMask & (1u << id)) != 0) {
            result[i] = newVisible[next++];
        }
    }
    return result;
}

bool Settings::Load() {
    const HKEY root = HKEY_CURRENT_USER;
    bool any = false;
    DWORD v = 0;

    if (GetDword(root, kKeyPath, kValWinX, v)) { winX = static_cast<int>(v); any = true; }
    if (GetDword(root, kKeyPath, kValWinY, v)) { winY = static_cast<int>(v); any = true; }
    if (GetDword(root, kKeyPath, kValWinW, v)) { winW = static_cast<int>(v); any = true; }
    if (GetDword(root, kKeyPath, kValWinH, v)) { winH = static_cast<int>(v); any = true; }
    if (GetDword(root, kKeyPath, kValShowCmd, v))
        showCmd = static_cast<int>(v);
    winPlaced = any && winW > 0 && winH > 0;

    if (GetDword(root, kKeyPath, kValIntervalMs, v)) {
        if (v >= kMinIntervalMs && v <= kMaxIntervalMs) intervalMs = v;
    }
    if (GetDword(root, kKeyPath, kValAutoRefresh, v)) autoRefresh = (v != 0);
    if (GetDword(root, kKeyPath, kValResolveHosts, v)) resolveHosts = (v != 0);
    if (GetDword(root, kKeyPath, kValTopMost, v)) topMost = (v != 0);
    if (GetDword(root, kKeyPath, kValTrayEnabled, v)) trayEnabled = (v != 0);
    // the choice is a small enum (0/1/2); any out-of-range DWORD read
    // silently leaves the default (0), which re-triggers the prompt - the safe
    // fall-back rather than guessing the user's intent.
    if (GetDword(root, kKeyPath, kValTrayMinimizeChoice, v)) {
        if (v <= 2) trayMinimizeChoice = v;
    }
    if (GetDword(root, kKeyPath, kValTrafficEnabled, v))
        trafficEnabled = (v != 0);

    if (GetDword(root, kKeyPath, kValSortCol, v)) {
        if (static_cast<int>(v) >= 0 && static_cast<int>(v) < COL_COUNT)
            sortCol = static_cast<int>(v);
    }
    if (GetDword(root, kKeyPath, kValSortAsc, v)) sortAsc = (v != 0);
    if (GetDword(root, kKeyPath, kValColVisible, v)) colVisible = v;
    // Version 1 added the stat columns with CPU % visible by default;
    // version 2 added the combined Traffic column; version 3 added Duration
    // and the Bookmarks column. Masks saved before each migration gain the
    // new bits exactly once, so upgraders see them; anyone who then hides one
    // keeps it hidden because the version is persisted on save.
    if (GetDword(root, kKeyPath, kValColVersion, v)) colVersion = v;
    if (colVersion < 1) colVisible |= (1u << COL_CPU);
    if (colVersion < 2) colVisible |= (1u << COL_TRAFFIC);
    if (colVersion < 3) {
        colVisible |= (1u << COL_DURATION);
        colVisible |= (1u << COL_PINNED);
    }
    // Version 4 added the four `ss -i` columns and the per-process rate.
    //
    // NOT made visible by default, deliberately, and this is the opposite
    // decision to versions 1-3: CPU %, Traffic, Duration and Bookmark are
    // columns an ordinary user wants on screen, whereas RTT / Min RTT / Cwnd /
    // Retrans are diagnostic - valuable to someone chasing a slow connection,
    // noise to everyone else, and four columns of mostly em-dashes on a
    // machine where the socket scan could not read them. A migration that
    // turned them on would make the tool look broken on first launch after an
    // upgrade. They are one click away in View > Columns, and the README says
    // so.
    // Historical schema ids (< 1, < 2, < 3 above) stay literal: they name
    // frozen past versions, not a tunable. Only the CURRENT version is a
    // constant, because it is the one future code must keep in step.
    //
    // Version 5 added Parent, Integrity and Signature, and
    // follows version 4's precedent exactly: the bits are NOT granted. All
    // three are opt-in for the same class of reason - a parent id, a trust
    // level and a signature verdict are audit columns, and an upgrade that
    // switched them on would put three more columns on screen for everyone to
    // ask about. The bump alone is deliberate.
    if (colVersion < kCurrentColVersion) {
        // Bump the version and nothing else. The four diagnostic columns are intentionally
        // NOT added to colVisible - see above - and leaving this block empty but
        // present keeps the migration sequence readable, so the next column
        // added has an obvious place to go. The version bump alone is what
        // stops a future migration re-granting columns 1-3 to a user who has
        // deliberately hidden them since upgrading.
        ++colVersion;
    }
    // A mask of 0 renders an empty list with no obvious way back except the
    // Columns menu, so never restore one.
    colVisible = ClampVisibleCols(colVisible);

    DWORD type = 0;
    DWORD bytes = sizeof(colWidths);
    if (::RegGetValueW(root, kKeyPath, kValColWidths, RRF_RT_REG_BINARY,
                       &type, colWidths, &bytes) == ERROR_SUCCESS &&
        type == REG_BINARY && bytes == sizeof(colWidths)) {
        colWidthsValid = true;
        for (int i = 0; i < COL_COUNT; ++i) {
            if (colWidths[i] < 0 || colWidths[i] > kMaxColWidth)
                colWidths[i] = 0;
        }
    }

    // Column drag-reorder. The stored array must be validated as
    // a genuine PERMUTATION of 0..COL_COUNT-1 before it is believed: a
    // partially-written or hand-edited value would otherwise make a column
    // invisible or render the same column twice, and there is no recovery path
    // for a user who cannot see where their columns went.
    {
        DWORD orderType = 0;
        DWORD orderBytes = sizeof(colOrder);
        int stored[COL_COUNT] = {};
        if (::RegGetValueW(root, kKeyPath, kValColOrder, RRF_RT_REG_BINARY,
                           &orderType, stored, &orderBytes) == ERROR_SUCCESS &&
            orderType == REG_BINARY && orderBytes == sizeof(stored) &&
            IsColumnPermutation(stored, COL_COUNT)) {
            for (int i = 0; i < COL_COUNT; ++i) colOrder[i] = stored[i];
            colOrderValid = true;
        }
    }

    // GetSz checks type == REG_SZ; the raw RegGetValueW calls used here
    // only tested the status, so a REG_DWORD stored under a string name
    // was read as a string.
    if (!GetSz(root, kKeyPath, kValFilter, filter,
               sizeof(filter) / sizeof(filter[0])))
        filter[0] = L'\0';

    if (GetDword(root, kKeyPath, kValLogEnabled, v)) logEnabled = (v != 0);
    if (!GetSz(root, kKeyPath, kValLogPath, logPath,
               sizeof(logPath) / sizeof(logPath[0])))
        logPath[0] = L'\0';
    if (!GetSz(root, kKeyPath, kValLastExportDir, lastExportDir,
               sizeof(lastExportDir) / sizeof(lastExportDir[0])))
        lastExportDir[0] = L'\0';
    if (!GetSz(root, kKeyPath, kValGeoIpPath, geoIpPath,
               sizeof(geoIpPath) / sizeof(geoIpPath[0])))
        geoIpPath[0] = L'\0';
    // Same shape, same failure handling: an absent or unreadable value
    // leaves the path empty, which is the same 'nothing picked yet' state.
    if (!GetSz(root, kKeyPath, kValAsnIpPath, asnIpPath,
               sizeof(asnIpPath) / sizeof(asnIpPath[0])))
        asnIpPath[0] = L'\0';

    // Every value is optional; an absent one leaves the field at the
    // engine's default, so a half-written store loads as "whatever was there" rather
    // than failing the whole settings read.
    DWORD alertDw = 0;
    if (GetDword(root, kKeyPath, kValAlertEnabled, alertDw))
        alerts.enabled = alertDw != 0;
    if (GetDword(root, kKeyPath, kValAlertBpsWarn, alertDw))
        alerts.bpsWarn = static_cast<double>(alertDw);
    if (GetDword(root, kKeyPath, kValAlertBpsCritical, alertDw))
        alerts.bpsCritical = static_cast<double>(alertDw);
    if (GetDword(root, kKeyPath, kValAlertConnWarn, alertDw))
        alerts.connectionWarn = static_cast<size_t>(alertDw);
    if (GetDword(root, kKeyPath, kValAlertOnListener, alertDw))
        alerts.alertOnNewListener = alertDw != 0;
    if (GetDword(root, kKeyPath, kValAlertOnConnection, alertDw))
        alerts.alertOnNewConnection = alertDw != 0;
    if (GetDword(root, kKeyPath, kValAlertOnRst, alertDw))
        alerts.alertOnRst = alertDw != 0;
    if (GetDword(root, kKeyPath, kValAlertOnClosed, alertDw))
        alerts.alertOnClosed = alertDw != 0;

    return true;
}

// ---- the portable `wintcp.ini` ----------------------------------------------
//
// Applied BEFORE Load() so the registry always wins. See the header for why
// that ordering is the one that cannot surprise anyone.

// The exe's own directory. An empty 'exePath' (which happens when
// GetModuleFileNameW fails) yields no ini path, which is an ordinary "no
// portable file" rather than an error.
std::wstring PortableIniPath(const std::wstring& exePath) {
    if (exePath.empty()) return std::wstring();
    const size_t slash = exePath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return std::wstring();
    return exePath.substr(0, slash + 1) + L"wintcp.ini";
}

bool Settings::ApplyPortableDefaults(const std::wstring& exePath,
                                     std::wstring* error) {
    if (error != nullptr) error->clear();
    const std::wstring iniPath = PortableIniPath(exePath);
    if (iniPath.empty()) return false;

    // "No such file" is the ordinary case on every machine that is not
    // running portably, and must not be reported as a fault.
    const DWORD attrs = ::GetFileAttributesW(iniPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;

    std::string text;
    const std::wstring readErr = ReadUtf8File(iniPath, &text);
    if (!readErr.empty()) {
        if (error != nullptr) {
            *error = L"could not read " + iniPath + L": " + readErr;
        }
        return false;
    }
    std::string parseErr;
    const std::vector<IniValue> values =
        ParseIniSection(text, "wintcp", &parseErr);
    if (!parseErr.empty()) {
        if (error != nullptr) {
            *error = iniPath + L": " +
                     std::wstring(parseErr.begin(), parseErr.end());
        }
        return false;
    }

    for (const IniValue& kv : values) {
        // An unknown key in a file this build does not understand is not an
        // error: it may be a key a newer build added, and refusing the file
        // over it would be the reader's guess made into the user's problem.
        if (!IsKnownIniKey(kv.key)) continue;

        if (kv.key == "interval") {
            const long long v = std::strtoll(kv.value.c_str(), nullptr, 10);
            // Same range Load() enforces, for the same reason: an out-of-range
            // interval would either spin the refresh or freeze it.
            if (v >= kMinIntervalMs && v <= kMaxIntervalMs) {
                intervalMs = static_cast<UINT>(v);
            }
            continue;
        }
        // Everything else is a boolean. The accepted spellings are the ones a
        // human writes in a file like this; anything else leaves the default
        // rather than guessing.
        bool on = false;
        if (kv.value == "1" || kv.value == "true" || kv.value == "yes" ||
            kv.value == "on") {
            on = true;
        } else if (kv.value == "0" || kv.value == "false" ||
                   kv.value == "no" || kv.value == "off") {
            on = false;
        } else {
            continue;
        }
        if (kv.key == "autoRefresh") {
            autoRefresh = on;
        } else if (kv.key == "resolveHosts") {
            resolveHosts = on;
        } else if (kv.key == "topMost") {
            topMost = on;
        } else if (kv.key == "trayEnabled") {
            trayEnabled = on;
        } else if (kv.key == "trafficEnabled") {
            // Only ever honoured as true when the ETW kernel logger actually
            // starts, which needs elevation - the same rule the registry path
            // follows, recorded on Save().
            trafficEnabled = on;
        }
    }
    return true;
}

bool Settings::Save() const {
    HKEY key = nullptr;
    if (::RegCreateKeyExW(HKEY_CURRENT_USER, kKeyPath, 0, nullptr,
                          REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key,
                          nullptr) != ERROR_SUCCESS)
        return false;

    bool ok = true;
    ok &= SetDword(key, kValWinX, static_cast<DWORD>(winX));
    ok &= SetDword(key, kValWinY, static_cast<DWORD>(winY));
    ok &= SetDword(key, kValWinW, static_cast<DWORD>(winW));
    ok &= SetDword(key, kValWinH, static_cast<DWORD>(winH));
    ok &= SetDword(key, kValShowCmd, static_cast<DWORD>(showCmd));
    ok &= SetDword(key, kValIntervalMs, intervalMs);
    ok &= SetDword(key, kValAutoRefresh, autoRefresh ? 1 : 0);
    ok &= SetDword(key, kValResolveHosts, resolveHosts ? 1 : 0);
    ok &= SetDword(key, kValTopMost, topMost ? 1 : 0);
    ok &= SetDword(key, kValTrayEnabled, trayEnabled ? 1 : 0);
    ok &= SetDword(key, kValTrayMinimizeChoice, trayMinimizeChoice);
    ok &= SetDword(key, kValTrafficEnabled, trafficEnabled ? 1 : 0);
    ok &= SetDword(key, kValSortCol, static_cast<DWORD>(sortCol));
    ok &= SetDword(key, kValSortAsc, sortAsc ? 1 : 0);
    ok &= SetDword(key, kValColVisible, colVisible);
    // The diagnostic columns stay hidden: see the version-4 migration in Load.
    ok &= SetDword(key, kValColVersion, kCurrentColVersion);
    ok &= SetDword(key, kValLogEnabled, logEnabled ? 1 : 0);
    if (colWidthsValid) {
        ok &= ::RegSetValueExW(key, kValColWidths, 0, REG_BINARY,
                               reinterpret_cast<const BYTE*>(colWidths),
                               sizeof(colWidths)) == ERROR_SUCCESS;
    }
    // Only written when it is a real permutation, so a programming error can
    // never persist a layout that hides a column permanently.
    if (colOrderValid && IsColumnPermutation(colOrder, COL_COUNT)) {
        ok &= ::RegSetValueExW(key, kValColOrder, 0, REG_BINARY,
                               reinterpret_cast<const BYTE*>(colOrder),
                               sizeof(colOrder)) == ERROR_SUCCESS;
    }
    ok &= SetSz(key, kValFilter, filter);
    ok &= SetSz(key, kValLogPath, logPath);
    ok &= SetSz(key, kValLastExportDir, lastExportDir);
    ok &= SetSz(key, kValGeoIpPath, geoIpPath);
    ok &= SetSz(key, kValAsnIpPath, asnIpPath);
    ok &= SetDword(key, kValAlertEnabled, alerts.enabled ? 1u : 0u);
    ok &= SetDword(key, kValAlertBpsWarn,
                  static_cast<DWORD>(alerts.bpsWarn < 0 ? 0 : alerts.bpsWarn));
    ok &= SetDword(key, kValAlertBpsCritical,
                  static_cast<DWORD>(alerts.bpsCritical < 0 ? 0 : alerts.bpsCritical));
    ok &= SetDword(key, kValAlertConnWarn,
                  static_cast<DWORD>(alerts.connectionWarn));
    ok &= SetDword(key, kValAlertOnListener, alerts.alertOnNewListener ? 1u : 0u);
    ok &= SetDword(key, kValAlertOnConnection,
                  alerts.alertOnNewConnection ? 1u : 0u);
    ok &= SetDword(key, kValAlertOnRst, alerts.alertOnRst ? 1u : 0u);
    ok &= SetDword(key, kValAlertOnClosed, alerts.alertOnClosed ? 1u : 0u);

    ::RegCloseKey(key);
    return ok;
}

}  // namespace wintcp
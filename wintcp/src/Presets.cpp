// Presets.cpp
// SPDX-License-Identifier: Apache-2.0
// HKCU\Software\WinTCP\Presets\<name> - one saved view per subkey.
//
// Every read is type- and size-checked. A registry value of the wrong type
// under the right name is entirely possible (a hand edit, an older build, a
// truncated write, a script), and RegGetValueW with only a status check will
// happily reinterpret a REG_DWORD as a string, so each value is probed first
// and refused unless its type, its length and its NUL all make sense.

#include "Presets.h"
#include "Settings.h"   // RegReadBoundedString (the one string-read policy)

#include <algorithm>
#include <cwchar>
#include <vector>

// Registry access, so the module links with nothing added to the build files.
#pragma comment(lib, "advapi32.lib")

namespace wintcp {
namespace {

const wchar_t* kPresetsPath = L"Software\\WinTCP\\Presets";

// Schema stamp. Written last (see Save), so a save interrupted part way
// through leaves a preset with no Version, which Load refuses - a truncated
// write can never be mistaken for a complete view.
constexpr DWORD kPresetVersion = 1;

const wchar_t* kValVersion    = L"Version";
const wchar_t* kValFilter     = L"Filter";
const wchar_t* kValColVisible = L"ColVisible";
const wchar_t* kValSortCol    = L"SortCol";
const wchar_t* kValSortAsc    = L"SortAsc";
const wchar_t* kValSources    = L"Sources";

// lpcchName in/out is the buffer size in characters INCLUDING the
// terminator, and on success it comes back as the number of characters
// written, excluding it. On ERROR_MORE_DATA it is NOT updated (measured:
// a 1-character probe of a 14-character key name left it at 1), so a
// size query is useless here and the buffer has to be grown by retrying.
// Passing the first attempt's size straight to a second call is what
// silently makes an enumeration return nothing at all.
//
// This retry loop is REAL (unlike the dead one Bookmarks.cpp used to carry,
// which /GL proved unreachable). The bounds are named because a preset name
// is free text written by the user and 64 characters is a guess; the ladder
// reaches 4096, which is past any name this tool could have written, and the
// refusal is total rather than silent - a half-read name would apply as a
// different preset.
constexpr size_t kSubKeyNameProbeChars = 64;
constexpr int kSubKeyNameAttempts = 4;
constexpr size_t kSubKeyNameGrowth = 4;

// Bounded so a pathological or corrupt key cannot spin a caller loop forever.
// Same value and the same name as Bookmarks.cpp's kMaxSubKeys on purpose.
constexpr DWORD kMaxSubKeys = 65536u;

bool ReadSubKeyName(HKEY key, DWORD index, std::wstring* out) {
    size_t cap = kSubKeyNameProbeChars;
    for (int attempt = 0; attempt < kSubKeyNameAttempts; ++attempt) {
        std::vector<wchar_t> buf(cap, L'\0');
        DWORD have = static_cast<DWORD>(cap);
        const LSTATUS rc =
            ::RegEnumKeyExW(key, index, buf.data(), &have, nullptr, nullptr,
                            nullptr, nullptr);
        if (rc == ERROR_SUCCESS) {
            if (have >= cap) return false;   // would have been truncated
            out->assign(buf.data(), have);
            return true;
        }
        if (rc != ERROR_MORE_DATA) return false;
        cap *= kSubKeyNameGrowth;
    }
    return false;   // a name that will not fit in the ladder above
}

// Read a REG_SZ / REG_EXPAND_SZ of at most 'maxChars' characters.
//
// The size query and the data read disagree by one wchar_t, and the error is
// invisible until a perfectly legal value at the cap is rejected. RegSetValueExW
// on a REG_SZ stores (n + 1) * sizeof(wchar_t) bytes; the data read reports
// exactly that back, but the SIZE query reports (n + 2) * sizeof(wchar_t) - the
// terminator counted twice. Measured, not assumed. So the size query is only
// used to size the buffer, and every exact decision is taken on what the data
// read actually copied in.
//
// Returns false for a missing value, the wrong type, a byte count that is not
// a whole number of wchar_t, a length over the cap, or data whose last wchar
// is not a NUL (a half-written string). Callers treat every one of those as
// "this preset is not loadable".
// Trust rules live in Settings::RegReadBoundedString: this was a
// byte-identical clone of the same copy in Bookmarks.cpp.
bool ReadString(HKEY key, const wchar_t* name, size_t maxChars,
                std::wstring* out) {
    return RegReadBoundedString(key, name, maxChars, out);
}

bool ReadDword(HKEY key, const wchar_t* name, DWORD* out) {
    DWORD value = 0;
    DWORD type = 0;
    DWORD bytes = sizeof(value);
    if (::RegGetValueW(key, nullptr, name, RRF_RT_REG_DWORD, &type, &value,
                       &bytes) != ERROR_SUCCESS)
        return false;
    if (type != REG_DWORD || bytes != sizeof(value)) return false;
    *out = value;
    return true;
}

bool WriteDword(HKEY key, const wchar_t* name, DWORD value) {
    return ::RegSetValueExW(key, name, 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&value),
                            sizeof(value)) == ERROR_SUCCESS;
}

bool WriteString(HKEY key, const wchar_t* name, const std::wstring& value) {
    const DWORD bytes =
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return ::RegSetValueExW(key, name, 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(value.c_str()),
                            bytes) == ERROR_SUCCESS;
}

}  // namespace

std::wstring Presets::CanonicalName(const std::wstring& name) {
    size_t first = 0;
    while (first < name.size() && (name[first] == L' ' || name[first] == L'\t'))
        ++first;
    size_t last = name.size();
    while (last > first &&
           (name[last - 1] == L' ' || name[last - 1] == L'\t')) {
        --last;
    }
    const std::wstring trimmed = name.substr(first, last - first);
    if (trimmed.empty()) return std::wstring();
    if (trimmed.size() > kMaxPresetNameChars) return std::wstring();
    // '.' and '..' are the registry's own reserved names.
    if (trimmed == L"." || trimmed == L"..") return std::wstring();
    for (const wchar_t ch : trimmed) {
        if (ch == L'\\') return std::wstring();   // would create a subkey
        if (ch < 0x20) return std::wstring();     // invisible in a dialog
        if (ch == 0) return std::wstring();      // registry would truncate
    }
    return trimmed;
}

bool Presets::IsValidName(const std::wstring& name) {
    return !CanonicalName(name).empty();
}

bool Presets::Exists(const std::wstring& name) {
    const std::wstring clean = CanonicalName(name);
    if (clean.empty()) return false;
    const std::wstring path = std::wstring(kPresetsPath) + L"\\" + clean;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, KEY_READ, &key) !=
        ERROR_SUCCESS)
        return false;
    ::RegCloseKey(key);
    return true;
}

PresetSave Presets::Save(const std::wstring& name, const PresetView& view,
                         bool allowOverwrite) {
    const std::wstring clean = CanonicalName(name);
    if (clean.empty()) return PresetSave::kInvalidName;

    // Open first and read the disposition the registry itself reports, rather
    // than a separate Exists() probe: the two would be a check-then-act pair
    // and could disagree.
    HKEY key = nullptr;
    DWORD disposition = 0;
    const std::wstring path = std::wstring(kPresetsPath) + L"\\" + clean;
    const LSTATUS open = ::RegCreateKeyExW(
        HKEY_CURRENT_USER, path.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, nullptr, &key, &disposition);
    if (open != ERROR_SUCCESS) return PresetSave::kFailed;

    const bool existed = (disposition != REG_CREATED_NEW_KEY);
    if (existed && !allowOverwrite) {
        // Nothing is written. The key was only opened for KEY_WRITE, so this
        // really is a no-op on the existing preset's values.
        ::RegCloseKey(key);
        return PresetSave::kExists;
    }

    // Read the outgoing preset first so a failed overwrite can be put back.
    // A failure here is not fatal: we simply lose the safety net.
    PresetView previous;
    const bool havePrevious = existed && Load(clean, &previous);

    bool ok = true;
    ok &= WriteString(key, kValFilter, view.filter);
    ok &= WriteDword(key, kValColVisible, ClampVisibleCols(view.colVisible));
    // A sort column outside the current set is not a loadable preset: the
    // column may simply not exist any more, and applying a view that cannot
    // be rendered would be a lie about what was saved.
    ok &= WriteDword(key, kValSortCol, static_cast<DWORD>(view.sortColumn));
    ok &= WriteDword(key, kValSortAsc, view.sortAsc ? 1 : 0);
    // Bits this build does not know about are simply not written; a preset
    // saved by a newer version still loads here instead of failing whole.
    ok &= WriteDword(key, kValSources, view.sources & kPresetSourceAll);

    // The version goes last and only once everything else landed, so an
    // interrupted save is recognisable as incomplete rather than as a
    // half-populated but "valid" view.
    if (ok) ok = WriteDword(key, kValVersion, kPresetVersion);

    ::RegCloseKey(key);

    if (!ok) {
        if (existed) {
            if (havePrevious) (void)Save(clean, previous, true);  // best effort
        } else {
            // Do not leave a half-written preset behind.
            ::RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
        }
        return PresetSave::kFailed;
    }
    return existed ? PresetSave::kOverwrote : PresetSave::kCreated;
}

bool Presets::Load(const std::wstring& name, PresetView* out) {
    if (out == nullptr) return false;
    const std::wstring clean = CanonicalName(name);
    if (clean.empty()) return false;
    const std::wstring path = std::wstring(kPresetsPath) + L"\\" + clean;

    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, KEY_QUERY_VALUE,
                        &key) != ERROR_SUCCESS)
        return false;

    DWORD version = 0;
    bool ok = ReadDword(key, kValVersion, &version) &&
              (version == kPresetVersion);

    // Published only on full success, so a caller that keeps its current view
    // on failure never sees a half-applied one.
    PresetView v;

    DWORD sortCol = 0;
    ok = ok && (ReadDword(key, kValSortCol, &sortCol) != 0);
    if (ok && (sortCol >= static_cast<DWORD>(COL_COUNT))) ok = false;
    if (ok) v.sortColumn = static_cast<int>(sortCol);

    DWORD asc = 0;
    ok = ok && (ReadDword(key, kValSortAsc, &asc) != 0);
    if (ok) v.sortAsc = (asc != 0);

    DWORD cols = 0;
    ok = ok && (ReadDword(key, kValColVisible, &cols) != 0);
    // A stored mask of 0 would restore a list with no columns and no way back
    // except the Columns menu, so it is clamped exactly as Settings clamps it.
    if (ok) v.colVisible = ClampVisibleCols(cols);

    DWORD sources = 0;
    ok = ok && (ReadDword(key, kValSources, &sources) != 0);
    if (ok) v.sources = sources & kPresetSourceAll;

    std::wstring filter;
    ok = ok && ReadString(key, kValFilter, kMaxPresetFilterChars, &filter);
    if (ok) v.filter = filter;

    ::RegCloseKey(key);
    if (!ok) return false;
    *out = v;
    return true;
}

bool Presets::Delete(const std::wstring& name) {
    const std::wstring clean = CanonicalName(name);
    // A name that cannot exist cannot be present, so the postcondition
    // "nothing is stored under this name" already holds.
    if (clean.empty()) return true;
    const std::wstring path = std::wstring(kPresetsPath) + L"\\" + clean;
    const LSTATUS rc = ::RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND ||
           rc == ERROR_PATH_NOT_FOUND;
}

std::vector<std::wstring> Presets::List() {
    std::vector<std::wstring> names;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, kPresetsPath, 0, KEY_READ, &key) !=
        ERROR_SUCCESS)
        return names;   // no presets saved yet is not a failure

    // Bounded so a pathological or corrupt key cannot spin here.
    for (DWORD index = 0; index < kMaxSubKeys; ++index) {
        std::wstring name;
        if (!ReadSubKeyName(key, index, &name)) break;   // end, or unreadable
        names.push_back(name);
    }
    ::RegCloseKey(key);
    // The registry compares names case-insensitively; the sort is on the
    // literal name so a menu built from this is still in a stable order.
    std::sort(names.begin(), names.end());
    return names;
}

const wchar_t* PresetSaveToString(PresetSave result) {
    switch (result) {
        case PresetSave::kCreated:     return L"Preset created";
        case PresetSave::kOverwrote:   return L"Preset replaced";
        case PresetSave::kExists:      return L"A preset with this name already exists";
        case PresetSave::kInvalidName: return L"Invalid preset name";
        case PresetSave::kFailed:      return L"Could not write the preset";
    }
    return L"Unknown result";
}

}  // namespace wintcp

// Bookmarks.cpp
// SPDX-License-Identifier: Apache-2.0
// HKCU\Software\WinTCP\Bookmarks - one subkey per remote endpoint, holding
// Tag (REG_DWORD), Note (REG_SZ) and When (REG_QWORD, UTC unix seconds).
//
// Every entry point that takes an address builds its key through the one
// NormalizeAddress() in Bookmarks.h, so "what Add stored" and "what
// IsBookmarked looks for" cannot be two different strings.

#include "Bookmarks.h"
#include "Settings.h"   // RegReadBoundedString (the one string-read policy)

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <vector>

// Registry access, so the module links with nothing added to the build files.
#pragma comment(lib, "advapi32.lib")

namespace wintcp {

// The tag constants in the header must stay the row tags from Connection.h.
static_assert(kBookmarkTagNone == 0 && kBookmarkTagRed == 1 &&
              kBookmarkTagAmber == 2 && kBookmarkTagBlue == 3 &&
              kBookmarkTagGreen == 4 && kBookmarkTagCount == 5,
              "bookmark tags drifted from RowTag");

namespace {

const wchar_t* kBookmarksPath = L"Software\\WinTCP\\Bookmarks";

const wchar_t* kValTag  = L"Tag";
const wchar_t* kValNote = L"Note";
const wchar_t* kValWhen = L"When";

// Every enumerated subkey name, and the address literals they are built from,
// are far below this; the cap only exists so a corrupt or hand-written key
// cannot hand the parser an unbounded string.
constexpr size_t kMaxAddressChars = 128;

// Bounded so a pathological key cannot spin a caller loop forever.
constexpr DWORD kMaxSubKeys = 65536u;

// FILETIME epoch arithmetic, named because the two functions below are the
// only bridge between the registry's UTC unix seconds and the Windows
// 1601-based tick count, and both magic numbers are needed in both
// directions: ticks are 100 ns, and 11644473600 seconds separate the two
// epochs. A digit lost in either one moves every bookmark's timestamp.
constexpr std::uint64_t kFileTimeTicksPerSecond = 10000000ULL;
constexpr std::uint64_t kFileTimeEpochOffsetTicks = 116444736000000000ULL;

// The first byte of fe80::/8, which is where a numeric scope id carries
// meaning. Same name as Utils.cpp's copy on purpose, so a grep finds both.
constexpr unsigned char kLinkLocalFirstByte = 0xFE;

// A link-local address written without a scope is completed with the
// interface index, which is exactly what the display code appends
// (TcpTable.cpp PrintIpv6 renders "fe80::1%12"). Using it here rather than
// dropping the scope is the difference between one bookmark and two.
const wchar_t* const kDefaultScopeIndex = L"1";

std::wstring MakePath(const std::wstring& address, UINT port) {
    const std::wstring norm = NormalizeAddress(address);
    if (norm.empty()) return std::wstring();
    return std::wstring(kBookmarksPath) + L"\\" + MakeBookmarkKey(norm, port);
}

bool OpenKey(const std::wstring& path, REGSAM access, HKEY* out) {
    if (path.empty()) return false;
    return ::RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, access, out) ==
           ERROR_SUCCESS;
}

// Read a bounded REG_SZ. Same contract as the one in Presets.cpp, including
// the measured one-wchar_t disagreement between the size query and the data
// read: the size query is only used to size the buffer, and the length,
// terminator and cap decisions are all taken on what the data read actually
// copied in. The wrong type, a length over the cap, a byte count that is not
// whole wchar_t, or a missing terminator are all a clean false rather than a
// truncated string.
// Trust rules live in Settings::RegReadBoundedString: this was a
// byte-identical clone of the same copy in Presets.cpp, and a registry string
// read is exactly the place where two copies of one security check become a
// silent disagreement.
bool ReadString(HKEY key, const wchar_t* name, size_t maxChars,
                std::wstring* out) {
    return RegReadBoundedString(key, name, maxChars, out);
}

bool WriteString(HKEY key, const wchar_t* name, const std::wstring& value) {
    const DWORD bytes =
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return ::RegSetValueExW(key, name, 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(value.c_str()),
                            bytes) == ERROR_SUCCESS;
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

bool ReadQword(HKEY key, const wchar_t* name, std::uint64_t* out) {
    ULARGE_INTEGER value = {};
    DWORD type = 0;
    DWORD bytes = sizeof(value);
    if (::RegGetValueW(key, nullptr, name, RRF_RT_REG_QWORD, &type, &value,
                       &bytes) != ERROR_SUCCESS)
        return false;
    if (type != REG_QWORD || bytes != sizeof(value)) return false;
    *out = value.QuadPart;
    return true;
}

bool WriteQword(HKEY key, const wchar_t* name, std::uint64_t value) {
    ULARGE_INTEGER u = {};
    u.QuadPart = value;
    return ::RegSetValueExW(key, name, 0, REG_QWORD,
                            reinterpret_cast<const BYTE*>(&u),
                            sizeof(u)) == ERROR_SUCCESS;
}

// True for fe00::/8 - see the note on NormalizeAddress().
bool IsScopedFamily(const unsigned char* a) {
    return a[0] == kLinkLocalFirstByte;
}

bool IsUnspecified(const unsigned char* a) {
    for (int i = 0; i < 16; ++i) {
        if (a[i] != 0) return false;
    }
    return true;
}

// RFC 4291 ::ffff:0:0/96, the full 96-bit prefix - Windows produces these
// constantly for a dual-stack socket talking to an IPv4 peer.
bool IsV4Mapped(const unsigned char* a) {
    for (int i = 0; i < 10; ++i) {
        if (a[i] != 0) return false;
    }
    return a[10] == 0xFF && a[11] == 0xFF;
}

// Split a subkey name back into the address and port it encodes. False for a
// name this module would not have written.
bool SplitKey(const std::wstring& name, std::wstring* address, UINT* port) {
    if (name.empty() || name.size() >= kMaxAddressChars) return false;
    const size_t close = name.rfind(L']');
    size_t colon = std::wstring::npos;
    std::wstring addr;
    if (close != std::wstring::npos) {
        // Bracketed IPv6: "[addr]:port".
        colon = name.rfind(L':');
        if (colon == std::wstring::npos || colon < close) return false;
        addr = name.substr(1, close - 1);
    } else {
        colon = name.rfind(L':');
        if (colon == std::wstring::npos || colon == 0) return false;
        addr = name.substr(0, colon);
    }
    const std::wstring portText = name.substr(colon + 1);
    if (portText.empty() || portText.size() > 5) return false;
    for (const wchar_t ch : portText) {
        if (ch < L'0' || ch > L'9') return false;
    }
    const unsigned long value = ::wcstoul(portText.c_str(), nullptr, 10);
    if (value > 65535ul) return false;
    *address = addr;
    *port = static_cast<UINT>(value);
    return true;
}

}  // namespace

const wchar_t* BookmarkTagLabel(unsigned tag) {
    switch (tag) {
        case kBookmarkTagRed:   return L"Red";
        case kBookmarkTagAmber: return L"Amber";
        case kBookmarkTagBlue:  return L"Blue";
        case kBookmarkTagGreen: return L"Green";
        case kBookmarkTagNone:  return L"None";
        default:                return L"Unknown";
    }
}

std::uint64_t FileTimeToUnixSeconds(const FILETIME& ft) {
    ULARGE_INTEGER ticks = {};
    ticks.LowPart = ft.dwLowDateTime;
    ticks.HighPart = ft.dwHighDateTime;
    // 11644473600 seconds between 1601-01-01 and 1970-01-01.
    if (ticks.QuadPart < kFileTimeEpochOffsetTicks) return 0;
    return (ticks.QuadPart - kFileTimeEpochOffsetTicks) /
           kFileTimeTicksPerSecond;
}

FILETIME UnixSecondsToFileTime(std::uint64_t seconds) {
    ULARGE_INTEGER ticks = {};
    ticks.QuadPart = seconds * kFileTimeTicksPerSecond +
                     kFileTimeEpochOffsetTicks;
    FILETIME out;
    out.dwLowDateTime = ticks.LowPart;
    out.dwHighDateTime = ticks.HighPart;
    return out;
}

std::wstring NormalizeAddress(const std::wstring& address) {
    // Unwrap the bracketed form (Utils::JoinEndpoint writes that), so a scope
    // suffix is stripped in the right order. The ']' is found by position
    // rather than by requiring it to be the last character: the bracketed
    // form is "[addr]" or "[addr]:port", and the port is the other half of
    // the identity, not part of the address. Swallowing it here would make
    // "1.2.3.4:80" and "1.2.3.4" the same key.
    std::wstring text = address;
    if (text.size() >= 2 && text.front() == L'[') {
        const size_t close = text.find(L']');
        if (close == std::wstring::npos) return std::wstring();
        text = text.substr(1, close - 1);
    }
    // Trim whitespace, so a value pasted out of a list cell does not become
    // a second bookmark of the same endpoint.
    size_t first = 0;
    while (first < text.size() && (text[first] == L' ' || text[first] == L'\t' ||
                                   text[first] == L'\r' || text[first] == L'\n')) {
        ++first;
    }
    size_t last = text.size();
    while (last > first && (text[last - 1] == L' ' || text[last - 1] == L'\t' ||
                            text[last - 1] == L'\r' || text[last - 1] == L'\n')) {
        --last;
    }
    text = text.substr(first, last - first);
    if (text.empty() || text.size() > kMaxAddressChars)
        return std::wstring();

    // Split off "%<scope>". InetPtonW does not accept the suffix, and a
    // scope that is not a plain decimal id is not something two callers can
    // be trusted to compare identically, so an unparseable scope makes the
    // whole address unusable rather than being dropped.
    std::wstring scope;
    const size_t pct = text.find(L'%');
    if (pct != std::wstring::npos) {
        scope = text.substr(pct + 1);
        text.resize(pct);
        if (scope.empty() || scope.size() > 10) return std::wstring();
        for (const wchar_t ch : scope) {
            if (ch < L'0' || ch > L'9') return std::wstring();
        }
    }
    if (text.empty()) return std::wstring();

    // The family actually parsed has to be recorded, not sniffed out of the
    // bytes afterwards: InetPtonW(AF_INET) writes its four bytes at the
    // START of the buffer while InetPtonW(AF_INET6) writes sixteen, so the
    // two layouts cannot be told apart from the contents. "2001:db8::1" and
    // "1.2.3.4" both leave bytes[10] and bytes[11] zero, and guessing from
    // that turns one of them into the other.
    unsigned char bytes[16] = {0};
    int family = 0;
    // AF_INET6 is tried first because InetPtonW(AF_INET6, "1.2.3.4", ...) is
    // valid too, and a std::wstring carries no family to disambiguate with.
    if (::InetPtonW(AF_INET6, text.c_str(), bytes) == 1) {
        family = AF_INET6;
    } else if (::InetPtonW(AF_INET, text.c_str(), bytes) == 1) {
        family = AF_INET;
    } else {
        return std::wstring();
    }

    wchar_t v4buf[INET_ADDRSTRLEN] = {0};
    if (family == AF_INET) {
        if (!scope.empty()) return std::wstring();   // meaningless on IPv4
        IN_ADDR v4 = {};
        std::memcpy(&v4.S_un.S_addr, bytes, 4);    // four bytes, at offset 0
        if (::InetNtopW(AF_INET, &v4, v4buf,
                        static_cast<size_t>(INET_ADDRSTRLEN)) == nullptr) {
            return std::wstring();
        }
        if (v4.S_un.S_addr == 0) return std::wstring();   // 0.0.0.0
        for (wchar_t& ch : v4buf) {
            if (ch != L'\0') ch = static_cast<wchar_t>(::towlower(ch));
        }
        return std::wstring(v4buf);
    }

    if (IsV4Mapped(bytes)) {
        // A dual-stack socket reaching an IPv4 peer reports ::ffff:1.2.3.4,
        // which must land on the same key as the bare form. The v4 tail is
        // printed in whatever case the input used; lowercasing keeps an
        // upper-case spelling from becoming a second bookmark. A scope on a
        // v4 address is meaningless, so it is refused rather than appended.
        if (!scope.empty()) return std::wstring();
        IN_ADDR v4 = {};
        std::memcpy(&v4.S_un.S_addr, bytes + 12, 4);
        if (::InetNtopW(AF_INET, &v4, v4buf,
                        static_cast<size_t>(INET_ADDRSTRLEN)) == nullptr) {
            return std::wstring();
        }
        for (wchar_t& ch : v4buf) {
            if (ch != L'\0') ch = static_cast<wchar_t>(::towlower(ch));
        }
        return std::wstring(v4buf);
    }

    // "::" is the placeholder a listening or unbound row shows. It is not an
    // endpoint, so it must never become a key.
    if (IsUnspecified(bytes)) return std::wstring();

    wchar_t out[INET6_ADDRSTRLEN] = {0};
    if (::InetNtopW(AF_INET6, bytes, out,
                    static_cast<size_t>(INET6_ADDRSTRLEN)) == nullptr) {
        return std::wstring();
    }
    const std::wstring literal(out);

    // A global address is not ambiguous, so no scope is needed; one that is
    // present is kept, because the scope is not used to reach it and only has
    // to round-trip. A link-local address is a different story: dropping its
    // scope would merge the same address on two interfaces into one
    // bookmark, so a missing scope is replaced with a default interface
    // index - never with a zone NAME, because "eth0" is not the same string
    // on two machines and a name-keyed identity cannot be compared across
    // them.
    if (!IsScopedFamily(bytes)) return literal;

    if (scope.empty()) return literal + L"%" + kDefaultScopeIndex;
    return literal + L"%" + scope;
}

std::wstring MakeBookmarkKey(const std::wstring& normalizedAddress, UINT port) {
    // IPv6 literals already contain ':', so they are bracketed; the same
    // convention as Utils::JoinEndpoint, which is what the row model prints.
    const bool bracketed = normalizedAddress.find(L':') != std::wstring::npos;
    std::wstring out;
    if (bracketed) out.push_back(L'[');
    out += normalizedAddress;
    if (bracketed) out.push_back(L']');
    out.push_back(L':');
    out += std::to_wstring(port);
    return out;
}

std::wstring Bookmark::Key() const {
    return MakeBookmarkKey(address, port);
}

bool Bookmarks::Add(const std::wstring& address, UINT port, unsigned tag,
                    const std::wstring& note) {
    if (!IsValidBookmarkTag(tag)) return false;
    if (port > 65535u) return false;
    if (note.size() > kMaxNoteChars) return false;
    const std::wstring norm = NormalizeAddress(address);
    if (norm.empty()) return false;

    const std::wstring path =
        std::wstring(kBookmarksPath) + L"\\" + MakeBookmarkKey(norm, port);

    HKEY key = nullptr;
    DWORD disposition = 0;
    if (::RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr,
                          REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                          nullptr, &key, &disposition) != ERROR_SUCCESS) {
        return false;
    }

    bool ok = true;
    if (disposition == REG_CREATED_NEW_KEY) {
        ok &= WriteDword(key, kValTag, static_cast<DWORD>(tag));
        ok &= WriteString(key, kValNote, note);
    } else {
        // An existing bookmark keeps its tag and note. Re-adding has to be
        // safe to call from a refresh path without destroying what the user
        // typed; SetNote and SetColour are how those change.
        std::wstring existing;
        if (!ReadString(key, kValNote, kMaxNoteChars, &existing)) {
            // Unreadable (wrong type, truncated, oversized): rewrite it
            // rather than leave the entry permanently unloadable.
            ok &= WriteString(key, kValNote, note);
        }
        DWORD existingTag = 0;
        if (!ReadDword(key, kValTag, &existingTag)) {
            ok &= WriteDword(key, kValTag, static_cast<DWORD>(tag));
        }
    }
    // When is written last, so an interrupted Add leaves a loadable entry
    // with a stale-but-valid timestamp rather than a wrong one.
    FILETIME now = {};
    ::GetSystemTimeAsFileTime(&now);
    ok &= WriteQword(key, kValWhen, FileTimeToUnixSeconds(now));

    ::RegCloseKey(key);
    if (!ok) {
        if (disposition == REG_CREATED_NEW_KEY) {
            ::RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
        }
        return false;
    }
    return true;
}

bool Bookmarks::IsBookmarked(const std::wstring& address, UINT port) {
    const std::wstring path = MakePath(address, port);
    if (path.empty()) return false;
    HKEY key = nullptr;
    if (!OpenKey(path, KEY_QUERY_VALUE, &key)) return false;
    ::RegCloseKey(key);
    return true;
}

bool Bookmarks::GetNote(const std::wstring& address, UINT port,
                        std::wstring* out) {
    if (out == nullptr) return false;
    const std::wstring path = MakePath(address, port);
    if (path.empty()) return false;
    HKEY key = nullptr;
    if (!OpenKey(path, KEY_QUERY_VALUE, &key)) return false;
    const bool ok = ReadString(key, kValNote, kMaxNoteChars, out);
    ::RegCloseKey(key);
    return ok;
}

bool Bookmarks::SetNote(const std::wstring& address, UINT port,
                        const std::wstring& note) {
    if (note.size() > kMaxNoteChars) return false;
    const std::wstring path = MakePath(address, port);
    if (path.empty()) return false;
    HKEY key = nullptr;
    if (!OpenKey(path, KEY_SET_VALUE, &key)) return false;
    const bool ok = WriteString(key, kValNote, note);
    ::RegCloseKey(key);
    return ok;
}

bool Bookmarks::SetColour(const std::wstring& address, UINT port, unsigned tag) {
    if (!IsValidBookmarkTag(tag)) return false;
    const std::wstring path = MakePath(address, port);
    if (path.empty()) return false;
    HKEY key = nullptr;
    if (!OpenKey(path, KEY_SET_VALUE, &key)) return false;
    const bool ok = WriteDword(key, kValTag, static_cast<DWORD>(tag));
    ::RegCloseKey(key);
    return ok;
}

bool Bookmarks::Get(const std::wstring& address, UINT port, Bookmark* out) {
    if (out == nullptr) return false;
    const std::wstring path = MakePath(address, port);
    if (path.empty()) return false;
    HKEY key = nullptr;
    if (!OpenKey(path, KEY_QUERY_VALUE, &key)) return false;

    // Strict: a bookmark the caller cannot fully read is not a bookmark. This
    // is the difference from List, which skips unusable entries but still
    // reports them.
    Bookmark b;
    b.address = NormalizeAddress(address);
    b.port = port;
    DWORD tag = 0;
    bool ok = ReadDword(key, kValTag, &tag) && IsValidBookmarkTag(tag);
    if (ok) b.tag = tag;
    ok = ok && ReadString(key, kValNote, kMaxNoteChars, &b.note);
    ok = ok && ReadQword(key, kValWhen, &b.when);

    ::RegCloseKey(key);
    if (!ok) return false;
    *out = b;
    return true;
}

std::vector<Bookmark> Bookmarks::List(size_t* unreadable) {
    if (unreadable != nullptr) *unreadable = 0;
    std::vector<Bookmark> out;
    HKEY base = nullptr;
    if (!OpenKey(kBookmarksPath, KEY_READ, &base)) return out;

    for (DWORD index = 0; index < kMaxSubKeys; ++index) {
        // Buffer sized generously up front, because a size query is not
        // available: RegEnumKeyExW does not write the required length back
        // when it returns ERROR_MORE_DATA (measured - see the same note on
        // ReadSubKeyName in Presets.cpp), so the buffer is simply made big
        // enough for any name this module could have written and the retry
        // below is the safety net for anything hand-edited.
        std::wstring name;
        // Read the name ONCE, with a buffer this module's own writer could
        // never have exceeded (kMaxAddressChars + ":port" is the whole key).
        //
        // This used to be a `for (cap = ...; cap *= 4)` loop whose body ended
        // in an unconditional `break`, so the loop was dead code after the
        // first iteration - and the compiler proved it: under /GL+LTCG it
        // emitted C4702 "unreachable code", which /WX turns into a hard build
        // failure. So /GL/LTCG could not be turned on at all until this was
        // written as what it always was: a single bounded read. The retry loop
        // is only reachable if RegEnumKeyExW were to fail on a name this module
        // wrote, and the "safety net" comment above it described a
        // re-attempt that never happened.
        {
            std::vector<wchar_t> buf(kMaxAddressChars + 1, L'\0');
            DWORD have = static_cast<DWORD>(buf.size());
            const LSTATUS rc =
                ::RegEnumKeyExW(base, index, buf.data(), &have, nullptr,
                                nullptr, nullptr, nullptr);
            if (rc == ERROR_NO_MORE_ITEMS) break;   // end of the key
            if (rc != ERROR_SUCCESS) {
                if (unreadable != nullptr) ++(*unreadable);
                continue;
            }
            if (have > buf.size()) have = static_cast<DWORD>(buf.size());
            name.assign(buf.data(), have);
        }
        if (name.empty()) {
            // An empty or unreadable name is not a row; stop rather than spin
            // through the rest of a key we cannot parse.
            break;
        }
        if (name.size() > kMaxAddressChars) {
            if (unreadable != nullptr) ++(*unreadable);
            continue;
        }

        std::wstring addr;
        UINT port = 0;
        if (!SplitKey(name, &addr, &port)) {
            if (unreadable != nullptr) ++(*unreadable);
            continue;
        }
        const std::wstring norm = NormalizeAddress(addr);
        if (norm.empty() || MakeBookmarkKey(norm, port) != name) {
            // The stored name is not this module's canonical form, i.e. it was
            // written by hand or by a build with different rules. Counted
            // rather than guessed at.
            if (unreadable != nullptr) ++(*unreadable);
            continue;
        }

        HKEY key = nullptr;
        if (!OpenKey(std::wstring(kBookmarksPath) + L"\\" + name,
                     KEY_QUERY_VALUE, &key)) {
            if (unreadable != nullptr) ++(*unreadable);
            continue;
        }
        Bookmark b;
        b.address = norm;
        b.port = port;
        DWORD tag = 0;
        b.tag = ReadDword(key, kValTag, &tag) && IsValidBookmarkTag(tag)
                    ? tag
                    : kBookmarkTagNone;
        // A note or timestamp that is corrupt degrades to the default: the
        // bookmark exists and the caller still wants to see it. The count
        // says what happened.
        if (!ReadString(key, kValNote, kMaxNoteChars, &b.note)) {
            if (unreadable != nullptr) ++(*unreadable);
        }
        if (!ReadQword(key, kValWhen, &b.when)) {
            if (unreadable != nullptr) ++(*unreadable);
        }
        ::RegCloseKey(key);
        out.push_back(b);
    }
    ::RegCloseKey(base);

    std::sort(out.begin(), out.end(), [](const Bookmark& a, const Bookmark& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.port < b.port;
    });
    return out;
}

bool Bookmarks::Remove(const std::wstring& address, UINT port) {
    const std::wstring path = MakePath(address, port);
    // An address that cannot normalise cannot have been stored, so the
    // postcondition "nothing is stored under this identity" already holds.
    if (path.empty()) return true;
    const LSTATUS rc = ::RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND ||
           rc == ERROR_PATH_NOT_FOUND;
}

std::uint64_t Bookmarks::LastChangeUnixSeconds() {
    std::uint64_t newest = 0;
    for (const Bookmark& b : List()) {
        if (b.when > newest) newest = b.when;
    }
    return newest;
}

}  // namespace wintcp

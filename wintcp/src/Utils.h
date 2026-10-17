// Utils.h
// SPDX-License-Identifier: Apache-2.0
// Small general-purpose helpers used across the wintcp application.
// All functions here are Unicode (std::wstring) based.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7 or later (needed for QueryFullProcessImageNameW, InetNtopW, etc.)
#endif

#include <windows.h>

#include <cstdint>
#include <exception>   // std::exception for RunGuarded
#include <string>
#include <vector>

namespace wintcp {

// Binary unit ladder. One definition shared by FormatBytes (Utils.cpp),
// FormatBps (Alerts.cpp) and every future formatter: two spellings of 1024.0
// in two files disagreed about nothing yet, which is exactly when to unify —
// after the first divergence it is a bug hunt, not a rename.
constexpr double kBytesPerKB = 1024.0;
constexpr double kBytesPerMB = 1024.0 * 1024.0;
constexpr double kBytesPerGB = 1024.0 * 1024.0 * 1024.0;
constexpr double kBytesPerTB = 1024.0 * 1024.0 * 1024.0 * 1024.0;

// Formatting policy (C1). Every human-readable number in this codebase goes
// through exactly one formatter per unit, and the unit is in the name:
//   FormatBytes  (below) ......... byte counts ("12.3 KB")
//   FormatBps    (Alerts.h) ...... byte rates ("2 KB/s")
//   FormatDuration (ConnectionStore)  durations ("1d 4h")
//   FormatRttMs  (ConnectionStore) ... milliseconds ("24", "<1")
//   FormatBpsCell (ConnectionStore) . the two-direction rate cell
// A second formatter for an already-covered unit is a defect, not a helper —
// RateText was removed for exactly this (it spelled "2.0 KB/s" where FormatBps
// spells "2 KB/s"). Unknown readings never reach a formatter: the caller
// prints the app-wide em-dash (L"—"), so "no data" cannot be mistaken for a
// measurement in any unit.

// RAII wrapper for raw Win32 HANDLEs. Treats both nullptr and
// INVALID_HANDLE_VALUE as "not owning". Movable, not copyable.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE h) : h_(h) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) { reset(); h_ = other.h_; other.h_ = nullptr; }
        return *this;
    }

    HANDLE get() const { return h_; }
    explicit operator bool() const { return Valid(h_); }
    HANDLE* put() { reset(); return &h_; }

    void reset(HANDLE h = nullptr) {
        if (Valid(h_)) ::CloseHandle(h_);
        h_ = h;
    }

    HANDLE release() { HANDLE t = h_; h_ = nullptr; return t; }

private:
    static bool Valid(HANDLE h) { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    HANDLE h_ = nullptr;
};

// Convert a Win32 error code to a human readable message, e.g. from GetLastError().
// Never throws.
std::wstring FormatSystemError(DWORD errorCode);

// Current local time as L"YYYY-MM-DD HH:MM:SS". Never throws (returns L"?" on failure).
std::wstring FormatCurrentTime();

// Lowercase a wide string (for case-insensitive comparisons).
std::wstring ToLowerW(const std::wstring& s);

// Returns true if 'haystack' contains 'needle', case-insensitive.
// An empty needle always matches.
bool ContainsCaseInsensitive(const std::wstring& haystack, const std::wstring& needle);

// Convert a wide string to UTF-8 (for writing CSV files). Returns empty on failure.
std::string WideToUtf8(const std::wstring& s);

// Convert a narrow UTF-8/ascii literal to wide. Used for the few compile-
// time constants (e.g. the version string) that have to stay narrow for
// the resource compiler but are displayed in wide UI code.
std::wstring Utf8ToWide(const char* s);

// The "%<scope>" suffix an IPv6 address needs on its printed form, or L"" when
// it needs none. One home for the rule, because it is not cosmetic (C2):
//
//   * The connection store keys a sampled socket age by matching the ENDPOINT
//     STRING the socket scan produced against the one TcpTable printed. Two
//     renderings of one address that differ by a suffix are two different keys,
//     so the join silently misses and the row's traffic goes blank.
//   * A numeric scope id is meaningful only for fe80::/10 (which interface);
//     anywhere else it is noise that manufactures exactly that mismatch.
//
// Callers pass raw address bytes (network order) and the scope id their own
// API gave them; this only decides WHETHER and HOW to spell the suffix. The
// address text itself stays with the caller's InetNtopW (or hand-rolled) call,
// so this header needs no socket headers.
std::wstring Ipv6ScopeSuffix(const unsigned char raw[16], unsigned scopeId);

// Run fn() with worker-thread containment. Returns "" when fn()
// completes; otherwise a one-line UTF-8 description of the escaped exception.
// An uncaught exception in a std::thread or CreateThread worker calls
// std::terminate and takes the whole process down with no artefact — not even
// a minidump names the worker. Every long-lived worker wraps its unit of
// work in this and degrades through its own error channel instead of dying.
// Never throws itself: the handler's own allocations are guarded, because a
// worker that is already dying must not die from the error path too.
template <typename Fn>
std::string RunGuarded(Fn&& fn) noexcept {
    try {
        fn();
        return std::string();
    } catch (const std::exception& e) {
        try {
            std::string m("worker failed: ");
            m += e.what();
            return m;
        } catch (...) {
            return std::string("worker failed: details unavailable");
        }
    } catch (...) {
        return std::string("worker failed: unknown exception");
    }
}

// Write 'utf8Content' to 'path' as a file. Returns empty string on success,
// otherwise a human-readable error message. 'withBom' defaults to true
// (Excel-friendly CSV); pass false for JSON, where a BOM breaks parsers.
std::wstring WriteUtf8FileWithBom(const std::wstring& path,
                                  const std::string& utf8Content,
                                  bool withBom = true);

// Read a whole file as UTF-8 bytes. Returns empty string on success and fills
// 'content'; otherwise a human-readable error message and 'content' is left
// untouched.
//
// The counterpart to WriteUtf8FileWithBom, and deliberately NOT shape-checked
// here: a reader that accepted "any UTF-8 file" is one that will accept a
// bookmark file from the future, so the SIZE bound is enforced by the caller
// that knows its own schema. This only opens, reads and reports.
std::wstring ReadUtf8File(const std::wstring& path, std::string* content);

// Escape one CSV field according to RFC 4180 (quote if it contains , " \r \n).
std::string CsvEscapeUtf8(const std::string& field);

// Format an unsigned short port as a decimal string.
std::wstring FormatPort(UINT port);

// Combine "address" and port into L"address:port".
// IPv6 literals already contain ':' so they are wrapped in [ ] -> L"[::1]:80".
std::wstring JoinEndpoint(const std::wstring& addressLiteral, UINT port, bool isIpv6);

// Human readable byte count: "512 B", "12.3 KB", "4.56 MB", "1.23 GB".
std::wstring FormatBytes(ULONGLONG bytes);

// Case-insensitive substring test where 'haystack' is already lowercase
// (used by the hot filter path; avoids re-lowering per row).
bool HasLowerSubstring(const std::wstring& haystackLower,
                       const std::wstring& needleLower);

// DPI of a window in pixels-per-inch. Uses GetDpiForWindow when
// available (Win10 1607+), otherwise the system DPI. hwnd == nullptr gives
// the system DPI (used before any window exists). Never returns 0.
UINT QueryDpiForWindow(HWND hwnd);

// Show 'path' in Explorer with the file pre-selected. One implementation
// for the context menu and the Details button, which had drifted into two
// spellings of the same action: the menu ran the "explore" verb against a
// FILE path (a folder verb - the shell answers SE_ERR_NOASSOC, so the menu
// item failed while the button worked), while the button runs
// "explorer.exe /select,". Returns true when Explorer was launched;
// otherwise false with 'error' set, and the caller reports it.
bool ShowFileInExplorer(const std::wstring& path, std::wstring* error);

// Expose a plain-text summary as a window's accessible name through
// the Dynamic Annotation API (IAccPropServices), so screen readers and
// UIA agents can read owner-drawn content (Details body, Charts values)
// that no pixel scraping would recover. Best-effort and silent: when the
// annotation service is unavailable the window simply keeps its default
// accessibility behaviour. 'name' is capped internally, so callers pass
// the full text without pre-truncating.
void SetAccessibleName(HWND hwnd, const std::wstring& name);

// ---- did a Win32 string read fit? ---------------------------------------
//
// A family of Win32 calls fills a caller-supplied buffer and signals trouble in
// the RETURN VALUE, never through GetLastError:
//
//   0            the call failed
//   >= capacity  the buffer was too small, and 'buffer' does NOT hold the value
//
// `bufferWasTooSmall` exists because `rc == 0` is the test four call sites were
// using, and it is the wrong one: 0 means failure, and truncation is reported as
// a size. Measured, because the distinction decides whether this helper works:
//
//   GetEnvironmentVariableW  value 15 chars, cap 16 -> rc=15   fits
//                           value 16 chars, cap 16 -> rc=17   required size
//   GetCurrentDirectoryW    fits -> rc = length;  too small -> rc = required
//   GetModuleFileNameW      too small -> rc = capacity exactly
//   GetTempPathW            too small -> rc = required size
//
// So `>=` is right and `== cap` is not: three of the four report a size LARGER
// than the capacity, and only GetModuleFileNameW reports exactly the capacity.
// Using `== cap` would therefore miss the other three.
//
// The measured 15-into-16 row is the one that matters for correctness: a value
// that exactly fills the buffer is NOT flagged, so there is no off-by-one and
// no false refusal at the boundary.
inline bool bufferWasTooSmall(DWORD rc, size_t capacity) {
    return rc == 0 || rc >= capacity;
}

// ---- stdout / stderr writers ----------------------------------------------
//
// The ONE implementation of the byte-stream writers. They used to be
// file-local helpers in CliCommands.cpp, which made Commands.cpp - the shared
// layer both front ends link - depend on a symbol defined in the CLI-only TU:
// StreamOut is declared in Commands.h, called by Commands.cpp's CmdListInto,
// and defined beside the CLI's Emit. The GUI project links Commands.cpp but
// not CliCommands.cpp, so its Release build only survived because /OPT:REF
// discarded the unreferenced TU; the Debug configurations (/OPT:NOREF) failed
// with LNK2019 on wintcp::StreamOut. Moving the writers here makes the shared
// layer self-contained; the CLI keeps its own Emit on top of these.
//
// AcquireStdHandle falls back to CONOUT$ and attaches to the parent console,
// which is what lets a GUI-subsystem process still write to the console it was
// launched from.
HANDLE AcquireStdHandle(DWORD id);
void WriteStream(HANDLE h, const std::string& s);
void WriteOut(const std::string& s);
void WriteErr(const std::string& s);
// StreamOut is declared in Commands.h (the shared header); it is DEFINED here
// with the other writers so Commands.cpp links without the CLI-only TU.
void StreamOut(const std::string& s);

}  // namespace wintcp

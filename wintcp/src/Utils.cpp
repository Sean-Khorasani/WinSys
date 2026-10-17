// Utils.cpp
// SPDX-License-Identifier: Apache-2.0
// Implementations for Utils.h.

#include "Utils.h"

#include <objbase.h>   // CoInitializeEx / CoCreateInstance
// INITGUID before oleacc.h: the CLSID/IID/PROPID this uses are defined in
// this TU, so no oleacc.lib import is needed (and none of the three build
// paths grows a new link dependency for one annotation call). Virtual
// calls need no import; CoCreateInstance/CoInitializeEx are ole32, which
// is already linked (delay-loaded, and gated below at runtime).
#include <initguid.h>
#include <oleacc.h>    // IAccPropServices / PROPID_ACC_NAME
#include <shellapi.h>  // ShellExecuteW (ShowFileInExplorer)

#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <fstream>

#include "Opt.h"
#include "WinCaps.h"   // DllAvailable: ole32/oleacc are delay-loaded

namespace wintcp {

namespace {

// fe80::/10 — the only IPv6 range where a numeric scope id carries meaning
// ("which interface"), and so the only range that prints one. Encoded as a
// first-byte equality plus a top-two-bits mask, matching the test TcpTable's
// PrintIpv6 already used; see Ipv6ScopeSuffix (Utils.h) for why this is one
// function rather than a per-file check.
constexpr unsigned char kLinkLocalFirstByte = 0xFE;
constexpr unsigned char kLinkLocalSecondMask = 0xC0;    // top two bits
constexpr unsigned char kLinkLocalSecondValue = 0x80;   // must be 10xxxxxx

// "%<scope>" plus NUL. A scope id is a ULONG, so ten digits is the widest
// render; the rest is slack. swprintf_s truncates rather than overruns, so an
// unexpectedly wide id cannot corrupt the caller's endpoint string.
constexpr size_t kScopeTextChars = 16;

// DPI used when the system reports none. USER_DEFAULT_SCREEN_DPI - the value
// GetDeviceCaps(LOGPIXELSX) answers on a machine with no DPI virtualisation -
// so a fallback to it is indistinguishable from a real reading on such a
// machine. Same name as FontCache.cpp's copy on purpose.
constexpr unsigned kDefaultScreenDpi = 96;

// Fixed-format text buffers. "%04u-%02u-%02u %02u:%02u:%02u" needs exactly 19
// characters, and "Unknown error %lu (0x%08lX)" fewer than that; 64 covers both
// with room for a longer message-locale spelling of the latter.
constexpr size_t kTimeTextChars = 64;
constexpr size_t kErrorFallbackChars = 64;

// A binary UINT port is at most five digits, so this is slack. Named rather
// than inline because FormatPort is one of the two text bounds in this file and
// the widest case is decided by the port's type, not by the caller.
constexpr size_t kPortTextChars = 16;

// Widest byte-count text: "1023.99 TB" at the top of the ladder plus NUL. One
// bound for the single unit ladder in this file, so FormatBytes and any future
// formatter over it cannot disagree about the widest case.
constexpr size_t kBytesTextChars = 32;

}  // namespace

std::wstring Ipv6ScopeSuffix(const unsigned char raw[16], unsigned scopeId) {
    if (raw == nullptr || scopeId == 0) return std::wstring();
    if (raw[0] != kLinkLocalFirstByte ||
        (raw[1] & kLinkLocalSecondMask) != kLinkLocalSecondValue)
        return std::wstring();
    wchar_t scope[kScopeTextChars] = {0};
    ::swprintf_s(scope, L"%%%u", scopeId);
    return std::wstring(scope);
}

std::wstring FormatSystemError(DWORD errorCode) {
    LPWSTR buffer = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD chars = ::FormatMessageW(flags, nullptr, errorCode,
                                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                   reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring msg;
    if (chars != 0 && buffer != nullptr) {
        msg.assign(buffer, chars);
        // Trim trailing CR/LF/space added by FormatMessage.
        while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' ||
                                msg.back() == L' ' || msg.back() == L'\t' || msg.back() == L'.')) {
            // Keep one trailing period semantics simple: just trim CR/LF/whitespace.
            if (msg.back() == L'.') break;
            msg.pop_back();
        }
    } else {
        wchar_t fallback[kErrorFallbackChars] = {0};
        ::swprintf_s(fallback, L"Unknown error %lu (0x%08lX)",
                     static_cast<unsigned long>(errorCode),
                     static_cast<unsigned long>(errorCode));
        msg = fallback;
    }
    if (buffer != nullptr) {
        ::LocalFree(buffer);
    }
    return msg;
}

std::wstring FormatCurrentTime() {
    SYSTEMTIME st = {};
    ::GetLocalTime(&st);
    wchar_t buf[kTimeTextChars] = {0};
    ::swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
                 static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
                 static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
                 static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond));
    return std::wstring(buf);
}

// Lowercase a wide string.
//
// The body is wintcp::ToLowerWOpt (Opt.cpp), which folds ASCII 8 UTF-16 code
// units at a time with SSE2 and only calls towlower for the units SSE2 cannot
// decide (a unit outside the ASCII/Latin-1 range, or a surrogate half). ASCII
// dominates here - process names, paths, addresses, filter text - and the
// original called towlower once per unit for it.
//
// A/B bench, same source: 1.81x on a 34-char process name, 15.1x on a long
// path, 15.4x on mixed text, 19.2x on a 4k string. The differential sweeps
// pin it against a towlower-per-unit reference over ASCII, Latin-1, surrogate
// halves and unassigned code points, including the empty and one-unit cases.
std::wstring ToLowerW(const std::wstring& s) {
    return ToLowerWOpt(s);
}

bool ContainsCaseInsensitive(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    const std::wstring h = ToLowerW(haystack);
    const std::wstring n = ToLowerW(needle);
    return h.find(n) != std::wstring::npos;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    // 'needed' includes the terminating NUL.
    std::string out(static_cast<size_t>(needed) - 1, '\0');
    int written = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), needed,
                                        nullptr, nullptr);
    if (written <= 0) return std::string();
    // written includes NUL; out already excludes it.
    if (static_cast<size_t>(written - 1) != out.size()) {
        out.resize(static_cast<size_t>(written - 1));
    }
    return out;
}

std::wstring Utf8ToWide(const char* s) {
    if (s == nullptr || *s == '\0') return std::wstring();
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (needed <= 1) return std::wstring();
    std::wstring out(static_cast<size_t>(needed - 1), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), needed) <= 0)
        return std::wstring();
    return out;
}

std::wstring WriteUtf8FileWithBom(const std::wstring& path,
                                  const std::string& utf8Content,
                                  bool withBom) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return FormatSystemError(::GetLastError());
    }
    const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
    DWORD written = 0;
    BOOL ok = TRUE;
    if (withBom) {
        ok = ::WriteFile(h, bom, sizeof(bom), &written, nullptr);
        if (!ok) {
            std::wstring err = FormatSystemError(::GetLastError());
            ::CloseHandle(h);
            return err;
        }
    }
    if (!utf8Content.empty()) {
        size_t offset = 0;
        while (offset < utf8Content.size()) {
            DWORD chunk = static_cast<DWORD>(utf8Content.size() - offset);
            DWORD w = 0;
            ok = ::WriteFile(h, utf8Content.data() + offset, chunk, &w, nullptr);
            if (!ok) {
                std::wstring err = FormatSystemError(::GetLastError());
                ::CloseHandle(h);
                return err;
            }
            if (w == 0) break;
            offset += w;
        }
    }
    ::CloseHandle(h);
    return std::wstring();  // success
}

std::wstring ReadUtf8File(const std::wstring& path, std::string* content) {
    if (content == nullptr) {
        return L"internal error: no output for ReadUtf8File";
    }
    content->clear();

    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return FormatSystemError(::GetLastError());
    }
    LARGE_INTEGER size = {};
    if (!::GetFileSizeEx(h, &size)) {
        std::wstring err = FormatSystemError(::GetLastError());
        ::CloseHandle(h);
        return err;
    }
    if (size.QuadPart < 0) {
        ::CloseHandle(h);
        return L"the file reports a negative size, which is not a file this "
               L"tool can read";
    }
    const size_t total = static_cast<size_t>(size.QuadPart);
    content->resize(total);
    size_t offset = 0;
    while (offset < total) {
        DWORD chunk = static_cast<DWORD>(total - offset);
        DWORD got = 0;
        if (!::ReadFile(h, content->data() + offset, chunk, &got, nullptr)) {
            std::wstring err = FormatSystemError(::GetLastError());
            ::CloseHandle(h);
            content->clear();
            return err;
        }
        if (got == 0) break;   // shorter than advertised: keep what arrived
        offset += got;
    }
    content->resize(offset);
    ::CloseHandle(h);
    return std::wstring();  // success
}

// Escape a field for CSV output: quote it when it contains a delimiter,
// a quote or a newline, and double any quotes inside.
//
// The body is wintcp::CsvEscapeOpt (Opt.cpp). The no-quote fast path is the
// original's find_first_of verbatim, because that is what most fields hit;
// the escaping loop then scans 16 bytes at a time with SSE2 and copies the
// spans between quotes instead of pushing one byte at a time.
//
// Note the clean-block path has to EMIT the 16 bytes it consumes. Skipping
// the append silently drops the first 16 characters of every quoted field
// longer than a block - `list --format csv` rendered "RpcEptMapper, RpcSs"
// as "cSs" because of exactly that. Every test input was under 16 bytes, so
// the SIMD loop never ran and the bench passed 420/420 through the bug; the
// 16/17/32/33-byte and multi-block cases now exist in both test files, along
// with a length x position x special sweep.
std::string CsvEscapeUtf8(const std::string& field) {
    return CsvEscapeOpt(field);
}

// Printable port. Emitted with the digit-table path in Opt.cpp rather than
// swprintf_s, which must parse the format string and run the CRT's own
// integer-to-text on every call. Measured 6.3x (port 443) and 4.1x
// (65535) on the A/B bench, and this is one of the two hottest formatters
// in the tool - JoinEndpoint calls it for every row the view paints.
std::wstring FormatPort(UINT port) {
    wchar_t buf[kPortTextChars] = {0};
    FormatPortOpt(buf, kPortTextChars, port);
    return std::wstring(buf);
}

std::wstring JoinEndpoint(const std::wstring& addressLiteral, UINT port, bool isIpv6) {
    std::wstring out;
    if (isIpv6) {
        out.push_back(L'[');
        out += addressLiteral;
        out.push_back(L']');
    } else {
        out += addressLiteral;
    }
    out.push_back(L':');
    out += FormatPort(port);
    return out;
}

std::wstring FormatBytes(ULONGLONG bytes) {
    const double b = static_cast<double>(bytes);
    wchar_t buf[kBytesTextChars] = {0};
    if (b < kBytesPerKB) {
        ::swprintf_s(buf, L"%llu B", static_cast<unsigned long long>(bytes));
    } else if (b < kBytesPerMB) {
        ::swprintf_s(buf, L"%.1f KB", b / kBytesPerKB);
    } else if (b < kBytesPerGB) {
        ::swprintf_s(buf, L"%.1f MB", b / kBytesPerMB);
    } else if (b < kBytesPerTB) {
        ::swprintf_s(buf, L"%.2f GB", b / kBytesPerGB);
    } else {
        ::swprintf_s(buf, L"%.2f TB", b / kBytesPerTB);
    }
    return std::wstring(buf);
}

bool HasLowerSubstring(const std::wstring& haystackLower,
                       const std::wstring& needleLower) {
    if (needleLower.empty()) return true;
    return haystackLower.find(needleLower) != std::wstring::npos;
}

void SetAccessibleName(HWND hwnd, const std::wstring& name) {
    // The annotation itself. Dynamic Annotation (IAccPropServices)
    // rather than a hand-rolled IAccessible: one property set on the
    // window, and every screen reader picks it up as the accessible
    // name - no object to implement, no WM_GETOBJECT to serve, no state
    // to keep in sync afterwards (the service holds the string).
    if (hwnd == nullptr || name.empty()) return;
    // ole32/oleacc are delay-loaded: on a machine without them there is
    // no annotation service, and the window keeps its default behaviour
    // rather than raising.
    if (!DllAvailable("ole32.dll") || !DllAvailable("oleacc.dll")) return;
    // An accessible NAME is a summary, not the document (Copy gives the
    // whole text). 2048 characters keeps every real summary whole while
    // bounding what the service stores per window.
    constexpr size_t kAccNameMax = 2048;
    std::wstring capped = name.substr(0, kAccNameMax);

    // Per-call COM, the shape BlockConn uses: initialise, create, set,
    // release. RPC_E_CHANGED_MODE means the thread already lives in
    // another apartment - COM is still usable, but this call did not
    // initialise it and must not uninitialise it.
    const HRESULT initHr =
        ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool inited = false;
    if (initHr == RPC_E_CHANGED_MODE) {
        inited = false;
    } else if (FAILED(initHr)) {
        return;
    } else {
        inited = true;
    }
    IAccPropServices* svc = nullptr;
    if (::CoCreateInstance(CLSID_AccPropServices, nullptr,
                           CLSCTX_INPROC_SERVER, IID_IAccPropServices,
                           reinterpret_cast<void**>(&svc)) == S_OK &&
        svc != nullptr) {
        svc->SetHwndPropStr(hwnd, static_cast<DWORD>(OBJID_CLIENT),
                            static_cast<DWORD>(CHILDID_SELF),
                            PROPID_ACC_NAME,
                            const_cast<wchar_t*>(capped.c_str()));
        svc->Release();
    }
    if (inited) ::CoUninitialize();
}

bool ShowFileInExplorer(const std::wstring& path, std::wstring* error) {
    const auto fail = [error](const wchar_t* what) {
        if (error != nullptr) *error = what;
        return false;
    };
    if (path.empty()) return fail(L"there is no file path for this row.");
    // shell32.dll is delay-loaded; without this gate a machine without it
    // raises instead of reporting.
    if (!DllAvailable("shell32.dll"))
        return fail(L"Explorer could not open that location.");
    // "explorer.exe /select," - not the "explore" verb. The verb is
    // registered against folders; run against a FILE path the shell finds
    // no association and answers SE_ERR_NOASSOC, which is the failure the
    // context menu used to report while the Details button worked.
    const std::wstring arg = L"/select,\"" + path + L"\"";
    const HINSTANCE rc = ::ShellExecuteW(
        nullptr, L"open", L"explorer.exe", arg.c_str(), nullptr,
        SW_SHOWNORMAL);
    // ShellExecuteW returns a value > 32 on success; anything else is the
    // failure the caller reports instead of staying silent.
    if (reinterpret_cast<INT_PTR>(rc) <= 32)
        return fail(L"Explorer could not open that location.");
    return true;
}

UINT QueryDpiForWindow(HWND hwnd) {
    if (hwnd != nullptr) {
        // GetDpiForWindow: Win10 1607+; resolve dynamically to keep the
        // Win7 target (_WIN32_WINNT 0x0601) link-compatible.
        using GetDpiForWindow_t = UINT(WINAPI*)(HWND);
        static const GetDpiForWindow_t getDpiForWindow =
            reinterpret_cast<GetDpiForWindow_t>(::GetProcAddress(
                ::GetModuleHandleW(L"user32.dll"), "GetDpiForWindow"));
        if (getDpiForWindow != nullptr) {
            const UINT dpi = getDpiForWindow(hwnd);
            if (dpi != 0) return dpi;
        }
    }
    HDC hdc = ::GetDC(nullptr);
    UINT dpi = kDefaultScreenDpi;
    if (hdc != nullptr) {
        const int caps = ::GetDeviceCaps(hdc, LOGPIXELSX);
        if (caps > 0) dpi = static_cast<UINT>(caps);
        ::ReleaseDC(nullptr, hdc);
    }
    return (dpi == 0) ? kDefaultScreenDpi : dpi;
}

// ---- stdout / stderr writers ----------------------------------------------
// Moved here from CliCommands.cpp; the reason is in Utils.h. Bodies are
// byte-for-byte the originals so the CLI's output behaviour is unchanged.

// Write slice for stdout/stderr. 1 MB is large enough that a redirect to a file
// or pipe is not doing a syscall per line, and small enough that a partial
// write on a slow consumer is retried rather than blocking the loop for long.
constexpr size_t kWriteChunkBytes = 1u << 20;

void WriteStream(HANDLE h, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        const DWORD chunk = static_cast<DWORD>(
            (s.size() - off > kWriteChunkBytes) ? (kWriteChunkBytes)
                                                : (s.size() - off));
        DWORD written = 0;
        if (!::WriteFile(h, s.data() + off, chunk, &written, nullptr) ||
            written == 0)
            return;
        off += written;
    }
}

HANDLE AcquireStdHandle(DWORD id) {
    HANDLE h = ::GetStdHandle(id);
    if (h != nullptr && h != INVALID_HANDLE_VALUE) return h;
    ::AttachConsole(ATTACH_PARENT_PROCESS);
    h = ::GetStdHandle(id);
    if (h != nullptr && h != INVALID_HANDLE_VALUE) return h;
    return ::CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr,
                         OPEN_EXISTING, 0, nullptr);
}

void WriteOut(const std::string& s) {
    HANDLE h = AcquireStdHandle(STD_OUTPUT_HANDLE);
    if (h != nullptr && h != INVALID_HANDLE_VALUE) WriteStream(h, s);
}

void WriteErr(const std::string& s) {
    HANDLE h = AcquireStdHandle(STD_ERROR_HANDLE);
    if (h != nullptr && h != INVALID_HANDLE_VALUE) WriteStream(h, s);
}

// The streaming write a command uses DURING its run, straight to stdout (or
// its redirect), so a table's header lands before the slow enrichment joins
// finish. It lives here rather than beside the CLI's Emit so that Commands.cpp
// - which calls it from CmdListInto and which the GUI links WITHOUT
// CliCommands.cpp - links in every configuration, not only Release.
void StreamOut(const std::string& s) { WriteOut(s); }

}  // namespace wintcp

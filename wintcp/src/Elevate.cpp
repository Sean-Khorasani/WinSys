// Elevate.cpp
// SPDX-License-Identifier: Apache-2.0
// See Elevate.h.

#include "Elevate.h"

#include <shellapi.h>

#include <cstring>
#include <vector>

#include "Utils.h"   // bufferWasTooSmall - the truncation check

namespace wintcp {
namespace {

// Marker switched into the command line by the relaunch. Chosen to be
// something no real user would pass.
constexpr wchar_t kElevatedMarker[] = L"--__wintcp-elevated";

// Paths are read into twice MAX_PATH. A path longer than MAX_PATH is legal on
// modern Windows, and this is the one caller that must never silently truncate
// one: the truncated string is what gets quoted and handed to the shell, so
// elevation would launch the wrong file or fail with an error pointing nowhere
// near the cause. Both the image path and the current directory use it.
constexpr DWORD kPathBufChars = MAX_PATH * 2;

// Slack on top of the rebuilt command line: the marker, its quotes and a
// separator. Rounded well past the few dozen characters they actually cost so
// the reserve never has to be recomputed.
constexpr size_t kCmdLineSlackChars = 64;

// MessageBox body. A path and an error number have to fit, and 256 wide chars
// covers any path worth printing without allocating per failure.
constexpr size_t kMsgBufChars = 256;

// Cached so the answer is computed once per process; it cannot change.
bool g_cachedElevated = false;
bool g_cachedInitialized = false;
bool g_adminMember = false;
bool g_adminMemberInitialized = false;

// Note: the parameter cannot be called "access" - TOKEN_QUERY and friends
// are macros, and a macro that expands inside the parameter list produces
// exactly the broken declaration this used to have.
HANDLE OpenCurrentToken(DWORD access) {
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), access, &token) == FALSE)
        return nullptr;
    return token;
}

}  // namespace

bool IsElevated() {
    if (g_cachedInitialized) return g_cachedElevated;
    g_cachedInitialized = true;

    HANDLE token = OpenCurrentToken(TOKEN_QUERY);
    if (token == nullptr) {
        // No token to inspect: treat as unelevated rather than assuming the
        // best. A wrong "yes" here would mean silently skipping the consent
        // prompt, which is the failure mode that matters.
        g_cachedElevated = false;
        return false;
    }
    TOKEN_ELEVATION el = {};
    DWORD needed = 0;
    const BOOL got =
        ::GetTokenInformation(token, TokenElevation, &el, sizeof(el), &needed);
    ::CloseHandle(token);
    g_cachedElevated = (got != FALSE) && (el.TokenIsElevated != 0);
    return g_cachedElevated;
}

bool IsAdminMember() {
    if (g_adminMemberInitialized) return g_adminMember;
    g_adminMemberInitialized = true;

    // "Can this user elevate?" is answered by the LINKED token, not by
    // IsUserAnAdmin(). On a filtered launch of an admin account the
    // Administrators SID is not enabled in the current token, so
    // IsUserAnAdmin() returns FALSE - yet the user can perfectly well
    // consent to UAC. A linked token existing is precisely the
    // "elevation is possible" signal.
    HANDLE token = OpenCurrentToken(TOKEN_QUERY | TOKEN_DUPLICATE);
    if (token == nullptr) {
        g_adminMember = false;
        return false;
    }
    DWORD needed = 0;
    ::GetTokenInformation(token, TokenLinkedToken, nullptr, 0, &needed);
    if (needed < sizeof(HANDLE)) {
        ::CloseHandle(token);
        g_adminMember = false;
        return false;
    }
    std::vector<BYTE> buf(needed);
    HANDLE linked = nullptr;
    const BOOL got = ::GetTokenInformation(token, TokenLinkedToken, buf.data(),
                                           needed, &needed);
    if (got != FALSE && needed >= sizeof(HANDLE))
        std::memcpy(&linked, buf.data(), sizeof(HANDLE));
    ::CloseHandle(token);

    if (linked != nullptr) {
        g_adminMember = true;
        ::CloseHandle(linked);
    } else {
        g_adminMember = false;
    }
    return g_adminMember;
}

std::wstring ElevationUnavailableReason() {
    if (IsElevated()) return std::wstring();
    if (IsAdminMember()) return std::wstring();

    // A standard account has no linked token and no way to gain one, so the
    // answer is permanent. Distinguishing it from "token introspection
    // failed" matters, because the advice differs: the first is final, the
    // second may be a transient policy artefact.
    HANDLE token = OpenCurrentToken(TOKEN_QUERY);
    if (token == nullptr) {
        return L"Could not inspect this process's security token, so "
               L"elevation cannot be attempted.";
    }
    ::CloseHandle(token);

    return L"This feature needs administrator rights, and this account is not "
           L"a member of the Administrators group.\n\nWinTCP does not need "
           L"elevation for the connection list, Details view, filters or "
           L"export - only for the features that read live packet or TLS "
           L"data.";
}

bool IsElevatedInstance() {
    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (argv == nullptr) return false;
    bool found = false;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr && ::wcscmp(argv[i], kElevatedMarker) == 0) {
            found = true;
            break;
        }
    }
    ::LocalFree(argv);
    return found;
}

bool WasRelaunchedForElevation() { return IsElevatedInstance(); }

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    LUID luid;
    if (!::LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        ::CloseHandle(token);
        return false;
    }
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = ::AdjustTokenPrivileges(token, FALSE, &tp,
                                            sizeof(tp), nullptr, nullptr);
    // AdjustTokenPrivileges returns TRUE even when it granted only some
    // privileges. The documented partial-failure signal is
    // GetLastError() == ERROR_NOT_ALL_ASSIGNED, which we treat as "the token
    // did not carry it" - expected for a standard-user token.
    const bool granted =
        (ok != FALSE && ::GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    ::CloseHandle(token);
    return granted;
}

bool Reelevate(const std::wstring& featureName) {
    if (IsElevated()) return false;            // nothing to do
    if (IsElevatedInstance()) return false;    // already the elevated copy
    if (!IsAdminMember()) return false;        // standard account

    // Rebuild the command line with the marker appended, preserving whatever
    // the user originally passed (including a CLI invocation, which must stay
    // a CLI invocation after the relaunch).
    std::wstring cmd = ::GetCommandLineW();

    // A quoted path is required if the image path contains spaces, which it
    // normally does. Quote it unconditionally - GetCommandLine returns the
    // raw string, and a bare path with spaces would be split into arguments.
    //
    // `== 0` tested for failure; truncation is reported as the CAPACITY, not
    // as 0 (measured: an 8-char buffer for this exe returned 8). So a path
    // longer than MAX_PATH would have been SILENTLY TRUNCATED, and that
    // truncated string is what gets quoted into the command line below - so
    // elevation would have launched the wrong file, or failed with an error
    // that points nowhere near the real cause. Refusing is the right answer: the
    // caller reports the refusal rather than elevating to a partial path.
    wchar_t exePath[kPathBufChars] = {0};
    const DWORD exeLen = ::GetModuleFileNameW(nullptr, exePath, kPathBufChars);
    if (bufferWasTooSmall(exeLen, kPathBufChars)) return false;

    std::wstring newCmd;
    newCmd.reserve(cmd.size() + kPathBufChars + kCmdLineSlackChars);
    newCmd += L"\"";
    newCmd += exePath;
    newCmd += L"\"";
    // Carry over the original arguments (skip argv[0]).
    int argc = 0;
    LPWSTR* argv = ::CommandLineToArgvW(cmd.c_str(), &argc);
    if (argv != nullptr) {
        for (int i = 1; i < argc; ++i) {
            newCmd += L" \"";
            newCmd += argv[i];
            newCmd += L"\"";
        }
        ::LocalFree(argv);
    }
    newCmd += L" \"";
    newCmd += kElevatedMarker;
    newCmd += L"\"";

    // Same defect as the image path above. GetCurrentDirectoryW reports a
    // too-small buffer as the REQUIRED size (measured: 14 for an 8-char
    // buffer), so `== 0` passed and 'dir' was left empty - and an empty lpCurrentDirectory
    // tells the elevated child to start wherever the shell feels like.
    wchar_t dir[kPathBufChars] = {0};
    const DWORD dirLen = ::GetCurrentDirectoryW(kPathBufChars, dir);
    if (bufferWasTooSmall(dirLen, kPathBufChars)) dir[0] = L'\0';

    // "runas" is what makes UAC prompt. Returns FALSE with
    // ERROR_CANCELLED when the user clicks No - which must NOT be treated as
    // an error, just as "the user declined".
    //
    // Use ShellExecuteExW, NOT CreateProcessW. CreateProcessW has no concept of
    // a verb: it starts the child at the caller's token level, so the call
    // that was SUPPOSED to trigger a UAC prompt silently relaunched the same
    // unprivileged process - the old comment above even described "runas"
    // behaviour that the code below did not implement. ShellExecuteExW routes
    // through the shell, which is what actually honours the verb.
    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;   // wchar_t[MAX_PATH] decays to LPWSTR
    // newCmd already holds the full quoted command line:
    //   "<exePath>" "arg1" ... "marker"
    // lpParameters is the part AFTER the leading quoted path and one space.
    std::wstring params = newCmd.substr(wcslen(exePath) + 3);
    sei.lpParameters = params.c_str();
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpDirectory = dir;   // keep the caller's cwd for the elevated process

    const BOOL ok = ::ShellExecuteExW(&sei);
    if (ok == FALSE) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_CANCELLED) {
            ::MessageBoxW(nullptr,
                          L"Administrator permission was declined, so this "
                          L"feature is unavailable.\n\nThe rest of WinTCP "
                          L"works without it.",
                          L"WinTCP", MB_OK | MB_ICONINFORMATION);
        } else {
            wchar_t msg[kMsgBufChars] = {0};
            ::swprintf_s(msg,
                         L"Could not start an elevated copy of WinTCP for "
                         L"'%ls' (error %lu).",
                         featureName.c_str(), static_cast<unsigned long>(err));
            ::MessageBoxW(nullptr, msg, L"WinTCP", MB_OK | MB_ICONERROR);
        }
        return false;
    }
    // ShellExecuteExW with SEE_MASK_NOCLOSEPROCESS gives us a process handle,
    // unlike CreateProcessW which returned PROCESS_INFORMATION. The thread
    // handle is always null; only the process handle needs closing.
    if (sei.hProcess != nullptr) ::CloseHandle(sei.hProcess);
    (void)featureName;
    return true;
}

}  // namespace wintcp

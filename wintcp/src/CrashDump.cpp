// CrashDump.cpp
// SPDX-License-Identifier: Apache-2.0
// See CrashDump.h.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include "CrashDump.h"

#include "WinCaps.h"   // DllAvailable: shell32.dll is delay-loaded

#include <windows.h>
#include <dbghelp.h>   // MINIDUMP_* types only; the DLL is loaded dynamically
#include <shlobj.h>    // SHGetFolderPathW (shell32.lib, already linked)
#include <stdio.h>

namespace wintcp {
namespace {

// At most this many dumps are kept (plus the one just written). A crash loop
// must not fill a disk: each crash past the cap deletes the single oldest, so
// the directory converges at ~11 x a few hundred KB. Filenames embed UTC
// time, so lexicographic order IS chronological order and no timestamps need
// parsing.
constexpr int kMaxCrashDumps = 10;

// Every path the crash handler formats goes into a buffer of twice MAX_PATH.
// Same reasoning Elevate.cpp gives for the same width: a truncated path points
// at a file that does not exist, and here there is no second attempt. The
// filter cannot heap-allocate, so the width is one fixed constant rather than
// something computed from the path.
constexpr size_t kCrashPathChars = MAX_PATH * 2;

// Prose added around a path. The breadcrumb line needs room for its fixed
// wording; the stderr line needs a few more for the exception clause.
constexpr size_t kCrashNoteSlackChars = 64;
constexpr size_t kCrashMsgSlackChars = 128;

// "YYYY-MM-DD HH:MM:SSZ" is 20 characters, so this is slack. The filter must
// not depend on a locale to format a timestamp it is about to lose.
constexpr size_t kCrashStampChars = 64;

// "no minidump (<reason>)" plus NUL: the reason is one of six fixed strings,
// and none is longer than a short sentence.
constexpr size_t kCrashWhyChars = 256;

// g_crashDir is resolved ONCE at startup (InstallCrashHandler). The crash
// filter must NOT call the heap-allocating path that used to build this on
// every crash: after STATUS_HEAP_CORRUPTION or exhaustion, the very act of
// allocating can fault again and lose the dump. A plain null-terminated
// static buffer sidesteps that entirely.
wchar_t g_crashDir[kCrashPathChars] = {0};

std::wstring ResolveCrashDir() {
    // shell32.dll is delay-loaded, and this runs at startup - a DllAvailable
    // gate is still required for the same reason CrashDumpDir() documents
    // above, but here, on a healthy thread, allocation is fine.
    if (!DllAvailable("shell32.dll")) return std::wstring();

    wchar_t appdata[MAX_PATH] = {0};
    if (::SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr,
                           SHGFP_TYPE_CURRENT, appdata) != S_OK ||
        appdata[0] == L'\0')
        return std::wstring();
    std::wstring dir(appdata);
    dir += L"\\WinTCP\\crashes";
    return dir;
}

void EnsureDir(const wchar_t* dir) {
    // CreateDirectory fails when the directory exists; that is the common
    // case, not an error. Create the parent first - one call cannot make two
    // levels, and checking existence first would race a concurrent run.
    //
    // Stack-only path arithmetic: the previous form used std::wstring::substr,
    // which heap-allocates. EnsureDir is called from inside the crash filter,
    // where allocation is precisely what can fail.
    if (dir == nullptr || dir[0] == L'\0') return;
    const wchar_t* sep = ::wcsrchr(dir, L'\\');
    if (sep != nullptr && sep != dir) {
        wchar_t parent[MAX_PATH] = {0};
        const size_t n = static_cast<size_t>(sep - dir);
        if (n < sizeof(parent) / sizeof(parent[0])) {
            ::wcsncpy_s(parent, dir, n);
            ::CreateDirectoryW(parent, nullptr);
        }
    }
    ::CreateDirectoryW(dir, nullptr);
}

// Delete the single oldest dump when past the cap. One deletion per crash
// keeps the directory bounded at kMaxCrashDumps+1 without ever enumerating
// into a list: the whole function uses one stack buffer, no heap, no vector,
// because it runs inside the crash handler where allocation is suspect.
// Only our own "wintcp-*.dmp" names are managed; foreign files are left alone.
// Best-effort throughout: any failure leaves the new dump in place, because
// pruning must never endanger the artefact it was asked to make room for.
void PruneOldDumps(const wchar_t* dir) {
    wchar_t pattern[kCrashPathChars] = {0};
    ::swprintf_s(pattern, L"%ls\\wintcp-*.dmp", dir);
    WIN32_FIND_DATAW fd = {};
    const HANDLE h = ::FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    int count = 0;
    wchar_t oldest[MAX_PATH] = {0};
    do {
        // FindFirstFile returns names in filesystem order, not sorted, so the
        // oldest is found by comparison: our names embed UTC time, which means
        // lexicographic order IS chronological order and no timestamps need
        // parsing. wcscmp on untrusted names is safe: all are NUL-terminated
        // by the API contract.
        if (count == 0 || ::wcscmp(fd.cFileName, oldest) < 0) {
            ::wcsncpy_s(oldest, fd.cFileName, _TRUNCATE);
        }
        ++count;
    } while (::FindNextFileW(h, &fd) != FALSE);
    ::FindClose(h);
    if (count > kMaxCrashDumps && oldest[0] != L'\0') {
        wchar_t victim[kCrashPathChars] = {0};
        ::swprintf_s(victim, L"%ls\\%ls", dir, oldest);
        ::DeleteFileW(victim);
    }
}

// Wide path -> ASCII, one unit at a time, because this runs inside the crash
// filter: no CRT locale, no heap, and a path holding non-ASCII is better shown
// as '?' than not shown at all.
void Narrow(const wchar_t* in, char* out, size_t cap) {
    if (out == nullptr || cap == 0) return;
    size_t i = 0;
    for (; i + 1 < cap && in != nullptr && in[i] != L'\0'; ++i) {
        out[i] = (in[i] < 128) ? static_cast<char>(in[i]) : '?';
    }
    out[i] = '\0';
}

// The on-disk breadcrumb, written into the same directory as the dumps. stderr
// is not always there - a GUI launch, a detached process, a handle nobody
// reads - and the dump itself is exactly the thing that can fail, so the proof
// that the handler ran has to live where the next person will already be
// looking: the crashes folder. It is also the only record that survives a
// filter that dies part-way, which is what heap corruption does.
//
// Called TWICE per crash: once before the dump attempt with a progress line,
// once after with the outcome. If the second write never happens, the first
// one is still on disk and still says the handler ran and how far it got.
//
// 'what' selects the second line: nullptr means the dump was written and the
// path is printed; a non-null string is the whole clause, printed as-is (with
// the path appended while there is progress to name it).
void WriteCrashNote(const wchar_t* dir, const wchar_t* stamp, DWORD code,
                    const wchar_t* dumpPath, const char* what) {
    wchar_t note[kCrashPathChars] = {0};
    ::swprintf_s(note, L"%ls\\wintcp-last-crash.txt", dir);

    char line2[kCrashPathChars + kCrashNoteSlackChars] = {0};
    if (what == nullptr && dumpPath != nullptr) {
        char narrow[kCrashPathChars] = {0};
        Narrow(dumpPath, narrow, sizeof(narrow));
        ::sprintf_s(line2, "handler ran; minidump: %s", narrow);
    } else if (what != nullptr && dumpPath != nullptr) {
        char narrow[kCrashPathChars] = {0};
        Narrow(dumpPath, narrow, sizeof(narrow));
        ::sprintf_s(line2, "handler ran; %s %s", what, narrow);
    } else {
        ::sprintf_s(line2, "handler ran; %s", (what != nullptr) ? what : "");
    }

    char text[kCrashPathChars + kCrashWhyChars] = {0};
    ::sprintf_s(text, "wintcp crashed at %ls UTC; exception 0x%08lX\r\n%s\r\n",
                stamp, static_cast<unsigned long>(code), line2);

    HANDLE f = ::CreateFileW(note, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD put = 0;
        ::WriteFile(f, text, static_cast<DWORD>(::strlen(text)), &put, nullptr);
        ::CloseHandle(f);
    }
}

// Everything below runs INSIDE the crashing process on the crashing thread,
// so it follows crash-handler discipline: stack buffers only, no heap, no
// locks, no CRT locale calls, and every API failure falls through to the next
// step rather than aborting. A half-written dump with a breadcrumb is worth
// more than a perfect dump that never got written because step two failed.
LONG WINAPI CrashFilter(EXCEPTION_POINTERS* xp) {
    const DWORD code = (xp != nullptr && xp->ExceptionRecord != nullptr)
                           ? xp->ExceptionRecord->ExceptionCode
                           : 0xC0000005u;
    wchar_t path[kCrashPathChars] = {0};
    wchar_t stamp[kCrashStampChars] = {0};
    bool dumped = false;
    // Why there is no dump - named precisely rather than as one catch-all.
    // Every failure used to report "dump directory unavailable", so a missing
    // dbghelp.dll or a refused write pointed the reader at a directory that
    // was perfectly healthy, and the one case the message existed for (a truly
    // unresolvable folder) was indistinguishable from two others.
    const char* why = "dump directory unavailable";

    if (g_crashDir[0] != L'\0') {
        EnsureDir(g_crashDir);
        SYSTEMTIME st = {};
        ::GetSystemTime(&st);
        ::swprintf_s(path, L"%ls\\wintcp-%04u%02u%02u-%02u%02u%02u-%lu.dmp",
                     g_crashDir, st.wYear, st.wMonth, st.wDay, st.wHour,
                     st.wMinute, st.wSecond,
                     static_cast<unsigned long>(::GetCurrentProcessId()));
        ::swprintf_s(stamp, L"%04u-%02u-%02u %02u:%02u:%02uZ",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                     st.wSecond);
        // Before anything else, the record that the handler ran. Everything
        // below this line can fail, fault or be skipped; this is the one write
        // that has to come first, because a crash that loses its artefact
        // halfway through is precisely the case nobody can otherwise tell from
        // a program that simply exited.
        WriteCrashNote(g_crashDir, stamp, code, path, "writing minidump");

        // dbghelp is loaded dynamically, not linked: a missing DLL must degrade
        // to "breadcrumb only" rather than fail the whole filter at load time.
        HMODULE dbg = ::LoadLibraryW(L"dbghelp.dll");
        if (dbg == nullptr) {
            why = "dbghelp.dll could not be loaded";
        } else {
            typedef BOOL(WINAPI* MiniDumpWriteDump_t)(
                HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                const PMINIDUMP_EXCEPTION_INFORMATION,
                const PMINIDUMP_USER_STREAM_INFORMATION,
                const PMINIDUMP_CALLBACK_INFORMATION);
            auto dump = reinterpret_cast<MiniDumpWriteDump_t>(
                ::GetProcAddress(dbg, "MiniDumpWriteDump"));
            if (dump == nullptr) {
                why = "MiniDumpWriteDump is not exported";
            } else {
                HANDLE f = ::CreateFileW(
                    path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
                if (f == INVALID_HANDLE_VALUE) {
                    why = "cannot create the dump file";
                } else {
                    MINIDUMP_EXCEPTION_INFORMATION info = {};
                    info.ThreadId = ::GetCurrentThreadId();
                    info.ExceptionPointers = xp;
                    info.ClientPointers = FALSE;
                    dumped = dump(::GetCurrentProcess(),
                                  ::GetCurrentProcessId(), f, MiniDumpNormal,
                                  &info, nullptr, nullptr) != FALSE;
                    ::CloseHandle(f);
                    if (!dumped) {
                        why = "MiniDumpWriteDump failed";
                        ::DeleteFileW(path);   // no partial artefacts
                    }
                }
            }
            ::FreeLibrary(dbg);
        }
        if (dumped) PruneOldDumps(g_crashDir);
        // Then the outcome. When this second write is the one that never
        // happens, the first is still on disk and still says the handler ran
        // and how far it got.
        if (dumped) {
            WriteCrashNote(g_crashDir, stamp, code, path, nullptr);
        } else {
            char noDump[kCrashWhyChars] = {0};
            ::sprintf_s(noDump, "no minidump (%s)", why);
            WriteCrashNote(g_crashDir, stamp, code, nullptr, noDump);
        }
    }
    // The breadcrumb names the dump when there is one and says precisely why
    // not when there is not. stderr, not stdout: a crash report is
    // diagnostics, never data, and a pipeline parsing stdout
    // must not receive it.
    char msg[kCrashPathChars + kCrashMsgSlackChars] = {0};
    if (dumped) {
        char narrow[kCrashPathChars] = {0};
        Narrow(path, narrow, sizeof(narrow));
        ::sprintf_s(msg, "fatal: unhandled exception 0x%08lX; minidump: %s\r\n",
                    code, narrow);
    } else {
        ::sprintf_s(msg,
                    "fatal: unhandled exception 0x%08lX; no minidump (%s)\r\n",
                    code, why);
    }
    const HANDLE err = ::GetStdHandle(STD_ERROR_HANDLE);
    if (err != nullptr && err != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ::WriteFile(err, msg,
                    static_cast<DWORD>(strlen(msg)), &written, nullptr);
    }
    ::OutputDebugStringA(msg);
    // Let the system terminate the process. Returning EXECUTE_HANDLER here
    // (rather than CONTINUE_SEARCH into WER) keeps the exit prompt: the dump
    // is already on disk and a WER dialog adds nothing but a hang for scripts.
    return EXCEPTION_EXECUTE_HANDLER;
}

}  // namespace

std::wstring CrashDumpDir() {
    return std::wstring(g_crashDir);
}

void CrashForTest() {
    // Volatile through a function boundary so no optimizer may prove the null
    // dereference and delete it (which /O2 will do to a locally-obvious null
    // write). A genuine AV, not abort() or throw: those travel CRT paths that
    // may or may not reach the SEH filter, while an AV always does.
    static volatile int* const p = nullptr;
    *p = 1;
    // Unreachable, but a [[noreturn]] that returns is itself UB if ever
    // reached (e.g. under a hypervisor that maps page zero). Terminate loudly
    // rather than fall off the end.
    ::TerminateProcess(::GetCurrentProcess(), 0xC0000409u);
}

void InstallCrashHandler() {
    static bool installed = false;   // idempotent: main + harness share it
    if (installed) return;
    installed = true;
    // Resolve the dump directory NOW, on a healthy thread, before the handler
    // is needed. CrashFilter cannot afford to build it: that path used to
    // allocate (std::wstring), which is exactly what is unsafe after a heap
    // failure. See the g_crashDir comment above.
    const std::wstring dir = ResolveCrashDir();
    if (dir.size() < sizeof(g_crashDir) / sizeof(g_crashDir[0])) {
        ::wcscpy_s(g_crashDir, dir.c_str());
    }
    ::SetUnhandledExceptionFilter(&CrashFilter);
}

}  // namespace wintcp

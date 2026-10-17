// WinCaps.cpp
// SPDX-License-Identifier: Apache-2.0
// See WinCaps.h.
//
// The libraries probed here, and WHY each one is a candidate at all:
//
//   crypt32.dll  Certificate subject/issuer for the TLS column. Genuinely
//                optional: it is absent from Nano Server and from some
//                container base images. NOTE the TLS column has no producer at
//                all today (see Connection.h), so nothing currently needs
//                crypt32 either; the probe is kept because the column is real
//                and this is the one dependency it would need beyond ws2_32.
//   pdh.dll      Disk read/write rates. Present since NT4, but the PhysicalDisk
//                counters are a DISMISSIBLE optional component ("Performance
//                Counters" in the Windows Features dialog) and are genuinely
//                off on stripped images - which is a different failure from a
//                missing DLL, and the report distinguishes them.
//   user32.dll   DPI awareness. GetDpiForWindow is Win10 1607+; Utils.cpp
//                already resolves it dynamically. Reported so a user on an
//                older build learns the window is unscaled rather than broken.
//   iphlpapi.dll MANDATORY - it owns GetExtendedTcpTable, which is how the app
//                enumerates connections at all. Probed only so that its
//                absence is reported as a hard error with an explanation
//                instead of an access violation at startup. Never delay-loaded.
//
// What is NOT here, deliberately: KERNEL32, USER32/GDI32's core, ADVAPI32
// (the registry IS the settings store), SHELL32, COMDLG32, COMCTL32, ole32,
// OLEAUT32 and ws2_32. All have shipped in every Windows SKU since XP
// including Server Core, and delay-loading them would buy no portability while
// costing a SEH-based failure mode at every call site - see the size notes
// section 7.3 for why "absent on some Windows" is not, for these, true.

#include "WinCaps.h"

#include "Utils.h"   // Utf8ToWide for the user-facing capability names
#include "StreamCapture.h"   // CaptureToolsPresent, for the capture row

#include <pdh.h>

namespace wintcp {
namespace {

// LoadLibrary used strictly as a PROBE of whether an optional system library
// is usable.
//
// WHY THE ERROR MODE IS SAVED AROUND IT: a DLL that exists but is not a valid
// image - a zero-byte file left beside the exe, a truncated download, bit-rot
// on an old install - does not make LoadLibraryA return NULL quietly. The
// loader raises the hard error STATUS_INVALID_IMAGE_FORMAT (0xC0000020) and
// the default handler puts a modal "Bad Image" message box on the desktop,
// naming the DLL. That box is modal, it is not about the feature being probed,
// and it fires every time a probe runs - so a diagnostic tool that is doing its
// job of reporting "this library is unusable" instead interrupts the user.
//
// SEM_FAILCRITICALERRORS is what suppresses it; SEM_NOOPENFILEERRORBOX
// covers the neighbouring open-failure path. The previous mode is OR-ed in
// rather than replaced, so flags another part of the process set are not
// dropped for the duration, and the original is restored on return. The mode
// is process-wide, so this is brief by construction: one LoadLibraryA and
// straight back. Nothing here changes what the probe RETURNS - LoadLibraryA
// still fails on a bad image, and the caller still sees "absent".
//
// Deliberately NOT LoadLibraryEx with LOAD_LIBRARY_SEARCH_* flags: those need
// a KB2533623 on Win7 and would themselves become the compatibility problem
// this file exists to avoid.
HMODULE ProbeLoadLibrary(const char* name) {
    // Capture the caller's mode, then OR our flags in rather than overwrite:
    // SetErrorMode REPLACES the whole mode, so setting only ours would silently
    // drop a flag another part of the process had already set (SEM_NOGPFAULT-
    // ERRORBOX, for instance) for the length of this call.
    const UINT saved = ::SetErrorMode(0);
    ::SetErrorMode(saved | SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    const HMODULE m = ::LoadLibraryA(name);
    ::SetErrorMode(saved);
    return m;
}

// Is a DLL loadable at all?
bool DllPresent(const char* name) {
    const HMODULE m = ProbeLoadLibrary(name);
    if (m == nullptr) return false;
    // FreeLibrary balances the LoadLibrary. The first version of this helper
    // dropped the handle, which is a leak of one reference per probe - the
    // same defect I fixed in DllAvailable above, and the same audit caught it:
    // it proves the bug is a *pattern*, not an isolated line. Probes run at
    // most once per process (WinCapabilities caches the result), so impact is
    // small - but the shape belongs in exactly one place and this is it.
    ::FreeLibrary(m);
    return true;
}

// Is a specific entry point present in an already-loaded DLL? Used where the
// API is version-gated inside a DLL that is certainly there (DPI), which is a
// different failure from the DLL being absent and needs a different message.
bool ProcPresent(const char* dll, const char* proc) {
    const HMODULE m = ::GetModuleHandleA(dll);
    if (m == nullptr) return false;
    return ::GetProcAddress(m, proc) != nullptr;
}

// One PDH query, asked and immediately dropped. The point is to distinguish
// "the DLL is missing" from "the counters are switched off", which both present
// as an empty disk panel and have opposite remedies.
CapState ProbePdh(std::wstring* detail) {
    if (!DllPresent("pdh.dll")) {
        *detail = L"pdh.dll is not present on this system";
        return CapState::Missing;
    }
    HQUERY q = nullptr;
    if (::PdhOpenQueryW(nullptr, 0, &q) != ERROR_SUCCESS) {
        *detail =
            L"the performance counters are not available (they are an "
            L"optional Windows feature and can be switched off)";
        return CapState::Unavailable;
    }
    HCOUNTER c = nullptr;
    const bool added =
        ::PdhAddEnglishCounterW(q, L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                                0, &c) == ERROR_SUCCESS;
    if (c != nullptr) ::PdhCloseQuery(c);
    ::PdhCloseQuery(q);
    if (!added) {
        *detail =
            L"the PhysicalDisk performance counters are not installed "
            L"(Windows Features > Performance Counters)";
        return CapState::Unavailable;
    }
    return CapState::Available;
}

// The set of libraries this build delay-loads, and therefore the set whose
// call sites must gate themselves with DllAvailable() before the first call.
//
// THIS LIST AND THE /DELAYLOAD FLAGS MUST AGREE. Nothing at compile time
// enforces it, so the failure mode is a crash on a machine that lacks one of
// these - the exact outcome the whole exercise exists to prevent. The three
// build definitions (the project build, CMakeLists.txt, wintcp.vcxproj) each carry the
// list; this table is the single place that says what the list should BE, and
// the selftest checks each entry resolves or is legitimately absent, so a
// library that disappears from Windows entirely is discovered rather than
// assumed.
//
// What stays EAGER, and why - this is the "Win32 basics" line:
//
//   KERNEL32  process, files, modules, threads, the loader itself
//   USER32    the window, every message, every dialog
//   GDI32     painting: brushes, DCs, DrawText
//   COMCTL32  the listview the connection table IS
//   ADVAPI32  the registry, which is the settings store (HKCU\Software\WinTCP)
//   IPHLPAPI  owns GetExtendedTcpTable - how the app lists connections at all
//   WS2_32    sockets, and the DNS the resolver needs
//
// All seven have shipped in every Windows SKU since XP, including Server Core
// and Nano Server. Delay-loading them would buy no portability whatsoever while
// adding a gate to every call site in the GUI - so the line is drawn at
// "needed to draw a window or read the table", not at "technically optional".
struct DelayedDll {
    const char* name;
    const char* usedFor;   // for the report; never shown raw to a user
};

// Ordered as they appear in the build files, so a diff between this and a
// /DELAYLOAD list is readable.
//
// 'usedFor' is the user-facing feature name and is CAPITALISED, like every
// other line in the report. It began lowercase, and a report whose rows read
// "Administrator", "GeoIP database", "disk read/write rates" looks like two
// different tools wrote it - which undercuts the point of having one report.
constexpr DelayedDll kDelayedDlls[] = {
    {"comdlg32.dll", "Open/Save file dialogs"},
    {"crypt32.dll",  "TLS certificate subject and issuer"},
    {"ole32.dll",    "Windows Firewall rules (COM)"},
    {"oleaut32.dll", "Windows Firewall rules (COM automation types)"},
    {"pdh.dll",      "Disk read/write rates"},
    {"shell32.dll",  "Tray icon and opening a file location"},
};

// psapi.dll IS NOT IN THIS TABLE, and that is a measured fact rather than an
// oversight. `psapi.lib` is in the link line and `ProcessInfo.cpp` /
// `ProcStats.cpp` really do call `GetModuleBaseNameW` and
// `GetProcessMemoryInfo`, so it reads like a dependency - this table listed it
// for a while, and it was wrong. On this SDK `psapi.h` `#define`s both names to
// `K32GetModuleBaseNameW` and `K32GetProcessMemoryInfo`, which KERNEL32
// exports directly:
//
//     dumpbin /imports build\wintcp.exe  ->  K32GetModuleBaseNameW
//                                             K32GetProcessMemoryInfo
//
// psapi.dll never appears in the import table - not before this work, not
// after, and not in the 13-import baseline it was derived from. Listing it
// cost three things: a `LNK4199: /DELAYLOAD:psapi.dll ignored; no imports
// found` warning on two of three build paths, a capability row describing a
// dependency that does not exist, and two `DllAvailable("psapi.dll")` gates
// paying a LoadLibrary to ask about a library the process was never going to
// load.
//
// The lesson, kept because it will recur with any Windows import library:
// **which DLL a call resolves to is a property of the headers, not of the .lib
// you linked.** Verify with `dumpbin /imports` before writing a dependency
// down. The link line is not evidence of anything.

constexpr int kDelayedDllCount =
    static_cast<int>(sizeof(kDelayedDlls) / sizeof(kDelayedDlls[0]));

// Does a dedicated probe below already answer for this library? Those probes
// are strictly better - they can tell a missing library from a disabled
// counter, and they carry the remedy - so the generic loop must not add a
// second, blunter line for the same library.
//
//   crypt32.dll  -> "TLS certificate subject and issuer"
//   pdh.dll      -> "Disk read/write rates" (three-way probe)
//   oleaut32.dll -> covered by the ole32.dll entry, because the two provide one
//                   feature between them. Two lines saying the same thing for
//                   one firewall capability is the duplicate-row defect again.
bool HasDedicatedProbe(const char* dllName) {
    return std::strcmp(dllName, "crypt32.dll") == 0 ||
           std::strcmp(dllName, "pdh.dll") == 0 ||
           std::strcmp(dllName, "oleaut32.dll") == 0;
}

std::vector<Capability> BuildCapabilities() {
    std::vector<Capability> caps;

    // --- stream capture (pktmon + etl2pcap) ---
    {
        Capability c;
        c.what = L"Stream capture (pktmon)";
        c.install = L"";   // nothing to install; it is a SKU difference
        // Registered here so `about` and `stat` can answer "can this machine
        // capture a stream?" without the caller having to know that the answer
        // needs TWO exes. CaptureAvailable() owns the real probe and the
        // elevation half; this row reports the tool half only, because a
        // capability row that said "unavailable: run as administrator" for
        // every standard user would be noise - that is a permission, not a
        // missing capability, and CapState::Unavailable is not what a report
        // of "what this machine can do" wants to say.
        std::wstring why;
        c.state = CaptureToolsPresent(&why) ? CapState::Available
                                            : CapState::Missing;
        if (c.state == CapState::Missing) c.detail = why;
        caps.push_back(c);
    }

    // --- disk counters (pdh) ---
    {
        Capability c;
        c.what = L"Disk read/write rates";
        c.install = L"Windows Features > Performance Counters";
        c.state = ProbePdh(&c.detail);
        caps.push_back(c);
    }

    // --- TLS certificate details (crypt32) ---
    {
        Capability c;
        c.what = L"TLS certificate subject and issuer";
        c.detail = L"crypt32.dll is not present on this system";
        c.install = L"";   // no user-facing remedy; it is a SKU difference
        c.state = DllPresent("crypt32.dll") ? CapState::Available
                                             : CapState::Missing;
        caps.push_back(c);
    }

    // --- per-monitor DPI (user32, Win10 1607+) ---
    {
        Capability c;
        c.what = L"Per-monitor DPI scaling";
        c.detail =
            L"GetDpiForWindow needs Windows 10 1607 or newer; the window is "
            L"being scaled for 96 DPI instead";
        c.install = L"";   // the remedy is a newer Windows, not a package
        c.state = ProcPresent("user32.dll", "GetDpiForWindow")
                      ? CapState::Available
                      : CapState::Missing;
        caps.push_back(c);
    }

    // --- the mandatory one, reported rather than assumed ---
    {
        Capability c;
        c.what = L"Connection enumeration";
        c.detail =
            L"iphlpapi.dll is not present, so WinTCP cannot list "
            L"connections; this is required, not optional";
        c.install = L"";
        c.state = DllPresent("iphlpapi.dll") ? CapState::Available
                                             : CapState::Missing;
        caps.push_back(c);
    }

    // --- the delay-loaded libraries, each as its own capability ---
    //
    // One entry per delay-loaded DLL, carrying the user-facing consequence of
    // its absence. This is the list that makes /DELAYLOAD safe to read: a
    // maintainer can see, in one place, exactly which libraries may be missing
    // and what stops working when they are - rather than having to derive it
    // from the linker flags plus a mental map of the call sites.
    //
    // SKIP anything a dedicated probe above already covered. The first version
    // did not, and the report then listed pdh.dll TWICE on a machine with the
    // counters off - once with the actionable remedy ("Windows Features >
    // Performance Counters") and once as a generic "the library that provides
    // this is not present". Two lines for one library, the second strictly less
    // useful than the first, is how a user learns to distrust the report. The
    // dedicated probe stays authoritative because it can distinguish
    // absent-DLL from counters-disabled; the generic entry cannot.
    //
    // Matched BY NAME, not by a hand-aligned parallel array: an array indexed in
    // lockstep with kDelayedDlls silently misaligns the moment someone reorders
    // that table, and the symptom would be a duplicated or missing capability
    // line rather than a compile error. A name comparison cannot drift that way.
    for (int i = 0; i < kDelayedDllCount; ++i) {
        if (HasDedicatedProbe(kDelayedDlls[i].name)) continue;
        Capability c;
        c.what = Utf8ToWide(kDelayedDlls[i].usedFor);
        if (DllAvailable(kDelayedDlls[i].name)) {
            c.state = CapState::Available;
        } else {
            c.state = CapState::Missing;
            c.detail = L"the library that provides this is not present on "
                       L"this system; the feature is disabled rather than "
                       L"failing";
            // No remedy is named, and that is deliberate: every library on this
            // list is part of Windows itself, so there is nothing for a user
            // to install. Naming a package that would not help is worse than
            // saying nothing - see the caps.no-remedy-names-a-dll selftest and
            // the note on CapState above.
            c.install = L"";
        }
        caps.push_back(c);
    }

    return caps;
}

// The user-facing name for a delay-loaded library, e.g. "the Open/Save file
// dialogs" for comdlg32.dll. Returns an empty string for a library that is not
// in kDelayedDlls - which is itself a defect worth reporting loudly rather than
// papering over with a fallback, so DelayLoadGuard below does exactly that.
//
// Returns by VALUE, deliberately: the first version returned `const wchar_t*`
// into a temporary std::wstring's c_str(), which is a use-after-free the
// moment the full expression ends. Call sites here hold the result across
// several concatenations, so the bug would have been live, not theoretical.
std::wstring DelayedDllFeature(const char* dllName) {
    for (int i = 0; i < kDelayedDllCount; ++i) {
        if (std::strcmp(kDelayedDlls[i].name, dllName) == 0) {
            return Utf8ToWide(kDelayedDlls[i].usedFor);
        }
    }
    return std::wstring();
}

}  // namespace

bool DllAvailable(const char* dllName) {
    if (dllName == nullptr || dllName[0] == L'\0') return false;

    // CACHE, AND DO NOT HOLD A REFERENCE.
    //
    // The first version called LoadLibraryA and dropped the handle, which
    // increments the module's reference count and never decrements it. SysStats
    // asks this question on every refresh tick whenever the PDH query could
    // not be opened - so on a machine with the counters switched off, a tool
    // left running overnight leaked one pdh.dll reference per tick. That is
    // invisible for hours and then shows up as a mysterious handle exhaustion
    // in an unrelated part of the process. The answer cannot change while the
    // process runs (a DLL that failed to load will not appear later, and one
    // that loaded stays loaded), so caching is both correct and necessary.
    //
    // The cache is keyed on the kDelayedDlls table, which is where every caller
    // gets its name from. An unrecognised name is probed once per call with the
    // reference properly released - correctness over speed for a path nothing
    // uses, and it means a typo cannot silently corrupt the cache.
    for (int i = 0; i < kDelayedDllCount; ++i) {
        if (std::strcmp(kDelayedDlls[i].name, dllName) == 0) {
            // THE SENTINEL MUST BE WHAT ZERO-INITIALISATION PRODUCES.
            // 0 = not yet probed, 1 = present, 2 = absent.
            //
            // This is written down because getting it backwards was a real
            // bug, caught by the CLI test suite rather than by inspection:
            // an earlier version used -1 for "unprobed" with an explicit
            // initialiser, and
            // a later simplification to `= {}` made every slot zero - which
            // under the old encoding meant ABSENT. So every deferred library
            // reported itself missing, the crash handler could not resolve its
            // dump directory, and two `crashtest` checks failed. The lesson is
            // the encoding, not the style: with `= {}`, unprobed MUST be 0.
            //
            // Written and read without a lock: two threads racing to probe the
            // same DLL both perform the same LoadLibrary and store the same
            // value, so the race is benign, and a torn int read is not possible
            // on any platform this builds for. std::atomic would be the pedantic
            // spelling and would cost a fence in a path that runs on every
            // refresh tick.
            static int cache[kDelayedDllCount] = {};
            int& slot = cache[i];
            if (slot == 0) {
                const HMODULE m = ProbeLoadLibrary(kDelayedDlls[i].name);
                if (m == nullptr) {
                    slot = 2;   // absent, and remembered
                } else {
                    // Keep it loaded on purpose. The delay-load helper will
                    // LoadLibrary the same module again on first use, and
                    // releasing here would just churn the refcount; holding one
                    // reference for the process lifetime is what the OS would do
                    // anyway for a system DLL.
                    slot = 1;
                }
            }
            return slot == 1;
        }
    }

    const HMODULE m = ProbeLoadLibrary(dllName);
    if (m == nullptr) return false;
    ::FreeLibrary(m);
    return true;
}

bool DelayLoadGuard(HWND owner, const char* dllName) {
    if (DllAvailable(dllName)) return true;

    // kDelayedDlls and the /DELAYLOAD flags in the three build files are
    // maintained by hand and nothing at compile time cross-checks them. A
    // call site guarded against a library that is NOT in that table would fail
    // here with the library plainly missing from the build's delay-load list -
    // i.e. a crash the gate was supposed to prevent. Say which library, so the
    // mismatch is a one-line fix rather than a mystery.
    const std::wstring feature = DelayedDllFeature(dllName);
    std::wstring text;
    if (feature.empty()) {
        text = L"This feature is unavailable: the library that provides it (";
        text += Utf8ToWide(dllName);
        text += L") is not present on this system.\r\n\r\n"
                L"This is a build inconsistency: that library is not listed as "
                L"delay-loaded, so its absence could not have been handled.";
    } else {
        // "provides it" vs "provides them" - the kDelayedDlls entries are
        // singular or plural features and getting this backwards reads like a
        // machine translation. Cheaper to derive than to police by eye.
        const wchar_t* pronoun =
            (!feature.empty() && feature.back() == L's') ? L"it" : L"them";
        text = L"WinTCP cannot use ";
        text += feature;
        text += L" on this system, because the library that provides ";
        text += pronoun;
        text += L" (";
        text += Utf8ToWide(dllName);
        text += L") is not present.\r\n\r\nThe rest of WinTCP is unaffected.";
    }
    ::MessageBoxW(owner, text.c_str(), L"Feature unavailable",
                  MB_OK | MB_ICONINFORMATION);
    return false;
}

const std::vector<Capability>& WinCapabilities() {
    // Function-local static: thread-safe initialisation under C++11 and later,
    // so the CLI's single-threaded start and the GUI's are both correct, and
    // the probe runs at most once per process.
    static const std::vector<Capability> caps = BuildCapabilities();
    return caps;
}

bool WinAllCapabilitiesPresent() {
    for (const Capability& c : WinCapabilities()) {
        if (c.state != CapState::Available) return false;
    }
    return true;
}

}  // namespace wintcp
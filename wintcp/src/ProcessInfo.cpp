// ProcessInfo.cpp
// SPDX-License-Identifier: Apache-2.0
// PID -> process name resolution. Strategy, in order:
//   1. Well-known pseudo PIDs (0 = ownerless rows like TIME_WAIT -> "-",
//      4 = System).
//   2. Cache hit revalidated with OpenProcess + GetProcessTimes (creation
//      time) - the cheap path used on every auto-refresh.
//   3. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ) +
//      QueryFullProcessImageNameW() for the full path; derive base name.
//   4. Fallback: GetModuleBaseNameW().
//   5. Fallback: one Toolhelp32 snapshot per refresh batch.
// Access-denied / exited processes yield a descriptive label.

#include "ProcessInfo.h"

#include <psapi.h>
#include <tlhelp32.h>

// Per-thread enumeration. tlhelp32.h already supplies
// THREADENTRY32 / Thread32First / Thread32Next; <condition_variable> and
// <thread> are for the private refresher that keeps the ~48 ms snapshot off the
// UI thread (see ProcessInfo.h for the measurement that forces it).
#include <condition_variable>
#include <mutex>
#include <thread>

// WinVerifyTrust and the file-info wrapper. softpub.h supplies
// WINTRUST_ACTION_GENERIC_VERIFY_V2, wintrust.h the entry point.
#include <softpub.h>
#include <wintrust.h>

#include <algorithm>

#include "Utils.h"

namespace wintcp {
namespace {

// FILETIME -> a single 64-bit count of 100ns ticks since 1601. One place, so the
// two shifts-and-ors below cannot drift apart.
ULONGLONG Ft100ns(const FILETIME& ft) {
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}


// Extract L"foo.exe" from L"C:\\dir\\foo.exe".
std::wstring BaseName(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return path;
    if (pos + 1 >= path.size()) return path;
    return path.substr(pos + 1);
}

// Turn a WinVerifyTrust LONG into one of the five states. The
// distinction that matters is NOSIGNATURE vs everything else: an unsigned
// binary is the normal case for most of what runs and is NOT a finding, so it
// gets its own state instead of being folded into "invalid".
SignatureState StateFromTrustLONG(LONG rc) {
    if (rc == ERROR_SUCCESS) return kSigValid;
    // TRUST_E_NOSIGNATURE (0x800B0100) is the "there is no signature here"
    // answer; TRUST_E_SUBJECT_FORMUNKNOWN (0x800B0003) is the same idea for a
    // file that could not be a signed PE at all. Both HRESULTs have the
    // severity bit set, so they are compared as raw DWORDs.
    const DWORD code = static_cast<DWORD>(rc);
    if (code == 0x800B0100UL || code == 0x800B0003UL) return kSigUnsigned;
    if ((code & 0x80000000UL) != 0) return kSigInvalid;   // a TRUST_E_* verdict
    return kSigError;                                     // the provider failed
}

// Windows mandatory-integrity RIDs, the values WinNT.h spells as
// SECURITY_MANDATORY_<LEVEL>_RID: S-1-16-<rid>. Kept as one map from rid to enum
// rather than a threshold comparison, and spelled as named constants because
// the numbers alone (4096, 28672) are indistinguishable from tuning values -
// and a wrong one labels a protected process as a normal one.
constexpr DWORD kRidUntrusted = 0;
constexpr DWORD kRidLow = 4096;
constexpr DWORD kRidMedium = 8192;
constexpr DWORD kRidHigh = 12288;
constexpr DWORD kRidSystem = 16384;
constexpr DWORD kRidProtected = 28672;

// A cheap fingerprint of the FILE, so a path whose contents were
// replaced is re-verified rather than inheriting the old verdict. A path is
// not a stable identity for a file - which is why Windows ships versioned
// side-by-side directories and why "same path" cannot mean "same binary".
ImageStamp StampOf(const std::wstring& path) {
    ImageStamp s;
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad) == 0)
        return s;
    s.size = (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) |
             fad.nFileSizeLow;
    s.write = (static_cast<ULONGLONG>(fad.ftLastWriteTime.dwHighDateTime) << 32) |
              fad.ftLastWriteTime.dwLowDateTime;
    s.valid = true;
    return s;
}

bool SameStamp(const ImageStamp& a, const ImageStamp& b) {
    return a.valid && b.valid && a.size == b.size && a.write == b.write;
}

// What a process token says about its integrity.
struct IntegrityReading {
    IntegrityLevel level = kIntegrityUnknown;
    bool appContainer = false;
};

// TOKEN_QUERY is the only access this needs, which is why an unelevated
// WinTCP can usually still read the answer - the token is opened for reading
// only, never asked for anything the caller does not already hold on its own
// process.
//
// The RID is the LAST subauthority of a mandatory label whose authority is
// (SECURITY_NT_AUTHORITY, SECURITY_MANDATORY_LABEL_AUTHORITY_RID); that is the
// documented encoding of S-1-16-<rid>. Anything else - a token with no label, a
// label from a different authority, a zero-length SID - is reported as unknown
// rather than defaulted to Medium, because "Medium" for a process whose level
// could not be read is a guess dressed as a measurement.
IntegrityReading ReadIntegrity(HANDLE process) {
    IntegrityReading out;
    HANDLE tok = nullptr;
    if (::OpenProcessToken(process, TOKEN_QUERY, &tok) == 0) return out;

    BYTE isApp = 0;
    DWORD got = 0;
    if (::GetTokenInformation(tok, TokenIsAppContainer, &isApp,
                              sizeof(isApp), &got) != 0) {
        out.appContainer = (isApp != 0);
    }

    // THE TWO-CALL PATTERN IS REQUIRED, not tidy. A mandatory label is a
    // TOKEN_MANDATORY_LABEL followed by the SID itself, and that SID is LONGER
    // than the PSID field that points at it - S-1-16-8192 is 12 bytes where the
    // pointer is 8. So a buffer of exactly sizeof(TOKEN_MANDATORY_LABEL) is
    // always too small, GetTokenInformation fails with ERROR_INSUFFICIENT_BUFFER,
    // and the obvious-looking code then reports "unknown integrity" for every
    // process on the machine. That is what the first version of this function
    // did, and the column rendered as an em-dash down both sides of the table.
    DWORD need = 0;
    ::GetTokenInformation(tok, TokenIntegrityLevel, nullptr, 0, &need);
    if (need == 0) { ::CloseHandle(tok); return out; }
    std::vector<BYTE> buf(need);
    got = 0;
    const BOOL ok = ::GetTokenInformation(tok, TokenIntegrityLevel, buf.data(),
                                          need, &got);
    ::CloseHandle(tok);
    if (ok == 0) return out;

    const TOKEN_MANDATORY_LABEL* tml =
        reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buf.data());
    if (tml->Label.Sid == nullptr) return out;

    // `Label` is a SID_AND_ATTRIBUTES rather than a bare PSID in this SDK, and
    // the attributes are not used here.
    PSID sid = tml->Label.Sid;
    PSID_IDENTIFIER_AUTHORITY auth = ::GetSidIdentifierAuthority(sid);
    if (auth == nullptr) return out;
    // A SID's IdentifierAuthority is SIX bytes, not a number: S-1-16-8192 encodes
    // it as {0,0,0,0,0,16} and carries 8192 as the single subauthority. So the
    // authority value being tested is the LAST byte - Value[5] - and both of the
    // two earlier versions of this check were wrong: one compared Value[0]
    // against SECURITY_NT_AUTHORITY read as a brace list (a syntax error), and
    // the next compared Value[0]/Value[1] against 5 and 16, which are zero in
    // every real mandatory label. Either way the function answered "unknown"
    // for every process on the machine, and the column was an em-dash down both
    // sides of a 310-row table while looking entirely plausible in review.
    //
    // Comparing Value[5] against the mandatory-label RID IS the whole test: an
    // integrity label carrying any other authority is not something this column
    // has an opinion about.
    constexpr UCHAR kAuthorityLastByte = 5;
    constexpr UCHAR kMandatoryLabelAuthorityRid = 16;
    if (auth->Value[kAuthorityLastByte] != kMandatoryLabelAuthorityRid)
        return out;

    const DWORD subCount = *::GetSidSubAuthorityCount(sid);
    if (subCount == 0) return out;
    out.level = IntegrityFromRid(*::GetSidSubAuthority(sid, subCount - 1));
    return out;
}

}  // namespace

const wchar_t* IntegrityLabel(IntegrityLevel lvl) {
    switch (lvl) {
        case kIntegrityUntrusted: return L"Untrusted";
        case kIntegrityLow:       return L"Low";
        case kIntegrityMedium:    return L"Medium";
        case kIntegrityHigh:      return L"High";
        case kIntegritySystem:    return L"System";
        case kIntegrityProtected: return L"Protected";
        default:                  return L"—";
    }
}

const wchar_t* SignatureLabel(SignatureState state) {
    switch (state) {
        case kSigValid:    return L"Signed";
        case kSigInvalid:  return L"BAD SIG";
        case kSigUnsigned: return L"unsigned";
        case kSigError:    return L"sig?";
        default:           return L"—";
    }
}

IntegrityLevel IntegrityFromRid(DWORD rid) {
    // Exact equality, not >= : these are fixed constants of the security
    // model, and an unfamiliar future RID must read as "unknown" rather than
    // silently claiming the nearest known level.
    switch (rid) {
        case kRidUntrusted: return kIntegrityUntrusted;
        case kRidLow:       return kIntegrityLow;
        case kRidMedium:    return kIntegrityMedium;
        case kRidHigh:      return kIntegrityHigh;
        case kRidSystem:    return kIntegritySystem;
        case kRidProtected: return kIntegrityProtected;
        default:            return kIntegrityUnknown;
    }
}

void ProcessResolver::Clear() {
    cache_.clear();
    snapshot_.clear();
    snapshotBuilt_ = false;
    // signatureCache_ is deliberately NOT cleared: it is keyed by path
    // and carries the file stamp each verdict was taken against, so a stale
    // entry is detected and re-verified on the next hit rather than trusted.
    // Dropping it would only buy re-verification work.
}

void ProcessResolver::BuildSnapshotIfNeeded() {
    if (snapshotBuilt_) return;
    snapshotBuilt_ = true;
    snapshot_.clear();
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            SnapEntry se;
            se.name = pe.szExeFile;
            // th32ParentProcessID comes free on the entry already being
            // walked, so the parent costs nothing beyond this snapshot. The
            // alternative - NtQueryInformationProcess(ProcessBasicInformation)
            // per PID - is one kernel round trip per process per refresh to
            // learn the same number.
            se.ppid = pe.th32ParentProcessID;
            snapshot_.emplace(pe.th32ProcessID, std::move(se));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
}

std::vector<ProcessRecord> EnumerateProcesses(bool captureLifetime) {
    std::vector<ProcessRecord> out;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;   // caller reports
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue;   // the Idle process
            ProcessRecord r;
            r.pid = pe.th32ProcessID;
            r.ppid = pe.th32ParentProcessID;
            r.name = pe.szExeFile;
            if (captureLifetime) {
                HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                               FALSE, r.pid);
                if (process != nullptr) {
                    FILETIME exited = {}, kernel = {}, user = {};
                    r.processCreateKnown = ::GetProcessTimes(
                        process, &r.processCreate, &exited, &kernel, &user) != FALSE;
                    ::CloseHandle(process);
                }
            }
            out.push_back(std::move(r));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return out;
}

void ProcessResolver::ResolveOne(DWORD pid, Entry& e) {
    e = Entry();

    if (pid == 0) {
        // Ownerless rows (TIME_WAIT, unowned UDP endpoints): show an em dash
        // instead of a misleading process name.
        e.name = L"—";
        return;
    }
    if (pid == 4) {
        e.name = L"System";
        e.path = L"System";
        return;
    }

    // Least-privilege first. PROCESS_VM_READ is what makes protected / PPL
    // processes reject the OpenProcess outright, so when the heavier open is
    // denied, retry with the lighter mask: both QueryFullProcessImageNameW and
    // GetProcessTimes need only PROCESS_QUERY_LIMITED_INFORMATION, and a path
    // resolves the process's icon and signature. Normal processes still take
    // the heavy handle (it succeeds first) and keep VM_READ for the
    // module-name fallback below.
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                             FALSE, pid);
    if (h == nullptr)
        h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h != nullptr) {
        wchar_t full[MAX_PATH * 2] = {0};
        DWORD len = static_cast<DWORD>(sizeof(full) / sizeof(full[0]));
        if (::QueryFullProcessImageNameW(h, 0, full, &len) && len > 0) {
            e.path.assign(full, len);
            e.name = BaseName(e.path);
        } else {
            // Fallback for the rare process whose image path cannot be queried
            // (protected, or gone between the snapshot and this call).
            //
            // NO GATE HERE, and that is deliberate. A DllAvailable("psapi.dll")
            // guard was added and then removed: on this SDK psapi.h #defines
            // GetModuleBaseNameW to K32GetModuleBaseNameW, which KERNEL32
            // exports, so this call never touches psapi.dll. The gate would have
            // asked about a library the process is not going to load. See the
            // note on kDelayedDlls in WinCaps.cpp - which DLL a call resolves to
            // is decided by the headers, not by the .lib in the link line.
            wchar_t base[MAX_PATH] = {0};
            const DWORD n = ::GetModuleBaseNameW(h, nullptr, base,
                static_cast<DWORD>(sizeof(base) / sizeof(base[0])));
            if (n > 0) e.name.assign(base, n);
        }
        FILETIME cr {}, ex {}, kr {}, ui {};
        if (::GetProcessTimes(h, &cr, &ex, &kr, &ui)) {
            e.create = cr;
            e.createKnown = true;
        }
        // Read while the handle is open rather than reopening it: this
        // is the only handle the function has, and OpenProcessToken needs one.
        // A failure is silent by construction - ReadIntegrity answers
        // kIntegrityUnknown and the column shows the em-dash that every other
        // unreadable reading uses.
        const IntegrityReading ir = ReadIntegrity(h);
        e.integrity = ir.level;
        e.appContainer = ir.appContainer;
        ::CloseHandle(h);
    }

    // The snapshot is taken at most once per batch, and is now wanted for
    // EVERY pid rather than only for a name that fell through - because the
    // parent is part of what a row shows. It is still one CreateToolhelp32Snapshot
    // per refresh, which is the cost this design already budgets for; the
    // previous "only on a name miss" rule could not supply a parent for a
    // process whose image path DID resolve.
    BuildSnapshotIfNeeded();
    {
        const auto it = snapshot_.find(pid);
        if (it != snapshot_.end()) {
            if (e.name.empty() && !it->second.name.empty())
                e.name = it->second.name;
            // ppidKnown is set even when ppid is 0: PID 0 is a real parent
            // answer (a process created by the kernel itself), and calling it
            // "unknown" would make those rows indistinguishable from the ones
            // the snapshot did not cover.
            e.ppid = it->second.ppid;
            e.ppidKnown = true;
            // A parent id equal to its own child is the classic Toolhelp race
            // (the parent exited and its id was recycled between the walking of
            // the two entries), and printing the child as its own parent would
            // be nonsense in a tree view.
            if (e.ppid != 0 && e.ppid != pid) {
                const auto pit = snapshot_.find(e.ppid);
                if (pit != snapshot_.end()) e.parentName = pit->second.name;
            }
        }
    }

    if (e.name.empty()) {
        // Protected / elevated / dead process: pick the best label.
        HANDLE hq = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hq != nullptr) {
            e.name = L"<access denied>";
            ::CloseHandle(hq);
        } else {
            const DWORD err = ::GetLastError();
            e.name = (err == ERROR_INVALID_PARAMETER) ? L"<exited>" : L"<access denied>";
        }
    }

    // LAST, because it needs the resolved image path, and only when the
    // caller opted in. A row whose path never resolved stays kSigUnchecked,
    // which renders as the em-dash - not as "unsigned", because an image
    // WinTCP could not find is not an image it has cleared.
    if (verifySignatures_ && !e.path.empty()) {
        e.signature = SignatureForPath(e.path);
    }
}

SignatureState ProcessResolver::SignatureForPath(const std::wstring& path) {
    // The pseudo-images for pid 0 / 4 have a "path" that is a label, not a
    // file. Asking the trust provider about them would only produce a
    // confusing NOSIGNATURE for a string.
    if (path.empty() || path == L"System" || path.find(L':') == std::wstring::npos)
        return kSigUnchecked;

    const ImageStamp stamp = StampOf(path);
    const auto it = signatureCache_.find(path);
    if (it != signatureCache_.end() && SameStamp(stamp, it->second.second))
        return it->second.first;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;          // never pop the trust dialog
    // Revocation is OFF deliberately. WTD_REVOKE_WHOLECHAIN would let the
    // provider reach a CRL/OCSP endpoint, turning a background verification
    // into a network wait that can outlive the refresh that asked for it. A
    // revoked-but-not-yet-expired certificate still reports as Signed here;
    // that is a documented limit of an offline check, not a silent one.
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    // nullptr, not INVALID_HANDLE_VALUE: the first parameter is an HWND (the
    // window a trust UI would parent to, and WTD_UI_NONE means there is none).
    // Passing a non-null HWND would tie a background verification to a window.
    const LONG rc = ::WinVerifyTrust(nullptr, &action, &wd);

    // The close leg is mandatory: WinVerifyTrust keeps state in the WINTRUST_DATA
    // between the VERIFY and CLOSE calls, and skipping it leaks per verification.
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(nullptr, &action, &wd);

    const SignatureState state = StateFromTrustLONG(rc);
    // A path whose stamp could not be read is still cached: an unreadable file
    // will not become readable on the next refresh, and re-running the trust
    // provider every refresh to reach the same answer is pure cost. The entry
    // is invalidated only if a LATER stamp is readable and different.
    signatureCache_[path] = std::make_pair(state, stamp);
    return state;
}

const ProcessResolver::Entry* ProcessResolver::ResolvePid(DWORD pid) {
    bool valid = false;
    auto it = cache_.find(pid);

    if (it != cache_.end()) {
        if (pid == 4) {
            valid = true;   // static label, never changes
        } else {
            HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (h != nullptr) {
                FILETIME cr {}, ex {}, kr {}, ui {};
                if (::GetProcessTimes(h, &cr, &ex, &kr, &ui) &&
                    it->second.createKnown &&
                    ::CompareFileTime(&cr, &it->second.create) == 0) {
                    valid = true;
                }
                ::CloseHandle(h);
            } else {
                const DWORD err = ::GetLastError();
                if (err != ERROR_INVALID_PARAMETER) {
                    // Still not openable (denied/protected): reuse the
                    // cached label; we cannot observe a recycle here.
                    valid = true;
                }
            }
            if (!valid) cache_.erase(it);
        }
    }

    if (!valid) {
        Entry fresh;
        ResolveOne(pid, fresh);
        it = cache_.emplace(pid, std::move(fresh)).first;
    }
    return &it->second;
}

void ProcessResolver::ResolveBatch(std::vector<Connection>& rows) {
    // The snapshot is rebuilt at most once per batch. Every pid
    // wants it, not only a name lookup that missed - the cost is still one
    // CreateToolhelp32Snapshot per refresh, and BuildSnapshotIfNeeded is what
    // keeps it to exactly one even though ResolveOne asks for every pid.
    snapshotBuilt_ = false;
    snapshot_.clear();

    // ONE resolution per DISTINCT pid per batch, not one per row.
    //
    // The result for a pid is a function of the pid and the cached entry
    // alone - it never depends on which row asked - so the first row carrying
    // a pid resolves it and every later row with the same pid copies that
    // answer instead of paying another OpenProcess + GetProcessTimes +
    // CloseHandle round trip to reach the identical conclusion. A busy machine
    // shows thousands of connections spread over a few hundred processes, so
    // most rows repeat a pid already resolved earlier in the same batch: the
    // per-row form scaled its kernel traffic with ROWS, this scales it with
    // DISTINCT PIDS. Bench stage [E] measures that difference directly
    // (before: 142.9 ms/op over 50000 rows).
    //
    // Verification leans on this harder than anything else here: without it every ROW
    // of a process would call WinVerifyTrust for the same image, which is the
    // difference between one chain build per process and one per connection.
    //
    // 'done' holds pointers, not copies: entries are stable in cache_ across
    // later insertions, and an entry is only ever erased while its own pid is
    // being re-resolved - before its pointer is published.
    std::unordered_map<DWORD, const Entry*> done;

    for (Connection& c : rows) {
        const DWORD pid = c.identity.pid;
        auto seen = done.find(pid);
        if (seen == done.end()) {
            seen = done.emplace(pid, ResolvePid(pid)).first;
        }
        const Entry& e = *seen->second;
        c.display.processName = e.name;
        c.display.processPath = e.path;
        c.procMeta.processCreate = e.create;
        c.procMeta.processCreateKnown = e.createKnown;
        // Copied rather than pointed at, exactly like every
        // other piece of resolved metadata: the row outlives the entry whenever
        // the process dies and its cache slot is erased.
        c.security.ppid = e.ppid;
        c.security.ppidKnown = e.ppidKnown;
        c.security.parentName = e.parentName;
        c.security.integrity = static_cast<unsigned>(e.integrity);
        c.security.appContainer = e.appContainer;
        c.security.signature = static_cast<unsigned>(e.signature);
    }
}

bool ProcessResolver::VerifyProcess(DWORD pid, const FILETIME& expectedCreate,
                                    bool expectKnown, std::wstring& errorMessage) {
    if (pid == 0 || pid == 4) {
        errorMessage = L"That row does not belong to a killable user process.";
        return false;
    }
    if (!expectKnown) {
        errorMessage = L"The process lifetime was not captured; refresh before acting.";
        return false;
    }
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                             FALSE, pid);
    if (h == nullptr) {
        errorMessage = L"Could not open process: " + FormatSystemError(::GetLastError());
        return false;
    }
    const bool ok = VerifyProcessHandle(h, expectedCreate, errorMessage);
    ::CloseHandle(h);
    if (ok) errorMessage.clear();
    return ok;
}

bool ProcessResolver::VerifyProcessHandle(HANDLE process,
                                          const FILETIME& expectedCreate,
                                          std::wstring& errorMessage) {
    if (process == nullptr || process == INVALID_HANDLE_VALUE) {
        errorMessage = L"The process handle is invalid.";
        return false;
    }
    bool ok = false;
    const DWORD processState = ::WaitForSingleObject(process, 0);
    if (processState == WAIT_OBJECT_0) {
        errorMessage = L"The process has exited since it was captured.";
    } else if (processState == WAIT_FAILED) {
        errorMessage = L"Could not verify whether the process is still running: " +
                       FormatSystemError(::GetLastError());
    } else if (processState != WAIT_TIMEOUT) {
        errorMessage = L"Could not verify whether the process is still running.";
    } else {
        FILETIME cr {}, ex {}, kr {}, ui {};
        if (::GetProcessTimes(process, &cr, &ex, &kr, &ui)) {
            if (::CompareFileTime(&cr, &expectedCreate) == 0) {
                ok = true;
            } else {
                errorMessage =
                    L"PID reuse detected: this PID now belongs to a different "
                    L"process than when the row was captured.\n"
                    L"Press F5 to refresh and try again.";
            }
        } else {
            errorMessage = L"Could not verify the process creation time: " +
                           FormatSystemError(::GetLastError());
        }
    }
    if (ok) errorMessage.clear();
    return ok;
}

void QueryServiceNames(std::map<DWORD, std::wstring>& out) {
    out.clear();
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == nullptr) return;   // best effort; Service column stays empty

    std::map<DWORD, std::wstring> found;
    DWORD resume = 0;
    for (;;) {
        DWORD bytesNeeded = 0, count = 0;
        ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded,
                                &count, &resume, nullptr);
        if (::GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0) break;
        std::vector<BYTE> buf(bytesNeeded);
        const BOOL ok = ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO,
                                                SERVICE_WIN32, SERVICE_STATE_ALL,
                                                buf.data(), bytesNeeded,
                                                &bytesNeeded, &count, &resume, nullptr);
        if (!ok) break;
        const auto* entries =
            reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            const DWORD pid = entries[i].ServiceStatusProcess.dwProcessId;
            if (pid == 0 || entries[i].lpServiceName == nullptr) continue;
            auto& slot = found[pid];
            if (!slot.empty()) slot += L", ";
            slot += entries[i].lpServiceName;
        }
        if (bytesNeeded == 0) break;   // all pages read (defensive)
    }
    ::CloseServiceHandle(scm);
    out.swap(found);
}

std::wstring QueryProcessCommandLine(DWORD pid) {
    // ProcessCommandLineInformation = 60 (stable, undocumented-but-widely
    // used NT information class); resolved dynamically from ntdll.
    using NtQueryInformationProcess_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQueryInformationProcess_t ntqip = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        if (HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll"))
            ntqip = reinterpret_cast<NtQueryInformationProcess_t>(
                ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
    }
    if (ntqip == nullptr) return std::wstring();

    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                             FALSE, pid);
    if (h == nullptr)
        h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr) return std::wstring();

    std::wstring result;
    struct UnicodeStringHeader {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;              // compiler inserts alignment padding
    };
    // ProcessCommandLineInformation class id (undocumented, stable — same
    // lineage as kSystemExtendedHandleInformation in SocketTraffic.cpp, which
    // names its class the same way). A command line over 1 MB is not a command
    // line, it is a corrupt length; fall back to one page rather than trusting
    // it, the way the handle-table query falls back to a slab.
    constexpr ULONG kProcessCommandLineInfoClass = 60;
    constexpr ULONG kMaxCommandLineBytes = 1024u * 1024u;
    constexpr ULONG kCommandLineFallbackBytes = 4096;
    ULONG len = 0;
    LONG st = ntqip(h, kProcessCommandLineInfoClass, nullptr, 0,
                    &len);   // STATUS_INFO_LENGTH_MISMATCH
    if (len < sizeof(UnicodeStringHeader) || len > kMaxCommandLineBytes)
        len = kCommandLineFallbackBytes;
    std::vector<BYTE> buf(len);
    st = ntqip(h, kProcessCommandLineInfoClass, buf.data(), len, &len);
    if (st >= 0) {                                // NT_SUCCESS
        const auto* us = reinterpret_cast<const UnicodeStringHeader*>(buf.data());
        if (us->Buffer != nullptr && us->Length > 0 && (us->Length % sizeof(wchar_t)) == 0)
            result.assign(us->Buffer, us->Length / sizeof(wchar_t));
    }
    ::CloseHandle(h);
    return result;
}

namespace {
// EnumWindows callback for PostCloseToProcessWindows. A file-scope function
// rather than a local lambda: a local function definition is ill-formed in
// C++ and the compiler rejects it outright.
struct CloseEnumCtx {
    DWORD pid;
    int posted;
};

BOOL CALLBACK CloseEnumProc(HWND hwnd, LPARAM param) {
    auto* c = reinterpret_cast<CloseEnumCtx*>(param);
    DWORD ownerPid = 0;
    ::GetWindowThreadProcessId(hwnd, &ownerPid);
    if (ownerPid != c->pid) return TRUE;    // keep enumerating
    // WM_CLOSE, exactly as clicking the X would send. Posting rather than
    // sending is required: SendMessage would block until the target handles
    // it, and a hung app would hang WinTCP.
    if (::PostMessageW(hwnd, WM_CLOSE, 0, 0) != FALSE) ++c->posted;
    return TRUE;
}
}  // namespace

bool PostCloseToProcessWindows(DWORD pid) {
    if (pid == 0) return false;
    CloseEnumCtx ctx = {pid, 0};
    // EnumWindows visits every top-level window exactly once, which is what
    // makes this safe. A re-scan loop would post WM_CLOSE repeatedly to a
    // window that ignores the first message, because it stays in the list.
    ::EnumWindows(&CloseEnumProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.posted > 0;
}

// ---- per-thread enumeration ------------------------------------------------
//
// The design here is driven by one measured number rather than a guess, so it
// is worth stating plainly - the function below looks over-engineered otherwise:
//
//   CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)   ~48 ms
//   per thread: OpenThread + GetThreadTimes      ~11 us
//
// Measured on this machine, 2000 iterations each: a 39-thread process cost
// 49 ms, a 456-thread process cost 54 ms. The cost is the KERNEL-WIDE walk, not
// the threads - so incremental cleverness about the thread count would buy
// nothing. The only lever is how often it happens.
//
// Details rebuilds its model on every refresh tick, on the UI thread, at the
// product cadence of every 2 seconds, for as long as the window is open. An
// inline call would therefore freeze the UI for 48 ms twice a second. Hence the
// cache, the worker, and the "never blocks" contract on ProcessThreads().
namespace {

// How stale a published snapshot may get before another is requested.
constexpr unsigned kThreadCacheTtlMs = 2000;

// Take one Toolhelp pass and the per-thread queries that follow it. Runs on the
// worker thread and touches no shared state, so the lock is never held across it.
std::vector<ThreadInfo> SampleThreads(DWORD pid) {
    std::vector<ThreadInfo> out;
    if (pid == 0) return out;

    // TH32CS_SNAPTHREAD takes no PID filter: the flag set says which objects to
    // walk, and the PID argument is ignored for threads. That is precisely why
    // this costs 48 ms - the whole machine's threads are walked and then
    // filtered right here.
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (::Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            ThreadInfo ti;
            ti.tid = te.th32ThreadID;
            ti.basePriority = te.tpBasePri;

            // THREAD_QUERY_LIMITED_INFORMATION, deliberately not
            // THREAD_QUERY_INFORMATION. Measured on this machine: with LIMITED,
            // every thread of every process opened successfully, including all
            // ~456 of PID 4's. With the broader right, PID 4's threads failed
            // 454 times out of 454. So LIMITED is simultaneously the
            // least-privilege choice and the only one that works for the most
            // privileged process on the box - and PID 4 is exactly the row
            // somebody is most likely to open Details on.
            HANDLE th =
                ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ti.tid);
            if (th != nullptr) {
                FILETIME created = {}, exited = {}, kernel = {}, user = {};
                if (::GetThreadTimes(th, &created, &exited, &kernel, &user)) {
                    ti.create100ns = Ft100ns(created);
                    // Parenthesised per term on purpose. `|` and `+` do not
                    // associate the way the arithmetic reads, and the written
                    // form silently folds the low word of the kernel time into
                    // the user time - a wrong number rather than an error.
                    ti.cpu100ns = Ft100ns(kernel) + Ft100ns(user);
                    ti.timesKnown = true;
                }
                ::CloseHandle(th);
            }
            out.push_back(ti);
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
    return out;
}

// One published snapshot plus the worker that refreshes it.
//
// A single cached PID rather than a map: Details follows one selected row, so
// there is one thing to be current about, and switching rows just re-requests.
// The list is tens-to-low-hundreds of small entries, so the copy out of the
// lock is free.
struct ThreadCache {
    std::mutex mu;
    std::condition_variable cv;
    std::thread worker;
    bool workerStarted = false;
    bool stop = false;
    bool dirty = false;         // a refresh has been asked for
    DWORD wantedPid = 0;
    DWORD havePid = 0;          // which PID `rows` describes
    std::vector<ThreadInfo> rows;
    ULONGLONG takenAt = 0;      // GetTickCount64 at publication
    bool haveResult = false;

    // A joinable std::thread that is still running when its owner's destructor
    // runs calls std::terminate. So the worker is stopped and joined here rather
    // than left running into static teardown, where it could be part-way through
    // a Toolhelp snapshot when main() returns.
    ~ThreadCache() {
        if (!workerStarted) return;
        {
            std::lock_guard<std::mutex> lk(mu);
            stop = true;
        }
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }
};

void ThreadWorker(ThreadCache* c);

ThreadCache& Cache() {
    static ThreadCache* c = new ThreadCache();
    return *c;
}

ULONGLONG NowMs() { return ::GetTickCount64(); }

void ThreadWorker(ThreadCache* c) {
    std::unique_lock<std::mutex> lk(c->mu);
    for (;;) {
        c->cv.wait(lk, [c] { return c->stop || c->dirty; });
        if (c->stop) return;
        const DWORD pid = c->wantedPid;
        // The expensive part, deliberately outside the lock: a reader must never
        // queue behind a 48 ms kernel walk, and holding the lock here would
        // charge every caller for it.
        lk.unlock();
        std::vector<ThreadInfo> fresh = SampleThreads(pid);
        lk.lock();
        c->rows = std::move(fresh);
        c->havePid = pid;
        c->takenAt = NowMs();
        c->haveResult = true;
        c->dirty = false;
    }
}

// Called with c->mu already held. Spawning under the lock keeps two concurrent
// first callers from both creating a worker.
void EnsureWorkerLocked(ThreadCache* c) {
    if (c->workerStarted) return;
    c->workerStarted = true;
    c->worker = std::thread(ThreadWorker, c);
}

}  // namespace

std::vector<ThreadInfo> ProcessThreads(DWORD pid, bool allowBlocking,
                                       bool* known, unsigned* ageMs) {
    if (known != nullptr) *known = false;
    if (ageMs != nullptr) *ageMs = UINT_MAX;
    if (pid == 0) return {};

    ThreadCache& c = Cache();

    // --- fast path: something fresh is already published for this PID.
    {
        std::lock_guard<std::mutex> lk(c.mu);
        const bool have =
            c.haveResult && c.havePid == pid &&
            (NowMs() - c.takenAt) < kThreadCacheTtlMs;
        if (have) {
            if (known != nullptr) *known = true;
            if (ageMs != nullptr) {
                const ULONGLONG age = NowMs() - c.takenAt;
                *ageMs = (age > UINT_MAX) ? UINT_MAX : static_cast<unsigned>(age);
            }
            return c.rows;
        }
        // Ask the worker for a refresh either way. Harmless if one is already
        // in flight: the worker takes the newest request when it wakes.
        c.wantedPid = pid;
        c.dirty = true;
        EnsureWorkerLocked(&c);
        c.cv.notify_one();
        if (!allowBlocking) {
            // The GUI path. Return whatever exists, even for a DIFFERENT pid,
            // rather than an empty list: a caller rendering this has no way to
            // tell "stale, wrong process" from "this process has no threads",
            // and the second is never true. known=false says which it is.
            if (c.haveResult && c.havePid == pid) {
                if (known != nullptr) *known = true;
                if (ageMs != nullptr) *ageMs = 0;
            }
            return c.rows;
        }
    }

    // --- blocking path, one-shot caller. The lock is RELEASED above, so the
    // sample below does not hold it: SampleThreads is the 48 ms part, and a
    // reader must never queue behind it. The worker may run this concurrently
    // for the same PID, which is wasted work but not a correctness problem -
    // both samples are of the same process and the last writer wins.
    std::vector<ThreadInfo> fresh = SampleThreads(pid);
    {
        std::lock_guard<std::mutex> lk(c.mu);
        c.rows = fresh;
        c.havePid = pid;
        c.takenAt = NowMs();
        c.haveResult = true;
        c.dirty = false;
        if (known != nullptr) *known = true;
        if (ageMs != nullptr) *ageMs = 0;
        return c.rows;
    }
}

}  // namespace wintcp

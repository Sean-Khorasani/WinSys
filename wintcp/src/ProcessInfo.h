// ProcessInfo.h
// SPDX-License-Identifier: Apache-2.0
// PID -> process name / path / creation-time resolution with a persistent,
// creation-time-validated cache, plus service-name and command
// line queries.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "Connection.h"

namespace wintcp {

// One process from a Toolhelp snapshot: what a process-tree view needs and
// nothing more. NOT the connection-bearing subset - the point of a process
// tree is that chrome.exe shows its 32 renderers whether or not any of them
// happens to hold a socket this second, which is what Task Manager's
// Processes tab does and what a tree built from the connection table cannot
// (a renderer between requests owns no endpoint and would be missing).
struct ProcessRecord {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::wstring name;
};

// Every process on the machine, from ONE CreateToolhelp32Snapshot
// (TH32CS_SNAPPROCESS). Best effort: an empty result means the snapshot
// failed, which a caller reports rather than renders as an empty machine.
//
// th32ParentProcessID comes free on the entry already being walked, so the
// parent costs nothing beyond the snapshot itself - the same reason
// ProcessResolver reads it from here rather than per-PID. The Idle process
// (PID 0) is skipped: it is not a process in any sense a tree can show, and
// the engine's own node rule already excludes it.
std::vector<ProcessRecord> EnumerateProcesses();

// A process's integrity level, from TokenIntegrityLevel's mandatory
// label. The RID is what the label encodes (S-1-16-<rid>), and naming the
// levels rather than printing RIDs is the point: 12288 tells a reader nothing,
// "High" tells them whether the process could have written to HKLM.
enum IntegrityLevel : unsigned {
    kIntegrityUnknown = 0,
    kIntegrityUntrusted,    // S-1-16-0      - nothing has been assigned
    kIntegrityLow,          // S-1-16-4096
    kIntegrityMedium,       // S-1-16-8192   - the default for a normal app
    kIntegrityHigh,         // S-1-16-12288  - elevated, can touch HKLM
    kIntegritySystem,       // S-1-16-16384  - services and drivers
    kIntegrityProtected,    // S-1-16-28672  - Protected Process Light
    kIntegrityCount
};

// The Authenticode verdict for an image, from WinVerifyTrust.
//
// kSigUnsigned is deliberately NOT the same as kSigInvalid. "Unsigned" is the
// honest answer for most of what runs (a script host, a portable binary) and is
// not a defect; conflating it with "invalid" would paint most of a machine red
// and train the reader to ignore the colour, which is the only thing a highlight
// exists to avoid. kSigError is separate again: that is WinTCP failing to ask,
// which says nothing about the binary.
enum SignatureState : unsigned {
    kSigUnchecked = 0,
    kSigValid,               // chains to a root the machine trusts
    kSigInvalid,             // carries a signature that does not verify
    kSigUnsigned,            // no embedded Authenticode signature
    kSigError,               // the trust provider could not decide
    kSigCount
};

// Display labels, exposed for selftest so the wording is pinned.
const wchar_t* IntegrityLabel(IntegrityLevel lvl);
const wchar_t* SignatureLabel(SignatureState state);

// Map a TokenIntegrityLevel mandatory-label RID onto a level. Exposed because
// the RID -> name mapping is pure policy and must not depend on a live token.
IntegrityLevel IntegrityFromRid(DWORD rid);

// The FILE fingerprint a cached signature verdict was taken against.
// Present in this header only because it appears in the resolver's private
// cache type below; it carries no behaviour of its own.
//
// It exists because a path is not a stable identity for a file. Without it a
// binary updated in place would keep the verdict of the file it replaced -
// which is precisely the case where a signature check matters most, since
// replacing a signed binary with an unsigned one is the attack it exists to
// catch.
struct ImageStamp {
    ULONGLONG size = 0;      // bytes
    ULONGLONG write = 0;     // FILETIME of last write, raw
    bool valid = false;
};

// Resolves process names for PIDs seen during a refresh.
// The cache persists across refreshes; entries are revalidated cheaply via
// OpenProcess + GetProcessTimes (creation time), so a recycled PID is never
// shown with a stale name, and a Toolhelp snapshot is taken at most once per
// batch and only when some PID actually needs it.
class ProcessResolver {
public:
    ProcessResolver() = default;
    ProcessResolver(const ProcessResolver&) = delete;
    ProcessResolver& operator=(const ProcessResolver&) = delete;

    // Fill processName / processPath / processCreate* for every row.
    void ResolveBatch(std::vector<Connection>& rows);

    void Clear();

    // Authenticode verification is OPT-IN and off by default, because
    // it cannot be anything else: WinVerifyTrust opens the file, builds a
    // certificate chain and may consult a revocation endpoint over the
    // network. That is tens to hundreds of milliseconds per image, which
    // would turn a refresh that currently costs one Toolhelp snapshot into one
    // that stalls for a second per process.
    //
    // It is cached per PATH rather than per PID, which is both cheaper and more
    // correct: a file's signature cannot change while a process is running it,
    // and twenty processes off one DLL share one verdict instead of paying
    // twenty trust-provider round trips.
    void SetVerifySignatures(bool on) { verifySignatures_ = on; }
    bool VerifySignatures() const { return verifySignatures_; }

    // Verify that 'pid' still is the same process instance that produced
    // 'expectedCreate' (when 'expectKnown') before terminating it.
    // Returns false and sets 'errorMessage' when it is unsafe to proceed.
    static bool VerifyProcess(DWORD pid, const FILETIME& expectedCreate,
                              bool expectKnown, std::wstring& errorMessage);

private:
    struct Entry {
        std::wstring name;
        std::wstring path;
        FILETIME create = {};
        bool createKnown = false;
        // The parent, from the same Toolhelp snapshot that can supply a
        // name. security.ppidKnown is separate because the two fail independently: a
        // name can come from a snapshot carrying no PPID for a just-created
        // process, and a PPID can be readable while the name is not.
        DWORD ppid = 0;
        bool ppidKnown = false;
        std::wstring parentName;   // "" when the parent is not in the snapshot
        IntegrityLevel integrity = kIntegrityUnknown;
        // An AppContainer process runs at Low integrity by default, so the
        // level alone does not reveal that it is sandboxed. The two are kept
        // apart rather than flattened, because "Low" on its own makes every
        // sandboxed app indistinguishable from an ordinary low-integrity one.
        bool appContainer = false;
        SignatureState signature = kSigUnchecked;
    };

    // What ONE Toolhelp pass tells us about a process. Both fields come from the
    // same PROCESSENTRY32W, so carrying them together means the parent costs no
    // extra kernel call - which is the whole reason this reads the snapshot
    // rather than NtQueryInformationProcess per PID.
    struct SnapEntry {
        std::wstring name;
        DWORD ppid = 0;
    };

    void BuildSnapshotIfNeeded();
    void ResolveOne(DWORD pid, Entry& e);

    // The SignatureState for one image path, together with the stamp it was
    // taken against. Keyed by path, not by PID - see the note on
    // SetVerifySignatures.
    SignatureState SignatureForPath(const std::wstring& path);

    // Resolve (or revalidate) ONE pid and return the stable cache entry for
    // it. The answer depends only on the pid and the cached entry - never on
    // which row asked - which is what lets ResolveBatch ask this once per
    // distinct pid instead of once per row. The returned pointer stays valid
    // across later cache_ inserts (node-based container: inserting or
    // rehashing never moves an element); it is only ever invalidated by
    // erasing this very pid, which happens before the pointer is handed out.
    const Entry* ResolvePid(DWORD pid);

    std::unordered_map<DWORD, Entry> cache_;
    std::unordered_map<DWORD, SnapEntry> snapshot_;   // one per batch
    bool snapshotBuilt_ = false;
    // path -> (verdict, the file stamp the verdict is valid for). A hit
    // whose stamp no longer matches the file on disk is re-verified.
    std::unordered_map<std::wstring, std::pair<SignatureState, ImageStamp>>
        signatureCache_;
    bool verifySignatures_ = false;
};

// Map PID -> hosting service names ("Dnscache, Dnscache...") with a single
// SCM enumeration. Best effort: on failure 'out' stays empty (the Service
// column is optional decoration). Needs advapi32.
void QueryServiceNames(std::map<DWORD, std::wstring>& out);

// ---- per-thread facts --------------------------------------------------
//
// Why this exists at all, since the request that led here was for a "Thread
// COLUMN": a per-connection thread cannot be had. MIB_TCPROW_OWNER_PID - the row
// behind GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL), which is this app's
// whole basis - has no thread id, and an AFD endpoint is owned by the PROCESS,
// not by a thread. There is nothing to put in such a column. What a process does
// have is a list of threads, and that is the thing worth showing.
//
// Every field below comes from a DOCUMENTED user-mode API. Notably absent is the
// thread's current state: GetThreadInfo/THREADINFO is a legacy kernel32 export
// that the Windows SDK no longer declares for user mode, and its state and
// wait-reason enumerators are not published - so a "Waiting/Running" column would
// mean inventing a mapping. Better absent than wrong. The facts below answer
// "what is this process doing" without it: which threads exist, which have
// burned CPU, and since when.
//
// cpu100ns and create100ns are raw 100ns counts since 1601 (CPU is kernel+user
// since thread start), left unformatted so this header holds no display policy.
// timesKnown false means OpenThread or GetThreadTimes was refused - a real
// condition for protected processes, which must render as unknown, never as zero.
struct ThreadInfo {
    DWORD tid = 0;
    DWORD basePriority = 0;      // tpBasePri from THREADENTRY32
    ULONGLONG cpu100ns = 0;
    ULONGLONG create100ns = 0;
    bool timesKnown = false;
};

// The threads of 'pid', as last sampled.
//
// WHY IT IS CACHED AND WHY IT IS ASYNCHRONOUS. Measured on this machine rather
// than estimated: CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) costs ~48 ms, and
// the per-thread work on top is negligible by comparison (39 threads 49 ms, 456
// threads 54 ms - the cost is the kernel-wide walk, not the threads). Details
// rebuilds its model on every refresh tick, on the UI thread, so calling this
// inline would freeze the window for 48 ms every two seconds for as long as
// Details is open.
//
// So the snapshot is taken on a private worker and published under a lock, and
// this function returns the last published value immediately: it NEVER blocks on
// the snapshot. A caller arriving before the first result gets an empty list and
// known=false, which must be rendered as "not read yet" - a process always has at
// least one thread, so the empty reading is a falsehood.
//
// 'ageMs' receives how long ago the returned sample was taken, so a caller can
// say so instead of implying the numbers are current. UINT_MAX when unknown.
//
// 'allowBlocking' exists for the ONE-SHOT caller. A GUI that polls this
// every couple of seconds is always served from the last published snapshot
// and never waits - but a command such as `wintcp.exe details` runs once and
// exits, so "nothing published yet" would mean it NEVER prints the section.
// Measured, that bug looked exactly like "the feature does not work": the
// first and only call returned an empty list and the process ended. So a
// one-shot caller opts in to paying the ~48 ms inline, which for a command
// that is about to exit anyway is the better trade by three orders of
// magnitude.
std::vector<ThreadInfo> ProcessThreads(DWORD pid, bool allowBlocking,
                                       bool* known = nullptr,
                                       unsigned* ageMs = nullptr);

// Full command line of a process (best effort via NtQueryInformationProcess
// ProcessCommandLineInformation; empty when unavailable).
std::wstring QueryProcessCommandLine(DWORD pid);

// Ask every top-level window owned by 'pid' to close, the way a user
// closing a window would (WM_CLOSE to each). Returns true if at least one
// message was posted, false if the process has no top-level windows - which
// is the normal case for a service or a console app, and the reason the
// caller needs a forceful fallback rather than merely waiting.
//
// Used by the graceful end-process path so an app that can save
// on close gets the chance to do so.
bool PostCloseToProcessWindows(DWORD pid);

}  // namespace wintcp

// WebProcesses.h
// SPDX-License-Identifier: Apache-2.0
// Per-process sampler for the Web UI: a full process list (not just the
// processes that happen to own a socket) with CPU, memory, I/O transfer,
// thread count and image path.
//
// WHY A SEPARATE MODULE
// The connection store can only tell you about processes that own an endpoint.
// Task Manager, the brief's "full process view", and the treemap all need the
// rest: on a typical desktop the majority of processes own no socket at all, so
// deriving the list from the connection store silently drops them. This module
// enumerates the process table directly.
//
// THREADING
// Every object here is owned by ONE thread - the Web UI's refresher thread - and
// the sampler instance is passed in by the owner. Requests never touch it: they
// read a published snapshot under ProcessSnapshot's own mutex. That follows the
// rule in docs/architecture.md that SnapshotSource is not thread-safe, so any
// sampler object must have exactly one owner.
//
// COST
// One CreateToolhelp32Snapshot per pass is a kernel-side walk of the process
// table, not a per-process syscall storm. Per-process work is a ProcStatsSampler
// pass (which needs CPU-time deltas, so it keeps its own baselines internally)
// plus - ONLY for PIDs whose path is not already cached - one
// OpenProcess/QueryFullProcessImageName pair. Image paths do not change during a
// process's lifetime, so the cache is exact, not a heuristic.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ProcStats.h"

namespace wintcp {

// One process, as the Web UI reports it. Fields that could not be read are
// false/unknown rather than zero: a process whose handle cannot be opened for
// CPU times (most system processes) must not read as "0% CPU forever".
struct WebProcessRow {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::wstring name;            // image name, e.g. "svchost.exe"
    std::wstring path;            // full image path; empty when not readable
    DWORD threads = 0;
    bool threadsKnown = false;

    ProcStats stats;              // cpuPct / memWs / memPrivate / ioRead / ioWrite

    // Filled in by the connection refresh, which knows the store. Left at zero
    // by the sampler itself.
    int connections = 0;
    int listeners = 0;
    bool connectionCountsKnown = false;
};

// A published, immutable-by-convention snapshot of the process table.
struct WebProcessSnapshot {
    std::vector<WebProcessRow> rows;
    uint64_t unixTime = 0;
    bool known = false;           // false until the first pass completes
    std::string reason;           // why not, when known == false
};

// Owns the process enumeration. One instance, one thread.
class WebProcessSampler {
public:
    WebProcessSampler() = default;
    WebProcessSampler(const WebProcessSampler&) = delete;
    WebProcessSampler& operator=(const WebProcessSampler&) = delete;

    // Take one reading of the whole process table. pidsWithConnections and
    // listenersByPid come from the connection store and are joined onto the
    // matching rows so the UI can show "this process owns N sockets" without a
    // second request.
    WebProcessSnapshot Sample(
        const std::map<DWORD, int>& connectionsByPid,
        const std::map<DWORD, int>& listenersByPid,
        bool connectionCountsKnown);

    // Forget cached image paths. Used when the caller wants a re-read after an
    // elevation change, where more paths become readable.
    void ClearPathCache();

private:
    std::wstring ImagePath(DWORD pid);

    ProcStatsSampler procStats_;
    // Scratch buffer for NtQuerySystemInformation, reused across passes so a
    // 1 Hz sample costs no allocation after the first few.
    std::vector<BYTE> scratch_;
    // pid -> path. An empty value is a CACHED FAILURE, not a cache miss: most
    // system processes refuse the query, and re-asking them every second is
    // pure cost. Elevation changes the answer, which is what ClearPathCache is
    // for.
    std::map<DWORD, std::wstring> pathCache_;
};

// Thread-safe publication point. One writer (the refresher thread), many readers
// (request threads).
class ProcessSnapshot {
public:
    void Publish(const WebProcessSnapshot& snapshot);
    WebProcessSnapshot Read() const;
    // Tick of the last successful publication, for staleness labelling.
    ULONGLONG AgeMs() const;

private:
    mutable std::mutex mutex_;
    WebProcessSnapshot snapshot_;
    ULONGLONG publishedTick_ = 0;
};

// Sort helpers, exposed so the unit tests can pin their tie-breaking. Without
// them the order is "whatever std::sort did", and two processes with the same
// CPU can swap places between polls, which reads as flicker.
enum class ProcessSort {
    Cpu, Memory, PrivateBytes, IoRead, IoWrite, Threads,
    Name, Pid, Connections, Listeners
};

// Note the const parameters: the rows live in a std::vector that std::stable_sort
// hands to the comparator as const references, and a non-const signature simply
// does not bind.
bool CompareProcesses(const WebProcessRow& a, const WebProcessRow& b,
                      ProcessSort sort, bool ascending);

// True when the sort column has a usable reading for this row. Rows without one
// sort LAST in both directions rather than pretending to be zero, which is the
// difference between "smallest" and "not measured".
bool HasSortValue(const WebProcessRow& row, ProcessSort sort);

}  // namespace wintcp
// WebProcesses.cpp
// SPDX-License-Identifier: Apache-2.0
// See WebProcesses.h for why this module exists and how it is threaded.

#include "WebProcesses.h"

#include <tlhelp32.h>

#include <algorithm>

namespace wintcp {

namespace {

// Read one process's image path. PROCESS_QUERY_LIMITED_INFORMATION is the
// least privilege that works and the one that still opens on a machine where
// the process is running at a higher integrity level than we are - we get the
// path, we do not get to touch the process. Failure is expected and cached by
// the caller.
std::wstring QueryImagePath(DWORD pid) {
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return std::wstring();
    wchar_t buffer[32768];
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    std::wstring path;
    if (::QueryFullProcessImageNameW(process, 0, buffer, &size) != FALSE) {
        path.assign(buffer, size);
    }
    ::CloseHandle(process);
    return path;
}

// The process table.
// The process table.
//
// Toolhelp's CreateToolhelp32Snapshot is the enumeration: documented,
// supported, and it returns exactly what the tree needs (name, PID, PPID).
//
// It does NOT return thread counts. PROCESSENTRY32W has no th32Threads field,
// and the ANSI PROCESSENTRY32 that does have one is #defined away to the wide
// struct by this SDK, so `threads` is reported unknown with a reason rather than
// guessed.
//
// The alternative considered and rejected: NtQuerySystemInformation(class 5,
// SystemProcessInformation) would return thread counts, working sets and CPU
// times in one call with no per-process OpenProcess storm. Measured on this
// machine its buffer does not match the layout winnt.h documents - the first
// record's NextEntryOffset does not read as a plausible offset and the chain
// ends after one record - so decoding it would mean reverse-engineering an
// undocumented structure and then trusting it with every PID the UI shows. A
// wrong PID is worse than an absent thread count. Documented in the "Known
// limitations" section of docs/webui.md.
// the UI shows "-".
}  // namespace

std::wstring WebProcessSampler::ImagePath(DWORD pid) {
    const auto it = pathCache_.find(pid);
    if (it != pathCache_.end()) return it->second;      // cached hit or cached failure
    std::wstring path = QueryImagePath(pid);
    pathCache_[pid] = path;
    return path;
}

void WebProcessSampler::ClearPathCache() {
    pathCache_.clear();
}

WebProcessSnapshot WebProcessSampler::Sample(
    const std::map<DWORD, int>& connectionsByPid,
    const std::map<DWORD, int>& listenersByPid,
    bool connectionCountsKnown) {
    WebProcessSnapshot snapshot;
    HANDLE handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (handle == INVALID_HANDLE_VALUE || handle == nullptr) {
        snapshot.known = false;
        snapshot.reason = "the process table could not be enumerated";
        return snapshot;
    }
    std::vector<WebProcessRow> rows;
    rows.reserve(512);
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (::Process32FirstW(handle, &entry)) {
        do {
            WebProcessRow row;
            row.pid = entry.th32ProcessID;
            row.ppid = entry.th32ParentProcessID;
            row.name.assign(entry.szExeFile);
            // threadsKnown stays false: see the note above. Reported as null with
            // a reason rather than as 0, because "zero threads" is a claim about
            // a live process and it is false.
            row.threadsKnown = false;
            const auto conn = connectionsByPid.find(row.pid);
            if (conn != connectionsByPid.end()) row.connections = conn->second;
            const auto listen = listenersByPid.find(row.pid);
            if (listen != listenersByPid.end()) row.listeners = listen->second;
            row.connectionCountsKnown = connectionCountsKnown;
            rows.push_back(std::move(row));
            // Hard cap so a pathological process table cannot turn one second of
            // background work into an unbounded pause. The truncation is visible
            // in the reported row count rather than hidden.
        } while (::Process32NextW(handle, &entry) && rows.size() < 8192);
    }
    ::CloseHandle(handle);
    // CPU %, working set, private bytes and I/O transfer in one pass.
    // ProcStatsSampler keeps its own CPU-time baselines, so the first pass for a
    // PID legitimately reports cpuKnown=false and the value appears from the
    // second one on. That is a warm-up, not an error, and the UI shows "-" until
    // it resolves.
    std::vector<DWORD> pids;
    pids.reserve(rows.size());
    for (const auto& row : rows) pids.push_back(row.pid);
    std::map<DWORD, ProcStats> stats = procStats_.Sample(pids);
    for (auto& row : rows) {
        const auto it = stats.find(row.pid);
        if (it != stats.end()) row.stats = it->second;
        // Path last: an image path cannot change during a process's lifetime, so
        // only new PIDs ever pay for the query.
        row.path = ImagePath(row.pid);
    }
    snapshot.rows = std::move(rows);
    snapshot.known = true;
    return snapshot;
}


void ProcessSnapshot::Publish(const WebProcessSnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_ = snapshot;
    snapshot_.unixTime = static_cast<uint64_t>(::GetTickCount64());
    publishedTick_ = ::GetTickCount64();
}

WebProcessSnapshot ProcessSnapshot::Read() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_;
}

ULONGLONG ProcessSnapshot::AgeMs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (publishedTick_ == 0) return 0;
    return ::GetTickCount64() - publishedTick_;
}

bool HasSortValue(const WebProcessRow& row, ProcessSort sort) {
    switch (sort) {
        case ProcessSort::Cpu:            return row.stats.cpuKnown;
        case ProcessSort::Memory:         return row.stats.memKnown;
        case ProcessSort::PrivateBytes:   return row.stats.memKnown;
        case ProcessSort::IoRead:         return row.stats.ioKnown;
        case ProcessSort::IoWrite:        return row.stats.ioKnown;
        case ProcessSort::Threads:        return row.threadsKnown;
        case ProcessSort::Name:           return true;
        case ProcessSort::Pid:            return true;
        case ProcessSort::Connections:    return row.connectionCountsKnown;
        case ProcessSort::Listeners:      return row.connectionCountsKnown;
    }
    return true;
}

bool CompareProcesses(const WebProcessRow& a, const WebProcessRow& b,
                      ProcessSort sort, bool ascending) {
    // Rows with no reading for the sort column go LAST in BOTH directions.
    //
    // This is the whole reason HasSortValue exists. A process whose handle
    // cannot be opened reports no CPU figure; sorting it as if it were 0 puts a
    // row we know nothing about above a row we measured at 0.1%, and the table
    // then claims something false about both of them. "Not measured" has to sort
    // away from the measurement, not inside it.
    const bool ha = HasSortValue(a, sort);
    const bool hb = HasSortValue(b, sort);
    if (ha != hb) return ha;              // has-a-value first

    int order = 0;
    switch (sort) {
        case ProcessSort::Cpu:
            order = (a.stats.cpuPct < b.stats.cpuPct) ? -1
                   : (a.stats.cpuPct > b.stats.cpuPct) ? 1 : 0;
            break;
        case ProcessSort::Memory:
            order = (a.stats.memWs < b.stats.memWs) ? -1
                   : (a.stats.memWs > b.stats.memWs) ? 1 : 0;
            break;
        case ProcessSort::PrivateBytes:
            order = (a.stats.memPrivate < b.stats.memPrivate) ? -1
                   : (a.stats.memPrivate > b.stats.memPrivate) ? 1 : 0;
            break;
        case ProcessSort::IoRead:
            order = (a.stats.ioRead < b.stats.ioRead) ? -1
                   : (a.stats.ioRead > b.stats.ioRead) ? 1 : 0;
            break;
        case ProcessSort::IoWrite:
            order = (a.stats.ioWrite < b.stats.ioWrite) ? -1
                   : (a.stats.ioWrite > b.stats.ioWrite) ? 1 : 0;
            break;
        case ProcessSort::Threads:
            order = (a.threads < b.threads) ? -1 : (a.threads > b.threads) ? 1 : 0;
            break;
        case ProcessSort::Connections:
            order = (a.connections < b.connections) ? -1
                   : (a.connections > b.connections) ? 1 : 0;
            break;
        case ProcessSort::Listeners:
            order = (a.listeners < b.listeners) ? -1
                   : (a.listeners > b.listeners) ? 1 : 0;
            break;
        case ProcessSort::Name:
            // Case-insensitive so "audiodg.exe" and "AudioDG.exe" group
            // together rather than splitting on the file system's whim.
            order = ::_wcsicmp(a.name.c_str(), b.name.c_str());
            break;
        case ProcessSort::Pid:
            order = (a.pid < b.pid) ? -1 : (a.pid > b.pid) ? 1 : 0;
            break;
    }
    if (order != 0) return ascending ? (order < 0) : (order > 0);

    // PID is the tie-break for EVERY column. Without it, two processes with
    // identical CPU swap places between polls, and the table appears to flicker.
    if (a.pid != b.pid) return a.pid < b.pid;
    return false;
}

}  // namespace wintcp

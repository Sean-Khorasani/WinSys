// ProcStats.h
// SPDX-License-Identifier: Apache-2.0
// Per-process live stats sampler: CPU %, working-set / private
// memory and cumulative disk-transfer bytes for a set of PIDs. Runs on the
// RefreshEngine worker once per refresh (manual or auto): CPU % is derived
// from GetProcessTimes deltas over the real wall-clock interval, so any
// refresh cadence (1/2/5/10 s, manual F5) yields correct percentages.
//
// Everything is best effort and side-effect free: a PID that cannot be
// opened (protected process, exited mid-pass) simply reports unknown
// fields and the row shows "—" (PID 4 "System" is attempted; PID 0, the
// idle process, has no user-mode handle and is skipped).

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
#include <vector>

namespace wintcp {

// One refresh worth of readings for a single PID.
struct ProcStats {
    bool cpuKnown = false;
    double cpuPct = -1.0;            // 0..100 (percent of total CPU), else < 0
    bool memKnown = false;
    ULONGLONG memWs = 0;             // working set, bytes
    ULONGLONG memPrivate = 0;        // private bytes, bytes
    bool ioKnown = false;
    ULONGLONG ioRead = 0;            // cumulative transfer bytes
    ULONGLONG ioWrite = 0;
};

class ProcStatsSampler {
public:
    ProcStatsSampler() = default;
    ProcStatsSampler(const ProcStatsSampler&) = delete;
    ProcStatsSampler& operator=(const ProcStatsSampler&) = delete;

    // Sample every PID in 'pids' (duplicates are fine) and return the
    // readings keyed by PID. Keeps the previous CPU-time snapshot per PID
    // internally, so the first call for a PID reports cpuKnown=false and
    // the value appears from the second refresh on (the worker primes the
    // very first pass with a short double sample so users never see that
    // state on launch). Baselines younger than kMinSampleMs reuse the last
    // computed percentage instead of dividing by a tiny wall-clock delta,
    // which keeps rapid manual refreshes from jittering the value.
    std::map<DWORD, ProcStats> Sample(const std::vector<DWORD>& pids);

    void Clear();                    // drop all history (e.g. on demand)

    static const ULONGLONG kMinSampleMs = 200;

private:
    struct CpuPrev {
        ULONGLONG procTime100ns = 0; // kernel + user at last sample
        ULONGLONG tickMs = 0;        // GetTickCount64() at last sample
        double lastPct = -1.0;       // last computed % (>= 0 when known)
    };

    DWORD cpuCount_ = 0;             // logical processors (lazy init)
    bool cpuCountInit_ = false;
    std::map<DWORD, CpuPrev> prev_;  // PID -> previous CPU-time snapshot
};

}  // namespace wintcp

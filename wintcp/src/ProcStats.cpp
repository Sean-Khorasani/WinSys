// ProcStats.cpp
// SPDX-License-Identifier: Apache-2.0
// See ProcStats.h. One OpenProcess per PID per refresh (~3 cheap queries
// on the handle); failures degrade to "unknown", never to an error.

#include "ProcStats.h"

#include <psapi.h>

namespace wintcp {
namespace {

// FILETIME counts 100 ns intervals and GetTickCount64 counts milliseconds, so
// turning a tick delta into the FILETIME scale needs this factor; a wrong one
// silently rescales every CPU percentage rather than failing loudly.
constexpr ULONGLONG kFileTime100nsPerMs = 10000;

// CPU% is reported on a 0..100 scale so a value is renderable as-is. The clamp
// bounds and the initial scaling share the constant: a clamp expressed in a
// different scale from the value it bounds is how a "103%" row happens.
constexpr double kPctScale = 100.0;

ULONGLONG FileTimeToU64(const FILETIME& ft) {
    ULARGE_INTEGER u = {};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

}  // namespace

void ProcStatsSampler::Clear() {
    prev_.clear();
}

std::map<DWORD, ProcStats> ProcStatsSampler::Sample(
    const std::vector<DWORD>& pids) {
    if (!cpuCountInit_) {
        cpuCountInit_ = true;
        // GetSystemInfo reports only the primary processor group, which caps
        // the count at 64. On a multi-socket or high-core-count single CPU
        // (e.g. 96-thread Threadripper) the percentage figures would then
        // understate the machine's true capacity. GetActiveProcessorCount sums
        // every group when given ALL_PROCESSOR_GROUPS - but that entry point
        // does not exist on Windows 7, so resolve it dynamically rather than
        // forcing a hard dependency on a function the baseline OS cannot
        // provide. If it is missing, the old GetSystemInfo number is the
        // fallback: a 64-cap system is losing nothing on a Win7 box anyway.
        using GetActiveProcessorCountFn = DWORD(WINAPI*)(WORD);
        const HMODULE k32 = ::GetModuleHandleW(L"kernel32.dll");
        const auto fn = (k32 != nullptr)
            ? reinterpret_cast<GetActiveProcessorCountFn>(
                  ::GetProcAddress(k32, "GetActiveProcessorCount"))
            : nullptr;
        const DWORD n = (fn != nullptr) ? fn(ALL_PROCESSOR_GROUPS) : 0;
        if (n != 0) {
            cpuCount_ = n;
        } else {
            SYSTEM_INFO si = {};
            ::GetSystemInfo(&si);
            cpuCount_ = (si.dwNumberOfProcessors != 0) ? si.dwNumberOfProcessors : 1;
        }
    }

    std::map<DWORD, ProcStats> out;
    std::map<DWORD, bool> seen;   // sample each PID once per pass
    const ULONGLONG nowTick = ::GetTickCount64();

    for (const DWORD pid : pids) {
        // PID 0 is the idle process and has no user-mode handle; PID 4
        // ("System") is attempted and tolerated like any other process.
        if (pid == 0) continue;
        if (!seen.emplace(pid, true).second) continue;

        ProcStats ps;
        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                     PROCESS_VM_READ,
                                 FALSE, pid);
        if (h == nullptr) continue;   // exited / protected -> unknown

        // --- CPU times (need the handle before memory/IO anyway) ---------
        FILETIME cr {}, ex {}, kr {}, us {};
        if (::GetProcessTimes(h, &cr, &ex, &kr, &us)) {
            const ULONGLONG procTime =
                FileTimeToU64(kr) + FileTimeToU64(us);
            auto it = prev_.find(pid);
            if (it == prev_.end()) {
                prev_[pid] = CpuPrev{procTime, nowTick, -1.0};
            } else if (nowTick > it->second.tickMs &&
                       nowTick - it->second.tickMs >= kMinSampleMs) {
                const ULONGLONG wall100ns =
                    (nowTick - it->second.tickMs) * kFileTime100nsPerMs;
                if (procTime >= it->second.procTime100ns &&
                    wall100ns > 0) {
                    const double pct =
                        kPctScale *
                        static_cast<double>(procTime -
                                            it->second.procTime100ns) /
                        static_cast<double>(wall100ns) /
                        static_cast<double>(cpuCount_);
                    // Clamp: PID reuse between samples can produce wild
                    // deltas; the resolver owns recycle detection, here we
                    // just keep the display sane.
                    ps.cpuKnown = true;
                    ps.cpuPct = (pct < 0.0)   ? 0.0
                                : (pct > kPctScale) ? kPctScale
                                                    : pct;
                }
                it->second.procTime100ns = procTime;
                it->second.tickMs = nowTick;
                if (ps.cpuKnown) it->second.lastPct = ps.cpuPct;
            } else if (it->second.lastPct >= 0.0) {
                // Too soon since the last measurement (rapid manual
                // refresh / coalesced worker passes): keep the baseline
                // untouched and reuse the last percentage instead of
                // dividing by a tiny, jitter-prone wall-clock delta.
                ps.cpuKnown = true;
                ps.cpuPct = it->second.lastPct;
            }
        }

        // --- memory --------------------------------------------------------
        // NO GATE HERE, and that is deliberate. A DllAvailable("psapi.dll")
        // guard was added and then removed: psapi.h #defines
        // GetProcessMemoryInfo to K32GetProcessMemoryInfo, a KERNEL32 export, so
        // this call resolves out of kernel32 and psapi.dll is never loaded. The
        // gate would have been a LoadLibrary for nothing. See kDelayedDlls in
        // WinCaps.cpp - the link line is not evidence of a dependency.
        PROCESS_MEMORY_COUNTERS_EX pmc = {};
        pmc.cb = sizeof(pmc);
        if (::GetProcessMemoryInfo(
                h, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                sizeof(pmc))) {
            ps.memKnown = true;
            ps.memWs = pmc.WorkingSetSize;
            ps.memPrivate = pmc.PrivateUsage;
        }

        // --- disk / device transfer counters -------------------------------
        IO_COUNTERS io = {};
        if (::GetProcessIoCounters(h, &io)) {
            ps.ioKnown = true;
            ps.ioRead = io.ReadTransferCount;
            ps.ioWrite = io.WriteTransferCount;
        }

        ::CloseHandle(h);
        out.emplace(pid, ps);
    }

    // Forget PIDs we no longer see so a recycled PID cannot inherit a
    // stale CPU baseline (map stays proportional to the process count).
    for (auto it = prev_.begin(); it != prev_.end();) {
        if (seen.find(it->first) == seen.end())
            it = prev_.erase(it);
        else
            ++it;
    }
    return out;
}

}  // namespace wintcp

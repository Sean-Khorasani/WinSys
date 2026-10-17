// RefreshEngine.h
// SPDX-License-Identifier: Apache-2.0
// Background worker: enumerates endpoints, resolves processes and
// service names off the UI thread and hands a complete snapshot to a
// callback running on the worker thread (the UI posts it to itself).

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "Connection.h"
#include "ProcStats.h"

namespace wintcp {

struct RefreshResult {
    std::vector<Connection> rows;
    std::map<DWORD, std::wstring> services;   // PID -> service names
    std::map<DWORD, ProcStats> procStats;     // PID -> live stats
    std::map<DWORD, PidTraffic> traffic;      // PID -> bytes (fallback source)
    // Per-SOCKET counters from the same scan as `traffic`. Kept separate
    // because it answers a different question and only this one may mark a row
    // `perRowBytes` (the per-PID total cannot honestly be split across a
    // process's connections). Without it the Speed column is a permanent
    // em-dash: nothing in the tree ever set that flag.
    std::vector<SocketBytes> socketBytes;
    std::wstring error;                       // empty on success
    std::wstring timeText;                    // local time of the snapshot
};

// Refresh watchdog policy (R8): a pure decision function over timestamps, so
// the rule is pinnable headlessly and the window only executes it.
//
// A dead refresh worker is a frozen list that LOOKS alive — the most
// misleading failure this UI has. The watchdog arms on the status tick: past
// the threshold with no posted result (success OR error — either proves the
// worker alive), the view is declared stale and the worker restarted; past
// the restart cap, auto-refresh is switched off loudly rather than looped
// forever. Every bound below is part of the decision, so all three live here
// next to the function instead of scattered across the caller.
constexpr UINT kWatchdogIntervalFactor = 4;   // missed intervals before stale
constexpr ULONGLONG kWatchdogFloorMs = 15000;  // ...or this long, whichever is longer
constexpr int kMaxWatchdogRestarts = 3;      // then auto-refresh goes off, loudly

enum class WatchdogAction {
    Healthy,        // result recent enough; reset restart history
    StaleRestart,   // overdue: restart the worker once
    StaleGiveUp,    // overdue past the restart cap: switch auto-refresh off
};

inline WatchdogAction RefreshWatchdogNext(ULONGLONG nowMs, ULONGLONG baseMs,
                                          UINT intervalMs, int restarts) {
    // The floor dominates on fast cadences (4 x 2 s = 8 s would false-positive
    // on two consecutive slow passes), the factor dominates on slow ones (a
    // 60 s cadence that misses 4 ticks is 4 minutes of dead UI).
    const ULONGLONG threshold =
        (static_cast<ULONGLONG>(kWatchdogIntervalFactor) * intervalMs >
         kWatchdogFloorMs)
            ? static_cast<ULONGLONG>(kWatchdogIntervalFactor) * intervalMs
            : kWatchdogFloorMs;
    const ULONGLONG age = (nowMs >= baseMs) ? (nowMs - baseMs) : 0;
    if (age <= threshold) return WatchdogAction::Healthy;
    // Recovered workers are forgiven: a healthy age resets history at the
    // caller, so restarts only accumulate across CONSECUTIVE stale periods.
    if (restarts >= kMaxWatchdogRestarts) return WatchdogAction::StaleGiveUp;
    return WatchdogAction::StaleRestart;
}

class RefreshEngine {
public:
    // Invoked on the worker thread with an owned result; must not throw.
    using Callback = std::function<void(std::unique_ptr<RefreshResult>)>;

    // optional per-PID traffic source (the non-admin socket
    // fallback) sampled on the worker with the same PID set as procStats.
    // ETW totals are joined on the UI thread instead, so the callback
    // returning an empty map means "no fallback data this pass".
    using TrafficSource =
        std::function<std::map<DWORD, PidTraffic>(const std::vector<DWORD>&)>;

    // Same scan, per-SOCKET counters instead of per-PID. Separate from
    // TrafficSource so a caller that only wants process totals is never handed
    // numbers it might sum into an N-times-too-large process figure.
    using SocketByteSource =
        std::function<std::vector<SocketBytes>(const std::vector<DWORD>&)>;

    RefreshEngine() = default;
    ~RefreshEngine();

    RefreshEngine(const RefreshEngine&) = delete;
    RefreshEngine& operator=(const RefreshEngine&) = delete;

    // Spawn the worker. Returns false if already running.
    bool Start(Callback cb);

    // Arm (or disarm, with an empty function) the worker-side traffic
    // source. Call before Request()/Start(); guarded like cb_.
    void SetTrafficSource(TrafficSource src);

    // Arm the per-socket counter source. Like TrafficSource it is a UI-armed
    // side channel and disarms with an empty function.
    void SetSocketByteSource(SocketByteSource src);

    // Ask for a refresh. Coalesces: requests made while busy trigger exactly
    // one follow-up pass.
    void Request();

    // Signal stop and join the worker. Safe to call multiple times.
    void Stop();

    // Ask the worker to exit WITHOUT waiting: sets stop_ and wakes it, then
    // returns. The thread may still be inside a pass (or the kernel);
    // Running() reports when it is actually gone. For the watchdog, which
    // runs on the UI thread and must never block it — Stop() can wait up to
    // kEngineStopTimeoutMs. Safe to call multiple times, like Stop().
    void RequestStop();

    // Undo a RequestStop that proved premature: a result arriving after the
    // stop was asked means the worker was slow, not dead, and killing it
    // would inflict exactly the frozen list the watchdog exists to prevent.
    // Harmless if the thread already exited (the flag is then moot).
    void CancelStop();

    // Join an already-finished worker without blocking: returns true when no
    // thread is owned afterwards (already gone, or just reaped), false while
    // the thread still runs. Lets the watchdog restart a dead worker without
    // ever waiting on the UI thread. A detached (wedged-then-abandoned)
    // worker counts as gone — a replacement may transiently overlap it, which
    // the sink registry tolerates by design (see Stop()).
    bool ReapIfExited();

    bool Running() const { return thread_.joinable(); }

private:
    void Run();

    std::thread thread_;
    std::mutex m_;
    std::condition_variable cv_;
    bool stop_ = false;
    bool workPending_ = false;
    Callback cb_;
    TrafficSource trafficSource_;    // guarded by m_
    SocketByteSource socketByteSource_;  // guarded by m_
};

}  // namespace wintcp

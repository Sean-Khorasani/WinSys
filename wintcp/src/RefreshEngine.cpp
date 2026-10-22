// RefreshEngine.cpp
// SPDX-License-Identifier: Apache-2.0
// Worker thread: build one snapshot per pass and hand it to a callback.
// The snapshot itself comes from SnapshotSource, which is shared with the
// command line - this file is only the threading.

#include "RefreshEngine.h"

#include <unordered_set>

#include "ProcessInfo.h"
#include "Snapshot.h"
#include "Utils.h"

namespace wintcp {
namespace {

// How long Stop() waits for the worker before detaching it, and the slice it
// polls the join in. 8 s is deliberately longer than any bounded pass (the
// traffic scan's own ceiling is 4 s plus margin), so a detach means the worker
// is genuinely stuck in the kernel rather than merely slow. 50 ms slices keep
// shutdown responsive without spin-waiting.
constexpr ULONGLONG kEngineStopTimeoutMs = 8000;
constexpr DWORD kEngineStopPollMs = 50;

}  // namespace

RefreshEngine::~RefreshEngine() {
    Stop();
}

bool RefreshEngine::Start(Callback cb) {
    if (thread_.joinable()) return false;
    if (detachedRunning_.load()) return false;   // a detached worker may still be live
    {
        std::lock_guard<std::mutex> lk(m_);
        cb_ = std::move(cb);
        stop_ = false;
        workPending_ = true;   // do one pass right away
    }
    thread_ = std::thread([this] {
        Run();
        detachedRunning_.store(false);
    });
    return true;
}

void RefreshEngine::Request() {
    {
        std::lock_guard<std::mutex> lk(m_);
        if (stop_) return;
        workPending_ = true;
    }
    cv_.notify_all();
}

void RefreshEngine::SetTrafficSource(TrafficSource src) {
    std::lock_guard<std::mutex> lk(m_);
    trafficSource_ = std::move(src);
}

void RefreshEngine::SetSocketByteSource(SocketByteSource src) {
    std::lock_guard<std::mutex> lk(m_);
    socketByteSource_ = std::move(src);
}

void RefreshEngine::RequestStop() {
    {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = true;
        workPending_ = false;
    }
    cv_.notify_all();
}

void RefreshEngine::CancelStop() {
    {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = false;
        workPending_ = true;   // the cancelled stop stole a cycle: run now
    }
    cv_.notify_all();
}

bool RefreshEngine::ReapIfExited() {
    // No lock: thread_ is only ever touched from the owning (UI) thread —
    // the worker never touches it — so there is no race to guard. (Stop()
    // is likewise owner-called; shutdown joins from the same thread.)
    if (!thread_.joinable()) return true;
    if (::WaitForSingleObject(thread_.native_handle(), 0) != WAIT_OBJECT_0)
        return false;
    thread_.join();
    return true;
}

void RefreshEngine::Stop() {
    RequestStop();
    if (!thread_.joinable()) return;
    // Bounded join. A pass can be inside the socket-traffic scan, which is
    // itself bounded, but a pass must never be able to hold up shutdown
    // indefinitely: an unbounded join here is what made the app (and the UI
    // harness) look hung after finishing all its work. If the worker has not
    // finished shortly after the scan budget plus a margin, detach it.
    //
    // The detach is provably harmless, not hopefully so, by two mechanisms:
    //  1) Run() checks stop_ before invoking the callback, so a worker that
    //     finishes after Stop() drops its result instead of posting it.
    //  2) Even in the race between that check and the callback, the callback
    //     only touches the refcounted WorkerSink (payload registry) and the
    //     heap-owned fallback flag - never a MainWindow member - so running
    //     it against a destroyed window is safe. A PostMessage to the dead
    //     hwnd fails and the payload is deleted.
    const ULONGLONG deadline = ::GetTickCount64() + kEngineStopTimeoutMs;
    while (::GetTickCount64() < deadline) {
        if (::WaitForSingleObject(thread_.native_handle(), kEngineStopPollMs) ==
            WAIT_OBJECT_0) {
            thread_.join();
            return;
        }
    }
    detachedRunning_.store(true);
    thread_.detach();
}

void RefreshEngine::Run() {
    // The resolver, the CPU-baseline sampler and the GeoIP database all carry
    // state between passes by design, so they live in one SnapshotSource for
    // the life of the worker rather than being rebuilt each pass.
    SnapshotSource source;
    SnapshotOptions options;
    options.resolveProcesses = true;
    options.procStats = true;

    for (;;) {
        {
            std::unique_lock<std::mutex> lk(m_);
            cv_.wait(lk, [this] { return stop_ || workPending_; });
            if (stop_) return;
            workPending_ = false;
        }

        auto result = std::make_unique<RefreshResult>();
        // R2: a throwing pass posts an error, it never kills the worker. The
        // build below touches parsers, maps and callbacks — any of which can
        // throw on corrupt input — and an uncaught throw here is
        // std::terminate for the whole process.
        const std::string workerErr = RunGuarded([&] {
            Snapshot snap;
            if (source.Build(options, &snap)) {
                // non-admin per-PID TCP totals from the socket
                // fallback (armed by the UI only when the traffic columns are
                // visible and the ETW session could not start). Returns an
                // empty map when disarmed - one atomic check, no scan.
                //
                // This stays here rather than moving into SnapshotSource because
                // it is a UI-armed side channel: the sampler needs a window-owned
                // object, and a command line has no reason to run it.
                std::vector<DWORD> pids;
                pids.reserve(snap.rows.size());
                {
                    std::unordered_set<DWORD> seen;
                    seen.reserve(snap.rows.size());
                    for (const Connection& c : snap.rows)
                        if (seen.insert(c.identity.pid).second) pids.push_back(c.identity.pid);
                }
                TrafficSource traffic;
                SocketByteSource socketBytes;
                {
                    std::lock_guard<std::mutex> lk(m_);
                    traffic = trafficSource_;
                    socketBytes = socketByteSource_;
                }
                if (traffic) result->traffic = traffic(pids);
                // Per-socket counters, same scan, same arming flag. Read on the UI
                // side by ApplySocketBytes, which is the only thing allowed to set
                // a row's perRowBytes flag - the per-PID total cannot be split
                // honestly across a process's connections.
                if (socketBytes) result->socketBytes = socketBytes(pids);

                result->rows = std::move(snap.rows);
                result->services = std::move(snap.services);
                result->procStats = std::move(snap.procStats);
                result->timeText = std::move(snap.timeText);
            } else {
                result->error = std::move(snap.error);
                result->timeText = std::move(snap.timeText);
            }
        });   // RunGuarded
        if (!workerErr.empty()) {
            // Half a row set with real-looking values is worse than an
            // honestly failed tick, so a throwing pass carries only the error.
            // The UI already renders result->error (the snap.error path above).
            result->error = Utf8ToWide(workerErr.c_str());
        }

        Callback cb;
        {
            std::lock_guard<std::mutex> lk(m_);
            if (stop_) return;   // shutting down: drop the pass, post nothing
            cb = cb_;
            if (workPending_) {
                // A refresh was requested while we were busy: run again.
            }
        }
        if (cb) {
            // A throwing UI callback must not kill the worker either. Unlike
            // the build half there is nothing left to post through — the
            // callback IS the post — so a failed tick is dropped outright and
            // the next pass follows within one interval.
            (void)RunGuarded([&] { cb(std::move(result)); });
        }
        // Loop back; the predicate re-checks workPending_/stop_.
    }
}

}  // namespace wintcp

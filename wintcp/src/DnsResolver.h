// DnsResolver.h
// SPDX-License-Identifier: Apache-2.0
// Asynchronous reverse-DNS for remote endpoints: a dedicated
// worker thread resolves PTR records with getnameinfo(NI_NAMEREQD) while
// the UI thread keeps painting. Results (positive and negative) are cached
// per address; each result is delivered to a sink running on the worker
// thread, which normally posts it to the window.
//
// Known trade-off: getnameinfo has no timeout parameter, so the lookup is
// run on a *detached helper thread* per address, and the worker bounds its
// wait to a per-tick budget (kDnsTimeoutDefault, tunable via --dns-timeout).
// A lookup that exceeds the budget is reported back as "pending" - the cell
// shows `host: pending` instead of `—` - and the worker moves on to the
// next address WITHOUT being blocked by the stalled query. The helper
// thread runs to completion in the background and silently caches its result
// when it returns. This is the same "one stuck call costs one helper thread
// instead of the whole pool" shape SocketTrafficSampler uses for stalled
// getproc/GetExtendedTcpTable calls (see SocketTraffic.cpp:816).
//
// The old header claimed a cancellation timeout was impossible and
// that a worker pool would multiply DNS load for no win. That is no longer
// the shape: the worker stays single-threaded, the budget is a per-lookup
// ceiling (not the wait itself - the wait is the budget), and a one-shot CLI
// pass that asks for --dns still blocks for its answers (Lookup is still
// synchronous for the command line), but the GUI's refresh never stalls on a
// wedged resolver. A one-line advisory is emitted on stderr when lookups
// are abandoned as stalled, so a script reading stdout still sees a clean
// table and the count of pending lookups lives on stderr.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace wintcp {

class DnsResolver {
public:
    // Sentinel written into Result::hostname when a lookup exceeded the
    // per-tick budget but has not yet finished. Rendered as `host: pending`
    // so a row never looks resolved when its name is still in flight. The
    // empty-string case (a finished lookup with no PTR / a failure) is and
    // stays `host: —`.
    static constexpr const wchar_t* kPendingHost = L"...pending...";

    // Per-lookup budget in milliseconds. The worker waits at most this long
    // on a single getnameinfo call before abandoning it as stalled and moving
    // to the next queued address. Tuned for the GUI refresh cadence (one tick
    // must not be eaten by one wedged resolver).
    static constexpr unsigned kDnsTimeoutDefault = 3000;

    enum class State {
        kDone,      // hostname holds the finished answer ("" = no PTR)
        kPending,   // lookup exceeded the budget; helper still running
    };

    struct Result {
        std::wstring address;    // as given to Offer()
        std::wstring hostname;   // the finished name, or "" on failure
        State state = State::kDone;   // kPending while a lookup is still in flight
    };
    // Invoked on the worker thread; must not throw.
    using Sink = std::function<void(std::unique_ptr<Result>)>;

    DnsResolver() = default;
    ~DnsResolver();

    DnsResolver(const DnsResolver&) = delete;
    DnsResolver& operator=(const DnsResolver&) = delete;

    // Set the per-looked-up per-tick budget before Start. Zero = default.
    void SetTimeoutMs(unsigned ms) { timeoutMs_ = ms; }
    unsigned TimeoutMs() const { return timeoutMs_; }

    // Advisory sink for stalls only: one line per lookup that exceeded the
    // budget, written to stderr by the CLI so stdout stays byte-identical to
    // a run with no stalled resolvers. The GUI leaves this set to a no-op
    // (a stalled name simply shows `pending`). Optional; may be left empty.
    using StallSink = std::function<void(unsigned pendingCount, unsigned timeoutMs)>;
    void SetStallSink(StallSink s) { stallSink_ = std::move(s); }

    // Number of lookups abandoned as stalled since Start(). For the CLI's
    // "N lookup(s) exceeded..." advisory; the GUI reads StuckCount() to paint
    // a status hint.
    unsigned StuckCount() const { return stuck_.load(); }

    // Spawn the (idle until offers arrive) worker. False if already running.
    bool Start(Sink sink);

    // Stop and join the worker. Helper threads for in-flight lookups are
    // detached and run to completion in the background; the worker itself
    // joins promptly (it is only blocked on its cv_, not on getnameinfo).
    void Stop();

    // Gate: when disabled, queued lookups wait instead of running.
    void SetEnabled(bool on);
    bool Enabled() const { return enabled_.load(); }

    // Queue 'addr' for resolution unless it is empty, a wildcard ("*"),
    // already resolved (cached), or already queued.
    void Offer(const std::wstring& addr);

    void ClearCache();

    // One blocking reverse-DNS lookup. Returns "" when there is no PTR record
    // or the query fails.
    //
    // Public because the command line needs it: a one-shot pass has no worker
    // to hand results to, and asking for `--dns` should mean "wait for the
    // answers" rather than "print a frame of em-dashes and exit". The GUI does
    // NOT use this - it uses the worker above, so a slow query never stalls
    // painting. Both paths share the cache-free core (getnameinfo) so they
    // cannot disagree about what a given address resolves to.
    //
    // TimeoutMs bounds the CLI one-shot wait too. Pass 0 for the
    // default budget; a stuck helper here still blocks the CLI thread (the
    // CLI is opt-in and explicitly waits), but the bound is now configurable
    // instead of unbounded.
    static std::wstring Lookup(const std::wstring& addr,
                               unsigned timeoutMs = kDnsTimeoutDefault);

private:
    void Run();

    std::thread thread_;
    std::mutex m_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::atomic<bool> enabled_{false};
    std::deque<std::wstring> queue_;
    std::unordered_set<std::wstring> queued_;
    std::unordered_map<std::wstring, std::wstring> cache_;  // addr -> host ("" = none)
    // Insertion-order of cache_ keys, for the size cap. Offer() guarantees
    // each address is inserted at most once (it refuses an address already in
    // cache_ or queued_), so this stays a deduplicated queue: popping the
    // front is by construction a still-present cache_ key.
    std::deque<std::wstring> cacheOrder_;
    Sink sink_;
    // Per-lookup budget (ms). Zero at construction, defaulted at first Start.
    unsigned timeoutMs_ = kDnsTimeoutDefault;
    // Lookups abandoned as stalled since Start(). Read by StuckCount().
    std::atomic<unsigned> stuck_{0};
    // Optional advisory: one line per stall, on stderr. Set by the CLI;
    // the GUI leaves it null (pending is shown inline instead).
    StallSink stallSink_;
    // In-flight helpers: addr -> (done flag, result). The worker waits on
    // each helper's done flag up to timeoutMs_; a helper that finishes late
    // simply writes into cache_ when it returns and is dropped.
    struct InFlight {
        std::shared_ptr<std::atomic<bool>> done;
        std::shared_ptr<std::wstring> host;
        std::unique_ptr<Result> result;
    };
    std::unordered_map<std::wstring, InFlight> inFlight_;
};

}  // namespace wintcp

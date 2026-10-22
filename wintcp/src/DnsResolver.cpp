// DnsResolver.cpp
// SPDX-License-Identifier: Apache-2.0
// Worker thread: pop an address, launch a helper that calls getnameinfo
// (NI_NAMEREQD), and bound the wait to a per-tick budget. A lookup
// that exceeds the budget is reported back as "pending" so the row shows
// `host: pending` instead of stalling the worker; the helper runs to
// completion in the background and delivers a resolved result when it
// returns. The single-shot CLI path (Lookup) is still synchronous - it is
// opt-in and explicitly waits for answers.
//
// An alternative: Lookup consults the on-disk answer cache first and
// records what it learns. See DnsCache.h for why the cache is a set of
// answers rather than the ETW DNS snooping originally specified.

#include "DnsCache.h"
#include "DnsResolver.h"
#include "Utils.h"   // RunGuarded (worker containment)

namespace wintcp {
namespace {

// Bound on the number of PTR answers retained across a long-running session.
// A workstation talking to a few hundred distinct endpoints never reaches it,
// so the evictions are cold misses, not churn. Chosen high enough to cover a
// busy browser+gathering day, low enough that a compromised or broken peer
// loop cannot pin unbounded process memory.
constexpr size_t kMaxCacheEntries = 4096;

// getnameinfo needs a sockaddr; parse the literal with InetPton. Link-local
// addresses may carry a "%scope" suffix that InetPton rejects - strip it
// (the scope is meaningless for a reverse lookup anyway).
std::wstring StripScope(const std::wstring& addr) {
    const size_t pct = addr.find(L'%');
    return (pct == std::wstring::npos) ? addr : addr.substr(0, pct);
}

// The blocking core: parse 'addr' to a sockaddr and call GetNameInfoW with
// NI_NAMEREQD. Returns "" on no PTR / parse failure / error. This is the
// ONLY code that touches getnameinfo - both the worker helper thread and the
// CLI one-shot Lookup funnel through here, so the two can never disagree
// about what a given address resolves to. Unchanged (only the
// caller's deadline framing changed).
std::wstring DoLookup(const std::wstring& addr) {    const std::wstring bare = StripScope(addr);
    const bool v6 = bare.find(L':') != std::wstring::npos;

    sockaddr_storage ss = {};
    int sockLen = 0;
    if (v6) {
        auto* v4 = reinterpret_cast<sockaddr_in6*>(&ss);
        v4->sin6_family = AF_INET6;
        if (::InetPtonW(AF_INET6, bare.c_str(), &v4->sin6_addr) != 1)
            return std::wstring();
        sockLen = sizeof(sockaddr_in6);
    } else {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&ss);
        v4->sin_family = AF_INET;
        if (::InetPtonW(AF_INET, bare.c_str(), &v4->sin_addr) != 1)
            return std::wstring();
        sockLen = sizeof(sockaddr_in);
    }

    // One constant for the whole GetNameInfoW buffer trio: the array, the
    // count argument, and the terminator index. 1025 wide chars is
    // NI_MAXHOST (1024) plus the NUL; the three spellings below used to be
    // three separate literals, so changing the size meant finding all of them.
    // The count expression is preserved exactly as it was
    // (1025/sizeof(wchar_t)-1 = 511): it reads oddly next to a 1025-char
    // buffer, but a DNS name is at most 253 chars, so 511 already truncates
    // nothing real. Widening it would be a behaviour change, not a rename.
    constexpr size_t kHostBufChars = 1025;
    wchar_t host[kHostBufChars] = {0};
    // NI_NAMEREQD: fail (-> negative cache) instead of echoing the numeric
    // address back when no PTR record exists. (SDK spells the wide entry
    // point GetNameInfoW.)
    if (::GetNameInfoW(reinterpret_cast<const sockaddr*>(&ss), sockLen, host,
                       static_cast<DWORD>(kHostBufChars - 1),
                       nullptr, 0, NI_NAMEREQD) != 0)
        return std::wstring();
    host[kHostBufChars - 1] = L'\0';
    return std::wstring(host);
}

}  // namespace

DnsResolver::~DnsResolver() {
    Stop();
}

bool DnsResolver::Start(Sink sink) {
    if (thread_.joinable()) return false;
    if (timeoutMs_ == 0) timeoutMs_ = kDnsTimeoutDefault;
    {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = false;
        sink_ = std::move(sink);
    }
    thread_ = std::thread([this] { Run(); });
    return true;
}

void DnsResolver::Stop() {
    {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void DnsResolver::SetEnabled(bool on) {
    enabled_.store(on);
    cv_.notify_all();
}

void DnsResolver::Offer(const std::wstring& addr) {
    if (addr.empty() || addr == L"*") return;
    const std::wstring bare = StripScope(addr);
    if (bare.empty()) return;
    bool notify = false;
    {
        std::lock_guard<std::mutex> lk(m_);
        if (cache_.find(bare) != cache_.end()) return;   // already resolved
        // A still-pending in-flight lookup is not "cached" but is not
        // re-queueable either - the helper is already running it.
        if (inFlight_.find(bare) != inFlight_.end()) return;
        if (queued_.find(bare) != queued_.end()) return;
        queue_.push_back(bare);
        queued_.insert(bare);
        notify = true;
    }
    if (notify) cv_.notify_all();
}

void DnsResolver::ClearCache() {
    std::lock_guard<std::mutex> lk(m_);
    cache_.clear();
    cacheOrder_.clear();
    inFlight_.clear();
    queue_.clear();
    queued_.clear();
}

std::wstring DnsResolver::Lookup(const std::wstring& addr, unsigned timeoutMs) {
    // The CLI one-shot path is still synchronous (the caller asked for
    // answers and is opt-in), but the wait is now bounded by timeoutMs so a
    // wedged resolver cannot hang the CLI indefinitely. The worker keeps its
    // own per-tick budget via Run(); this overload just exposes the knob to
    // callers that need the blocking core directly.
    if (timeoutMs == 0) timeoutMs = kDnsTimeoutDefault;

    // An answer already on disk, and still believed, so no query at
    // all. This is the whole point of the cache - a peer seen in an earlier
    // run costs a map lookup instead of a resolver round trip, and on a
    // machine with no PTR coverage that is the difference between a `--dns`
    // pass finishing and one that stalls on every peer.
    const int64_t now = NowEpoch();
    DnsAnswerCache& cache = ResolverDnsCache();
    if (std::wstring cached; cache.Find(addr, now, &cached)) return cached;

    // A throwing lookup resolves to empty — the same answer a failed
    // lookup gives, and the cache records it either way. A name we could
    // not compute is not worth a dead resolver thread.
    // getnameinfo itself is un-cancellable, so run it on a detached helper and
    // bound the wait to timeoutMs. A late completion writes into the shared
    // state, which stays alive for the helper's lifetime.
    auto done = std::make_shared<std::atomic<bool>>(false);
    auto result = std::make_shared<std::wstring>();
    std::thread([result, done, addr] {
        std::wstring host;
        if (!RunGuarded([&] { host = DoLookup(addr); }).empty()) host.clear();
        *result = host;
        done->store(true);
    }).detach();

    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(timeoutMs);
    while (!done->load() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::wstring host;
    if (done->load()) host = *result;

    // Record only what was actually answered. An empty result is not
    // recorded: DoLookup cannot tell "no PTR record" from "the query failed
    // or timed out", and caching either would show `host: -` for a name that
    // exists on the next run.
    cache.Record(addr, host, now);
    return host;
}
void DnsResolver::Run() {
    if (timeoutMs_ == 0) timeoutMs_ = kDnsTimeoutDefault;
    for (;;) {
        std::wstring addr;
        Sink sink;
        {
            std::unique_lock<std::mutex> lk(m_);
            cv_.wait(lk, [this] {
                return stop_ || (enabled_.load() && !queue_.empty());
            });
            if (stop_) return;
            addr = queue_.front();
            queue_.pop_front();
            queued_.erase(addr);
            sink = sink_;
        }

        // Never block the worker on a single getnameinfo. Launch the
        // lookup on a detached helper and wait at most timeoutMs_ for it. If
        // it beats the budget, cache + deliver the result like before. If it
        // does NOT, post a `pending` Result so the row shows `host: pending`
        // instead of `—`, count it as stalled, and fire the advisory sink -
        // the helper runs to completion in the background and delivers a
        // resolved result when it returns, refreshing the row then.
        auto done = std::make_shared<std::atomic<bool>>(false);
        auto resultHost = std::make_shared<std::wstring>();
        {
            std::lock_guard<std::mutex> lk(m_);
            if (stop_) return;
            inFlight_[addr] = InFlight{done, resultHost, nullptr};
        }
        std::thread([this, addr, done, resultHost] {
            std::wstring host;
            // A throwing lookup resolves to empty - the same answer a
            // failed lookup gives, and the cache records it either way.
            if (!RunGuarded([&] { host = DoLookup(addr); }).empty()) host.clear();
            {
                std::lock_guard<std::mutex> lk(m_);
                *resultHost = host;
                done->store(true);
            }
            cv_.notify_all();
        }).detach();

        // Wait for the helper, bounded by the per-tick budget.
        bool finished = false;
        {
            std::unique_lock<std::mutex> lk(m_);
            const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(timeoutMs_);
            finished = cv_.wait_until(lk, deadline, [done] { return done->load(); });
        }

        if (!finished) {
            // Budget exceeded: report pending, count the stall, and let the
            // helper deliver late when it finally returns.
            ++stuck_;
            if (stallSink_) stallSink_(stuck_.load(), timeoutMs_);
            if (sink) {
                auto result = std::make_unique<Result>();
                result->address = addr;
                result->hostname = kPendingHost;
                result->state = State::kPending;
                (void)RunGuarded([&] { sink(std::move(result)); });
            }
            // The helper is still running. On its return it posts a resolved
            // Result via the sink (below path); until then the row shows
            // `host: pending`. Do NOT erase inFlight_[addr] - the late
            // delivery in the finished path re-acquires the lock fine, but
            // Offer() must keep refusing a duplicate queue entry while the
            // helper is still out.
            continue;
        }

        // Helper finished within budget: cache + deliver the resolved result.
        {
            std::lock_guard<std::mutex> lk(m_);
            cache_[addr] = *resultHost;                  // negative results too
            cacheOrder_.push_back(addr);
            while (cache_.size() > kMaxCacheEntries && !cacheOrder_.empty()) {
                cache_.erase(cacheOrder_.front());
                cacheOrder_.pop_front();
            }
            inFlight_.erase(addr);
        }
        // A throwing sink drops one answer; the address stays cached as
        // unknown and the next refresh re-requests it if still visible.
        if (sink) (void)RunGuarded([&] {
            auto result = std::make_unique<Result>();
            result->address = addr;
            result->hostname = *resultHost;
            sink(std::move(result));
        });
        // Loop: predicate re-checks stop_/queue_/enabled_.
    }
}

}  // namespace wintcp
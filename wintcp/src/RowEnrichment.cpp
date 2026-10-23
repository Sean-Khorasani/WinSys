// RowEnrichment.cpp
// SPDX-License-Identifier: Apache-2.0
// See RowEnrichment.h.

#include "RowEnrichment.h"

#include <algorithm>
#include <unordered_set>

namespace wintcp {

RowEnrichment::~RowEnrichment() { StopDnsWorker(); }

void RowEnrichment::StartDnsWorker(HWND hwnd,
                                   const std::shared_ptr<WorkerSink>& sink) {
    // The sink carries the window the results are posted to, and this is the
    // call that starts posting - so this is the call that sets it. The
    // refresh worker sets the same field for its own messages; relying on
    // whichever worker started first to fill it in would post results to a
    // null hwnd whenever the DNS worker ran before the refresh one.
    sink->hwnd = hwnd;
    // A per-lookup budget so a wedged resolver stalls at most one tick
    // instead of the whole queue. The row cells render `pending` for the rows
    // still in flight; the status-bar hint comes from the stall sink below.
    dns_.SetTimeoutMs(DnsResolver::kDnsTimeoutDefault);
    dns_.SetStallSink([sink](unsigned pending, unsigned /*ms*/) {
        // Post a status hint; the row cells already show `pending`. Guarded
        // so a late fire during shutdown does not dereference a torn-down
        // window.
        if (sink->hwnd != nullptr && !sink->shuttingDown)
            ::PostMessageW(sink->hwnd, WM_APP_DNS_STALLED,
                           static_cast<WPARAM>(pending), 0);
    });
    dns_.Start([sink](std::unique_ptr<DnsResolver::Result> r) {
        DnsResolver::Result* raw = r.release();
        bool registered = false;
        {
            std::lock_guard<std::mutex> lk(sink->m);
            if (!sink->shuttingDown) {
                sink->pendingDns.insert(raw);
                registered = true;
            }
        }
        if (registered) {
            // Guard against a null or closing sink hwnd: if the window is gone,
            // PostMessageW fails and we clean up the pending entry instead of
            // leaking it.
            if (sink->hwnd == nullptr || sink->shuttingDown) {
                std::lock_guard<std::mutex> lk(sink->m);
                if (sink->pendingDns.erase(raw) != 0) delete raw;
            } else if (::PostMessageW(sink->hwnd, WM_APP_DNS_RESULT, 0,
                                      reinterpret_cast<LPARAM>(raw)) == FALSE) {
                std::lock_guard<std::mutex> lk(sink->m);
                if (sink->pendingDns.erase(raw) != 0) delete raw;
            }
        } else {
            delete raw;
        }
    });
    dns_.SetEnabled(dnsEnabled_);
}

void RowEnrichment::StopDnsWorker() { dns_.Stop(); }

RowEnrichment::Effect RowEnrichment::OnDnsResult(
    DnsResolver::Result* payload, ConnectionStore& store,
    const std::shared_ptr<WorkerSink>& sink, bool filterActive) {
    if (payload == nullptr) return Effect::kNone;
    {
        std::lock_guard<std::mutex> lk(sink->m);
        if (sink->pendingDns.erase(payload) == 0)
            return Effect::kNone;   // not ours (freed during shutdown)
    }
    const std::unique_ptr<DnsResolver::Result> result(payload);
    if (!store.SetHostname(result->address, result->hostname))
        return Effect::kNone;
    // Hostname affects filtering and sorting only when one of them is in
    // play; otherwise a repaint is enough. Which sort column the store is
    // using is the store's own statement; whether a filter is active is the
    // caller's, and is passed in rather than guessed at here.
    if (store.SortColumn() == COL_HOST || filterActive)
        return Effect::kReapply;
    return Effect::kRepaint;
}

void RowEnrichment::OfferAll(ConnectionStore& store) {
    for (const Connection& r : store.Rows()) dns_.Offer(r.display.remoteAddress);
}

void RowEnrichment::OfferGeoIp(ConnectionStore& store) {
    if (!geo_.Loaded()) return;
    // The distinct-address memo is what keeps this cheap. A busy machine has
    // thousands of rows but far fewer distinct peers (every one of a
    // browser's connections to one CDN edge shares an address), and looking
    // each up again is pure waste. 'seen' is scoped to this call rather than
    // kept on the object: the row set is replaced wholesale on every refresh,
    // so a persistent cache would have to be invalidated anyway and a
    // per-pass set is provably correct with no invalidation logic to get
    // wrong.
    std::unordered_set<std::wstring> seen;
    seen.reserve(store.Rows().size());
    for (const Connection& r : store.Rows()) {
        if (r.display.remoteAddress.empty()) continue;
        if (!seen.insert(r.display.remoteAddress).second) continue;
        std::wstring code;
        if (r.identity.family == AF_INET) {
            // Rows carry the address as text, so parse back to the integer
            // the tree walk wants. A remote address in the store always came
            // from the stack, so this cannot fail; if it somehow does,
            // skipping is correct and must not blank a country another row
            // already set.
            in_addr v4 = {};
            if (::InetPtonW(AF_INET, r.display.remoteAddress.c_str(), &v4) != 1)
                continue;
            code = geo_.LookupV4(ntohl(v4.S_un.S_addr));
        } else {
            IN6_ADDR v6 = {};
            if (::InetPtonW(AF_INET6, r.display.remoteAddress.c_str(), &v6) != 1)
                continue;
            code = geo_.LookupV6(reinterpret_cast<const unsigned char*>(&v6));
        }
        // An empty code is written too: it clears a stale value when a peer
        // moves out of a covered range, and SetCountry is a no-op when the
        // value is already right, so this costs nothing.
        store.SetCountry(r.display.remoteAddress, code);
    }
}

void RowEnrichment::OfferAsn(ConnectionStore& store) {
    if (!asnGeo_.Loaded()) return;
    std::unordered_set<std::wstring> seen;
    seen.reserve(store.Rows().size());
    for (const Connection& r : store.Rows()) {
        if (r.display.remoteAddress.empty()) continue;
        if (!seen.insert(r.display.remoteAddress).second) continue;
        AsnInfo info;
        if (r.identity.family == AF_INET) {
            in_addr v4 = {};
            if (::InetPtonW(AF_INET, r.display.remoteAddress.c_str(), &v4) != 1)
                continue;
            info = asnGeo_.LookupAsnV4(ntohl(v4.S_un.S_addr));
        } else {
            IN6_ADDR v6 = {};
            if (::InetPtonW(AF_INET6, r.display.remoteAddress.c_str(), &v6) != 1)
                continue;
            info = asnGeo_.LookupAsnV6(reinterpret_cast<const unsigned char*>(&v6));
        }
        // Written even when empty: that clears a stale AS number when the file
        // is reloaded with different contents, exactly as the CLI path does.
        store.SetAsn(r.display.remoteAddress, info.number, info.org);
    }
}

bool RowEnrichment::LoadCountry(const std::wstring& path,
                                std::wstring* error) {
    return geo_.Load(path, error);
}

bool RowEnrichment::LoadAsn(const std::wstring& path, std::wstring* error) {
    return asnGeo_.Load(path, error);
}

void RowEnrichment::OfferLocalJoins(ConnectionStore& store) {
    OfferGeoIp(store);
    OfferAsn(store);
}

}  // namespace wintcp

// RowEnrichment.h
// SPDX-License-Identifier: Apache-2.0
//
// The per-row enrichment: reverse DNS, the country lookup and the ASN lookup.
//
// Extracted from MainWindow because the three have a shape the window does
// not: two are local and synchronous (a tree walk over a mapped file is
// microseconds), one is a worker thread with a queue and a per-lookup
// budget, and all three write into the same store column by column. The
// window's job with them is to offer, repaint and report - not to hold them.
//
// The interface is deliberately narrow in one direction: this class NEVER
// asks the window to do anything. The DNS result handler returns an effect
// the caller maps, so the enrichment layer cannot know a list view exists.
// The pickers stay in the window (they are dialogs, they write settings),
// and load through LoadCountry/LoadAsn with a plain path.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <memory>
#include <string>

#include "ConnectionStore.h"
#include "DnsResolver.h"
#include "GeoIp.h"
#include "WorkerSink.h"

namespace wintcp {

class RowEnrichment {
public:
    RowEnrichment() = default;
    ~RowEnrichment();

    RowEnrichment(const RowEnrichment&) = delete;
    RowEnrichment& operator=(const RowEnrichment&) = delete;

    // Start the DNS worker. 'sink' is the shared mailbox the results are
    // posted into; 'hwnd' is the window they are posted to. Idempotent.
    void StartDnsWorker(HWND hwnd, const std::shared_ptr<WorkerSink>& sink);

    // Stop the worker. Late callbacks stay harmless: the sink is shared and
    // outlives the worker, and a post to a dead hwnd just fails.
    void StopDnsWorker();

    // View > Resolve hostnames. Set before the worker starts where possible;
    // the resolver reads it at offer time either way.
    void SetDnsEnabled(bool on) { dnsEnabled_ = on; dns_.SetEnabled(on); }
    bool DnsEnabled() const { return dnsEnabled_; }

    // How many reverse lookups the resolver abandoned as stalled. The
    // IN-FLIGHT count does not come from here: it arrives through the stall
    // sink, because the resolver's own queue is behind a mutex and the
    // window needs the number on its own message anyway.
    unsigned DnsStalled() const { return dns_.StuckCount(); }

    // What the window should do about a DNS result. The caller maps these to
    // its own controls; this layer only reports which is needed.
    enum class Effect { kNone, kRepaint, kReapply };

    // Take ownership of a posted result, apply its hostname to the store, and
    // return the effect. 'filterActive' says the window currently filters:
    // a hostname can change which rows match, so a reapply is needed even
    // when the sort column is not the host. Removes the payload from the sink
    // first: a result that is not in the mailbox is not ours (it was freed
    // during shutdown).
    Effect OnDnsResult(DnsResolver::Result* payload, ConnectionStore& store,
                       const std::shared_ptr<WorkerSink>& sink,
                       bool filterActive);

    // Offer every row's remote address to the resolver. Called after every
    // refresh while DNS is on.
    void OfferAll(ConnectionStore& store);

    // Fill the Country column from the loaded MMDB, synchronously. A no-op
    // when no country database is loaded.
    void OfferGeoIp(ConnectionStore& store);

    // Fill the ASN half of Country. Separate from OfferGeoIp because the two
    // databases are independent: either may be loaded without the other, and
    // a row must be able to carry a country with no ASN or an ASN with no
    // country. It runs even when the COUNTRY database is absent - which is
    // the case that would otherwise silently do nothing.
    void OfferAsn(ConnectionStore& store);

    // Load a country database from a path the caller already chose. Returns
    // false with a reason in 'error' - reporting it is the caller's job,
    // because a modal dialog is a window concern.
    bool LoadCountry(const std::wstring& path, std::wstring* error);
    // Same for the ASN database.
    bool LoadAsn(const std::wstring& path, std::wstring* error);

    bool CountryLoaded() const { return geo_.Loaded(); }
    bool AsnLoaded() const { return asnGeo_.Loaded(); }

    // The path each database was loaded from, for the settings line and the
    // About box. Empty when the database is not loaded.
    const std::wstring& CountrySourcePath() const { return geo_.SourcePath(); }
    const std::wstring& AsnSourcePath() const { return asnGeo_.SourcePath(); }

    // Re-offer both local joins after a load, so the columns fill at once
    // rather than on the next refresh tick. Unused by the window today - each
    // picker offers only the database it just loaded - but it is the honest
    // one-call form for a caller that swapped both files, and a caller should
    // not have to know there are two.
    void OfferLocalJoins(ConnectionStore& store);

private:
    DnsResolver dns_;
    GeoIpDatabase geo_;
    GeoIpDatabase asnGeo_;
    bool dnsEnabled_ = false;
};

}  // namespace wintcp

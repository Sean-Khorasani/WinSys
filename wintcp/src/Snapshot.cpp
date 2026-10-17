// Snapshot.cpp
// SPDX-License-Identifier: Apache-2.0
// See Snapshot.h.

#include "Snapshot.h"

#include <unordered_set>

#include "ConnectionStore.h"
#include "DnsResolver.h"
#include "GeoIp.h"
#include "Opt.h"
#include "TcpTable.h"
#include "Utils.h"

namespace wintcp {

namespace {

// Gap between the two CPU-baseline samples on the first pass ever. CPU % is a
// rate between two reads, so one sample alone yields nothing; 250 ms is long
// enough for the counters to move on a busy machine and short enough that the
// first painted frame (or first CLI line) is not visibly delayed. Once per
// source, never again.
constexpr DWORD kCpuPrimeWaitMs = 250;

// Width of the one-line GeoIP description ("version, N records, N nodes, N
// bytes"). A database version string is bounded by the format itself, so this is
// slack rather than a measured maximum - swprintf_s truncates rather than
// overruns, which is the whole reason a fixed buffer is acceptable here.
constexpr size_t kGeoDescriptionChars = 160;

// The distinct PIDs in 'rows', in first-appearance order.
//
// One entry per DISTINCT process, not per row: the stat sampler and the socket
// traffic fallback each build lookup structures from this list, so a duplicated
// PID (a browser with 2000 sockets) turned one insert per PID into 2000.
//
// The dedup itself is wintcp::DistinctPidsOpt (Opt.cpp), which replaces the
// original's std::unordered_set - one heap-allocated node per insert - with a
// flat open-addressing table: one allocation, no node headers, no per-element
// construction. Measured 3.4x (2000 sockets / 12 processes) to 15x (200 rows,
// all distinct) on the A/B bench.
//
// The pids are flattened to one contiguous array first. That is an extra
// sequential pass, which is the cheap direction, and it is what lets the flat
// table take a pointer instead of an accessor.
std::vector<DWORD> DistinctPids(const std::vector<Connection>& rows) {
    std::vector<DWORD> pids(rows.size());
    for (size_t i = 0; i < rows.size(); ++i) pids[i] = rows[i].identity.pid;
    return DistinctPidsOpt(pids.data(), pids.size());
}

}  // namespace

bool SnapshotSource::Build(const SnapshotOptions& options, Snapshot* out) {
    if (out == nullptr) return false;
    *out = Snapshot();
    out->timeText = FormatCurrentTime();

    if (!EnumerateEndpoints(out->rows, out->error)) return false;

    if (options.resolveProcesses) {
        // Signature verification is configured by SnapshotSource::SetVerifySignatures, NOT here.
        //
        // It was briefly read from SnapshotOptions as well, and having two ways
        // to say the same thing was immediately a bug: CmdListInto set the
        // resolver's flag for --signatures, and this line then overwrote it with
        // options.verifySignatures - which no CLI caller fills in, because
        // BuildStoreSnapshot has no such parameter. So `--signatures` printed an
        // em-dash on every row while the advice had already promised a verdict.
        // One mechanism, set by each entry point before Build.
        resolver_.ResolveBatch(out->rows);
    }

    // The service map is one SCM enumeration regardless of how many rows ask
    // for it, and an empty result is not an error - the Service column is
    // optional decoration.
    QueryServiceNames(out->services);
    for (Connection& c : out->rows) {
        const auto it = out->services.find(c.identity.pid);
        if (it != out->services.end()) c.display.serviceName = it->second;
    }

    if (options.procStats) {
        const std::vector<DWORD> pids = DistinctPids(out->rows);
        if (!statsPrimed_) {
            // First pass ever: CPU % needs two samples to exist. Take a
            // baseline, wait a short moment, sample again, so the very first
            // painted frame (or the first CLI line) already shows a real value
            // instead of an em-dash. The wait is short and only ever happens
            // once per source.
            stats_.Sample(pids);
            ::Sleep(kCpuPrimeWaitMs);
            statsPrimed_ = true;
        }
        out->procStats = stats_.Sample(pids);
    }

    // DNS is resolved synchronously here, once per distinct peer. DnsResolver
    // has its own cached/threaded path for the GUI's live view; for a one-shot
    // pass a blocking lookup per peer is the honest cost of asking for it, and
    // it stays opt-in precisely because it can take seconds.
    if (options.resolveDns) {
        std::unordered_set<std::wstring> seen;
        for (Connection& c : out->rows) {
            if (c.display.remoteAddress.empty()) continue;
            if (!seen.insert(c.display.remoteAddress).second) continue;
            const std::wstring host = DnsResolver::Lookup(c.display.remoteAddress);
            if (!host.empty()) c.display.hostname = host;
        }
    }

    if (options.geoIp && geo_.Loaded()) {
        for (Connection& c : out->rows) {
            if (c.display.remoteAddress.empty()) continue;
            const std::wstring code = (c.identity.family == AF_INET6)
                ? geo_.LookupV6(c.identity.remote6.s6_addr)
                : geo_.LookupV4(ntohl(c.identity.remote4.S_un.S_addr));
            if (!code.empty()) c.enrichment.country = code;
        }
    }

    // FinalizeRow is what fills protoLabel/stateLabel/lower* - the fields the
    // column text, the filter and the CLI field table all read. It MUST run
    // after every enrichment above, or those fields describe a row that has
    // since gained a name, a country or a hostname.
    for (Connection& c : out->rows) ConnectionStore::FinalizeRow(c);

    return true;
}

void SnapshotSource::Clear() {
    resolver_.Clear();
    stats_.Clear();
    // The priming flag is deliberately NOT reset: the CPU baselines were just
    // dropped, so the next Sample reports cpuKnown=false for a pass. Priming
    // again would add another 250 ms stall for no benefit.
}

bool SnapshotSource::LoadGeoIp(const wchar_t* path, std::wstring* error) {
    if (path == nullptr || *path == L'\0') {
        if (error != nullptr) *error = L"No GeoIP database path was given.";
        return false;
    }
    return geo_.Load(path, error);
}

bool SnapshotSource::GeoIpLoaded() const { return geo_.Loaded(); }

std::wstring SnapshotSource::GeoIpLookupV4(uint32_t hostOrderAddr) const {
    if (!geo_.Loaded()) return L"";
    return geo_.LookupV4(hostOrderAddr);
}

std::wstring SnapshotSource::GeoIpDescription() const {
    if (!geo_.Loaded()) return L"no database loaded";
    wchar_t buf[kGeoDescriptionChars] = {0};
    ::swprintf_s(buf, L"%ls, %llu records, %llu nodes, %zu bytes",
                 geo_.DatabaseVersion().c_str(),
                 static_cast<unsigned long long>(geo_.RecordCount()),
                 static_cast<unsigned long long>(geo_.NodeCount()),
                 geo_.FileSize());
    return buf;
}

}  // namespace wintcp

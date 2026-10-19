// Snapshot.h
// SPDX-License-Identifier: Apache-2.0
// ONE connection-snapshot pipeline, shared by the GUI and the CLI.
//
// WHY THIS EXISTS. There used to be two implementations of "enumerate the
// machine's endpoints and fill in everything we know about them": the body of
// RefreshEngine::Run, and a private copy called BuildSnapshot in Cli.cpp. They
// were the same code written twice, and they had already drifted - the GUI
// samples per-process stats and can join traffic, the CLI copy did neither, so
// `--format full` printed em-dashes for every enriched column. A second copy of
// anything is a second thing to forget to update.
//
// The rule this file enforces: there is exactly one place that produces a
// snapshot, and no HWND appears anywhere in it. That is what makes the whole
// feature set reachable from a console, and what lets a command be tested
// without creating a window.
//
// THREADING. SnapshotSource is NOT thread-safe - it holds the process resolver
// and the CPU-baseline sampler, both of which carry state between passes by
// design. Give each thread its own instance. RefreshEngine owns one on its
// worker thread; the CLI owns one on its own thread; the selftests make their
// own. Copying the class is deliberately disallowed so nobody passes one
// across a thread boundary by value.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <map>
#include <string>
#include <vector>

#include "Connection.h"
#include "GeoIp.h"
#include "ProcessInfo.h"
#include "ProcStats.h"

namespace wintcp {

// What a pass should gather. Everything is optional and off by default except
// process resolution, so a caller that only wants the endpoint list pays for
// nothing more.
struct SnapshotOptions {
    // Resolve each row's owning process name/path. Cheap after the first pass
    // (the resolver caches per PID) and on by default: a row without a process
    // name is barely useful to anyone.
    bool resolveProcesses = true;

    // Sample CPU%, working set, private bytes and disk counters. Needs two
    // samples per PID before a percentage exists; the first pass primes it.
    bool procStats = false;

    // Reverse-DNS the remote address. Slow (one DNS query per distinct peer) and
    // blocking, so it is opt-in for both front ends.
    bool resolveDns = false;

    // Attach GeoIP country codes. Requires 'geoIpPath' to name a database.
    bool geoIp = false;
    const wchar_t* geoIpPath = nullptr;

    // NOTE: Authenticode verification is deliberately NOT one of these
    // options. It is configured by SetVerifySignatures below, and having both
    // was a bug rather than a convenience - see the note in Snapshot.cpp.
};

// One complete pass. Mirrors RefreshResult minus the UI-only traffic hook, so
// the engine can forward it without copying or reshaping.
struct Snapshot {
    std::vector<Connection> rows;
    std::map<DWORD, std::wstring> services;   // PID -> service names
    std::map<DWORD, ProcStats> procStats;     // PID -> live stats
    std::wstring error;                       // empty on success
    std::wstring timeText;                    // local time of the pass
};

// Gathers snapshots. Not thread-safe; one per thread.
class SnapshotSource {
public:
    SnapshotSource() = default;

    SnapshotSource(const SnapshotSource&) = delete;
    SnapshotSource& operator=(const SnapshotSource&) = delete;

    // One pass. Returns false and fills 'out->error' when enumeration itself
    // fails (the IP Helper call); an enrichment step failing is not fatal and
    // leaves the affected fields unknown, because a missing country code is not
    // a reason to show the user an empty list.
    bool Build(const SnapshotOptions& options, Snapshot* out);

    // Drop the per-PID caches (resolver, CPU baselines, GeoIP database). Called
    // when the user switches database or disables a source, so the next pass
    // reflects the change rather than a stale cached answer.
    void Clear();

    // Turn Authenticode verification on or off for subsequent passes.
    //
    // A setter rather than a BuildStoreSnapshot parameter because the resolver
    // is what holds the flag, and threading a seventh positional bool through
    // nine call sites is how one of them ends up forgotten - which here would
    // mean a `--signatures` run that silently printed no verdicts.
    void SetVerifySignatures(bool on) { resolver_.SetVerifySignatures(on); }

    // Ask GeoIP to attach codes on the next pass. Loading the database is
    // separated from building a pass so a load failure can be reported with its
    // own message instead of being reported as "enumeration failed".
    bool LoadGeoIp(const wchar_t* path, std::wstring* error);
    void UnloadGeoIp();
    bool GeoIpLoaded() const;
    // Look up a country code for a host-order IPv4 address.
    // Returns empty when no database is loaded or the address is not global.
    std::wstring GeoIpLookupV4(uint32_t hostOrderAddr) const;
    // Version / record count, for `wintcp geoip info` and the About box.
    std::wstring GeoIpDescription() const;

private:
    ProcessResolver resolver_;   // persistent cache across passes
    ProcStatsSampler stats_;     // persistent CPU baselines across passes
    bool statsPrimed_ = false;   // the two-sample priming has happened
    // Move-only (GeoIpDatabase owns a memory-mapped file); this class is
    // already non-copyable, so holding one by value costs nothing.
    GeoIpDatabase geo_;
};

}  // namespace wintcp

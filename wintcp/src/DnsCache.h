// DnsCache.h
// SPDX-License-Identifier: Apache-2.0
// The alternative: persist the reverse-DNS answers this tool already
// earns, so `host:` answers from disk on a later run instead of re-querying
// every peer.
//
// WHAT THIS IS NOT. It is not the ETW DNS snooping originally
// asked for. That route is not implementable on this machine - three elevated
// probes of `Microsoft-Windows-DNS-Client` {1C950233-...} delivered zero
// events, and a parser written against an assumed schema would have
// compiled, passed its own tests and silently never fired. Caching what the
// resolver already returns needs no provider, no elevation and no assumed
// event layout: the same answers, one run later.
//
// THE TWO RULES THAT KEEP THIS HONEST, both of them about a cache being able
// to answer WRONG rather than slowly:
//
//   1. POSITIVE ANSWERS ONLY. DoLookup returns "" both for "no PTR record"
//      and for "the query failed or timed out", and the caller cannot tell
//      them apart. Caching that "" would turn one unreachable resolver into
//      an hour of this machine showing `host: -` for names that do exist.
//      So only a non-empty answer is ever written down.
//
//   2. EVERY ANSWER EXPIRES. Reverse DNS for a dynamic address changes when
//      the address is reassigned. An entry older than kPositiveTtlHours is
//      ignored and the peer is re-queried, so a stale name costs accuracy
//      rather than being shown as fact. An entry dated in the FUTURE is
//      refused too, because that is the one way a file could pin an answer
//      forever - see DnsEntryFresh.
//
// A cache that cannot be written is a cache that does not happen: every write
// is best-effort and the resolver is strictly faster or identical without it.
// The file is data in %APPDATA%\WinTCP, alongside blocked.txt.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace wintcp {

// One remembered answer.
struct DnsCacheEntry {
    std::wstring address;      // the bare literal, scope suffix already gone
    std::wstring hostname;     // the PTR answer, verbatim
    int64_t solvedEpoch = 0;   // seconds since the UNIX epoch when recorded
};

// How long an answer is believed. 24 h: long enough that a peer seen in the
// morning still answers that afternoon, short enough that a reassigned
// address is re-resolved the next day rather than carrying yesterday's name
// indefinitely. Named so the docs, the parser test and the freshness test
// cannot quote three different numbers.
constexpr int kPositiveTtlHours = 24;

// Seconds since the UNIX epoch, from the system clock. One helper so the
// cache's writer, its freshness test and any status line read the same
// clock rather than three spellings of "now" that can disagree by a tick.
int64_t NowEpoch();

// Caps. 1 MiB is roughly 13 k lines at the ~80 bytes an entry costs, so it
// is over 3x the entry cap below - a file that big is one we wrote, or one we
// refuse whole rather than partially trust.
constexpr size_t kMaxCacheBytes = 1u * 1024u * 1024u;

// Entries kept in memory and on disk. Matches DnsResolver's in-memory cap
// (kMaxDiskCacheEntries) so the disk file cannot outgrow what the session would
// have held anyway; past this the oldest entries are dropped.
constexpr size_t kMaxDiskCacheEntries = 4096;

// Where the cache lives: %APPDATA%\WinTCP\dns-cache.txt. Empty string if the
// roaming folder cannot be determined, in which case every caller must simply
// do nothing (a cache we cannot locate is not an error the user needs).
std::wstring DnsCachePath();

// Least-significant-bits nicety: strip a "%scope" suffix. Link-local literals
// carry one and InetPtonW rejects it; DnsResolver::StripScope does the same
// job for its own key, and the two must agree or fe80::1%12 and fe80::1 would
// be two cache entries for one peer.
std::wstring StripAddressScope(const std::wstring& addr);

// Is 'addr' a literal worth keying on? Strictly an IPv4 or IPv6 address in
// InetPtonW terms - never a hostname, so a corrupted line cannot make the
// cache answer for a name it was never asked about.
bool IsCacheableAddress(const std::wstring& addr);

// Is 'host' a plausible PTR answer? A dot-separated run of DNS labels, total
// <= 253 chars, each label <= 63 and alphanumeric-edged (a trailing dot is
// allowed, because that is what a resolver may hand back). Refusing a shape
// that is not a DNS name is what stops a corrupt line from persisting junk
// and then displaying it as a peer's identity.
bool IsCacheableHostname(const std::wstring& host);

// Serialize 'entries'. Pure, so a test can pin the bytes.
std::string SerializeDnsCache(const std::vector<DnsCacheEntry>& entries);

// Parse the whole file text. Pure. Returns "" on success; otherwise a
// human-readable reason in *error and *out is left untouched.
//
// A line that is not what this module writes is SKIPPED, not fatal: one bad
// line in a file that is otherwise ours costs one entry, while failing the
// whole file would let a single odd byte disable the cache for everyone. The
// things that DO fail the parse are the ones where trusting part of the file
// is worse than trusting none of it - invalid UTF-8, or a size over
// kMaxCacheBytes - and both are reported with the reason.
bool ParseDnsCacheText(const std::string& utf8,
                       std::vector<DnsCacheEntry>* out,
                       std::wstring* error);

// Is this entry believed right now? Both directions are checked: too old is
// stale, implausibly new is a corrupt file (see kMaxClockSkewSec).
bool DnsEntryFresh(const DnsCacheEntry& e, int64_t nowEpoch);

// ---------------------------------------------------------------------------
// The cache itself.
//
// The path is injected so a test runs against a directory of its own, with
// no %APPDATA% and no machine state. 'nowEpoch' is passed in rather than read
// from the clock for the same reason: expiry is pinned by a test, not by when
// the test happened to run.
// ---------------------------------------------------------------------------
class DnsAnswerCache {
public:
    explicit DnsAnswerCache(std::wstring path, bool enabled = true);

    bool Enabled() const { return enabled_; }
    void SetEnabled(bool on) { enabled_ = on; }

    // A fresh answer for 'addr', or false. A hit after the load, and only
    // for an entry that survives the freshness test.
    bool Find(const std::wstring& addr, int64_t nowEpoch, std::wstring* host);

    // Learn a positive answer. Refuses to record anything that is not a
    // cacheable address and hostname pair, and refuses a negative - see rule
    // (1) in the header comment.
    void Record(const std::wstring& addr, const std::wstring& host,
                int64_t nowEpoch);

    // Counters, for tests and for a status line: what was read, how often a
    // query was avoided, how many answers were written.
    size_t LoadedCount() const { return loaded_; }
    size_t HitCount() const { return hits_; }
    size_t RecordedCount() const { return recorded_; }

private:
    bool EnsureLoaded();
    bool AppendLine(const DnsCacheEntry& e);
    void CompactIfNeeded();
    bool RewriteAll();

    std::wstring path_;
    bool enabled_;
    bool loadAttempted_ = false;   // one read per process, success or not
    std::vector<DnsCacheEntry> entries_;   // oldest first, as read
    size_t loaded_ = 0;                    // entries believed after the load
    size_t hits_ = 0;
    size_t recorded_ = 0;
    mutable std::mutex m_;
};

// The cache the resolver actually uses: one per process, at DnsCachePath(),
// enabled by default. A function-local static rather than a member because
// DnsResolver::Lookup is static and must stay so - the command line needs a
// blocking one-shot with no object to own.
DnsAnswerCache& ResolverDnsCache();

}  // namespace wintcp

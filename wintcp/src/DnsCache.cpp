// DnsCache.cpp
// SPDX-License-Identifier: Apache-2.0
// See DnsCache.h for why this exists at all and for the two rules - positive
// answers only, everything expires - that decide what it is willing to
// believe. The shape follows BlockConn's ledger: same %APPDATA%\WinTCP
// directory, same write-temp-then-rename atomicity, same strict UTF-8 read,
// same R3 size caps.

#include "DnsCache.h"

#include <shlobj.h>    // SHCreateDirectoryExW (shell32.lib, already linked)
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>

#include "Utils.h"   // WideToUtf8 / Utf8ToWide / ReadUtf8File / bufferWasTooSmall

namespace wintcp {
namespace {

// One line, tab-separated, CRLF-terminated like the ledger. Kept beside the
// parser so the two are read together; the header comment block is written
// here too, so a fresh file explains itself to whoever opens it.
constexpr const char* kHeaderComment =
    "# wintcp reverse-DNS answer cache\r\n"
    "# address<TAB>hostname<TAB>solved(epoch seconds)\r\n"
    "# One line per answer. Positive answers only: a peer with no PTR record\r\n"
    "# is not recorded, so a resolver failure can never be mistaken for one.\r\n"
    "# An answer is believed for 24 h, then re-resolved.\r\n"
    "# This file is data: deleting it costs a re-query, nothing more.\r\n";

// Kept in the header address only. This is a DNS NAME, not a search path:
// one trailing dot is what a resolver may hand back and is dropped before
// the label run is checked.
std::wstring TrimOneTrailingDot(const std::wstring& s) {
    if (s.size() >= 2 && s.back() == L'.') return s.substr(0, s.size() - 1);
    return s;
}

}  // namespace

int64_t NowEpoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::wstring StripAddressScope(const std::wstring& addr) {
    const size_t pct = addr.find(L'%');
    return (pct == std::wstring::npos) ? addr : addr.substr(0, pct);
}

bool IsCacheableAddress(const std::wstring& addr) {
    const std::wstring bare = StripAddressScope(addr);
    if (bare.empty()) return false;
    // InetPtonW is the same parser the resolver uses to turn a literal into a
    // sockaddr, so "cacheable" and "resolvable" cannot drift apart.
    {
        IN_ADDR v4 = {};
        if (::InetPtonW(AF_INET, bare.c_str(), &v4) == 1) return true;
    }
    {
        IN6_ADDR v6 = {};
        if (::InetPtonW(AF_INET6, bare.c_str(), &v6) == 1) return true;
    }
    return false;
}

bool IsCacheableHostname(const std::wstring& host) {
    // A name that came back empty is the negative case, which is never
    // recorded; anything here must therefore have at least one label.
    if (host.empty()) return false;
    if (host.size() > 253) return false;   // the DNS name limit, not a guess

    const std::wstring body = TrimOneTrailingDot(host);
    if (body.empty()) return false;        // "." or ".." and friends
    // Explicit ASCII, not iswalnum: what a resolver hands back for a
    // non-ASCII name is punycode, so a character outside ASCII is a sign the
    // line was not written by this module - and a locale-dependent predicate
    // is the wrong tool for a rule that must not move with the environment.
    for (const wchar_t c : body) {
        const bool ok = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                        (c >= L'0' && c <= L'9') || c == L'-' || c == L'.';
        if (!ok) return false;
    }

    size_t labelStart = 0;
    while (labelStart <= body.size()) {
        size_t dot = body.find(L'.', labelStart);
        if (dot == std::wstring::npos) dot = body.size();
        const size_t len = dot - labelStart;
        if (len == 0 || len > 63) return false;   // empty label: ".." or ".a."
        // Alphanumeric-edged. A leading or trailing '-' is not a legal host
        // name, and accepting one would widen the file's contents without
        // widening what a resolver would ever return.
        const wchar_t first = body[labelStart];
        const wchar_t last = body[dot - 1];
        const auto edge = [](wchar_t c) {
            return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                   (c >= L'0' && c <= L'9');
        };
        if (!edge(first) || !edge(last)) return false;
        for (size_t i = labelStart + 1; i + 1 < dot; ++i) {
            if (body[i] != L'-' && !edge(body[i])) return false;
        }
        if (dot == body.size()) break;
        labelStart = dot + 1;
    }
    return true;
}

std::string SerializeDnsCache(const std::vector<DnsCacheEntry>& entries) {
    std::string out(kHeaderComment);
    for (const DnsCacheEntry& e : entries) {
        // The tab-separated choice is the ledger's: an address contains no
        // tab by construction (InetPtonW already proved it is a literal) and
        // a hostname contains no tab either (see IsCacheableHostname), so the
        // format needs no escaping.
        out += WideToUtf8(e.address);
        out += '\t';
        out += WideToUtf8(e.hostname);
        out += '\t';
        out += std::to_string(e.solvedEpoch);
        out += "\r\n";
    }
    return out;
}

// Is every byte plain ASCII? Checked BEFORE anything is decoded, so the file
// is believed only once it has been proven to be bytes this module could have
// written. A byte above 0x7F is refused here rather than being handed to a
// loose decoder that would substitute U+FFFD and report success - which is
// how a corrupt line would otherwise become a hostname nobody wrote.
bool FieldIsAscii(const std::string& s) {
    for (const char c : s) {
        if (static_cast<unsigned char>(c) > 0x7F) return false;
    }
    return true;
}

bool ParseDnsCacheText(const std::string& utf8,
                       std::vector<DnsCacheEntry>* out,
                       std::wstring* error) {
    if (error != nullptr) error->clear();
    if (out == nullptr) {
        if (error != nullptr) *error = L"no output buffer";
        return false;
    }
    out->clear();
    if (utf8.size() > kMaxCacheBytes) {
        if (error != nullptr) {
            *error = L"dns cache is " + std::to_wstring(utf8.size()) +
                     L" bytes, over the " + std::to_wstring(kMaxCacheBytes) +
                     L"-byte limit; refused whole rather than read in part";
        }
        return false;
    }

    size_t pos = 0;
    const size_t n = utf8.size();
    size_t lines = 0;
    while (pos < n) {
        size_t eol = utf8.find('\n', pos);
        if (eol == std::wstring::npos) eol = n;
        std::string line = utf8.substr(pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        ++lines;
        // A comment line, or a blank one: not an entry, not an error.
        if (line.empty() || line[0] == '#') continue;

        // Exactly three fields. Anything else is a line we did not write, and
        // is skipped rather than trusted - see the header note about why one
        // bad line is not fatal for the whole file.
        const size_t f1 = line.find('\t');
        if (f1 == std::string::npos) continue;
        const size_t f2 = line.find('\t', f1 + 1);
        if (f2 == std::string::npos) continue;
        if (line.find('\t', f2 + 1) != std::string::npos) continue;

        const std::string addressUtf8 = line.substr(0, f1);
        const std::string hostUtf8 = line.substr(f1 + 1, f2 - f1 - 1);
        const std::string epochText = line.substr(f2 + 1);
        if (!FieldIsAscii(addressUtf8) || !FieldIsAscii(hostUtf8)) continue;

        // Only now is a field converted to wide. The input is proven ASCII,
        // so the conversion is lossless and the validators below can be exact
        // about what they accept.
        const std::wstring address = Utf8ToWide(addressUtf8.c_str());
        const std::wstring host = Utf8ToWide(hostUtf8.c_str());
        if (!IsCacheableAddress(address)) continue;
        if (!IsCacheableHostname(host)) continue;

        // All digits, and no overflow. strtoll's error reporting is not worth
        // trusting here: a hand-rolled digit scan is both stricter and clearer
        // about what is refused.
        int64_t epoch = 0;
        bool digitsOk = !epochText.empty();
        for (size_t i = 0; i < epochText.size(); ++i) {
            const char c = epochText[i];
            if (c < '0' || c > '9') { digitsOk = false; break; }
            const int64_t next = epoch * 10 + (c - '0');
            if (next < epoch) { digitsOk = false; break; }   // overflow
            epoch = next;
        }
        if (!digitsOk) continue;

        // A duplicate address is impossible in a file this module wrote
        // (Record is the only writer and it checks first), but a hand-edited
        // one can repeat. The later line wins, which is the reading a human
        // intends.
        bool replaced = false;
        for (DnsCacheEntry& e : *out) {
            if (e.address == address) {
                e.hostname = host;
                e.solvedEpoch = epoch;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            DnsCacheEntry e;
            e.address = address;
            e.hostname = host;
            e.solvedEpoch = epoch;
            out->push_back(std::move(e));
        }
        // A file over the entry cap is not refused - its oldest entries are
        // dropped on the next compaction - but a file with a pathological
        // number of VALID lines is worth noticing, so the load compacts.
    }
    if (out->size() > kMaxDiskCacheEntries) {
        out->erase(out->begin(),
                   out->begin() + static_cast<ptrdiff_t>(
                                      out->size() - kMaxDiskCacheEntries));
    }
    return true;
}

bool DnsEntryFresh(const DnsCacheEntry& e, int64_t nowEpoch) {
    if (e.address.empty() || e.hostname.empty()) return false;
    if (e.solvedEpoch <= 0) return false;
    // One rule, stated once: the answer is believed while its age is between
    // zero and the TTL.
    //
    // The lower bound is what makes the upper bound meaningful, and it is why
    // there is no separate "clock skew" tolerance. A timestamp in the future
    // is refused here already, so there is nothing for a skew allowance to
    // permit - and that is the one way a file could otherwise pin an answer
    // forever, by dating it so the age never reaches the TTL. Serving an
    // entry from the future buys nothing: at worst it costs one re-query
    // after a roaming profile moves between machines with clocks apart, and
    // the answer is then re-recorded against this machine's clock.
    const int64_t age = nowEpoch - e.solvedEpoch;
    const int64_t ttl = static_cast<int64_t>(kPositiveTtlHours) * 3600;
    return age >= 0 && age <= ttl;
}

std::wstring DnsCachePath() {
    // Same folder and same failure contract as BlockConn's ledger key: a
    // MAX_PATH*2 buffer (a deep roaming profile is the only way to reach
    // MAX_PATH), and the return value checked with bufferWasTooSmall rather
    // than == 0, because a too-small buffer makes the API report the required
    // size and leave the buffer EMPTY - the check that once produced the
    // relative path "\\WinTCP\\blocked.txt".
    wchar_t roaming[MAX_PATH * 2] = {0};
    const DWORD n = ::GetEnvironmentVariableW(L"APPDATA", roaming,
                                              MAX_PATH * 2);
    if (bufferWasTooSmall(n, MAX_PATH * 2) || roaming[0] == L'\0') {
        return std::wstring();
    }
    return std::wstring(roaming) + L"\\WinTCP\\dns-cache.txt";
}

DnsAnswerCache& ResolverDnsCache() {
    static DnsAnswerCache cache(DnsCachePath());
    return cache;
}

DnsAnswerCache::DnsAnswerCache(std::wstring path, bool enabled)
    : path_(std::move(path)), enabled_(enabled) {}

bool DnsAnswerCache::EnsureLoaded() {
    if (loadAttempted_) return true;
    loadAttempted_ = true;   // One attempt per process: a cache we could not
                             // read is not retried, so a broken file costs one
                             // failed read rather than one per peer.
    if (path_.empty()) return false;

    std::string text;
    const std::wstring readErr = ReadUtf8File(path_, &text);
    if (!readErr.empty()) {
        // A missing cache is the normal first-run case, not an error worth
        // reporting: the read helper says "file not found" in the same
        // message it uses for a real failure.
        return false;
    }
    std::vector<DnsCacheEntry> parsed;
    std::wstring parseErr;
    if (!ParseDnsCacheText(text, &parsed, &parseErr)) return false;

    // Only entries that are still believed are kept. Trimming here rather
    // than at write time means a file that grew past the cap (an older build,
    // a hand edit) is brought back under it on the next compaction instead of
    // growing forever.
    const int64_t now = NowEpoch();
    for (const DnsCacheEntry& e : parsed) {
        if (DnsEntryFresh(e, now)) entries_.push_back(e);
    }
    loaded_ = entries_.size();
    return true;
}

bool DnsAnswerCache::Find(const std::wstring& addr, int64_t nowEpoch,
                          std::wstring* host) {
    if (!enabled_ || host == nullptr) return false;
    const std::wstring key = StripAddressScope(addr);
    if (key.empty()) return false;
    std::lock_guard<std::mutex> lock(m_);
    (void)EnsureLoaded();
    for (const DnsCacheEntry& e : entries_) {
        if (e.address != key) continue;
        if (!DnsEntryFresh(e, nowEpoch)) continue;
        *host = e.hostname;
        ++hits_;
        return true;
    }
    return false;
}

void DnsAnswerCache::Record(const std::wstring& addr, const std::wstring& host,
                            int64_t nowEpoch) {
    if (!enabled_) return;
    const std::wstring key = StripAddressScope(addr);
    if (key.empty()) return;
    // Rule (1): positive answers only. A caller that learned nothing gets no
    // write, so a resolver failure or a timeout cannot be remembered as "this
    // peer has no name".
    if (host.empty()) return;
    if (!IsCacheableAddress(key)) return;
    if (!IsCacheableHostname(host)) return;

    std::lock_guard<std::mutex> lock(m_);
    (void)EnsureLoaded();

    for (DnsCacheEntry& e : entries_) {
        if (e.address != key) continue;
        // Already recorded and unchanged: nothing to write. Re-recording the
        // same pair is what a re-query after an expiry-free hit would do, and
        // a file line per run for the same peer is how a cache grows without
        // bound.
        if (e.hostname == host && DnsEntryFresh(e, nowEpoch)) return;
        // Same address, different answer. This is the live case in a
        // long-running process, not a defensive one: a --watch pass or the
        // GUI worker can re-resolve an address it learned earlier in this same
        // session, and a re-answered PTR has to displace the old one. The
        // in-memory copy is REPLACED so Find returns the newer answer, and the
        // file gets a new LINE rather than a rewrite - the parser reads a
        // repeated address as later-wins, so append and replace agree, and one
        // line costs O(1) where rewriting the file costs O(entries).
        e.hostname = host;
        e.solvedEpoch = nowEpoch;
        ++recorded_;
        (void)AppendLine(e);
        CompactIfNeeded();
        return;
    }

    DnsCacheEntry e;
    e.address = key;
    e.hostname = host;
    e.solvedEpoch = nowEpoch;
    entries_.push_back(std::move(e));
    ++recorded_;
    if (!AppendLine(entries_.back())) return;
    CompactIfNeeded();
}

bool DnsAnswerCache::AppendLine(const DnsCacheEntry& e) {
    if (path_.empty()) return false;
    const std::string line =
        WideToUtf8(e.address) + "\t" + WideToUtf8(e.hostname) + "\t" +
        std::to_string(e.solvedEpoch) + "\r\n";

    // The parent directory is created from the FINAL separator only, the same
    // derivation BlockConn uses after the version that cut at the wrong index
    // and turned the directory itself into "dns-cache.txt".
    const size_t sep = path_.find_last_of(L'\\');
    if (sep != std::wstring::npos) {
        ::SHCreateDirectoryExW(nullptr, path_.substr(0, sep).c_str(), nullptr);
    }

    // OPEN_ALWAYS + seek to end: an append, so the entry written after a
    // crash is the only thing lost, not the whole file. No lock file and no
    // rewrite for the common case, which is one new line.
    HANDLE f = ::CreateFileW(path_.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                             nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                             nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER seek = {};
    seek.QuadPart = 0;
    ::SetFilePointerEx(f, seek, nullptr, FILE_END);
    DWORD written = 0;
    const BOOL ok = ::WriteFile(f, line.data(),
                                static_cast<DWORD>(line.size()), &written,
                                nullptr);
    ::CloseHandle(f);
    return ok && written == line.size();
}

void DnsAnswerCache::CompactIfNeeded() {
    if (entries_.size() <= kMaxDiskCacheEntries) return;
    // Entries are oldest-first; drop the excess from the front, then rewrite.
    entries_.erase(entries_.begin(),
                   entries_.begin() + static_cast<ptrdiff_t>(
                                       entries_.size() - kMaxDiskCacheEntries));
    (void)RewriteAll();
}

bool DnsAnswerCache::RewriteAll() {
    if (path_.empty()) return false;
    const std::string text = SerializeDnsCache(entries_);
    if (text.size() > kMaxCacheBytes) {
        // Refuse rather than truncate: a rewrite that silently drops entries
        // is a cache that loses answers it promised to keep, and the caller
        // still has the in-memory copy for this run.
        return false;
    }
    const std::wstring tmp = path_ + L".tmp";
    HANDLE f = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = ::WriteFile(f, text.data(),
                                static_cast<DWORD>(text.size()), &written,
                                nullptr);
    ::CloseHandle(f);
    if (!ok || written != text.size()) {
        ::DeleteFileW(tmp.c_str());
        return false;
    }
    // Rename over the real file: atomic on NTFS, so a kill mid-run leaves
    // either the previous cache or this one, never a half-written one.
    if (!::MoveFileExW(tmp.c_str(), path_.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ::DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

}  // namespace wintcp

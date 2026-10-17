// SocketTraffic.cpp
// SPDX-License-Identifier: Apache-2.0
// See SocketTraffic.h. The core mechanism was validated before it was wired
// in: as a standard user, OpenProcess(PROCESS_DUP_HANDLE) + DuplicateHandle +
// WSAIoctl(SIO_TCP_INFO) returns the exact per-socket BytesIn/BytesOut of
// another process.

// mstcpip.h gates SIO_TCP_INFO / TCP_INFO_v0 behind
// NTDDI_VERSION >= NTDDI_WIN10_RS2, and sdkddkver.h derives NTDDI_VERSION
// from _WIN32_WINNT (the project builds with 0x0601/Win7, which hides both
// - verified: GATE-HIDDEN-WITH-0601). Bump the target to Win10 for THIS
// translation unit only so the declarations are visible; the ctor probes
// runtime support, so pre-1709 systems degrade gracefully (Supported()
// stays false, no fallback is armed, nothing is scanned).
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0A00

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>   // must precede windows.h
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>     // SIO_TCP_INFO + TCP_INFO_v0 (Win10-gated, see above)

#include <cstring>
#include <set>
#include <thread>

#include "SocketTraffic.h"
#include "Utils.h"   // RunGuarded (worker containment)

namespace wintcp {
namespace {

// Undocumented-but-stable system handle table (Process Explorer /
// Process Hacker lineage): class 64 = SystemExtendedHandleInformation.
const ULONG kSystemExtendedHandleInformation = 64;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);

// Growth policy for the system handle-table query: start at 1 MB (a full
// table is several MB, so this usually succeeds on attempt one or two), retry
// at most 8 times, and on a length-mismatch grow by the reported need plus a
// 1 MB margin — or double when the kernel reports no need. 8 attempts of
// doubling from 1 MB reaches 256 MB, past which the table is either corrupt or
// growing pathologically; either way more attempts only stall shutdown.
constexpr int kHandleQueryAttempts = 8;
constexpr ULONG kHandleQuerySlabBytes = 1u << 20;

// Poll slice for the two progress waits in this file (the scan loop and the
// exit settle). 5 ms is fine-grained next to the 250 ms no-progress budget it
// serves: the wait ends at most one slice late, and the slice itself costs
// nothing measurable. One constant for both sites so they cannot drift apart.
constexpr DWORD kScanPollMs = 5;

struct SysHandleEntry {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SysHandleInfoEx {
    ULONG_PTR count;
    ULONG_PTR reserved;
    SysHandleEntry handles[1];
};

using NtQuerySystemInformation_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

// Read a socket's cumulative byte counters AND its kernel-reported connection
// age via SIO_TCP_INFO. 'ageMs' may be null: a caller that only wants the
// counters (the support probe) pays nothing extra, and TCP_INFO_v0 predates
// the age field being useful everywhere, so a zero is a real answer meaning
// "not reported" rather than a failure.
// What TCP_INFO_v0 carries beyond the byte counters.
//
// UNITS, AND THE MISTAKE THIS STRUCTURE MAKES IMPOSSIBLE. RttUs and MinRttUs
// are MICROseconds - ConnectionTimeMs is the only Ms field in the struct - while
// `ss -i`, whose field names these columns copy, prints milliseconds. The
// conversion is done HERE, once, and the fields below are named Ms so no
// downstream consumer can read the raw value by accident. Verified by probe on
// this host: a socket with TCP timestamps on reported a 4-tuple RTT of a few
// hundred microseconds, i.e. a fraction of a millisecond, which is what a
// loopback/LAN path looks like and is exactly the value that would print as
// "12000 ms" if the field were consumed raw.
//
// Cwnd and BytesRetrans are byte counts in both, so they pass through.
//
// Per-field `known` flags, not one. The kernel populates TimestampsEnabled
// whether or not it can measure an RTT, and a socket with timestamps off has a
// perfectly real congestion window; collapsing that into a single `known` would
// report "no data" and lose the half that is real.
struct TcpInfoExtras {
    unsigned rttMs = 0;
    unsigned minRttMs = 0;
    ULONGLONG cwnd = 0;
    ULONGLONG retransBytes = 0;
    bool rttKnown = false;
    bool cwndKnown = false;
    bool retransKnown = false;
    bool timestamps = false;
    bool timestampsKnown = false;
};

// Microseconds -> milliseconds, rounded to nearest, saturating rather than
// wrapping. A helper because the rounding rule has to be identical on both
// fields: truncating 999999us to "999 ms" and rounding it to "1000 ms" are
// both defensible alone and inconsistent together, and a reader comparing rtt
// against minrtt would see minrtt exceed rtt for no reason.
// UsToMs's arithmetic, named because this helper is the ONE place a raw
// TCP_INFO_v0 microsecond value becomes a number the UI shows, and a unit
// scale guessed at there is invisible everywhere else. The clamp is one hour
// expressed in microseconds - a wider RTT is not a reading worth showing - and
// the rounding half is half a millisecond, so 999999 us reads as 1000 ms
// rather than 999.
constexpr ULONG kRttClampUs = 3600000UL;
constexpr ULONG kUsPerMs = 1000UL;
constexpr ULONG kUsHalfMs = 500UL;

inline unsigned UsToMs(ULONG us) {
    if (us >= kRttClampUs) return kRttClampUs / kUsPerMs * kUsPerMs;
    return static_cast<unsigned>((us + kUsHalfMs) / kUsPerMs);
}

bool QueryTcpInfo(HANDLE h, ULONGLONG* in, ULONGLONG* out,
                  ULONGLONG* ageMs = nullptr,
                  TcpInfoExtras* extras = nullptr) {
    TCP_INFO_v0 info = {};
    int version = 0;
    DWORD returned = 0;
    // version = 0, NOT 1. Measured: this kernel returns WSAEINVAL for
    // TCP_INFO_v1, so asking for it makes EVERY ioctl fail - which reads as
    // "Windows does not populate these fields" and would have been dropped on a
    // false negative. v0 is also a prefix of every later version, so it is the
    // safe request; the extras that only v1 adds (the send-throttle
    // breakdown) are not worth an ioctl that does not come back.
    if (::WSAIoctl(static_cast<SOCKET>(reinterpret_cast<ULONG_PTR>(h)),
                   SIO_TCP_INFO, &version, sizeof(version), &info,
                   sizeof(info), &returned, nullptr, nullptr) != 0) {
        return false;
    }
    *in = info.BytesIn;
    *out = info.BytesOut;
    if (ageMs != nullptr) *ageMs = info.ConnectionTimeMs;
    if (extras != nullptr) {
        extras->rttMs = UsToMs(info.RttUs);
        extras->minRttMs = UsToMs(info.MinRttUs);
        extras->cwnd = info.Cwnd;
        extras->retransBytes = info.BytesRetrans;
        // An RTT of zero is not a reading of "zero latency" - it is "no RTT
        // available". So the test is the VALUE, not the timestamp flag.
        //
        // MEASURED, and this is why the obvious version is wrong: the first
        // version required `TimestampsEnabled && RttUs > 0`, reasoning that an
        // RTT is meaningless without TCP timestamps. The probe on this host
        // refuted it immediately - three readable sockets, ALL with ts=0, and
        // two of them reporting a perfectly good RTT:
        //     st=4 ts=0 mss=1460 rtt=23512us/15664us cwnd=16922
        //     st=4 ts=0 mss=536  rtt=86901us/79198us cwnd=1041
        // The kernel estimates RTT from its own retransmit timer when
        // timestamps are unavailable, and that estimate is good enough to be
        // worth showing. Requiring timestamps would have shipped a column that
        // is blank on every connection on this machine - a plausible-looking
        // implementation of a feature that never fires.
        //
        // So: TimestampsEnabled is reported as its own fact (it changes how much
        // the RTT can be trusted) and does not gate the value.
        extras->rttKnown = info.RttUs > 0;
        extras->cwndKnown = info.Cwnd > 0;
        extras->retransKnown = true;   // 0 is a real answer: no retransmits
        extras->timestamps = info.TimestampsEnabled != 0;
        extras->timestampsKnown = true;
    }
    return true;
}

// Capacity of the address text buffer below, in wchar_t (NOT bytes).
//
// WHY THIS EXISTS, because the four call sites used to say `sizeof(buf) / 2`
// and that is the "reconstruct a buffer size from far away" problem:
// the /2 is only correct because sizeof(wchar_t) == 2, which is a platform
// assumption stated nowhere, and a reader has to work it out to check the
// bound. InetNtopW counts wchar_t, not bytes, so the argument must be a
// character count and the arithmetic must not hide inside a division.
//
// The number itself, derived rather than guessed:
//   INET6_ADDRSTRLEN (46) is the longest IPv6 text form INCLUDING the NUL, so
//   that is what InetNtopW needs for AF_INET6. kScopeSuffixMaxChars (8) is the
//   longest scope suffix Ipv6ScopeSuffix can append: "%" plus a uint32, which
//   is at most 10 digits, so 11 - and 8 is not enough for that. See the
//   static_assert below; it fails to compile if either assumption stops holding.
constexpr size_t kScopeSuffixMaxChars = 12;   // '%' + up to 10 digits + slack
constexpr size_t kAddrTextChars = INET6_ADDRSTRLEN + kScopeSuffixMaxChars;
static_assert(kScopeSuffixMaxChars >= 11,
              "a scope id is a uint32: '%' plus ten digits plus the NUL");
static_assert(kAddrTextChars >= INET6_ADDRSTRLEN,
              "InetNtopW needs INET6_ADDRSTRLEN for AF_INET6");

// The socket's 4-tuple in the printable form the store keys on, so a sampled
// age can be matched to the row that owns it. Best effort: a listening socket
// has no peer and reports 0, which simply yields no entry.
void QuerySocketEndpoints(HANDLE h, std::wstring* local, UINT* localPort,
                          std::wstring* remote, UINT* remotePort) {
    SOCKET s = static_cast<SOCKET>(reinterpret_cast<ULONG_PTR>(h));
    wchar_t buf[kAddrTextChars] = {0};
    sockaddr_storage ss = {};
    int len = sizeof(ss);
    const int gsn = ::getsockname(s, reinterpret_cast<sockaddr*>(&ss), &len);
    if (gsn == 0 && len >= static_cast<int>(sizeof(sockaddr))) {
        if (ss.ss_family == AF_INET) {
            const auto* a = reinterpret_cast<const sockaddr_in*>(&ss);
            if (::InetNtopW(AF_INET, &a->sin_addr, buf,
                            static_cast<DWORD>(kAddrTextChars)) != nullptr)
                *local = buf;
            *localPort = ::ntohs(a->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            const auto* a = reinterpret_cast<const sockaddr_in6*>(&ss);
            if (::InetNtopW(AF_INET6, &a->sin6_addr, buf,
                            static_cast<DWORD>(kAddrTextChars)) != nullptr) {
                *local = buf;
                // The scope suffix follows the store's rule (Ipv6ScopeSuffix),
                // because this string is matched against the store's own
                // rendering to find the row that owns the socket.
                //
                // C2: this site used to append the scope for ANY nonzero
                // sin6_scope_id, which is a different rule from the store's
                // (fe80::/10 only). They agreed on every link-local address —
                // the case the old comment named — and disagreed on a
                // non-link-local socket carrying a scope id, where this side
                // printed a suffix the store did not. That is a silently
                // missed join, i.e. a blank Speed cell on a live connection,
                // so one rule now serves both sides.
                *local += Ipv6ScopeSuffix(a->sin6_addr.s6_addr,
                                          static_cast<unsigned>(a->sin6_scope_id));
            }
            *localPort = ::ntohs(a->sin6_port);
        }
    }
    len = sizeof(ss);
    if (::getpeername(s, reinterpret_cast<sockaddr*>(&ss), &len) == 0 &&
        len >= static_cast<int>(sizeof(sockaddr))) {
        if (ss.ss_family == AF_INET) {
            const auto* a = reinterpret_cast<const sockaddr_in*>(&ss);
            if (::InetNtopW(AF_INET, &a->sin_addr, buf,
                            static_cast<DWORD>(kAddrTextChars)) != nullptr)
                *remote = buf;
            *remotePort = ::ntohs(a->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            const auto* a = reinterpret_cast<const sockaddr_in6*>(&ss);
            if (::InetNtopW(AF_INET6, &a->sin6_addr, buf,
                            static_cast<DWORD>(kAddrTextChars)) != nullptr) {
                *remote = buf;
                // Same rule as the local half above; see the comment there.
                *remote += Ipv6ScopeSuffix(a->sin6_addr.s6_addr,
                                           static_cast<unsigned>(a->sin6_scope_id));
            }
            *remotePort = ::ntohs(a->sin6_port);
        }
    }
}

// SIO_TCP_INFO exists only on Windows 10 1709+. Probe it with a
// self-connected loopback TCP socket so older systems report "unsupported"
// instead of scanning handles that can never answer.
bool ProbeTcpInfoSupport() {
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return false;

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    bool ok = false;
    if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(listener, 1) == 0) {
        int addrLen = sizeof(addr);
        if (::getsockname(listener, reinterpret_cast<sockaddr*>(&addr),
                          &addrLen) == 0) {
            SOCKET client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (client != INVALID_SOCKET &&
                ::connect(client, reinterpret_cast<sockaddr*>(&addr),
                          sizeof(addr)) == 0) {
                SOCKET peer = ::accept(listener, nullptr, nullptr);
                if (peer != INVALID_SOCKET) {
                    ULONGLONG in = 0, out = 0;
                    ok = QueryTcpInfo(
                        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(client)),
                        &in, &out);
                    ::closesocket(peer);
                }
            }
            if (client != INVALID_SOCKET) ::closesocket(client);
        }
    }
    ::closesocket(listener);
    return ok;
}

// Read the system-wide handle table into 'buf', growing it as needed.
// Returns false only if the query is unavailable or genuinely fails; on
// failure 'buf' is left holding the previous pass's contents.
bool FetchSystemHandleTable(std::vector<BYTE>& buf) {
    static NtQuerySystemInformation_t ntqsi = [] {
        return reinterpret_cast<NtQuerySystemInformation_t>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                             "NtQuerySystemInformation"));
    }();
    if (ntqsi == nullptr) return false;

    // The buffer is reused across passes and only ever grows.
    ULONG len = buf.empty() ? kHandleQuerySlabBytes : static_cast<ULONG>(buf.size());
    for (int attempt = 0; attempt < kHandleQueryAttempts; ++attempt) {
        buf.resize(len);
        ULONG need = 0;
        const LONG status = ntqsi(kSystemExtendedHandleInformation, buf.data(),
                                  len, &need);
        if (status >= 0) return true;
        if (status == kStatusInfoLengthMismatch) {
            len = (need > len) ? need + kHandleQuerySlabBytes : len * 2;
            continue;
        }
        break;   // any other failure: caller keeps the previous totals
    }
    return false;
}

}  // namespace

SocketTrafficSampler::SocketTrafficSampler() {
    supported_ = ProbeTcpInfoSupport();
    if (supported_) socketTypes_ = LearnOwnSocketTypes();
}

// Learn which object-type indices the kernel gives to sockets, by matching
// our own known-good sockets against our own handle table.
//
// This is not an optimisation, it is a correctness requirement for the first
// refresh. The scan filters on socket object types to avoid touching the
// system's other tens of thousands of file/key/thread handles, but that
// filter is only usable once the set is non-empty. Before this existed the
// first pass issued one SIO_TCP_INFO per handle in the whole system: the
// list stayed empty for minutes instead of milliseconds, because the
// refresh result could not complete until a full-system sweep finished.

std::unordered_set<USHORT> SocketTrafficSampler::LearnOwnSocketTypes() {
    std::unordered_set<USHORT> types;
    // A connected loopback pair, so the sockets are unambiguously TCP.
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return types;
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    SOCKET client = INVALID_SOCKET, peer = INVALID_SOCKET;
    if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0 &&
        ::listen(listener, 1) == 0) {
        int addrLen = sizeof(addr);
        if (::getsockname(listener, reinterpret_cast<sockaddr*>(&addr),
                          &addrLen) == 0) {
            client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (client != INVALID_SOCKET &&
                ::connect(client, reinterpret_cast<sockaddr*>(&addr),
                          sizeof(addr)) == 0) {
                peer = ::accept(listener, nullptr, nullptr);
            }
        }
    }
    if (peer == INVALID_SOCKET) {   // no pair: cannot learn anything
        if (client != INVALID_SOCKET) ::closesocket(client);
        ::closesocket(listener);
        return types;
    }

    const DWORD self = ::GetCurrentProcessId();
    std::vector<BYTE> buf;
    if (FetchSystemHandleTable(buf)) {
        const auto* info = reinterpret_cast<const SysHandleInfoEx*>(buf.data());
        for (ULONG_PTR i = 0; i < info->count; ++i) {
            const SysHandleEntry& e = info->handles[i];
            if (e.UniqueProcessId != self) continue;
            const ULONG_PTR v = e.HandleValue;
            if (v == static_cast<ULONG_PTR>(listener) ||
                v == static_cast<ULONG_PTR>(client) ||
                v == static_cast<ULONG_PTR>(peer)) {
                types.insert(e.ObjectTypeIndex);
            }
        }
    }

    ::closesocket(peer);
    if (client != INVALID_SOCKET) ::closesocket(client);
    ::closesocket(listener);
    return types;
}

SocketTrafficSampler::~SocketTrafficSampler() = default;

std::map<DWORD, PidTraffic> SocketTrafficSampler::Sample(
    const std::vector<DWORD>& pids) {
    if (supported_ && !pids.empty()) {
        // One pass at a time, run ON THIS THREAD.
        //
        // Previously this function started a detached thread and then waited up
        // to the budget for it, because the walk itself issued the ioctls and
        // could therefore be wedged. Now the walk only does bookkeeping, which
        // always terminates; the ioctls run on kProbeWorkers detached threads,
        // and this thread waits on `finished` - a counter, not a join. So the
        // caller is never blocked by a socket that will not answer, which is
        // the entire point of the change.
        std::lock_guard<std::mutex> lk(stateLock_);
        if (scanInFlight_) return Totals(pids);   // never nested
        scanInFlight_ = true;
        scanAbandoned_ = false;
        ++generation_;
    }

    // The scratch is HEAP allocated and outlives this function whenever a
    // worker does not finish: a worker still inside the kernel holds this
    // pointer, so a stack local would dangle the moment Sample returns.
//
// ScratchOwner, not a bare pointer, and not a plain unique_ptr either -
// see its definition for why the "is a worker still live" test has to live in
    // a destructor. The short version: it is now freed on an unwind when the
// // free is safe, which the raw `new`/`delete` pair could not do.
    ScratchOwner scratchHolder(new ScanScratch());
    ScanScratch* const scratch = scratchHolder.get();
    scratch->generation = generation_;
    {
        std::lock_guard<std::mutex> lk(stateLock_);
        scratch->socketTypes = socketTypes_;
        scratch->typesKnown = !socketTypes_.empty();
    }
    scratch->pids = pids;

    // Whole-pass failure, as opposed to one socket stalling: if the handle
    // table could not be read at all there is nothing to merge, and merging a
    // partial pass would retire live sockets.
    bool tableOk = false;
    try {
        ScanHandles(*scratch);
        tableOk = true;
    } catch (...) {
        tableOk = false;
    }
    // A whole-pass failure used to end here: `tableOk` stayed false, the merge
    // below was skipped on both branches, and the caller saw an empty table with
    // nothing to indicate why. The consequence is real - merging a partial pass
    // would retire live sockets, so skipping is CORRECT - but correct-and-
    // silent is what makes a bug survive a year. Counted, and the count is
    // read by ScanFailureCount() so a consumer can name the cause.
    if (!tableOk) scanFailures_.fetch_add(1, std::memory_order_relaxed);

    // Wait for the WORKERS - but on PROGRESS, not on a deadline.
    //
    // A fixed budget is the wrong shape now that the walk cannot stall. It
    // answered a question nobody is asking any more: "how long might a socket
    // take?" The question is "are the workers still getting anywhere?", and
    // that has a much better answer available. Measured before this change:
    // a one-shot `list --traffic` took 8.3 s on this host, because a stalled
    // worker can never make progress, so the full kScanTimeoutMs elapsed and
    // then ShutdownScanForExit() waited out its own budget for the same thread.
    // Neither wait could ever have produced anything.
    //
    // So: keep waiting only while `finished` is still moving. A healthy pass
    // reads hundreds of sockets in milliseconds and is bounded by
    // kScanTimeoutMs exactly as before; a pass with a wedged worker gives up
    // after kNoProgressMs, because nothing after that point can arrive.
    const ULONGLONG hardDeadline =
        ::GetTickCount64() + static_cast<ULONGLONG>(kScanTimeoutMs);
    bool workersDone = scratch->queue.empty();
    size_t lastFinished = scratch->finished.load(std::memory_order_acquire);
    ULONGLONG lastProgress = ::GetTickCount64();
    while (!workersDone) {
        const size_t now = scratch->finished.load(std::memory_order_acquire);
        if (now >= scratch->queue.size()) {
            workersDone = true;
            break;
        }
        if (now != lastFinished) {
            lastFinished = now;
            lastProgress = ::GetTickCount64();
        } else if (::GetTickCount64() - lastProgress >=
                       static_cast<ULONGLONG>(kNoProgressMs) ||
                   ::GetTickCount64() >= hardDeadline) {
            break;
        }
        ::Sleep(kScanPollMs);
    }

    // A target whose slot was handed out but never finished is a socket
    // whose SIO_TCP_INFO has not returned. Remember it, so no later pass
    // spends another wedged worker on it. A target the cursor never REACHED is
    // deliberately not remembered: that one is merely work the budget ran out
    // on, and it may well be readable next tick.
    {
        const size_t cap = scratch->queue.size();
        const size_t reached = scratch->cursor.load(std::memory_order_acquire);
        const size_t doneCount =
            scratch->finished.load(std::memory_order_acquire);
        const size_t inFlight = (reached > doneCount) ? (reached - doneCount) : 0;
        // The unfinished ones are the LAST `inFlight` slots handed out: a
        // worker takes the next index the moment it finishes one, so exactly
        // one worker is inside a call per unfinished slot. That identifies them
        // with no per-slot state.
        std::vector<ProbeTarget> stalled;
        const size_t from = (cap > inFlight) ? (cap - inFlight) : 0;
        for (size_t i = from; i < cap; ++i) stalled.push_back(scratch->queue[i]);
        RememberStalled(stalled);
    }

    std::vector<SocketSample> read;
    {
        std::lock_guard<std::mutex> dl(scratch->dataLock);
        read = scratch->observed;
    }

    {
        std::lock_guard<std::mutex> lk(stateLock_);
        if (tableOk && workersDone) {
            // A COMPLETE pass may retire. `opened` is the full set of PIDs we
            // could read, so a socket missing from them really is closed. This
            // is what keeps a connection that has gone away from holding its
            // bytes for ever.
            std::vector<DWORD> scanned(scratch->opened.begin(),
                                       scratch->opened.end());
            MergeSample(read, scanned, pids);
        } else if (tableOk) {
            // INCOMPLETE: merge the reads but retire nothing. A PID whose
            // sockets were never reached would otherwise have them all counted
            // as closed, and its total would go DOWN - a traffic column that
            // decreases because the machine was busy is worse than a stale one.
            std::vector<DWORD> none;
            MergeSample(read, none, pids);
        }
        scanInFlight_ = false;
        if (!workersDone) {
            scanAbandoned_ = true;
            // Supersede, so a stalled worker's late reading is recognisable as
            // belonging to an old pass.
            ++generation_;
        }
    }
    if (!workersDone) timeouts_.fetch_add(1, std::memory_order_relaxed);

    if (workersDone) {
        // finished == queue.size() proves the LAST target was processed. It
        // does NOT prove the worker that processed it has returned from its
        // lambda. Freeing `scratch` here, before that happens, races the
        // worker's next NextTarget() call (which does scratch.cursor.fetch_add
        // on the allocation being freed) - a use-after-free. The previous
        // comment asserted that every worker had returned, which is exactly
        // the guarantee that was not yet true.
        //
        // IT WAITED ON THE WRONG COUNTER. The wait used liveThreads_, a
        // process-wide total across every pass, and it was UNBOUNDED: a pass
        // whose own workers were all done could block for ever on a thread an
        // EARLIER pass had left wedged inside SIO_TCP_INFO - a call
        // measured at 28 s and still running after 90 s, and which cannot be
        // cancelled. That is a real hang, not a theoretical one: it wedged
        // `list --traffic --watch 2 --count 4` for over 8 minutes at 0 CPU
        // with the main thread in Sleep. The construction argument beside the
        // old loop ("every worker is a few instructions from exiting") was
        // true only of the current pass's workers; it never held for the
        // global counter.
        //
        // Two changes, both necessary:
        //   1. Wait on THIS pass's workers (scratch.liveInPass). A pass with
        //      an empty queue spawns none, so it now tears down immediately
        //      instead of inheriting someone else's stuck threads.
        //   2. Bound even that wait, so the invariant this code depends on
        //      holds by construction rather than by argument. On expiry the
        //      scratch is abandoned instead of freed - exactly what the
        //      incomplete path below already does - because abandoning means
        //      never freeing, which is what makes it safe.
        const ULONGLONG joinDeadline =
            ::GetTickCount64() + static_cast<ULONGLONG>(kNoProgressMs);
        while (scratch->liveInPass.load(std::memory_order_acquire) != 0) {
            if (::GetTickCount64() >= joinDeadline) break;
            ::Sleep(kScanPollMs);
        }
        // The healthy case needs no work here at all, which is the point: the owner
        // frees the scratch on the way out - on the normal path AND if anything
        // between the allocation and here throws. The old `delete scratch` at
        // this spot could not do that, because a throw skipped it.
        if (scratch->liveInPass.load(std::memory_order_acquire) != 0) {
            // Defensive: by the argument above this pass's workers are all
            // within a few instructions of their decrement, so reaching here
            // means something above changed. Give up the teardown - not the
            // reading: every target was read and merged - and count it so it
            // is visible rather than silent. No generation bump: a worker
            // cannot still be publishing, because PublishOne runs before the
            // Finish() that made the pass complete.
            //
            // release() is what makes this a DELIBERATE leak rather than an
            // accidental one: the owner would otherwise free the block on the
            // way out, and a live worker is still reading it.
            scratchHolder.release();
            timeouts_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    // Otherwise it leaks, deliberately: a worker may still be writing to it.
    // One abandoned allocation per stalled pass, reclaimed at process exit -
    // the same trade ~SocketTrafficSampler already makes for itself.
    return Totals(pids);
}

unsigned SocketTrafficSampler::TimeoutCount() const {
    return timeouts_.load(std::memory_order_relaxed);
}

unsigned SocketTrafficSampler::ScanFailureCount() const {
    return scanFailures_.load(std::memory_order_relaxed);
}

bool SocketTrafficSampler::ShutdownScanForExit() {
    // A short GRACE wait, not the full scan budget.
    //
    // The reason this exists at all (see the header) is that a detached thread
    // keeps the process alive, so a `list --traffic` that left a worker inside
    // the kernel printed its rows and then hung. Waiting kScanTimeoutMs fixed
    // that, but it also cost every one-shot invocation a flat 4 seconds on a
    // machine that has a wedging socket - measured at 4.6 s end to end, of
    // which 4 s was this function waiting for threads that were never going to
    // return.
    //
    // By the time this is called the pass has already given up on everything it
    // could not read, so the only thing left worth waiting for is a worker that
    // is mid-socket and about to publish a reading. Half a second covers that
    // with room to spare; nothing covers a thread in the kernel.
    const ULONGLONG deadline =
        ::GetTickCount64() +
        static_cast<ULONGLONG>(kNoProgressMs) * 2;
    for (;;) {
        if (liveThreads_.load(std::memory_order_acquire) == 0) return true;
        if (::GetTickCount64() >= deadline) break;
        ::Sleep(kScanPollMs);
    }
    // Still running: the thread is inside the kernel and cannot be cancelled.
    // Report that rather than pretending the sampler is idle - the caller is
    // about to exit, and the leaked object is the documented trade-off.
    return false;
}

std::vector<SocketAge> SocketTrafficSampler::Ages(
    const std::vector<DWORD>& pids) const {
    std::vector<SocketAge> out;
    std::lock_guard<std::mutex> lk(stateLock_);
    for (DWORD pid : pids) {
        const auto it = live_.find(pid);
        if (it == live_.end()) continue;
        for (const auto& kv : it->second) {
            const LiveSock& s = kv.second;
            if (s.ageMs == 0) continue;      // kernel reported nothing
            if (s.localAddress.empty() || s.remoteAddress.empty()) continue;
            SocketAge a;
            a.localAddress = s.localAddress;
            a.localPort = s.localPort;
            a.remoteAddress = s.remoteAddress;
            a.remotePort = s.remotePort;
            a.ageMs = s.ageMs;
            a.known = true;
            out.push_back(std::move(a));
        }
    }
    return out;
}

// Per-socket cumulative counters, same scan, same lock discipline as Ages().
std::vector<SocketBytes> SocketTrafficSampler::Bytes(
    const std::vector<DWORD>& pids) const {
    std::vector<SocketBytes> out;
    std::lock_guard<std::mutex> lk(stateLock_);
    for (DWORD pid : pids) {
        const auto it = live_.find(pid);
        if (it == live_.end()) continue;
        for (const auto& kv : it->second) {
            const LiveSock& s = kv.second;
            // A socket with no endpoint identity cannot be joined to a row, so
            // publishing it would be an orphan. Skip rather than guess.
            if (s.localAddress.empty() || s.remoteAddress.empty()) continue;
            SocketBytes b;
            b.localAddress = s.localAddress;
            b.localPort = s.localPort;
            b.remoteAddress = s.remoteAddress;
            b.remotePort = s.remotePort;
            b.rx = s.in;
            b.tx = s.out;
            b.known = true;
            out.push_back(std::move(b));
        }
    }
    return out;
}

// Per-socket congestion state, same scan, same discipline as Ages() and
// Bytes(). Emitted for every socket that has an endpoint identity and reported
// AT LEAST ONE of the values, so the store can attach the real readings and
// leave the rest blank - rather than dropping the socket entirely because, say,
// the RTT was unavailable while the congestion window was perfectly good.
std::vector<SocketTcpInfo> SocketTrafficSampler::TcpInfo(
    const std::vector<DWORD>& pids) const {
    std::vector<SocketTcpInfo> out;
    std::lock_guard<std::mutex> lk(stateLock_);
    for (DWORD pid : pids) {
        const auto it = live_.find(pid);
        if (it == live_.end()) continue;
        for (const auto& kv : it->second) {
            const LiveSock& s = kv.second;
            if (s.localAddress.empty() || s.remoteAddress.empty()) continue;
            if (!s.rttKnown && !s.cwndKnown && !s.retransKnown) continue;
            SocketTcpInfo t;
            t.localAddress = s.localAddress;
            t.localPort = s.localPort;
            t.remoteAddress = s.remoteAddress;
            t.remotePort = s.remotePort;
            t.rttMs = s.rttMs;
            t.minRttMs = s.minRttMs;
            t.cwnd = s.cwnd;
            t.retransBytes = s.retransBytes;
            t.rttLive = s.rttKnown;
            t.cwndKnown = s.cwndKnown;
            t.retransKnown = s.retransKnown;
            t.timestamps = s.timestamps;
            t.timestampsKnown = s.timestampsKnown;
            out.push_back(std::move(t));
        }
    }
    return out;
}

// Fold one socket's reading into the totals immediately. Mirrors the
// per-sample half of MergeSample: a new handle starts a fresh LiveSock, a
// reused handle retires the old totals first, and the age/4-tuple are
// refreshed so a stale identity cannot survive a handle reuse.
void SocketTrafficSampler::PublishOne(const SocketSample& s) {
    std::lock_guard<std::mutex> lk(stateLock_);
    auto& live = live_[s.pid];
    auto h = live.find(s.handle);
    if (h == live.end()) {
        LiveSock fresh;
        fresh.in = s.bytesIn;
        fresh.out = s.bytesOut;
        fresh.ageMs = s.ageMs;
        fresh.localAddress = s.localAddress;
        fresh.localPort = s.localPort;
        fresh.remoteAddress = s.remoteAddress;
        fresh.remotePort = s.remotePort;
        // Copied on the FIRST sighting too, not only on update - a socket
        // read once and never again is exactly the long-lived connection these
        // columns are for, and a create-only copy would leave it permanently
        // blank.
        fresh.rttMs = s.rttMs;
        fresh.minRttMs = s.minRttMs;
        fresh.cwnd = s.cwnd;
        fresh.retransBytes = s.retransBytes;
        fresh.rttKnown = s.rttKnown;
        fresh.cwndKnown = s.cwndKnown;
        fresh.retransKnown = s.retransKnown;
        fresh.timestamps = s.timestamps;
        fresh.timestampsKnown = s.timestampsKnown;
        live[s.handle] = std::move(fresh);
        return;
    }
    if (s.bytesIn < h->second.in || s.bytesOut < h->second.out) {
        // Reused handle: retire the previous socket's totals first, so the
        // per-PID sum only ever grows.
        retired_[s.pid].rx += h->second.in;
        retired_[s.pid].tx += h->second.out;
    }
    h->second.in = s.bytesIn;
    h->second.out = s.bytesOut;
    if (s.ageMs != 0) h->second.ageMs = s.ageMs;
    if (!s.localAddress.empty()) h->second.localAddress = s.localAddress;
    if (!s.remoteAddress.empty()) h->second.remoteAddress = s.remoteAddress;
    h->second.localPort = s.localPort;
    h->second.remotePort = s.remotePort;
    // Retransmits and min RTT are CUMULATIVE/BEST-EVER: they only go up
    // (min RTT only goes down), so a smaller reading means a recycled socket
    // and must not overwrite a better one. RTT and cwnd are instantaneous and
    // are simply replaced. Copying all four unconditionally would let one
    // nonsensical sample reset a connection's whole congestion history.
    if (s.retransKnown && s.retransBytes >= h->second.retransBytes)
        h->second.retransBytes = s.retransBytes;
    h->second.retransKnown = h->second.retransKnown || s.retransKnown;
    if (s.rttKnown) {
        if (!h->second.rttKnown || s.minRttMs < h->second.minRttMs)
            h->second.minRttMs = s.minRttMs;
        h->second.rttMs = s.rttMs;
        h->second.rttKnown = true;
    }
    if (s.cwndKnown) {
        h->second.cwnd = s.cwnd;
        h->second.cwndKnown = true;
    }
    if (s.timestampsKnown) {
        h->second.timestamps = s.timestamps;
        h->second.timestampsKnown = true;
    }
}

// ---- the worker pool ---------------------------------------------------------
//
// Everything below is one change with one motive, and the motive is a
    // measurement rather than a theory (reproduced by
// temp/d2probe.cpp, which walks this machine's sockets one at a time and times
// each call):
//
//   of 391 sockets walked:   4 answered SIO_TCP_INFO
//                            387 failed immediately (WSAENOTSOCK / WSAENOTCONN)
//                            1 call took 28,281 ms   (a tailscaled socket)
//                            the next had not returned after 90 s (postgres)
//
// The call is not deadlocked and cannot be cancelled - it STALLS. Walking the
// table and issuing the ioctl inline therefore means one stall ends the pass,
    // and every socket behind it in the table goes unread. That is the defect
// describes, and it is why the per-socket Speed column is partial on machines
// that have one uncooperative socket.
//
// So the pass is split in two. Phase 1 walks the handle table and decides WHAT
// to read, issuing no ioctl, so it always finishes. Phase 2 farms the reads out
// to kProbeWorkers threads. A stalled call now costs one worker rather than the
// pass, and the caller (the refresh worker) never blocks on any of it.

// Take the next target, or nullptr when the queue is drained.
//
// `cursor.fetch_add` hands each caller a DISTINCT index and never repeats one,
// so it is itself the mutual exclusion - there is no compare-exchange to get
// wrong, and no second worker can ever receive a slot another worker is
// holding. Relaxed is therefore correct: the slot's contents were written
// before the queue was published to the workers, and nothing else touches them.
wintcp::ProbeTarget* SocketTrafficSampler::NextTarget(ScanScratch& scratch) {
    const size_t i = scratch.cursor.fetch_add(1, std::memory_order_relaxed);
    if (i >= scratch.queue.size()) return nullptr;
    return &scratch.queue[i];
}

void SocketTrafficSampler::CloseCachedSources(ScanScratch& scratch) {
    for (const auto& kv : scratch.sources) {
        if (kv.second != nullptr) ::CloseHandle(kv.second);
    }
    scratch.sources.clear();
}

void SocketTrafficSampler::ProbeTargetOne(const ProbeTarget& t,
                                          ScanScratch& scratch) {
    // The source-process handle is cached per PID, shared between workers.
    // Opening it is the second most expensive thing in the scan after the
    // ioctl, and the walk sees far more sockets than processes.
    HANDLE src = nullptr;
    {
        std::lock_guard<std::mutex> lk(scratch.dataLock);
        const auto it = scratch.sources.find(t.pid);
        if (it == scratch.sources.end()) {
            src = ::OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, t.pid);
            scratch.sources.emplace(t.pid, src);
        } else {
            src = it->second;
        }
        // OpenProcess succeeding is what tells MergeSample this PID's sockets
        // that are missing really are closed, rather than merely unread. It is
        // recorded before the call that might never return, deliberately: a
        // PID whose every socket stalls must NOT be recorded as scanned, or its
        // traffic would retire to zero.
        if (src != nullptr) scratch.opened.insert(t.pid);
    }
    // A slot that leaves here must still count as FINISHED. This was the only
    // exit from this function that did not call scratch.Finish(): every other
    // path (below) does, so `finished` undercounted the queue by one for every
    // target whose process was protected or had already gone away.
    //
    // That matters because Sample() waits for `finished` to reach
    // queue.size() and treats anything less as a pass that never completed.
    // One protected process anywhere in the queue therefore made EVERY pass
    // finish on the 250 ms no-progress window instead of on completion - and
    // the shortfall was then misattributed: `inFlight` is derived from
    // `reached - doneCount`, so the slots that were never counted looked like
    // workers still inside a call, the last slots handed out were named as
    // stalled, and RememberStalled put sockets that had done nothing wrong
    // into the skip set to be ignored on every later pass.
    if (src == nullptr) {
        scratch.Finish();
        return;   // protected or already gone
    }

    HANDLE dup = nullptr;
    if (!::DuplicateHandle(src, reinterpret_cast<HANDLE>(t.handle),
                           ::GetCurrentProcess(), &dup, 0, FALSE,
                           DUPLICATE_SAME_ACCESS)) {
        scratch.Finish();
        return;   // closed between enumeration and duplication
    }

    // ---- THE CALL THAT CAN STALL. Everything above is bookkeeping. ----
    ULONGLONG in = 0, out = 0, ageMs = 0;
    TcpInfoExtras extras;   // RTT / min RTT / cwnd / retransmits
    const bool ok = QueryTcpInfo(dup, &in, &out, &ageMs, &extras);
    const int wsaErr = ok ? 0 : ::WSAGetLastError();

    SocketSample sample;
    if (ok) {
        // One getsockname/getpeername pair per socket we already decided to
        // ioctl: the handle was duplicated and read anyway, so the extra cost
        // is two local calls on an open socket, not a second scan.
        QuerySocketEndpoints(dup, &sample.localAddress, &sample.localPort,
                             &sample.remoteAddress, &sample.remotePort);
    }
    ::CloseHandle(dup);

    if (!ok) {
        // Winsock, but SIO_TCP_INFO does not apply (UDP, or no connection).
        // Recording the type is what lets the fast filter skip it on every
        // later pass - this is the single biggest saving in the whole scan,
        // since 387 of 391 sockets on this machine answer this way.
        if (wsaErr != WSAENOTSOCK) {
            std::lock_guard<std::mutex> lk(scratch.typesLock);
            scratch.socketTypes.insert(t.typeIndex);
            scratch.typesKnown = true;
        }
        scratch.Finish();
        return;
    }
    {
        std::lock_guard<std::mutex> lk(scratch.typesLock);
        scratch.socketTypes.insert(t.typeIndex);
        scratch.typesKnown = true;
    }

    sample.pid = t.pid;
    sample.handle = t.handle;
    sample.bytesIn = in;
    sample.bytesOut = out;
    sample.ageMs = ageMs;
    sample.rttMs = extras.rttMs;
    sample.minRttMs = extras.minRttMs;
    sample.cwnd = extras.cwnd;
    sample.retransBytes = extras.retransBytes;
    sample.rttKnown = extras.rttKnown;
    sample.cwndKnown = extras.cwndKnown;
    sample.retransKnown = extras.retransKnown;
    sample.timestamps = extras.timestamps;
    sample.timestampsKnown = extras.timestampsKnown;
    // Publish NOW, not at the end of the pass. Another worker may stall at any
    // moment and this pass may never reach its merge at all, so a reading
    // recorded only at the end is a reading that is lost.
    PublishOne(sample);
    {
        std::lock_guard<std::mutex> lk(scratch.dataLock);
        scratch.observed.push_back(std::move(sample));
    }
    scratch.Finish();
}

void SocketTrafficSampler::RememberStalled(
    const std::vector<ProbeTarget>& stalled) {
    if (stalled.empty()) return;
    std::lock_guard<std::mutex> lk(stateLock_);
    if (stalled_.size() >= kStalledCap) stalled_.clear();
    for (const ProbeTarget& t : stalled) stalled_.insert({t.pid, t.handle});
}

unsigned SocketTrafficSampler::UnreadableCount() const {
    std::lock_guard<std::mutex> lk(stateLock_);
    return static_cast<unsigned>(stalled_.size());
}

void SocketTrafficSampler::ScanHandles(ScanScratch& scratch) {
    const std::vector<DWORD>& pids = scratch.pids;
    if (pids.empty()) return;
    if (!FetchSystemHandleTable(scratch.enumBuf)) return;

    const auto* info = reinterpret_cast<const SysHandleInfoEx*>(scratch.enumBuf.data());
    const std::unordered_set<DWORD> want(pids.begin(), pids.end());

    // Sockets already known to stall, snapshotted once so the walk does not
    // take stateLock_ 170,000 times.
    std::set<std::pair<DWORD, ULONG_PTR>> skip;
    {
        std::lock_guard<std::mutex> lk(stateLock_);
        skip = stalled_;
    }

    // ---- phase 1: decide WHAT to read. No ioctl below, so this half of the
    // pass cannot stall no matter what is in the table. ----
    scratch.queue.clear();
    scratch.cursor.store(0, std::memory_order_relaxed);
    for (ULONG_PTR i = 0; i < info->count; ++i) {
        const SysHandleEntry& e = info->handles[i];
        if (e.UniqueProcessId > MAXDWORD) continue;
        const DWORD pid = static_cast<DWORD>(e.UniqueProcessId);
        if (want.count(pid) == 0) continue;
        // Reject non-socket object types before the expensive part. This is
        // the single most important filter in the scan: the handle table
        // holds every file, key and thread handle on the system, and
        // DuplicateHandle + SIO_TCP_INFO per handle turns a millisecond
        // refresh into a minutes-long one.
        //
        // The type set is primed from our own sockets in the constructor, so
        // this rejects on the very first pass rather than only after one.
        if (scratch.typesKnown &&
            scratch.socketTypes.count(e.ObjectTypeIndex) == 0)
            continue;
        // A socket already known to stall is not tried again. Without
        // this, one uncooperative socket costs a wedged worker thread on
        // every refresh, forever.
        if (skip.count({pid, e.HandleValue}) != 0) continue;
        ProbeTarget t;
        t.pid = pid;
        t.handle = e.HandleValue;
        t.typeIndex = e.ObjectTypeIndex;
        scratch.queue.push_back(t);
    }
    if (scratch.queue.empty()) {
        scratch.done.store(true, std::memory_order_release);
        return;
    }

    // ---- phase 2: read them, on a bounded pool. ----
    //
    // DETACHED, and that is load-bearing. These workers can be stuck in the
    // kernel for as long as the kernel likes, so the scan thread must never
    // join them: it is the thread Sample() is waiting on, and joining would
    // reproduce the very defect this fixes. The workers own `scratch`, which
    // is why abandoning one is safe - see ScanScratch's comment. The scan
    // thread does NOT poll a `done` flag on the normal path; it polls
    // `finished` against the queue size, and only then waits on
    // liveThreads_==0 before releasing scratch.
    SocketTrafficSampler* self = this;
    for (int w = 0; w < kProbeWorkers; ++w) {
        liveThreads_.fetch_add(1, std::memory_order_acq_rel);
        scratch.liveInPass.fetch_add(1, std::memory_order_acq_rel);
        std::thread([self, &scratch] {
            while (ProbeTarget* t = self->NextTarget(scratch)) {
                // A throwing probe is an unread socket, not a dead pool.
                // NextTarget already handed the slot out, so skipping the
                // publish leaves exactly the state an ioctl failure leaves.
                (void)RunGuarded([&] { self->ProbeTargetOne(*t, scratch); });
            }
            // Scratch-local counter FIRST, because Sample() frees `scratch`
            // the moment it reaches zero and this is the last statement that
            // touches the scratch. Everything after it (`self->liveThreads_`,
            // then destruction of a lambda holding only a pointer and a
            // reference) does not, so releasing scratch on liveInPass == 0 is
            // safe for the same reason releasing it on liveThreads_ == 0 was.
            scratch.liveInPass.fetch_sub(1, std::memory_order_acq_rel);
            // The process-wide total. One fewer worker still running, released
            // with no lock held so a finished worker is never counted as live
            // at exit, which is what ShutdownScanForExit() reports on.
            self->liveThreads_.fetch_sub(1, std::memory_order_acq_rel);
        }).detach();
    }
}

void SocketTrafficSampler::MergeSample(const std::vector<SocketSample>& observed,
                                       const std::vector<DWORD>& scanned,
                                       const std::vector<DWORD>& pids) {
    const std::set<DWORD> pidSet(pids.begin(), pids.end());

    // PID-reuse safety: a PID without connection rows has exited - forget
    // it so a future process reusing the number starts from zero.
    for (auto it = live_.begin(); it != live_.end();)
        it = pidSet.count(it->first) != 0 ? std::next(it) : live_.erase(it);
    for (auto it = retired_.begin(); it != retired_.end();)
        it = pidSet.count(it->first) != 0 ? std::next(it) : retired_.erase(it);

    // 1) Fold this pass's reads (grouped per PID).
    std::map<DWORD, std::vector<const SocketSample*>> byPid;
    for (const SocketSample& s : observed)
        if (pidSet.count(s.pid) != 0) byPid[s.pid].push_back(&s);
    for (const auto& kv : byPid) {
        const DWORD pid = kv.first;
        auto& live = live_[pid];
        for (const SocketSample* s : kv.second) {
            auto h = live.find(s->handle);
            if (h == live.end()) {
                LiveSock fresh;
                fresh.in = s->bytesIn;
                fresh.out = s->bytesOut;
                fresh.ageMs = s->ageMs;
                fresh.localAddress = s->localAddress;
                fresh.localPort = s->localPort;
                fresh.remoteAddress = s->remoteAddress;
                fresh.remotePort = s->remotePort;
                live[s->handle] = std::move(fresh);
                continue;
            }
            if (s->bytesIn < h->second.in || s->bytesOut < h->second.out) {
                // Handle value reused for a new socket: retire the old
                // socket's totals before tracking the new one, so the
                // per-PID sum only ever grows.
                retired_[pid].rx += h->second.in;
                retired_[pid].tx += h->second.out;
            }
            h->second.in = s->bytesIn;
            h->second.out = s->bytesOut;
            // Refresh the age/identity of a socket we already track, so a
            // reused handle cannot leave a stale 4-tuple or a stale age
            // behind. The age only grows, so the newest reading is the
            // truthful one; a zero reading (kernel did not report) must not
            // erase a good earlier value.
            if (s->ageMs != 0) h->second.ageMs = s->ageMs;
            if (!s->localAddress.empty()) h->second.localAddress = s->localAddress;
            if (!s->remoteAddress.empty()) h->second.remoteAddress = s->remoteAddress;
            h->second.localPort = s->localPort;
            h->second.remotePort = s->remotePort;
        }
    }

    // 2) Sockets missing from a SCANNED PID are genuinely closed: retire
    //    their last totals. PIDs that could not be opened stay in 'scanned'
    //    absent on purpose - unknown state must not erase known totals.
    for (DWORD pid : scanned) {
        if (pidSet.count(pid) == 0) continue;
        const auto liveIt = live_.find(pid);
        if (liveIt == live_.end()) continue;
        const auto observedIt = byPid.find(pid);
        std::set<ULONG_PTR> seen;
        if (observedIt != byPid.end())
            for (const SocketSample* s : observedIt->second)
                seen.insert(s->handle);
        for (auto h = liveIt->second.begin(); h != liveIt->second.end();) {
            if (seen.count(h->first) == 0) {
                retired_[pid].rx += h->second.in;
                retired_[pid].tx += h->second.out;
                h = liveIt->second.erase(h);
            } else {
                ++h;
            }
        }
    }

    // 3) Cap the per-PID live map. Pruning by PID alone left a long-lived
    //    process that churns through handles (browsers, build agents)
    //    growing std::map<ULONG_PTR, LiveSock> without bound. Overflow is
    //    retired, never dropped, so totals stay monotonic - same contract
    //    as the closed-socket path above.
    for (auto& kv : live_) {
        auto& live = kv.second;
        while (live.size() > kMaxLiveSocketsPerPid) {
            // std::map iterates in key order, so this drops the lowest
            // handle values; the total is preserved either way.
            auto oldest = live.begin();
            retired_[kv.first].rx += oldest->second.in;
            retired_[kv.first].tx += oldest->second.out;
            live.erase(oldest);
        }
    }
}

std::map<DWORD, PidTraffic> SocketTrafficSampler::Totals(
    const std::vector<DWORD>& pids) const {
    std::map<DWORD, PidTraffic> out;
    // The totals are mutated on the scan thread, so read them under the same
    // lock. Without it this is a data race on std::map internals, which is
    // exactly the kind of corruption that surfaces much later as a random
    // access violation.
    std::lock_guard<std::mutex> lk(stateLock_);
    for (DWORD pid : pids) {
        PidTraffic t;
        const auto r = retired_.find(pid);
        if (r != retired_.end()) t = r->second;
        const auto l = live_.find(pid);
        if (l != live_.end()) {
            for (const auto& kv : l->second) {
                t.rx += kv.second.in;
                t.tx += kv.second.out;
            }
        }
        // Zero means "no data for this PID": omitted, so the store keeps
        // the cell at "—" instead of a misleading 0.
        if (t.rx != 0 || t.tx != 0) out[pid] = t;
    }
    return out;
}

}  // namespace wintcp

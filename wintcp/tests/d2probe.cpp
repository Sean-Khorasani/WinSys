// Diagnostic probe - measure WHICH call hangs and for how long.
//
// NOT part of the product. Built once, run detached, output read from a file.
// Answers: is the indefinite block in WSAIoctl(SIO_TCP_INFO), in
// getsockname/getpeername, in DuplicateHandle, or in OpenProcess - and does it
// ever return?
//
// Each socket is probed on its OWN thread so a hang is attributable to a
// specific (pid, handle) instead of stalling the whole walk the way the
// product's single-threaded scan does.

// Same gate-flip the product uses: mstcpip.h hides SIO_TCP_INFO / TCP_INFO_v0
// below NTDDI_WIN10_RS2, and _WIN32_WINNT 0x0601 puts us below it.
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>

#include <atomic>
#include <cstdio>
#include <map>
#include <set>
#include <thread>
#include <vector>

namespace {

using NtQuerySystemInformation_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

enum { kSystemExtendedHandleInformation = 64 };
enum { kStatusInfoLengthMismatch = 0xC0000004 };

// Field TYPES matter, not just field order. `GrantedAccess` is a 32-bit ULONG
// here; declaring it ULONG_PTR makes the struct 48 bytes instead of 40, so a
// walk using it runs 8 bytes per entry past the end of the buffer. That is not
// hypothetical: it is exactly what happened - the probe "discovered" a 336 KB
// heap over-read in the product, which turned out to be the probe's own stride
// error. The kernel's own filled length (need) divided by 40 lands exactly on
// the reported count, which is the cross-check that proves 40 is right.
struct SysHandleEntry {
    ULONG_PTR object;
    ULONG_PTR processUniqueId;
    ULONG_PTR handleValue;
    ULONG grantedAccess;
    USHORT creatorBackTraceIndex;
    USHORT objectTypeIndex;
    ULONG handleAttribute;
    ULONG reserved;
};
static_assert(sizeof(SysHandleEntry) == 40, "stride must be 40 bytes");

// Field order matters and getting it wrong is invisible: the first version of
// this probe declared `reserved` before `count`, so it read the handle count
// as 0, the type filter matched nothing, and the run reported "0 sockets to
// read" - the exact shape of a pass that measured nothing. Documented layout is
// { NumberOfHandles, Reserved, Handles[] }, i.e. count FIRST.
struct SysHandleInfoEx {
    ULONG_PTR count;
    ULONG_PTR reserved;
    SysHandleEntry handles[1];
};

std::vector<BYTE> FetchHandleTable(ULONG_PTR* outCount = nullptr) {
    if (outCount != nullptr) *outCount = 0;
    static NtQuerySystemInformation_t fn =
        reinterpret_cast<NtQuerySystemInformation_t>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                             "NtQuerySystemInformation"));
    if (fn == nullptr) return {};
    // Always pass a REAL buffer, never (nullptr, 0) to ask for the size - the
    // product's version does the same, and matching it is how this probe stays
    // honest: a probe that walks a different path than the product measures
    // something else.
    ULONG len = 1u << 20;
    for (int attempt = 0; attempt < 8; ++attempt) {
        std::vector<BYTE> buf(len);
        ULONG need = 0;
        const LONG st = fn(kSystemExtendedHandleInformation, buf.data(), len,
                           &need);
        if (st >= 0) {
            // Trust the RETURNED length for the walk, not the requested one:
            // the count field is only meaningful if the buffer actually holds
            // it, and reading `handles[i]` past `need` is an access violation.
            const ULONG usable = (need != 0 && need <= len) ? need : len;
            buf.resize(usable);
            if (usable >= sizeof(SysHandleInfoEx)) {
                if (outCount != nullptr)
                    *outCount =
                        reinterpret_cast<const SysHandleInfoEx*>(
                            buf.data())
                            ->count;
            }
            return buf;
        }
        if (static_cast<unsigned long>(st) != kStatusInfoLengthMismatch)
            return {};
        len = (need > len) ? need + (1u << 20) : len * 2;
    }
    return {};
}

// Which object-type indices are sockets?
//
// This MUST be a connected loopback pair, and the handle table MUST be fetched
// AFTER those sockets exist - matching the product's LearnOwnSocketTypes
// exactly. A bare unbound `socket()` teaches nothing: the first version of this
// probe did that and learned zero type indices, so the filter rejected all
// 176k handles and the run reported "0 sockets to read" - a plausible-looking
// pass that had measured nothing at all.
std::set<USHORT> LearnOwnSocketTypes() {
    std::set<USHORT> types;
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
    if (peer == INVALID_SOCKET) {
        if (client != INVALID_SOCKET) ::closesocket(client);
        ::closesocket(listener);
        std::printf("probe: no loopback pair, cannot learn socket types\n");
        return types;
    }
    // AFTER the sockets exist, exactly like the product.
    std::vector<BYTE> table = FetchHandleTable();
    if (table.empty()) {
        std::printf("probe: DEBUG inner handle-table fetch failed\n");
        ::closesocket(peer);
        ::closesocket(client);
        ::closesocket(listener);
        return types;
    }
    const DWORD self = ::GetCurrentProcessId();
    const auto* info = reinterpret_cast<const SysHandleInfoEx*>(table.data());
    // Bound the walk by what the buffer can actually hold. `count` is a claim
    // from the kernel; if it does not fit, honouring it walks off the end -
    // which is exactly how this probe crashed the first time it got real data.
    const size_t capacity = (table.size() - offsetof(SysHandleInfoEx, handles)) /
                            sizeof(SysHandleEntry);
    const ULONG_PTR entries = (info->count <= capacity) ? info->count : capacity;
    unsigned mineCounted = 0;
    for (ULONG_PTR i = 0; i < entries; ++i) {
        const SysHandleEntry& e = info->handles[i];
        if (e.processUniqueId != self) continue;
        ++mineCounted;
    }
    std::printf("probe: DEBUG pid=%lu claims=%llu capacity=%zu my handles=%u "
                "listener=%llu client=%llu peer=%llu\n",
                self, static_cast<unsigned long long>(info->count), capacity,
                mineCounted,
                static_cast<unsigned long long>(listener),
                static_cast<unsigned long long>(client),
                static_cast<unsigned long long>(peer));
    for (ULONG_PTR i = 0; i < entries; ++i) {
        const SysHandleEntry& e = info->handles[i];
        if (e.processUniqueId != self) continue;
        const ULONG_PTR v = e.handleValue;
        if (v == static_cast<ULONG_PTR>(listener) ||
            v == static_cast<ULONG_PTR>(client) ||
            v == static_cast<ULONG_PTR>(peer)) {
            types.insert(e.objectTypeIndex);
        }
    }
    ::closesocket(peer);
    ::closesocket(client);
    ::closesocket(listener);
    return types;
}
struct ProbeResult {
    DWORD pid = 0;
    ULONG_PTR handle = 0;
    long dupMs = -1;
    long ioctlMs = -1;
    long nameMs = -1;
    long peerMs = -1;
    int ioctlErr = 0;
    ULONGLONG bytesIn = 0, bytesOut = 0;
    // NOTE THE UNITS. RttUs/MinRttUs are MICROseconds - the only Ms field in
    // TCP_INFO_v0 is ConnectionTimeMs. `ss -i` prints milliseconds, so the
    // conversion has to divide; getting this wrong would report a 12 ms RTT as
    // 12000 ms.
    unsigned rttUs = 0, minRttUs = 0, cwnd = 0, sndWnd = 0, rcvWnd = 0;
    unsigned bytesRetrans = 0, dupAcks = 0, mss = 0, synRetrans = 0;
    unsigned char tcpState = 0;
    BOOLEAN tsEnabled = 0;
    std::atomic<bool> done{false};
};

void ProbeOne(DWORD pid, ULONG_PTR handle, ProbeResult* out) {
    const ULONGLONG t0 = ::GetTickCount64();
    HANDLE src = ::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                                FALSE, pid);
    if (src == nullptr) {
        out->done = true;
        return;
    }
    HANDLE dup = nullptr;
    if (!::DuplicateHandle(src, reinterpret_cast<HANDLE>(handle),
                           ::GetCurrentProcess(), &dup, 0, FALSE,
                           DUPLICATE_SAME_ACCESS)) {
        ::CloseHandle(src);
        out->done = true;
        return;
    }
    ::CloseHandle(src);
    out->dupMs = static_cast<long>(::GetTickCount64() - t0);

    ULONGLONG t1 = ::GetTickCount64();
    // Ask for the newest struct the OS will fill; the kernel writes only as
    // much as it knows and reports `returned`, so a v1/v2-capable host gives
    // the extra fields for free and an older one simply returns a shorter
    // structure. v0 is a prefix of every later version, which is what makes
    // that safe.
    TCP_INFO_v1 info = {};
    int version = 1;
    DWORD returned = 0;
    const int rc = ::WSAIoctl(static_cast<SOCKET>(
                                 reinterpret_cast<ULONG_PTR>(dup)),
                              SIO_TCP_INFO, &version, sizeof(version), &info,
                              sizeof(info), &returned, nullptr, nullptr);
    out->ioctlMs = static_cast<long>(::GetTickCount64() - t1);
    if (rc == 0) {
        out->bytesIn = info.BytesIn;
        out->bytesOut = info.BytesOut;
        out->rttUs = info.RttUs;
        out->minRttUs = info.MinRttUs;
        out->tcpInfo.cwnd = info.Cwnd;
        out->sndWnd = info.SndWnd;
        out->rcvWnd = info.RcvWnd;
        out->bytesRetrans = info.BytesRetrans;
        out->dupAcks = info.DupAcksIn;
        out->mss = info.Mss;
        out->synRetrans = info.SynRetrans;
        out->tcpState = static_cast<unsigned char>(info.State);
        out->tsEnabled = info.TimestampsEnabled;
    } else {
        out->ioctlErr = ::WSAGetLastError();
    }

    ULONGLONG t2 = ::GetTickCount64();
    sockaddr_storage ss = {};
    int len = sizeof(ss);
    ::getsockname(static_cast<SOCKET>(reinterpret_cast<ULONG_PTR>(dup)),
                  reinterpret_cast<sockaddr*>(&ss), &len);
    out->nameMs = static_cast<long>(::GetTickCount64() - t2);

    ULONGLONG t3 = ::GetTickCount64();
    len = sizeof(ss);
    ::getpeername(static_cast<SOCKET>(reinterpret_cast<ULONG_PTR>(dup)),
                  reinterpret_cast<sockaddr*>(&ss), &len);
    out->peerMs = static_cast<long>(::GetTickCount64() - t3);

    ::CloseHandle(dup);
    out->done = true;
}

}  // namespace

// ---- FETCH MODE A: the product's exact loop, verbatim -----------------------
//
// SocketTraffic.cpp::FetchSystemHandleTable does this:
//     ULONG len = buf.empty() ? (1<<20) : buf.size();
//     for (attempt 0..7) {
//         buf.resize(len);                       // <-- vector size == REQUESTED
//         status = NtQuerySystemInformation(64, buf.data(), len, &need);
//         if (status >= 0) return true;          // <-- accepts a SHORT fill
//         if (status == MISMATCH) { len = need + 1MB; continue; }
//         break;
//     }
// and ScanHandles then walks `for (i = 0; i < info->count; ++i)`.
//
// The question this answers: can info->count name entries past the end of the
// buffer the kernel actually filled? If the kernel reports SUCCESS while
// returning fewer bytes than count*sizeof(entry) needs, the walk reads past
// the fill. The vector's size is `len` (the request), not `need` (the fill),
// so there is slack - the question is whether the slack is ever exceeded.
int ProbeProductFetch() {
    std::printf("=== product-path fetch loop, 10 iterations ===\n");
    auto fn = reinterpret_cast<NtQuerySystemInformation_t>(
        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                         "NtQuerySystemInformation"));
    if (fn == nullptr) return 2;
    std::vector<BYTE> buf;
    for (int pass = 1; pass <= 10; ++pass) {
        ULONG len = buf.empty() ? (1u << 20) : static_cast<ULONG>(buf.size());
        ULONG filled = 0;
        int attempts = 0;
        bool ok = false;
        for (int attempt = 0; attempt < 8; ++attempt) {
            buf.resize(len);
            ULONG need = 0;
            const LONG status = fn(kSystemExtendedHandleInformation,
                                   buf.data(), len, &need);
            ++attempts;
            if (status >= 0) {
                ok = true;
                filled = need;
                break;
            }
            if (static_cast<unsigned long>(status) != kStatusInfoLengthMismatch)
                break;
            len = (need > len) ? need + (1u << 20) : len * 2;
        }
        if (!ok) {
            std::printf("pass %2d: FAILED after %d attempt(s)\n", pass,
                        attempts);
            continue;
        }
        const ULONG_PTR count =
            reinterpret_cast<const SysHandleInfoEx*>(buf.data())->count;
        const ULONG_PTR needed =
            offsetof(SysHandleInfoEx, handles) + count * sizeof(SysHandleEntry);
        const ULONG_PTR overBuffer = needed - buf.size();
        const ULONG_PTR overFill = needed - filled;
        std::printf(
            "pass %2d: attempts=%d bufSize=%lu filled=%lu count=%llu "
            "needs=%llu  fillSlack=%lld bufSlack=%lld%s\n",
            pass, attempts, buf.size(), filled,
            static_cast<unsigned long long>(count),
            static_cast<unsigned long long>(needed),
            static_cast<long long>(overFill),
            static_cast<long long>(overBuffer),
            (static_cast<long long>(overFill) > 0)
                ? "   <<< WALK EXCEEDS WHAT THE KERNEL FILLED"
                : "");
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    // Unbuffered: a run that dies with an access violation loses stdout's block
    // buffer with it, so the log ends up empty and says nothing about where it
    // crashed. A diagnostic tool that loses its own output on the interesting
    // failure is worse than no output.
    ::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc > 1 && ::wcscmp(argv[1], L"--productpath") == 0)
        return ProbeProductFetch();
    const unsigned long budgetMs =
        (argc > 1) ? ::wcstoul(argv[1], nullptr, 10) : 60000UL;

    WSADATA wsa;
    ::WSAStartup(MAKEWORD(2, 2), &wsa);

    // Learn the socket type indices FIRST - that makes and drops a loopback pair
    // and fetches its own handle table - then fetch the table this probe walks.
    // Two separate snapshots, which is exactly what the product does: it learns
    // types in the constructor and re-fetches per pass.
    const std::set<USHORT> sockTypes = LearnOwnSocketTypes();
    std::vector<BYTE> table = FetchHandleTable();
    if (table.empty()) {
        std::printf("probe: handle table unavailable\n");
        return 2;
    }
    if (sockTypes.empty()) {
        std::printf("probe: FAILED to learn socket type indices - the type "
                    "filter would reject every handle. Reporting nothing "
                    "rather than a plausible-looking zero.\n");
        return 2;
    }
    std::printf("probe: %zu table bytes, socket type indices =", table.size());
    for (USHORT t : sockTypes) std::printf(" %u", t);
    std::printf("\n");

    // Which PIDs? Ask the product, so the probe covers exactly the sockets the
    // product would try to read.
    std::vector<DWORD> pids;
    {
        FILE* f = nullptr;
        if (fopen_s(&f, "temp\\d2pids.txt", "r") == 0 && f != nullptr) {
            char line[64];
            while (fgets(line, sizeof(line), f) != nullptr) {
                const unsigned long v = ::strtoul(line, nullptr, 10);
                if (v != 0) pids.push_back(static_cast<DWORD>(v));
            }
            fclose(f);
        }
    }
    std::set<DWORD> want(pids.begin(), pids.end());
    std::printf("probe: %zu pids of interest\n", want.size());

    const auto* info = reinterpret_cast<const SysHandleInfoEx*>(table.data());
    const size_t capacity =
        (table.size() - offsetof(SysHandleInfoEx, handles)) /
        sizeof(SysHandleEntry);
    const ULONG_PTR entries =
        (info->count <= capacity) ? info->count : capacity;

    // SEQUENTIAL, exactly like the product's ScanHandles. This is the whole
    // point: a sequential walk is the only way to attribute a stall to a
    // specific socket. The previous version of this probe used one thread per
    // socket, which answered nothing - 4,278 concurrent ioctls queued behind
    // each other and 2,265 of them had not finished after 90 s, which looks
    // like "half the machine hangs" and is really "the probe stampeded the
    // driver". Every socket is logged the instant it is read, so the log ends
    // at the socket that stopped the walk.
    unsigned read = 0, ioctlFail = 0, slow = 0;
    unsigned withRtt = 0, withCwnd = 0, withRetx = 0, withTs = 0, withState = 0;
    std::map<DWORD, HANDLE> sources;
    const auto sourceFor = [&sources](DWORD pid) -> HANDLE {
        const auto it = sources.find(pid);
        if (it != sources.end()) return it->second;
        HANDLE h = ::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                                 FALSE, pid);
        sources.emplace(pid, h);
        return h;
    };

    for (ULONG_PTR i = 0; i < entries; ++i) {
        const SysHandleEntry& e = info->handles[i];
        if (e.processUniqueId > MAXDWORD) continue;
        const DWORD pid = static_cast<DWORD>(e.processUniqueId);
        if (want.count(pid) == 0) continue;
        if (sockTypes.count(e.objectTypeIndex) == 0) continue;

        HANDLE src = sourceFor(pid);
        if (src == nullptr) continue;
        HANDLE dup = nullptr;
        if (!::DuplicateHandle(src, reinterpret_cast<HANDLE>(e.handleValue),
                               ::GetCurrentProcess(), &dup, 0, FALSE,
                               DUPLICATE_SAME_ACCESS)) {
            continue;
        }

        // version 0, exactly as the product issues it. version 1 is REJECTED
        // by this kernel (WSAEINVAL), which is why the thread-per-socket run
        // reported zero RTT/cwnd/state across 2,013 successful reads: not one
        // ioctl actually succeeded, it just had not finished yet when the
        // budget expired. Getting this wrong would have looked like "the TCP_INFO
        // fields are empty on Windows" and the traffic columns would have been
        // dropped for no reason.
        const ULONGLONG t1 = ::GetTickCount64();
        TCP_INFO_v0 info0 = {};
        int version = 0;
        DWORD returned = 0;
        const int rc = ::WSAIoctl(static_cast<SOCKET>(
                                     reinterpret_cast<ULONG_PTR>(dup)),
                                  SIO_TCP_INFO, &version, sizeof(version),
                                  &info0, sizeof(info0), &returned, nullptr,
                                  nullptr);
        const long ioctlMs = static_cast<long>(::GetTickCount64() - t1);

        sockaddr_storage ss = {};
        int len = sizeof(ss);
        const ULONGLONG t2 = ::GetTickCount64();
        ::getsockname(static_cast<SOCKET>(reinterpret_cast<ULONG_PTR>(dup)),
                      reinterpret_cast<sockaddr*>(&ss), &len);
        const long nameMs = static_cast<long>(::GetTickCount64() - t2);
        len = sizeof(ss);
        const ULONGLONG t3 = ::GetTickCount64();
        ::getpeername(static_cast<SOCKET>(reinterpret_cast<ULONG_PTR>(dup)),
                      reinterpret_cast<sockaddr*>(&ss), &len);
        const long peerMs = static_cast<long>(::GetTickCount64() - t3);

        std::printf(
            "pid=%-6lu h=%-6llu ioctl=%-6ld gsn=%-4ld gpn=%-4ld %s",
            pid, static_cast<unsigned long long>(e.handleValue), ioctlMs,
            nameMs, peerMs,
            rc == 0 ? "ok " : "ERR");
        if (rc == 0) {
            ++read;
            std::printf(
                " st=%u ts=%u mss=%u rtt=%uus/%uus cwnd=%u snd=%u rcv=%u "
                "in=%llu out=%llu retx=%ub\n",
                static_cast<unsigned>(info0.State),
                info0.TimestampsEnabled ? 1u : 0u, info0.Mss, info0.RttUs,
                info0.MinRttUs, info0.Cwnd, info0.SndWnd, info0.RcvWnd,
                static_cast<unsigned long long>(info0.BytesIn),
                static_cast<unsigned long long>(info0.BytesOut),
                info0.BytesRetrans);
            if (info0.RttUs > 0) ++withRtt;
            if (info0.Cwnd > 0) ++withCwnd;
            if (info0.BytesRetrans > 0) ++withRetx;
            if (info0.TimestampsEnabled) ++withTs;
            if (info0.State >= 1 && info0.State <= 12) ++withState;
        } else {
            ++ioctlFail;
            std::printf(" wsaErr=%d\n", ::WSAGetLastError());
        }
        if (ioctlMs > 50 || nameMs > 50 || peerMs > 50) ++slow;
        ::CloseHandle(dup);
    }

    std::printf(
        "\n=== SEQUENTIAL WALK COMPLETE: %lu reads, %u ioctl errors, %u "
        "slow (>50ms) ===\n",
        read, ioctlFail, slow);
    std::printf(
        "=== of %lu readable sockets: %u non-zero RttUs, %u non-zero Cwnd, "
        "%u with retransmits, %u with TCP timestamps, %u a TCP state ===\n",
        read, withRtt, withCwnd, withRetx, withTs, withState);
    return 0;
}
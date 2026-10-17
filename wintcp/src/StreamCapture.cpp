// StreamCapture.cpp
// SPDX-License-Identifier: Apache-2.0
// See StreamCapture.h. Process spawning, temp files and pktmon invocation
// live here and nowhere else.

#include "StreamCapture.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

#include "Elevate.h"
#include "Pcapng.h"
#include "Utils.h"   // FormatSystemError, for the --out write failure

namespace wintcp {
namespace {

// How long any pktmon stage may take before it is given up on. A ceiling, not
// a wait: the return value is only used to decide success, and pktmon's own
// output is discarded, so the number exists to stop a wedged child from
// hanging the capture forever. 2 min is far above a real conversion (seconds on
// a filtered capture) and far below "the user gave up".
constexpr DWORD kToolTimeoutMs = 120000;

// Fixed capacities for the command lines and paths built below. Named because
// each one is the buffer for a format string whose length depends on a PATH, and
// a path that outgrows the buffer is a silently truncated command — pktmon then
// reports a syntax error about a file the user never named.
constexpr size_t kAddrFilterChars = 64;        // widest address, plus NUL
constexpr size_t kTempNameChars = 64;          // "wintcp-stream-<pid>-<tick>"
constexpr size_t kFilterArgChars = 96;         // "-t TCP -p N -p N -i <addr>"
constexpr size_t kMaxPathPlus = MAX_PATH + 64;      // a path plus its switches
constexpr size_t kTwoMaxPathPlus = 2 * MAX_PATH + 64;  // two quoted paths
constexpr size_t kOverSizeMsgChars = 160;      // the "too large" message

// Grace period after TerminateProcess, before the handles are dropped. Not a
// guess: the process object stays valid until the last handle closes, and
// reaping it here keeps a killed pktmon from lingering in a half-dead state
// with the capture drivers still attached.
constexpr DWORD kTerminateGraceMs = 2000;

// Bytes in an address field. CaptureTarget and TcpKey both store full 128-bit
// values regardless of family, so every copy and compare in this file uses the
// same width. Same name as TcpReasm.cpp's copy on purpose, so a grep finds both.
constexpr size_t kIpv6AddrBytes = 16;

// Widetest rendered address on its own, without the port. An IPv6 literal is 45
// characters at its specification maximum, so this is that plus slack; the
// endpoint form below adds the port and brackets on top of it.
constexpr size_t kIpTextChars = 64;
constexpr size_t kEndpointTextChars = 96;

// FormatStreamHex's per-line layout. Spelled out so the array bound and the
// snprintf sites that fill it cannot disagree about any part of it: the offset
// is 8 hex digits and two spaces, a byte takes three characters (two digits
// plus a space), the gutter bars are two, and the line ending is room for CRLF
// and slack.
constexpr size_t kHexOffsetChars = 8;
constexpr size_t kHexGutterChars = 2;
constexpr size_t kHexLineEndChars = 8;
// Pre-sizing for the assembled output: one line per bytesPerLine bytes, at a
// generous per-line estimate, plus slack for the short final line.
constexpr size_t kHexLineReserveChars = 80;
constexpr size_t kHexReserveSlack = 32;

// Run a console tool with no window and capture its exit code. Output is
// discarded: pktmon's messages are diagnostics, and the caller reports a
// stage name instead, which reads better than a wall of text.
int RunTool(const std::wstring& exe, const std::wstring& args) {
    std::wstring cmd = L"\"" + exe + L"\" " + args;
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    // CREATE_NO_WINDOW is what keeps a console flash from appearing behind
    // the GUI on every capture.
    if (::CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi) == 0)
        return -1;
    // If the tool hangs we must NOT just close the handle and walk away:
    // pktmon.exe then keeps running, alone and locked onto the capture
    // drivers, indefinitely. A timeout is an error, and the only sane
    // recovery is to kill the child before we report failure.
    const DWORD wait = ::WaitForSingleObject(pi.hProcess, kToolTimeoutMs);
    if (wait == WAIT_TIMEOUT) {
        ::TerminateProcess(pi.hProcess, 1);
        ::WaitForSingleObject(pi.hProcess, kTerminateGraceMs);   // let it die
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return -2;   // distinct from -1 (launch failure)
    }
    DWORD code = 0;
    if (::GetExitCodeProcess(pi.hProcess, &code) == 0) code = 0xFFFFFFFFu;
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

// Absolute path of a tool that ships in the system directory, or just the bare
// name when the directory could not be read. The bare name is a deliberate
// fallback, not laziness: CreateProcess searches PATH, so a relative answer can
// still work, and refusing outright would disable capture on a machine whose
// SystemDirectory call failed for an unrelated reason.
std::wstring SystemToolPath(const wchar_t* name) {
    wchar_t buf[MAX_PATH] = {0};
    const DWORD n = ::GetSystemDirectoryW(buf, MAX_PATH);
    // This was the house model, and it was already right. It now
    // names the shared rule so the two forms cannot drift apart again.
    if (bufferWasTooSmall(n, MAX_PATH)) return name;
    return std::wstring(buf, n) + L"\\" + name;
}

std::wstring PktmonPath() { return SystemToolPath(L"pktmon.exe"); }

// Etl2pcap turns pktmon's ETL into the pcapng the parser reads. It ships
// in the same directory, and before this it was named BARE on the conversion
// command line - so its absence surfaced as a capture that ran, waited, and was
// then thrown away at the conversion step. Probed up front instead, and invoked
// by absolute path.
std::wstring Etl2PcapPath() { return SystemToolPath(L"etl2pcap.exe"); }

// A temp path in the user's temp dir, created with a distinctive name so a
// stray file is recognisable. Returns empty on failure.
//
// The worst of the four by consequence, because the result is a WRITE
// TARGET. The old test was `== 0`, which detects failure and nothing else.
// GetTempPathW reports a too-small buffer as the REQUIRED size (measured: 35
// into an 8-char buffer), so the check passed with dir left empty and the
// returned path was a bare relative filename - meaning a capture would have
// been written into whatever the current directory happened to be, with
// nothing said about it.
std::wstring MakeTempPath(const wchar_t* ext) {
    wchar_t dir[MAX_PATH] = {0};
    const DWORD n = ::GetTempPathW(MAX_PATH, dir);
    if (bufferWasTooSmall(n, MAX_PATH)) return std::wstring();
    wchar_t name[kTempNameChars] = {0};
    ::swprintf_s(name, L"wintcp-stream-%lu-%lu%s",
                 ::GetCurrentProcessId(), ::GetTickCount(), ext);
    return std::wstring(dir) + name;
}

void RemoveIfPresent(const std::wstring& p) {
    if (!p.empty()) ::DeleteFileW(p.c_str());
}

// The ETL path chosen by StartCapture, read back by StopCapture. A file-scope
// variable rather than a ".path" sidecar file: two instances (or a crashed
// run leaving a stale sidecar) would otherwise disagree about which file is
// live, and a stale file would send StopCapture to convert something else.
std::wstring g_pendingEtl;

// Format an address for the pktmon -i filter. pktmon accepts bare IPv4; for
// IPv6 the plain form is used too, which is what its own help shows.
std::wstring FormatAddrForFilter(const unsigned char* a, bool v4) {
    wchar_t buf[kAddrFilterChars] = {0};
    if (v4) {
        ::swprintf_s(buf, L"%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    } else {
        ::swprintf_s(buf, L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                         L"%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                     a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    }
    return buf;
}


// "10.0.0.92:52417" or "[2606:b740::1]:443" for one endpoint of a canonical
// TcpKey. Needed because the reassembly directions are named for the SORTED
// pair, and a caller holding only a CaptureTarget (local/remote) cannot work
// out which half is which - so the labels have to come from the place that did
// the sorting.
std::wstring KeyEndpoint(const unsigned char* addr, uint16_t port, bool v4) {
    wchar_t buf[kEndpointTextChars] = {0};
    if (v4) {
        ::swprintf_s(buf, L"%u.%u.%u.%u:%u", addr[0], addr[1], addr[2], addr[3],
                     static_cast<unsigned>(port));
    } else {
        IN6_ADDR a6 = {};
        std::memcpy(a6.s6_addr, addr, kIpv6AddrBytes);
        wchar_t ip[kIpTextChars] = {0};
        if (::InetNtopW(AF_INET6, &a6, ip, kIpTextChars) != nullptr)
            ::swprintf_s(buf, L"[%s]:%u", ip, static_cast<unsigned>(port));
        else
            ::swprintf_s(buf, L"[?]:%u", static_cast<unsigned>(port));
    }
    return buf;
}
}  // namespace

// Elevation is delegated to Elevate.cpp, which owns the token logic and the
// "can this user elevate at all" question. The extra function here would
// exist only to rename it, so it is gone.
// Are the capture TOOLS on this machine? Probed once and cached, because
// the answer cannot change while the process runs and this is on a path the GUI
// asks about while building menus.
//
// BOTH tools, and that is the fix rather than a detail. Capture also needs
// etl2pcap to turn the ETL into a pcapng, and before this its absence surfaced
// as a capture that ran, waited for the user, and was then discarded at the
// conversion step - the worst possible time to discover it. Finding out up
// front is the difference between a disabled menu item and a lost capture.
//
// THE WORDING IS LOAD-BEARING, and it was wrong once. The first version of this
// string ended "...and elevating will not supply it." That reads correctly and
// shares a word with ElevationUnavailableReason(), whose advice is "this feature
// needs administrator rights". Two reasons a user has to tell apart should not
// use the same word: a support log containing both, or a report scanned for
// "elevat", cannot say which was which. The pre-emption is kept - the user
// should not go and try the obvious thing - but it is said in its own words, so
// "administrator" appears in exactly one of the two reasons and that one is the
// elevation reason.
bool CaptureToolsPresent(std::wstring* whyNot) {
    static int cached = -1;   // -1 not yet probed, 0 missing, 1 present
    static std::wstring cachedWhy;
    if (cached < 0) {
        const wchar_t* missing = nullptr;
        if (::GetFileAttributesW(PktmonPath().c_str()) ==
            INVALID_FILE_ATTRIBUTES) {
            missing = L"pktmon.exe";
        } else if (::GetFileAttributesW(Etl2PcapPath().c_str()) ==
                   INVALID_FILE_ATTRIBUTES) {
            missing = L"etl2pcap.exe";
        }
        if (missing == nullptr) {
            cached = 1;
        } else {
            cached = 0;
            cachedWhy = std::wstring(missing) +
                        L" was not found in the system directory. Stream "
                        L"capture needs it, and relaunching with more privilege "
                        L"will not help.";
        }
    }
    if (cached == 0 && whyNot != nullptr) *whyNot = cachedWhy;
    return cached == 1;
}
// The capture decision TABLE, split out from the two probes so that the
// order of the probes can be tested at all.
//
// WHY A PURE FUNCTION AND NOT JUST A COMMENTED IF-CHAIN. The order of the two
// checks is the entire fix, and an order buried in a function that reads live
// process state is untestable. Measured while writing the gate: it runs
// elevated, and when the token is good the two orders return the same verdict -
// so a mutation that moved the token check back in front of the tool check
// passed green. A test that cannot fail on the bug it was written for is not a
// test. Taking the two answers as parameters makes all four combinations
// reachable from any process, at any integrity level.
//
// The rule this encodes, in one sentence: a missing tool is reported as a
// missing tool, always, even when the token would also refuse - because "run as
// administrator" is advice the user cannot act on when the tool is the thing
// that is absent, and elevating will not conjure it.
CaptureGate EvaluateCaptureGate(bool toolsPresent, bool elevated,
                                const std::wstring& toolWhy,
                                const std::wstring& elevationWhy) {
    CaptureGate g;
    g.ok = false;
    // Deliberately a switch on both bits rather than early returns, so the whole
    // table reads in one place and no future edit can quietly reorder it.
    if (!toolsPresent) {
        // The tool's absence outranks the token. Both `if (!toolsPresent)` and
        // `if (!elevated)` refusing is correct; which one gets to EXPLAIN is not
        // symmetric, and the tool wins.
        g.why = toolWhy;
    } else if (!elevated) {
        g.why = elevationWhy;
    } else {
        g.ok = true;
        g.why.clear();
    }
    return g;
}

bool CaptureAvailable(std::wstring* whyNot) {
    // Two impure probes, then the table. This function is the only place that
    // knows what the gates are; EvaluateCaptureGate is the only place that
    // knows what order they go in.
    std::wstring toolWhy;
    const bool tools = CaptureToolsPresent(&toolWhy);
    const CaptureGate g = EvaluateCaptureGate(tools, IsElevated(), toolWhy,
                                              ElevationUnavailableReason());
    // Always write, even on success: a caller that reuses one whyNot buffer
    // across calls must not see the previous refusal's text after a pass.
    if (whyNot != nullptr) *whyNot = g.why;
    return g.ok;
}

void ClearCaptureFilter() {
    RunTool(PktmonPath(), L"filter remove");
}

bool StartCapture(const CaptureTarget& target, unsigned eventFlags,
                  const std::wstring& extraAddr, std::wstring* error) {
    const std::wstring exe = PktmonPath();
    const auto fail = [error](const wchar_t* what) {
        if (error != nullptr) *error = what;
        return false;
    };

    // The filter set is global and persists after our process exits, so it is
    // cleared both before and after. A leftover filter would silently
    // narrow some later, unrelated capture.
    RunTool(exe, L"filter remove");

    wchar_t ports[kFilterArgChars] = {0};
    ::swprintf_s(ports, L"-t TCP -p %u -p %u -i %s", target.localPort,
                 target.remotePort,
                 FormatAddrForFilter(target.localAddr, target.ipV4).c_str());
    std::wstring filt = std::wstring(L"filter add wintcp ") + ports;
    // The --filter passthrough. Built on the DYNAMIC string, never the fixed
    // `ports` buffer above: an IPv6 address can be 45 chars and a second
    // -i <ip> would push it past kFilterArgChars, silently truncating the
    // command - the exact failure pktmon's own truncation hides.
    if (!extraAddr.empty()) {
        filt += L" -i " + extraAddr;
    }
    if (RunTool(exe, filt) != 0)
        return fail(L"Could not start packet capture (pktmon filter). "
                     L"Another capture tool may be running.");

    const std::wstring etl = MakeTempPath(L".etl");
    if (etl.empty()) return fail(L"Could not create a temporary file name.");

    wchar_t start[kMaxPathPlus] = {0};
    // --pkt-size 0 = no truncation. Omitting it truncates each packet and
    // the stream becomes unreassemblable.
    // --flags is only emitted when the caller asked for a mask: 0 means
    // "capture every TCP lifecycle event", which is the default and the only
    // mode that yields a fully reassemblable stream.
    if (eventFlags == 0) {
        ::swprintf_s(start, L"start --capture --pkt-size 0 --file-name \"%s\"",
                     etl.c_str());
    } else {
        ::swprintf_s(start,
                     L"start --capture --pkt-size 0 --flags %u --file-name \"%s\"",
                     eventFlags, etl.c_str());
    }
    if (RunTool(exe, start) != 0) {
        RunTool(exe, L"filter remove");
        return fail(L"Could not start packet capture (pktmon start).");
    }
    g_pendingEtl = etl;
    return true;
}

CaptureResult StopCapture(const CaptureTarget& target) {
    return StopCapture(target, nullptr);
}

CaptureResult StopCapture(const CaptureTarget& target,
                          const std::wstring* savePcapngAs) {
    CaptureResult res;
    const std::wstring exe = PktmonPath();

    // Stop must precede the conversion: pktmon only merges and flushes the
    // ETL when it is stopped, and etl2pcap on an unflushed file yields
    // nothing at all.
    res.stage = L"pktmon stop";
    RunTool(exe, L"stop");
    ClearCaptureFilter();

    // The ETL path was chosen by StartCapture and kept in g_pendingEtl.
    const std::wstring etl = g_pendingEtl;
    g_pendingEtl.clear();
    if (etl.empty()) {
        res.stage = L"pktmon start";
        res.error = L"Capture was never started, so there is nothing to read.";
        return res;
    }

    std::wstring pcapng = etl;
    const size_t dot = pcapng.rfind(L'.');
    if (dot != std::wstring::npos) pcapng.resize(dot);
    pcapng += L".pcapng";

    res.stage = L"pktmon etl2pcap";
    wchar_t conv[kTwoMaxPathPlus] = {0};
    // etl.c_str(), not etl: a std::wstring passed to a variadic function is
    // bitwise-copied, so its buffer is never read and the path comes out as
    // whatever happened to be on the stack.
    // Absolute path. The bare name relied on PATH, so a machine where
    // pktmon ships but etl2pcap does not would fail HERE, after the capture.
    ::swprintf_s(conv, L"\"%s\" \"%s\" --out \"%s\"", Etl2PcapPath().c_str(),
                 etl.c_str(), pcapng.c_str());
    if (RunTool(exe, conv) != 0) {
        RemoveIfPresent(etl);
        RemoveIfPresent(pcapng);
        res.error = L"pktmon could not convert the capture to pcapng.";
        return res;
    }

    // Read the whole pcapng. ParsedPacket holds views into this buffer, so
    // it must stay alive for as long as the results do - hence 'buffer' is
    // declared before them and released only at the end of this function,
    // with the reassembled bytes copied out beforehand.
    res.stage = L"read";
    HANDLE f = ::CreateFileW(pcapng.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        RemoveIfPresent(etl);
        RemoveIfPresent(pcapng);
        res.error = L"The converted capture file could not be opened.";
        return res;
    }
    // Largest capture this tool will read into memory in one go. 512 MB is far
    // past any reasonable filtered capture and safely below the 2 GB/4 GB
    // cliffs further down (vector size, DWORD read length); the number and the
    // user-facing prose below come from this one constant so they cannot
    // disagree about the limit. Dev constant — memory policy, not a knob.
    constexpr LONGLONG kMaxCaptureBytes = 512ll * 1024 * 1024;
    LARGE_INTEGER size = {};
    ::GetFileSizeEx(f, &size);
    if (size.QuadPart <= 0 || size.QuadPart > kMaxCaptureBytes) {
        ::CloseHandle(f);
        RemoveIfPresent(etl);
        RemoveIfPresent(pcapng);
        if (size.QuadPart <= 0) {
            res.error = L"The capture produced no packets.";
        } else {
            // The MB figure is derived from the constant, not retyped: the
            // message and the check cannot disagree about the limit.
            wchar_t over[kOverSizeMsgChars] = {0};
            ::swprintf_s(over, L"The capture is larger than %lld MB; narrow it "
                               L"with a filter and try again.",
                         kMaxCaptureBytes / (1024 * 1024));
            res.error = over;
        }
        return res;
    }
    std::vector<unsigned char> buffer(static_cast<size_t>(size.QuadPart));
    DWORD got = 0;
    const BOOL readOk =
        ::ReadFile(f, buffer.data(), static_cast<DWORD>(buffer.size()), &got,
                   nullptr);
    ::CloseHandle(f);
    res.fileBytes = got;

    // --out: keep the capture BEFORE the temp files are deleted, and write it
    // from the buffer already in hand rather than re-reading the file - so the
    // bytes saved are provably the bytes that were parsed.
    if (savePcapngAs != nullptr && !savePcapngAs->empty()) {
        HANDLE out = ::CreateFileW(savePcapngAs->c_str(), GENERIC_WRITE, 0,
                                   nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out == INVALID_HANDLE_VALUE) {
            RemoveIfPresent(etl);
            RemoveIfPresent(pcapng);
            res.stage = L"write --out";
            res.error = L"Could not create the capture file: " +
                        FormatSystemError(::GetLastError());
            return res;
        }
        DWORD wrote = 0;
        // Chunked rather than one WriteFile, and the length checked: a short
        // write would otherwise be reported as a saved capture that is
        // silently truncated.
        bool writeOk = true;
        size_t off = 0;
        while (off < buffer.size()) {
            const DWORD chunk = static_cast<DWORD>(
                (std::min)(buffer.size() - off, size_t(1u << 20)));
            if (::WriteFile(out, buffer.data() + off, chunk, &wrote,
                            nullptr) == FALSE || wrote != chunk) {
                writeOk = false;
                break;
            }
            off += chunk;
        }
        ::CloseHandle(out);
        if (!writeOk) {
            RemoveIfPresent(etl);
            RemoveIfPresent(pcapng);
            res.stage = L"write --out";
            res.error = L"Could not write the whole capture file.";
            return res;
        }
    }

    // Temp files go away now regardless of what follows: they can be tens of
    // megabytes and are not worth keeping after a parse.
    RemoveIfPresent(etl);
    RemoveIfPresent(pcapng);

    if (readOk == FALSE) {
        res.stage = L"read";
        res.error = L"The converted capture file could not be read.";
        return res;
    }

    res.stage = L"parse";
    const PcapngParse parse = ParsePcapng(buffer.data(), got);
    res.packetsParsed = parse.packets.size();
    res.flowRecords = parse.flowRecords;
    res.blocksSeen = parse.blocksSeen;
    res.linkType = parse.linkType;
    if (!parse.ok) {
        res.error = L"Could not read the capture: " + parse.error;
        return res;
    }

    res.stage = L"reassemble";
    TcpKey want;
    std::memcpy(want.addrA, target.localAddr, kIpv6AddrBytes);
    std::memcpy(want.addrB, target.remoteAddr, kIpv6AddrBytes);
    want.portA = target.localPort;
    want.portB = target.remotePort;
    // Canonicalise: the two endpoints are given in caller order, but
    // MakeTcpKey-style sorting is what the packets were matched against.
    {
        const int c = std::memcmp(want.addrA, want.addrB, kIpv6AddrBytes);
        const bool swap = (c > 0) || (c == 0 && want.portA > want.portB);
        if (swap) {
            unsigned char ta[kIpv6AddrBytes];
            std::memcpy(ta, want.addrA, kIpv6AddrBytes);
            std::memcpy(want.addrA, want.addrB, kIpv6AddrBytes);
            std::memcpy(want.addrB, ta, kIpv6AddrBytes);
            const uint16_t tp = want.portA;
            want.portA = want.portB;
            want.portB = tp;
        }
    }
    // Name each direction by the endpoint that SENT it. toServer is direction
    // 'a', which is now whichever of local/remote sorted first - so this has to
    // be derived from the canonicalised key, never from target.label, or the
    // two halves of the dump come out the wrong way round on every connection
    // whose remote address sorts below its local one.
    res.dir1Label = KeyEndpoint(want.addrA, want.portA, target.ipV4);
    res.dir2Label = KeyEndpoint(want.addrB, want.portB, target.ipV4);

    res.stats = ReassembleStream(parse.packets, want, &res.toServer,
                                 &res.toClient);
    res.complete = res.stats.sawSyn && res.stats.sawFin && !res.stats.sawRst;
    res.ok = (res.stats.packetsMatched > 0);
    if (!res.ok) {
        res.error =
            L"No packets for this connection were captured. The connection "
            L"may have been idle while the capture was running, or it may "
            L"have been established before it started.";
    }
    return res;
}

CaptureTarget MakeCaptureTarget(const Connection& c) {
    CaptureTarget t;
    // Connection stores ports as UINT (they arrive that way from the MIB),
    // the capture target as uint16_t. The cast is exact: a TCP/UDP port is
    // 16-bit by definition, so the value can never be out of range.
    t.localPort = static_cast<uint16_t>(c.identity.localPort);
    t.remotePort = static_cast<uint16_t>(c.identity.remotePort);
    const bool v6 = (c.identity.family == AF_INET6);
    t.ipV4 = !v6;
    if (v6) {
        ::memcpy(t.localAddr, c.identity.local6.s6_addr, kIpv6AddrBytes);
        ::memcpy(t.remoteAddr, c.identity.remote6.s6_addr, kIpv6AddrBytes);
    } else {
        ::memcpy(t.localAddr, &c.identity.local4, 4);
        ::memcpy(t.remoteAddr, &c.identity.remote4, 4);
    }
    // The endpoint strings ALREADY include the port - appending it again
    // would render "10.0.0.5:52341:52341". Use them as-is.
    t.label = c.display.localEndpoint + L"  \xE2\x86\x94  " + c.display.remoteEndpoint;
    return t;
}



std::string FormatStreamHex(const std::string& bytes, size_t bytesPerLine) {
    std::string out;
    // Clamped, not merely defaulted: the line buffer below is sized from the
    // bound. The first version declared it as
    //     char line[16 + 1 + (bytesPerLine * 3) + ...]
    // which is a variable-length array - accepted by GCC, rejected by MSVC with
    // C2131, so the entire file failed to compile over a formatting helper.
    constexpr size_t kMaxPerLine = 64;
    if (bytesPerLine == 0 || bytesPerLine > kMaxPerLine) bytesPerLine = 16;
    out.reserve(bytes.size() / bytesPerLine * kHexLineReserveChars +
                kHexReserveSlack);

    // Worst case per line: 8 for the offset, 2 spaces, three characters per hex
    // byte, two for the gutter bars, one per ASCII byte, and the CRLF.
    char line[kHexOffsetChars + kHexGutterChars + kMaxPerLine * 3 +
              kHexGutterChars + kMaxPerLine + kHexLineEndChars];

    const size_t n = bytes.size();
    for (size_t off = 0; off < n; off += bytesPerLine) {
        const size_t run = (std::min)(bytesPerLine, n - off);
        const size_t room = sizeof(line);
        int at = 0;
        // The offset is this direction's OWN offset, not the direction index,
        // so it lines up with the TCP sequence base when a SYN was seen.
        at += ::snprintf(line + at, room - static_cast<size_t>(at), "%08zx  ", off);

        for (size_t i = 0; i < bytesPerLine; ++i) {
            // The half-way gap is what makes two hex columns instead of one
            // blob. It is skipped on a short final line rather than left
            // floating in the middle of nothing.
            if (i == (bytesPerLine / 2) && run > i)
                at += ::snprintf(line + at, room - static_cast<size_t>(at), " ");
            if (i < run) {
                at += ::snprintf(line + at, room - static_cast<size_t>(at), "%02x ",
                                 static_cast<unsigned>(
                                     static_cast<unsigned char>(bytes[off + i])));
            } else {
                at += ::snprintf(line + at, room - static_cast<size_t>(at), "   ");
            }
        }
        // Then the ASCII gutter and the closing bar. A byte that is not
        // printable becomes '.', the hexdump(1) convention readers expect.
        at += ::snprintf(line + at, room - static_cast<size_t>(at), " |");
        for (size_t i = 0; i < run; ++i) {
            const unsigned char c = static_cast<unsigned char>(bytes[off + i]);
            const bool printable = (c >= 0x20 && c < 0x7F);
            at += ::snprintf(line + at, room - static_cast<size_t>(at), "%c",
                             printable ? static_cast<char>(c) : '.');
        }
        at += ::snprintf(line + at, room - static_cast<size_t>(at), "|\r\n");
        if (at > 0) out.append(line, static_cast<size_t>(at));
    }
    return out;
}

bool ParseCaptureDir(const std::wstring& value, CaptureDir* out) {
    if (out == nullptr) return false;
    const std::wstring v = ToLowerW(value);
    if (v == L"both" || v == L"all" || v == L"0") {
        *out = CaptureDir::kBoth;
        return true;
    }
    // "first"/"a"/"1" and "second"/"b"/"2", plus the client/server spellings
    // that people reach for first. The synonyms are the point: this switch
    // exists to be typed quickly, and every accepted name here is unambiguous
    // about which half it means.
    if (v == L"first" || v == L"a" || v == L"1" || v == L"server" ||
        v == L"to-server" || v == L"toserver") {
        *out = CaptureDir::kFirst;
        return true;
    }
    if (v == L"second" || v == L"b" || v == L"2" || v == L"client" ||
        v == L"to-client" || v == L"toclient") {
        *out = CaptureDir::kSecond;
        return true;
    }
    return false;
}

// Mirror of ParseCaptureDir's "token OR number" shape, but for pktmon's event
// flag bitmask. Named spellings are preferred because --flags 5 is unguessable,
// but a bare number is accepted for the rare caller who knows the raw mask.
bool ParseCaptureFlags(const std::wstring& value, unsigned* out) {
    if (out == nullptr) return false;
    const std::wstring v = ToLowerW(value);
    unsigned m = 0;
    // Comma-separated, whitespace-tolerated, order-independent - the same reader
    // that ParseEventMask established so `--flags syn,rst` and `--flags rst,syn`
    // cannot disagree with each other or with the spelling table.
    size_t i = 0;
    while (i <= v.size()) {
        size_t comma = v.find(L',', i);
        if (comma == std::wstring::npos) comma = v.size();
        std::wstring t = v.substr(i, comma - i);
        while (!t.empty() && ::iswspace(t.front())) t.erase(t.begin());
        while (!t.empty() && ::iswspace(t.back())) t.pop_back();
        if (!t.empty()) {
            if (t == L"none" || t == L"0")
                m |= 0;
            else if (t == L"syn")
                m |= 1;                      // TCP_SYN per pktmon docs
            else if (t == L"fin")
                m |= 2;                      // TCP_FIN
            else if (t == L"rst")
                m |= 4;                      // TCP_RST
            else if (t == L"all" || t == L"syn,fin,rst" || t == L"7")
                m |= 7;                      // the whole documented mask
            else if (::iswdigit(t[0])) {
                // A bare bitmask (e.g. "5" = SYN+RST). Leading zero is caught
                // by the "none"/"0" branch above, so this is a genuine number.
                // Validate that EVERY character is a digit - a mix like "5x" is
                // a typo, not a lenient parse.
                bool allDigits = true;
                for (wchar_t ch : t) {
                    if (!::iswdigit(ch)) { allDigits = false; break; }
                }
                if (!allDigits) return false;
                unsigned n = 0;
                for (wchar_t ch : t) n = static_cast<unsigned>(n * 10 + (ch - L'0'));
                if (n > 7) return false;       // outside the documented mask range
                m |= n;
            }
            else
                return false;
        }
        if (comma == v.size()) break;
        i = comma + 1;
    }
    *out = m;
    return true;
}

}  // namespace wintcp

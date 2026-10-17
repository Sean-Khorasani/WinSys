// StreamCapture.h
// SPDX-License-Identifier: Apache-2.0
// Drives pktmon to capture one TCP connection, converts the ETL to pcapng,
// parses it and reassembles the stream. This is the only part of
// the follow-stream feature that touches the filesystem or spawns processes.
//
// WHAT IT DOES, IN ORDER:
//   1. pktmon filter remove        (the filter set is global and persistent)
//   2. pktmon filter add ... -t TCP -p <localport> -p <remoteport> [-i <ip>]
//   3. pktmon start --capture --pkt-size 0 --file-name <tmp>.etl
//   4. [caller shows a "capturing" window, the user browses for a few seconds]
//   5. pktmon stop                (flushes and merges the ETL)
//   6. pktmon etl2pcap <tmp>.etl --out <tmp>.pcapng
//   7. read + ParsePcapng + ReassembleStream
//   8. delete both temp files
//
// --pkt-size 0 is not optional: the default truncates each packet and a
// truncated stream cannot be reassembled.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <string>

#include "Connection.h"
#include "TcpReasm.h"

namespace wintcp {

// One connection to follow.
struct CaptureTarget {
    unsigned char localAddr[16] = {0};
    unsigned char remoteAddr[16] = {0};
    uint16_t localPort = 0;
    uint16_t remotePort = 0;
    bool ipV4 = true;
    // Display string for the window title, e.g. "10.0.0.92:52417".
    std::wstring label;
};

// Everything the follow-stream window needs to render honestly.
struct CaptureResult {
    bool ok = false;
    std::wstring error;

    ReasmResult toServer;
    ReasmResult toClient;
    ReasmStats stats;

    // Raw counters, so the window can say what happened rather than showing
    // an unexplained blank pane.
    size_t packetsParsed = 0;
    size_t flowRecords = 0;
    size_t blocksSeen = 0;
    size_t fileBytes = 0;
    unsigned linkType = 0;
    bool elevated = false;      // false => pktmon refused; see error
    bool complete = true;       // false => SYN and FIN both seen

    // Diagnostic line naming the stage that failed, for the "why is this
    // empty" case: "pktmon start", "etl2pcap", "parse", "reassemble".
    std::wstring stage;

    // Endpoint strings for the two reassembly directions, in the SAME order as
    // toServer / toClient - so dir1Label is the peer whose bytes are in
    // toServer.
    //
    // Filled here because this is where the order is decided: ReassembleStream
    // canonicalises the pair (lower address first, ties broken on the lower
    // port) and that sort is internal to TcpReasm. A caller cannot derive it,
    // and guessing would label the two halves of every stream the wrong way
    // round - which is the one mistake a stream dump must not make.
    std::wstring dir1Label;
    std::wstring dir2Label;
};

// Are pktmon.exe AND etl2pcap.exe present in the system directory?
// Probed once and cached; no elevation involved.
//
// SEPARATE FROM CaptureAvailable ON PURPOSE. This answers "does this machine
// have the tools", which is a capability - a property of the OS install - while
// CaptureAvailable answers "can this process drive them right now", which is a
// permission. Collapsing them is what let a standard user on a machine with no
// pktmon be told to run as administrator.
struct CaptureGate {
    bool ok;
    std::wstring why;   // empty when ok
};

// The decision table, as a pure function of the two probe answers and their two
// reasons. See its definition for why it is not written inline in
// CaptureAvailable - the short version is that the order of the checks is the
// fix, and an order inside a function that reads live process state cannot be
// tested on a machine where both orders happen to agree.
CaptureGate EvaluateCaptureGate(bool toolsPresent, bool elevated,
                                const std::wstring& toolWhy,
                                const std::wstring& elevationWhy);

// True when this process can drive pktmon at all: the tools must be present, and
// then the token must be good. Refusal explains which of the two failed, with
// the tool reported first whenever both would refuse - see the table.
bool CaptureAvailable(std::wstring* whyNot = nullptr);

// The tool half on its own, with no elevation involved: true when both capture
// exes are in the system directory. Cached; the answer cannot change while the
// process runs. This is what WinCaps reports as the "Stream capture (pktmon)"
// capability, because a missing tool is a property of the OS install while a
// missing token is a property of the caller - and a capability report that said
// "unavailable: run as administrator" to every standard user would be noise.
//
// BOTH exes, because capture needs both: etl2pcap converts pktmon's ETL into
// the pcapng the parser reads, and its absence used to surface as a capture
// that ran, waited, and was discarded at the conversion step.
bool CaptureToolsPresent(std::wstring* whyNot = nullptr);

// Build the target for a connection row. Takes the addresses from the
// BINARY fields, not the printable ones: the endpoint strings carry the
// port ("93.184.216.34:443", "[...]:443"), so parsing them rejects every
// row. The binary fields are what TcpTable fills and what SetTcpEntry and
// the other per-connection actions use; there is no string form that can
// fail to parse. IPv4 lands raw in the first 4 bytes, matching the layout
// ParseIpTcp produces for v4 packets, so reassembly keys agree.
CaptureTarget MakeCaptureTarget(const Connection& c);

// Install a filter and start capturing. Returns false and sets 'error' if
// pktmon could not be started. On success the capture is running and
// StopCapture() must be called even if the window is closed early.
//
// `eventFlags` is the pktmon `start --flags N` bitmask (SYN/FIN/RST, see
// ParseCaptureFlags). 0 emits no --flags and records everything - the
// historical and default behaviour - so existing callers that pass 0 are
// unchanged. A non-zero mask narrows the recorded events, which is a
// deliberate, caller-chosen trade-off.
bool StartCapture(const CaptureTarget& target, unsigned eventFlags,
                  const std::wstring& extraAddr, std::wstring* error);

// Stop, convert, parse, reassemble, and clean up. Safe to call even if
// StartCapture failed. Always clears any pktmon filter it installed.
CaptureResult StopCapture(const CaptureTarget& target);

// As above, but ALSO writes the converted capture to 'savePcapngAs' before the
// temp files are deleted, and reports the outcome in CaptureResult::error if
// that write failed.
//
// WHY A PARAMETER AND NOT A BYTES-FIELD ON THE RESULT. The capture is read into
// memory in one piece and may be up to 512 MB (kMaxCaptureBytes). Returning
// those bytes as a std::string on the result would double peak memory for every
// caller, including the ones that only want counters. Writing the file here -
// while the buffer is alive and before RemoveIfPresent - costs one copy and
// keeps the memory policy in exactly one place.
//
// The file written is the pktmon-converted pcapng, byte-for-byte, so it opens in
// Wireshark or tshark with no conversion by the reader.
CaptureResult StopCapture(const CaptureTarget& target,
                          const std::wstring* savePcapngAs);

// A hex dump of one reassembled direction, in the conventional layout: an
// 8-digit offset, 16 bytes as hex, then the same bytes as printable ASCII with
// '.' for everything else. Offsets are the direction's OWN stream offsets, so
// they match the TCP sequence base when one was seen.
//
// Pure: bytes in, text out, no capture machinery. Exposed so the formatting
// can be pinned by the selftest - the ASCII column in particular is the kind of
// detail that is wrong in a way nobody notices by eye.
std::string FormatStreamHex(const std::string& bytes, size_t bytesPerLine = 16);

// Which side(s) of a stream to print. The two halves are named for their
// endpoint rather than "client"/"server" for the reason given on ReasmResult:
// pktmon does not reliably report which end sent the SYN, so a client/server
// name would be an assertion the data does not support.
enum class CaptureDir : unsigned {
    kBoth = 0,
    kFirst,        // toServer  - dir1Label
    kSecond,       // toClient  - dir2Label
};

// Parse a --dir value. Accepts both / server / client / a / b / 1 / 2, in any
// case, because the point of the switch is to be typed quickly and the meaning
// is obvious from the accepted names. False on anything else - an unrecognised
// direction must be an error, never a silent both.
bool ParseCaptureDir(const std::wstring& value, CaptureDir* out);

// pktmon's `start --flags N` passthrough. The bitmask names the TCP lifecycle
// events pktmon should record (a filter on event TYPE, not on addresses - the
// address filter is the -p/-i part of `pktmon filter add`). pktmon documents:
//   1 = SYN   (connection establishment)
//   2 = FIN   (orderly close)
//   4 = RST   (abortive close)
// 0 means "no --flags flag" and records every packet type, which is the default
// and the only behaviour that reassembles a full stream. A partial mask is a
// deliberate narrowing for lighter captures - and one the caller chose, so a
// refused parse is an error rather than a silent default. Returns the resolved
// bitmask in `out` (0..7), false on a bad token.
bool ParseCaptureFlags(const std::wstring& value, unsigned* out);

// The default --flags a CLI `capture` uses. 0 = emit no --flags on the pktmon
// start line, which asks for everything (the historical behaviour). Centralised
// so the help text and the executor cannot drift about which mask is "default".
constexpr unsigned kCaptureFlagsDefault = 0;

// Remove any filter this tool installed. Called from both paths and from the
// destructor of the object that owns the flow, so an abandoned filter can
// never skew an unrelated later capture.
void ClearCaptureFilter();

}  // namespace wintcp

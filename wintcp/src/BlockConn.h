// BlockConn.h
// SPDX-License-Identifier: Apache-2.0
// Two-layer "block this connection":
//   Layer 1 - tear the live TCP connection down immediately.
//   Layer 2 - install Windows Firewall outbound rules so it cannot come back.
//
// Layer 1 is IPv4-only. Windows ships no supported public API for tearing down
// an individual IPv6 connection; see the long note on SetIpv6Teardown below.
// Layer 2 works for both families, so an IPv6 block still stops reconnection -
// it just cannot drop the connection that exists right now.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

// Firewall access uses COM (CLSID_NetFwPolicy2 -> INetFwPolicy2), not the old
// INetFwMgr. INetFwPolicy2 exists from Vista onward, so _WIN32_WINNT=0x0601 is
// sufficient and no symbol here needs a higher NTDDI.
//
// LINKING: no library is required. netfw.h declares its GUIDs as bare
// "EXTERN_C const CLSID CLSID_NetFwPolicy2", implying the historical
// hnetfw.lib - but no current Windows SDK ships it (10.0.19041.0 and
// 10.0.26100.0 contain only NetFW.TLB, a type library for #import), and
// linking it fails with LNK1104. BlockConn.cpp therefore takes the GUIDs from
// netfw.h's own DECLSPEC_UUID declarations via __uuidof, so the module links
// with nothing added to the .vcxproj and no hnetfw.lib on the link line.
// winsock2.h must come before windows.h so the winsock 2 declarations win over
// the older winsock.h pulled in by windows.h. The firewall COM headers are only
// needed by the .cpp, so they are not included here.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>   // ParseLedgerBytes hands back the parsed pairs

namespace wintcp {

// Every rule this module creates is named "<kRuleNamePrefix><suffix>". The
// prefix is the ownership tag: unblocking and cleanup only ever touch rules
// whose name starts with it, so a user-authored rule that happens to look
// similar is never deleted.
extern const wchar_t* const kRuleNamePrefix;   // L"WinTCP block: "

// The rule *name* (not the description) is what the Windows Firewall policy
// store actually caps. NET_FW_MAX_RULE_NAME_LEN is not defined by netfw.h;
// the effective limit is 255 characters, and a name that exceeds it is
// rejected by the service with 0x8007007A (ERROR_INVALID_NAME). We therefore
// truncate the label to keep prefix + address + ports + label under 255, and
// assert that the identity part of the name can never be truncated - the
// address and both ports are what make the name unique, so clipping them
// would make two different connections collide.
constexpr size_t kMaxRuleNameChars = 255;

enum class BlockOutcome {
    kBlocked,        // connection killed and rules in place
    kRulesOnly,      // rules in place, but the live connection could not be killed
    kKilledOnly,     // connection killed, but rule creation failed
    kFailed,
    kAlreadyBlocked, // both rules were already present; nothing was created
};

const wchar_t* BlockOutcomeToString(BlockOutcome o);

struct BlockRequest {
    bool ipv6 = false;
    unsigned char remoteAddr[16] = {0};   // raw network-order bytes
    uint16_t localPort = 0;               // host order
    uint16_t remotePort = 0;              // host order
    std::wstring label;                   // for the rule names
};

// Block the connection described by 'req': kill it if the family allows,
// then install the outbound firewall rules that stop it returning.
//
// 'error' is optional; when supplied it always receives a non-empty human
// readable string for every outcome except kBlocked and kAlreadyBlocked, and
// it is cleared first so a stale message from a previous call cannot be
// mistaken for this one's. Never throws.
BlockOutcome BlockConnection(const BlockRequest& req, std::wstring* error);

// Remove exactly the rules BlockConnection created for 'req'. Returns true
// when the connection is not blocked afterwards - including the case where it
// was never blocked in the first place. 'error' behaves as above.
bool UnblockConnection(const BlockRequest& req, std::wstring* error);

// True when both rules for 'req' are present and enabled. This reports what
// the firewall says, so a user who deleted or disabled our rule by hand is
// correctly reported as not blocked. Returns false (never throws) if the
// firewall cannot be queried at all.
bool IsConnectionBlocked(const BlockRequest& req);

// How many rules currently carry the WinTCP tag, in any direction or family.
//
// IMPORTANT - how this is counted, and why. It does NOT use
// INetFwRules::get__NewEnum. Measured on this machine: a rule created through
// INetFwRules::Add, verified present via INetFwRules::Item and via
// `netsh advfirewall firewall show rule name=...`, is **absent from the
// IEnumVARIANT enumeration** in the same process. netsh reports it correctly
// (RemoteIP 203.0.113.7/32, Protocol TCP, Action Block) and the rule does
// enforce; it is only the enumerator that is incomplete. So an
// enumeration-based count reported 0 for a rule that was really there, and
// RemoveAllWinTcpRules would have left every such rule behind - a firewall
// rule the user cannot remove is exactly the "block" that must never exist.
//
// So the count is done by asking the firewall for each name we could have
// created, via Item(). That is O(number of possible peers) rather than
// O(system rules), which is the right trade: correctness over speed for a
// count that runs on demand.
// A count that cannot be made is not a count of zero: an error
// channel because `blocks` reporting "0" for a ledger it refused to read is
// the silent-wrong-answer shape this tool does not otherwise ship. *error is
// optional and, when supplied, is set ONLY on that failure - a genuinely
// empty ledger is not an error.
int CountWinTcpRules(std::wstring* error = nullptr);

// Delete every rule carrying the WinTCP tag. Intended for "remove all the
// blocks this app created" on shutdown. Returns true when no tagged rule
// survives; the failing names are appended to 'error'.
bool RemoveAllWinTcpRules(std::wstring* error);

// One WinTCP-tagged rule as the viewer reports it. Enumerating the
// policy store cannot be used to FIND these (see the note on
// CountWinTcpRules above), so the list is driven from the ledger and probed
// by name - but once a rule is in hand every field below is read from the
// rule itself rather than from the ledger, so a rule the user edited in
// netsh or WF.msc is shown as it actually is, not as we recorded it.
struct BlockedRule {
    std::wstring name;          // the tagged rule name
    std::wstring remoteAddrs;   // what get_RemoteAddresses reports, verbatim
    std::wstring localPorts;    // get_LocalPorts, verbatim
    std::wstring remotePorts;   // get_RemotePorts, verbatim
    bool enabled = false;
    // True when the rule is an OUTBOUND BLOCK. A tagged rule the user turned
    // into a rule (disabled it, flipped it to allow, or changed direction) is
    // reflected here rather than assumed, and the viewer says so - a block
    // that is not blocking is the one thing this surface must not hide.
    bool isBlocking = false;
};

// List the tagged rules the firewall still reports, in ledger order.
// Returns false only when the policy could not be opened at all; a rule that
// has been deleted out from under us is simply absent from the result, which
// is the same rule CountWinTcpRules follows.
bool ListBlockedRules(std::vector<BlockedRule>* out, std::wstring* error);

// Delete ONE tagged rule by name, and drop that name from the ledger so a
// later RemoveAllWinTcpRules does not go looking for it. Returns false with
// the reason in 'error'.
//
// The ledger keeps its "endpoint\tports" pair SHAPE on rewrite: the removed
// name is blanked in place rather than the line being dropped or
// re-serialised. That matters because CountWinTcpRules and
// RemoveAllWinTcpRules both split on the tab and read the FIRST field, so a
// dropped or reshaped line would change what `blocks` counts - and the
// viewer is not allowed to change that number as a side effect of looking.
bool RemoveBlockedRule(const std::wstring& name, std::wstring* error);

// Enable or disable ONE tagged rule, leaving it installed.
//
// Disabling is a different operation from deleting, and the difference is the
// point: a disabled rule can be re-enabled with its identity intact, so "turn
// this off for an hour and put it back" is one step instead of delete-then-
// re-derive. A rule that has to be recreated is a rule whose name might change
// and whose description is lost.
//
// The rule is read back after the write, so a caller is told when the
// firewall accepted the change and when it refused it - a silent no-op here
// would leave the manager showing a state the firewall is not in.
bool SetBlockedRuleEnabled(const std::wstring& name, bool enabled,
                           std::wstring* error);

// Two PURE helpers so the viewer's ledger handling is testable
// without touching the real file. Both are the reason RemoveBlockedRule can
// promise not to change what `blocks` counts: the ledger's shape is decided
// here, once, rather than inline at two call sites that could disagree.

// The rule names a ledger line carries. A line is "endpoint\tports", so
// there are up to two; an empty field (the shape a removal leaves behind)
// is NOT a name, and a line with no tab yields its single name.
std::vector<std::wstring> SplitLedgerNames(const std::wstring& line);

// Blank every occurrence of 'name' in 'line' IN PLACE, leaving the tab
// separators where they are so the field count does not change. Returns
// true when anything was blanked. This is the whole trick behind not
// disturbing CountWinTcpRules, which splits on the tab and reads field 0.
bool BlankLedgerName(const std::wstring& line, const std::wstring& name,
                     std::wstring* out);

// Parse the ledger's bytes into rule-name pairs. PURE - no file, no
// registry, no environment - so the selftest can drive it with hostile input
// without touching the real ledger under %APPDATA%, which is the one thing it
// must never do. The file cap lives in ReadLedger (it needs the file size);
// this covers the per-line cap and UTF-8 validation.
//
// FALSE + error on bytes that cannot be trusted - a line over
// kLedgerMaxLineBytes, a NUL byte, or invalid UTF-8 - and *out is then left
// UNTOUCHED, so a caller can never half-apply a ledger it has already
// rejected. Refusing the whole file is deliberate: a skipped line is a rule
// name nobody recorded, and the whole point of the ledger is that
// RemoveAllWinTcpRules can still find the rule it created.
bool ParseLedgerBytes(const char* data, size_t len,
                      std::vector<std::wstring>* out, std::wstring* error);

// The per-line cap, in the header so the selftest that pins the boundary
// uses the same number the parser does rather than a copy of it. A name is at
// most kMaxRuleNameChars (255) wchar_t and a wchar_t is at most 4 bytes in
// UTF-8, so a line this code can legitimately write cannot exceed
// 2*255*4 + 1 = 2041 bytes; 4096 is 2x that headroom, and the limit is
// inclusive.
constexpr size_t kLedgerMaxLineBytes = 4096;

// --- Layer 1 detail ---------------------------------------------------------
//
// TRUTH ABOUT IPv6 TEARDOWN, as verified against the Windows 10/11 SDK
// headers (um\iphlpapi.h) rather than assumed:
//
//   * SetTcpEntry(_In_ PMIB_TCPROW) is the *only* connection-state mutator in
//     iphlpapi.h. Its comment block states outright: "The only state that it
//     can be set to is MIB_TCP_STATE_DELETE_TCB."
//   * There is no SetTcpEntry2, no SetTcp6Entry, and no IPv6 variant of the
//     MIB_TCPROW setter anywhere in the SDK. A recursive search of every
//     header in Include\10.0.26100.0 for SetTcpEntry2 / SetTcp6Entry returns
//     nothing. MIB_TCP6ROW is enumerated (GetTcp6Table) and owns-module lookup
//     works (GetOwnerModuleFromTcp6Entry) but it is never accepted as
//     teardown input.
//   * SetPerTcp6ConnectionEStats does take a PMIB_TCP6ROW, but it only sets
//     per-connection EStats (the TCP_ESTATS_TYPE set in shared\tcpestats.h -
//     data, send congestion, path, buffers, observed RTT, bandwidth, fine RTT).
//     It has no state/delete semantics; there is nothing to smuggle a
//     DELETE_TCB through it.
//
// So there is no supported public per-connection IPv6 teardown. The options
// that do exist (closing a duplicated socket handle, or a WFP callout that
// injects RST) are privileged, race with the connection already being gone,
// and are not a supported API contract. This module does not pretend
// otherwise: SetIpv6Teardown returns false with an explicit reason and
// BlockConnection then reports kRulesOnly rather than claiming a kill.

// Kill the live IPv4 TCP connection identified by the 4-tuple (localPort,
// remoteAddr, remotePort). 'remoteAddr' is 4 raw network-order bytes.
// 'localAddr' may be null to mean "any local address", which is what
// BlockConnection does: BlockRequest deliberately does not carry a local
// address, and a machine may hold the same local port bound to several
// addresses, so every matching row is torn down rather than leaving a sibling
// socket alive after the user asked for the connection to be gone.
// Returns false for a zero port or unspecified remote address, and for a
// connection that is no longer present.
bool SetIpv4Teardown(const unsigned char* remoteAddr, uint16_t localPort,
                     uint16_t remotePort, std::wstring* error);

// ========================================================================
// The firewall manager's rule layer
// ========================================================================
//
// BlockConnection is a SINGLE CONVERSATION: it takes a live row, kills it and
// writes the two rules that stop that peer returning. It is deliberately narrow
// because the user names a row they saw, not a policy they want.
//
// FwRule is the general form underneath the same primitives - a rule scoped by
// direction, action, protocol, address, ports and process. It exists so the tool
// can express a policy the user states ("block this process", "block inbound
// from this subnet") rather than only a reaction to a row.
//
// THE CONSTRAINT THAT SHAPES IT, and the reason an "allow" rule is not offered
// as a way to exclude a process: Windows Firewall's default conflict resolution
// is BLOCK WINS. Adding an allow rule for a process that an existing block rule
// also matches does NOT carve the process out of the block - the block still
// applies. Exclusion has therefore to be done by SCOPING the block (which is
// what the process field is for), or by having no block rule in the first
// place. This is not a limitation of this tool; it is how the platform behaves,
// and saying so is the difference between a user believing a peer is allowed
// when it is not.
//
// A second platform constraint, already measured and documented in BlockConn.cpp:
// a rule that restricts ports must have a CONCRETE protocol. Protocol = ANY
// rejects put_LocalPorts / put_RemotePorts with E_INVALIDARG, so a rule asking
// for ports with protocol "any" is refused here rather than silently created
// without its port restrictions.

struct FwRule {
    // Direction. false = OUTBOUND, which is what BlockConnection writes and
    // the default; true = INBOUND, for "stop this address reaching us".
    bool inbound = false;

    // Action. false = BLOCK. true = ALLOW, which is only meaningful as a
    // positive permit - see the block-wins note above for why it cannot be
    // used as an exclusion.
    bool allow = false;

    // 6 = TCP (IPPROTO_TCP), 17 = UDP (IPPROTO_UDP), 0 = any. 0 is only
    // accepted with both port fields at "*", per the platform constraint above.
    LONG protocol = 6;

    // The remote-address field of the rule, exactly as the firewall receives
    // it: "*" for any, or an address, a comma-separated list, or a CIDR
    // ("203.0.113.0/24"). Not parsed or validated here beyond the shape the
    // firewall will accept, because the firewall is the authority on address
    // syntax and a second parser here would be a second place to disagree.
    std::wstring remoteAddress = L"*";

    // Port fields, in the firewall's own list syntax: "*", "443",
    // "1-1024", "80,443". "*" means any.
    std::wstring localPorts = L"*";
    std::wstring remotePorts = L"*";

    // Process scope. Empty means "any program", which is the behaviour
    // BlockConnection has always written. Non-empty is a full image path and
    // goes into the rule's ApplicationName, so the rule matches that program
    // only - the way to express "block this process" or "block everyone
    // except by scoping the block".
    std::wstring processPath;

    // Optional service scope ("*" or a service short name). Empty means any.
    std::wstring service;

    // Human label, appended to the rule name within the 255-character cap.
    std::wstring label;
};

enum class FwRuleOutcome {
    kCreated,        // the rule was added
    kAlreadyPresent, // a rule with that identity was already there
    kFailed,
};

// Pure: is this rule expressible? Returns false with a reason. The checks are
// the platform constraints above plus a name-length one, so a refused rule is
// refused before anything is written to the firewall rather than after.
bool ValidateFwRule(const FwRule& rule, std::wstring* error);

// Pure: the rule's deterministic identity name, carrying the same WinTCP tag
// so ListBlockedRules and RemoveAllWinTcpRules can still find it. Two rules that
// differ in any scope field get different names, and the same rule always gets
// the same name - which is what makes kAlreadyPresent possible.
std::wstring BuildFwRuleName(const FwRule& rule);

// Create the rule. Returns kAlreadyPresent without writing anything when the
// identity already exists, so a repeat call is not an error and not a duplicate.
FwRuleOutcome AddFwRule(const FwRule& rule, std::wstring* name,
                        std::wstring* error);

}  // namespace wintcp

// BlockConn.cpp
// SPDX-License-Identifier: Apache-2.0
// Implementation of the two-layer connection block. See BlockConn.h for the
// full rationale and, in particular, for why layer 1 is IPv4-only.

#include "BlockConn.h"

#include <iphlpapi.h>
#include <netfw.h>
#include <shlobj.h>   // SHCreateDirectoryExW, for the ledger's parent folder

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <set>
#include <mutex>
#include <string>
#include <vector>

#include "Utils.h"     // WideToUtf8 / Utf8ToWide
#include "WinCaps.h"   // DllAvailable: ole32/oleaut32 are delay-loaded

// ---------------------------------------------------------------------------
// A NOTE ON LINKING, because the obvious thing here does not work.
//
// netfw.h declares its GUIDs as bare "EXTERN_C const CLSID CLSID_NetFwPolicy2",
// i.e. it *expects* an import library that defines them - the historical one is
// hnetfw.lib. That library is not shipped with any current Windows SDK: a
// search of Windows Kits 10.0.19041.0 and 10.0.26100.0 finds only
// um\<arch>\NetFW.TLB (a type library for #import), never an hnetfw.lib, and
// linking against it fails with LNK1104. The CLSIDs are implemented by
// FirewallAPI.dll, but that DLL does not export them by name either, so there
// is nothing for the linker to resolve a static import against.
//
// The fix is to use the GUIDs the compiler already has. Each coclass is
// forward declared just above its CLSID with DECLSPEC_UUID("..."), so
// __uuidof() yields the exact same GUID straight from the header, with no
// symbol to import and therefore no .lib at all. The CLSID_Tag::value members
// exist only to give __uuidof a type that appears exactly once, so the GUID
// can be passed as a plain 'const CLSID&' to CoCreateInstance.
//
// Verified: this links and runs with no hnetfw.lib anywhere in the link line.
// ---------------------------------------------------------------------------

// The four GUIDs this module needs, taken from netfw.h's own DECLSPEC_UUID
// declarations so that no import library is required (see the note above).
namespace wintcp {

// Defined here rather than in the anonymous namespace, because BlockConn.h
// declares it extern and every rule this module creates - the existing
// connection blocks and the general rules - has to be NAMEable from
// the public half of this file. Keeping it in an anonymous namespace would
// shadow the declaration and give the public code a different object.
const wchar_t* const kRuleNamePrefix = L"WinTCP block: ";

namespace {

constexpr CLSID kClsidPolicy2 = __uuidof(NetFwPolicy2);
constexpr CLSID kClsidRule = __uuidof(NetFwRule);
constexpr IID kIidPolicy2 = __uuidof(INetFwPolicy2);
constexpr IID kIidRule = __uuidof(INetFwRule);

// "error %lu" plus NUL, and "0x%08lX" plus NUL. Both are fixed formats over a
// bounded value, and swprintf_s truncates rather than overruns.
constexpr size_t kErrCodeChars = 32;
constexpr size_t kHresultChars = 16;

// Bytes in the address field of a BlockRequest. Same name as the copies in
// TcpReasm.cpp, TcpTable.cpp and StreamCapture.cpp on purpose, so a grep finds
// every place an address width is assumed - the firewall rule's hex identity
// and the all-zero test both read it.
constexpr size_t kIpv6AddrBytes = 16;
constexpr size_t kIpv4AddrBytes = 4;

}  // namespace

// Forward declarations for the ledger, which is defined at the end of the
// file. These must be OUTSIDE the anonymous namespace: a declaration there
// gives the function internal linkage, and a later definition of the same
// name in the same namespace is a different symbol (warning C5046, and at
// /WX that stops the build).
//
// Only the functions are forward-declared - NOT BlockRequest. Declaring the
// struct here too would introduce a second, incomplete BlockRequest inside
// the anonymous namespace, making every use of the real one ambiguous.
void LedgerRemember(const BlockRequest& req);
void LedgerForget(const BlockRequest& req);
void LedgerRememberRule(const std::wstring& name);

namespace {

// --- error formatting -------------------------------------------------------

std::wstring FormatWin32(DWORD code) {
    LPWSTR buf = nullptr;
    const DWORD n = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring text;
    if (n != 0 && buf != nullptr) {
        text.assign(buf, n);
    }
    if (buf != nullptr) {
        ::LocalFree(buf);
    }
    // FormatMessage likes to append a full stop and a CRLF, which would
    // otherwise be baked into text the user reads in a dialog.
    while (!text.empty() &&
           (text.back() == L'\r' || text.back() == L'\n' ||
            text.back() == L' ' || text.back() == L'.')) {
        text.pop_back();
    }
    if (text.empty()) {
        wchar_t codeBuf[kErrCodeChars];
        ::swprintf_s(codeBuf, L"error %lu", static_cast<unsigned long>(code));
        text = codeBuf;
    }
    return text;
}

std::wstring FormatHresult(HRESULT hr) {
    if (SUCCEEDED(hr)) {
        return L"ok";
    }
    wchar_t hex[kHresultChars];
    ::swprintf_s(hex, L"0x%08lX", static_cast<unsigned long>(hr));
    return std::wstring(hex) + L" (" + FormatWin32(static_cast<DWORD>(hr)) + L")";
}

void SetError(std::wstring* error, const std::wstring& text) {
    if (error != nullptr) {
        *error = text;
    }
}

std::wstring GetError(const std::wstring* error) {
    return (error != nullptr) ? *error : std::wstring();
}

bool IsAllZero(const unsigned char* raw, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (raw[i] != 0) {
            return false;
        }
    }
    return true;
}

void AppendHexByte(unsigned char b, std::wstring* out) {
    wchar_t hex[4];
    ::swprintf_s(hex, L"%02X", static_cast<unsigned>(b));
    out->append(hex);
}

// --- address rendering ------------------------------------------------------

// Fixed-width hex of the raw bytes. This is the *identity* half of a rule name:
// unlike the readable render it is the same length for every address, which is
// what makes the name-length budget exact rather than an estimate.
std::wstring FormatAddressHex(const unsigned char* raw, bool ipv6) {
    const int bytes = ipv6 ? static_cast<int>(kIpv6AddrBytes)
                           : static_cast<int>(kIpv4AddrBytes);
    std::wstring out;
    out.reserve(static_cast<size_t>(bytes) * 2);
    for (int i = 0; i < bytes; ++i) {
        AppendHexByte(raw[i], &out);
    }
    return out;
}

// Dotted-quad IPv4, RFC 5952 canonical IPv6. Only ever used in human-facing
// text, never as a lookup key: lookup is by the exact deterministic hex name
// (FormatAddressHex), so these formatting choices cannot cause a missed
// unblock. That is the invariant that actually matters, and it is why a
// hand-rolled renderer is acceptable here.
//
// Two deliberate differences from the connection table's rendering (C2), both
// confined to this cosmetic path:
//   * No scope suffix. A blocked fe80:: address therefore reads "fe80::1"
//     without saying which interface. BlockRequest carries no scope id today;
//     threading one through would change the stored rule name and description,
//     i.e. break rules created by earlier versions, so it is a feature change
//     rather than a refactor. Safe because the RULE IDENTITY is the hex name,
//     which has no such ambiguity.
//   * Not asserted byte-equal to InetNtopW. It follows the same RFC 5952
//     rules, but nothing pins the two together, so the old comment claiming
//     they "read the way the address column does" was a claim nobody checked.
//     Dropped rather than restated.
std::wstring FormatAddress(const unsigned char* raw, bool ipv6) {
    std::wstring out;
    if (raw == nullptr) {
        return out;
    }
    if (!ipv6) {
        for (int i = 0; i < 4; ++i) {
            if (i != 0) {
                out.push_back(L'.');
            }
            out.append(std::to_wstring(static_cast<unsigned>(raw[i])));
        }
        return out;
    }
    unsigned groups[8];
    for (int i = 0; i < 8; ++i) {
        groups[i] = (static_cast<unsigned>(raw[i * 2]) << 8) |
                    static_cast<unsigned>(raw[i * 2 + 1]);
    }
    int bestStart = -1;
    int bestLen = 0;
    int runStart = -1;
    int runLen = 0;
    for (int i = 0; i < 8; ++i) {
        if (groups[i] == 0) {
            if (runStart < 0) {
                runStart = i;
                runLen = 0;
            }
            ++runLen;
            if (runLen > bestLen) {
                bestLen = runLen;
                bestStart = runStart;
            }
        } else {
            runStart = -1;
            runLen = 0;
        }
    }
    // A single zero group stays "0"; collapsing it would not round-trip.
    if (bestLen < 2) {
        bestStart = -1;
        bestLen = 0;
    }
    bool needSep = false;
    for (int i = 0; i < 8; ++i) {
        if (bestStart >= 0 && i == bestStart) {
            out += L"::";
            i += bestLen - 1;
            needSep = false;
            continue;
        }
        if (needSep) {
            out.push_back(L':');
        }
        wchar_t hex[8];
        ::swprintf_s(hex, L"%x", groups[i]);
        out.append(hex);
        needSep = true;
    }
    if (out.empty()) {
        out = L"::";
    }
    return out;
}

// --- request validation -----------------------------------------------------

// Rule names may not contain control characters, and the name is the only
// handle we have for finding the rule again. A label we cannot reproduce
// faithfully is refused up front rather than silently mangled into a name that
// UnblockConnection would never look for.
bool IsLabelSafe(const std::wstring& label) {
    for (wchar_t c : label) {
        if (c < 0x20 || c == 0x7F) {
            return false;
        }
    }
    return true;
}

bool ValidateRequest(const BlockRequest& req, std::wstring* error) {
    if (req.localPort == 0) {
        SetError(error, L"local port is 0 - not a usable TCP endpoint");
        return false;
    }
    if (req.remotePort == 0) {
        SetError(error, L"remote port is 0 - not a usable TCP endpoint");
        return false;
    }
    const size_t addrBytes = req.ipv6 ? kIpv6AddrBytes : kIpv4AddrBytes;
    if (IsAllZero(req.remoteAddr, addrBytes)) {
        // The unspecified address matches no connection, and in the port-pair
        // rule it would behave as "any". Refuse rather than install a rule
        // that blocks nothing, or far more than the user pointed at.
        SetError(error,
                 L"remote address is unspecified (all zero) - there is no "
                 L"endpoint to block");
        return false;
    }
    if (!IsLabelSafe(req.label)) {
        SetError(error,
                 L"label contains control characters, which cannot appear in a "
                 L"Windows Firewall rule name");
        return false;
    }
    return true;
}

// --- rule naming ------------------------------------------------------------

// Two rules per blocked connection, told apart by a role suffix that is part of
// the name so both are found and removed as a set. The identity - hex address
// plus both ports - is emitted before the role, so "netsh advfirewall firewall
// show rule name=all" output can be matched against a connection row by eye:
//
//   WinTCP block: <addr-hex>-<local>-<remote>-endpoint [-<label>]
//   WinTCP block: <addr-hex>-<local>-<remote>-ports    [-<label>]
//
// kMaxRuleNameChars (255) is the cap the firewall service enforces; a longer
// name is rejected outright. The fixed part is prefix(12) + addr(8 or 32) +
// 1 + local(<=5) + 1 + remote(<=5) + 1 + role(<=7) = at most 64, so a label is
// trimmed into what is left rather than pushing the name over the limit.
constexpr size_t kNameFixedMax = 64;

std::wstring BuildRuleName(const BlockRequest& req, const wchar_t* role) {
    std::wstring name = kRuleNamePrefix;
    name += FormatAddressHex(req.remoteAddr, req.ipv6);
    name += L"-";
    name += std::to_wstring(static_cast<unsigned>(req.localPort));
    name += L"-";
    name += std::to_wstring(static_cast<unsigned>(req.remotePort));
    name += L"-";
    name += role;

    if (name.size() >= kMaxRuleNameChars) {
        // Unreachable with the constants above; if it ever became reachable we
        // must return the name untruncated rather than lose the identity.
        return name;
    }
    if (!req.label.empty()) {
        const size_t room = kMaxRuleNameChars - name.size() - 1;
        const std::wstring label =
            req.label.substr(0, (std::min)(room, req.label.size()));
        if (!label.empty()) {
            name += L"-";
            name += label;
        }
    }
    return name;
}

std::wstring BuildDescription(const BlockRequest& req) {
    std::wstring desc = L"Created by WinTCP. Blocks outbound traffic to ";
    desc += FormatAddress(req.remoteAddr, req.ipv6);
    desc += L" for local port ";
    desc += std::to_wstring(static_cast<unsigned>(req.localPort));
    desc += L" and remote port ";
    desc += std::to_wstring(static_cast<unsigned>(req.remotePort));
    desc += L". Delete via WinTCP or 'netsh advfirewall firewall delete rule "
            L"name=\"";
    desc += BuildRuleName(req, L"endpoint");
    desc += L"\"'.";
    return desc;
}

// --- COM plumbing -----------------------------------------------------------

// Shell-allocated BSTR: the lifetime is obvious at every call site, and freeing
// by hand invites a leak on the early-return paths that error handling here
// produces constantly.
struct BStr {
    BSTR p = nullptr;
    BStr() = default;
    explicit BStr(const std::wstring& s)
        : p(::SysAllocStringLen(s.c_str(), static_cast<UINT>(s.size()))) {}
    ~BStr() {
        if (p != nullptr) {
            ::SysFreeString(p);
        }
    }
    BStr(const BStr&) = delete;
    BStr& operator=(const BStr&) = delete;
    BStr(BStr&& other) noexcept : p(other.p) { other.p = nullptr; }
    BStr& operator=(BStr&&) = delete;
    operator BSTR() const { return p; }
    bool valid() const { return p != nullptr; }
};

template <typename T>
struct ComPtr {
    T* p = nullptr;
    ComPtr() = default;
    ~ComPtr() {
        if (p != nullptr) {
            p->Release();
        }
    }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    ComPtr(ComPtr&& o) noexcept : p(o.p) { o.p = nullptr; }
    // Move-assign is what lets the FwSession destructor drop the rule
    // collection before the policy object, in that order, without a hand
    // written Release() for each on every error path.
    ComPtr& operator=(ComPtr&& o) noexcept {
        if (this != &o) {
            if (p != nullptr) {
                p->Release();
            }
            p = o.p;
            o.p = nullptr;
        }
        return *this;
    }
    T* get() const { return p; }
    T** receive() { return &p; }
    T* operator->() const { return p; }
    explicit operator bool() const { return p != nullptr; }
};

// Owns the COM apartment, the policy object and the rule collection for the
// duration of one public API call. CoInitializeEx/CoUninitialize must be paired
// exactly once per successful init, and the rule collection must be released
// before the apartment, so both lifetimes are tied to this one object rather
// than hand-managed at a dozen return points.
class FwSession {
public:
    // A user-declared destructor suppresses the implicit default constructor,
    // so it is spelled out. The members are all default-initialised anyway;
    // Open() is what actually acquires anything.
    FwSession() = default;

    bool Open(std::wstring* error) {
        // ole32.dll and oleaut32.dll are delay-loaded (kDelayedDlls in
        // WinCaps.cpp), and this is the single choke point every firewall call
        // goes through: CoInitializeEx, CoCreateInstance and the BSTR
        // allocator are all reached from here or from code that runs only
        // after Open() returned true. Gating once here is therefore both
        // necessary and sufficient - without it, a machine lacking COM would
        // raise a delay-load exception on the CoInitializeEx below instead of
        // reporting that the firewall feature is unavailable, and no other
        // place in this file could catch it.
        if (!DllAvailable("ole32.dll") || !DllAvailable("oleaut32.dll")) {
            SetError(error,
                     L"the COM libraries that implement the Windows Firewall "
                     L"API (ole32.dll, oleaut32.dll) are not present on this "
                     L"system, so WinTCP cannot manage firewall rules");
            return false;
        }

        HRESULT hr = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (hr == RPC_E_CHANGED_MODE) {
            // The thread was already initialised to a different apartment by
            // the host application. COM is live and INetFwPolicy2 does not
            // care which apartment, so carry on - but we did not initialise,
            // so we must not uninitialise.
            inited_ = false;
        } else if (FAILED(hr)) {
            SetError(error, L"CoInitializeEx failed: " + FormatHresult(hr));
            return false;
        } else {
            inited_ = true;
        }

        hr = ::CoCreateInstance(kClsidPolicy2, nullptr, CLSCTX_INPROC_SERVER,
                                kIidPolicy2,
                                reinterpret_cast<void**>(policy_.receive()));
        if (FAILED(hr)) {
            SetError(error,
                     L"CoCreateInstance(CLSID_NetFwPolicy2) failed: " +
                         FormatHresult(hr) +
                         L" - the firewall API requires an elevated process, so "
                         L"WinTCP must be running as administrator");
            return false;
        }

        hr = policy_.get()->get_Rules(rules_.receive());
        if (FAILED(hr) || !rules_) {
            SetError(error, L"INetFwPolicy2::get_Rules failed: " + FormatHresult(hr));
            return false;
        }
        return true;
    }

    INetFwRules* rules() const { return rules_.get(); }
    HRESULT CurrentProfileTypes(long* types) const {
        return policy_.get() != nullptr && types != nullptr
            ? policy_.get()->get_CurrentProfileTypes(types)
            : E_POINTER;
    }

    FwSession(const FwSession&) = delete;
    FwSession& operator=(const FwSession&) = delete;

private:
    ComPtr<INetFwPolicy2> policy_;
    ComPtr<INetFwRules> rules_;
    bool inited_ = false;

public:
    ~FwSession() {
        rules_ = ComPtr<INetFwRules>();
        policy_ = ComPtr<INetFwPolicy2>();
        if (inited_) {
            ::CoUninitialize();
        }
    }
};

// --- rule operations --------------------------------------------------------

constexpr long kAllProfiles = NET_FW_PROFILE2_ALL;
constexpr long kSelectableProfiles = NET_FW_PROFILE2_DOMAIN |
                                     NET_FW_PROFILE2_PRIVATE |
                                     NET_FW_PROFILE2_PUBLIC;

// Look up one rule. 'found' separates "no such rule" from "present but
// disabled", because a rule the user switched off is not blocking anything and
// IsConnectionBlocked must say so.
bool QueryRule(INetFwRules* rules, const std::wstring& name, bool* found,
               bool* enabled, bool* isBlock, std::wstring* error) {
    *found = false;
    *enabled = false;
    *isBlock = false;

    BStr bname(name);
    if (!bname.valid()) {
        SetError(error, L"out of memory allocating rule name");
        return false;
    }
    ComPtr<INetFwRule> rule;
    const HRESULT hr = rules->Item(bname, rule.receive());
    if (FAILED(hr)) {
        // 0x80070490 "element not found" is how a missing rule surfaces.
        if (hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND) ||
            hr == REGDB_E_CLASSNOTREG) {
            return true;  // absent: a valid answer, not an error
        }
        SetError(error, L"INetFwRules::Item failed: " + FormatHresult(hr));
        return false;
    }
    if (!rule) {
        return true;  // null without a failure code: treat as absent
    }

    VARIANT_BOOL vb = VARIANT_FALSE;
    if (FAILED(rule.get()->get_Enabled(&vb))) {
        SetError(error, L"INetFwRule::get_Enabled failed");
        return false;
    }
    NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;
    if (FAILED(rule.get()->get_Direction(&dir))) {
        SetError(error, L"INetFwRule::get_Direction failed");
        return false;
    }
    NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
    if (FAILED(rule.get()->get_Action(&action))) {
        SetError(error, L"INetFwRule::get_Action failed");
        return false;
    }

    *found = true;
    *enabled = (vb != VARIANT_FALSE);
    *isBlock = (dir == NET_FW_RULE_DIR_OUT) && (action == NET_FW_ACTION_BLOCK);
    return true;
}

// Add one outbound block rule. Returns true when the rule is present
// afterwards - either because we just created it, or because an identically
// named rule was already there and was left alone.
bool EnsureRule(INetFwRules* rules, const std::wstring& name,
                const std::wstring& description,
                const std::wstring& remoteAddrText, const std::wstring& localPorts,
                const std::wstring& remotePorts, bool* created,
                std::wstring* error) {
    *created = false;

    BStr bname(name);
    if (!bname.valid()) {
        SetError(error, L"out of memory allocating rule name");
        return false;
    }
    {
        ComPtr<INetFwRule> existing;
        if (SUCCEEDED(rules->Item(bname, existing.receive()))) {
            return true;  // already installed
        }
    }

    BStr bdesc(description);
    BStr baddr(remoteAddrText);
    BStr blp(localPorts);
    BStr brp(remotePorts);
    if (!bdesc.valid() || !baddr.valid() || !blp.valid() || !brp.valid()) {
        SetError(error, L"out of memory allocating rule strings");
        return false;
    }

    ComPtr<INetFwRule> rule;
    HRESULT hr = ::CoCreateInstance(kClsidRule, nullptr, CLSCTX_INPROC_SERVER,
                                    kIidRule,
                                    reinterpret_cast<void**>(rule.receive()));
    if (FAILED(hr) || !rule) {
        SetError(error,
                 L"CoCreateInstance(CLSID_NetFwRule) failed: " + FormatHresult(hr));
        return false;
    }

    // Every property is checked. A half-configured rule that still got added
    // would block something nobody asked for and would be invisible until the
    // user went looking, so an unsettable property abandons the object instead
    // of continuing with defaults.
    struct Prop {
        const wchar_t* what;
        HRESULT hr;
    };
    // Protocol must be a CONCRETE protocol, not NET_FW_IP_PROTOCOL_ANY.
    //
    // Measured on this machine, not inferred: with Protocol = ANY (0),
    // put_LocalPorts and put_RemotePorts return E_INVALIDARG (0x80070057) for
    // EVERY value tried - "*", "54321", "54321,443", "1-100" - so the port
    // restrictions could never be applied and every block failed outright. With
    // Protocol = TCP (6) the identical strings return S_OK and INetFwRules::Add
    // succeeds. TCP is also the semantically right answer: the caller is
    // blocking a TCP connection, so a rule that also matched UDP traffic to
    // the same peer would block more than the user asked for.
    const LONG protocol = 6;   // IPPROTO_TCP
    const NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_OUT;
    const NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    const Prop props[] = {
        { L"Name",            rule.get()->put_Name(bname) },
        { L"Description",     rule.get()->put_Description(bdesc) },
        // Null application and service mean "any program" / "any service",
        // which is what makes the block apply to an already-running app.
        { L"ApplicationName", rule.get()->put_ApplicationName(nullptr) },
        { L"ServiceName",     rule.get()->put_ServiceName(nullptr) },
        { L"Protocol",        rule.get()->put_Protocol(protocol) },
        { L"LocalPorts",      rule.get()->put_LocalPorts(blp) },
        { L"RemotePorts",     rule.get()->put_RemotePorts(brp) },
        { L"RemoteAddresses", rule.get()->put_RemoteAddresses(baddr) },
        { L"Direction",       rule.get()->put_Direction(dir) },
        { L"Action",          rule.get()->put_Action(action) },
        { L"Profiles",        rule.get()->put_Profiles(kAllProfiles) },
        { L"Enabled",         rule.get()->put_Enabled(VARIANT_TRUE) },
        { L"EdgeTraversal",   rule.get()->put_EdgeTraversal(VARIANT_FALSE) },
    };
    for (const Prop& p : props) {
        if (FAILED(p.hr)) {
            SetError(error, std::wstring(L"setting rule ") + p.what + L" failed: " +
                                FormatHresult(p.hr));
            return false;
        }
    }

    hr = rules->Add(rule.get());
    if (FAILED(hr)) {
        SetError(error, L"INetFwRules::Add failed: " + FormatHresult(hr));
        return false;
    }

    // Read the name back. INetFwRules::Add can report success while the rule
    // is not enumerable afterwards - observed on this machine - and a block
    // that says it worked but cannot be found or removed is worse than one
    // that fails, because the user believes the peer is blocked.
    {
        ComPtr<INetFwRule> readBack;
        BStr probe(name);
        const HRESULT item = rules->Item(probe, readBack.receive());
        if (FAILED(item) || !readBack) {
            SetError(error, L"INetFwRules::Add reported success but the rule \"" +
                                name + L"\" is not retrievable (" +
                                FormatHresult(item) +
                                L"); Windows Firewall is not accepting new rules "
                                L"from this process - check that another firewall "
                                L"product is not enforcing its own policy");
            // Try to take it back out, so a rule that exists but cannot be
            // read is not left behind unreferenced.
            rules->Remove(probe);
            return false;
        }
    }

    *created = true;
    return true;
}

void RemoveRuleQuiet(INetFwRules* rules, const std::wstring& name) {
    BStr bname(name);
    if (!bname.valid()) {
        return;
    }
    ComPtr<INetFwRule> existing;
    if (SUCCEEDED(rules->Item(bname, existing.receive()))) {
        rules->Remove(bname);
    }
}

// ========================================================================
// The general firewall rule
// ========================================================================
//
// A second writer beside EnsureRule, deliberately: BlockConnection's two rules
// are a shipped, gated behaviour and this was NOT going to be a refactor of it.
// EnsureRule stays exactly as it is; this is the generalized path.

// Sanitise one scope value into the rule name. Determined by the value alone,
// so two rules that differ anywhere in their scope get different names, and
// the same rule always gets the same name - which is what makes
// kAlreadyPresent work. An empty field becomes "-" rather than vanishing, so
// "at its default" and "not stated" cannot collide with a real value.
std::wstring FwRuleNameToken(const std::wstring& value) {
    if (value.empty()) {
        return L"-";
    }
    // Escaped rather than substituted for. A single "_" would make several
    // distinct inputs collide - "a/b" and "a_b" would become the same token,
    // so one rule would silently stand in for another - so every unsafe
    // character is replaced by "_" plus its own hex value, which is unique
    // per character and kept inside the name-length budget.
    std::wstring token;
    token.reserve(value.size());
    for (const wchar_t ch : value) {
        // The name is the only handle for finding the rule again, so anything
        // the firewall or the shell would mangle is replaced rather than
        // passed through.
        const bool safe = (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
                          (ch >= L'0' && ch <= L'9') || ch == L'.' || ch == L',' ||
                          ch == L'-';
        if (safe) {
            token.push_back(ch);
            continue;
        }
        static const wchar_t kHex[] = L"0123456789ABCDEF";
        token.push_back(L'_');
        token.push_back(kHex[(static_cast<uint32_t>(ch) >> 12) & 0xF]);
        token.push_back(kHex[(static_cast<uint32_t>(ch) >> 8) & 0xF]);
        token.push_back(kHex[(static_cast<uint32_t>(ch) >> 4) & 0xF]);
        token.push_back(kHex[static_cast<uint32_t>(ch) & 0xF]);
    }
    return token;
}

}  // namespace

// ========================================================================
// The general firewall rule (public)
// ========================================================================
//
// Deliberately NOT in the anonymous namespace: these are the definitions the
// selftest links against and the product calls, so what is tested is what
// ships - the same rule PromptDialog's TemplateFits and
// BlockedPeersTemplateCapacity follow. A definition here that was also
// declared in BlockConn.h inside an anonymous namespace would be a separate
// function with the same name, which is precisely the ambiguity the compiler
// just reported.

bool ValidateFwRule(const FwRule& rule, std::wstring* error) {
    // Ports need a concrete protocol. Measured on this machine: with
    // Protocol = ANY, put_LocalPorts and put_RemotePorts return E_INVALIDARG
    // for every value tried, so the restriction could never be applied.
    // Refusing is better than creating a rule without its ports.
    const bool restrictsPorts =
        rule.localPorts != L"*" || rule.remotePorts != L"*";
    if (rule.protocol == 0 && restrictsPorts) {
        SetError(error,
                 L"a rule that restricts ports must specify a concrete "
                 L"protocol (tcp or udp): the firewall API rejects port "
                 L"restrictions on protocol any");
        return false;
    }
    if (rule.protocol != 0 && rule.protocol != 6 && rule.protocol != 17) {
        SetError(error,
                 L"protocol must be 6 (tcp), 17 (udp) or 0 (any); got " +
                     std::to_wstring(static_cast<unsigned>(rule.protocol)));
        return false;
    }

    // The address field is passed to the firewall verbatim. It has to be
    // something: an empty string is not "*", and a rule with no address field
    // is not a rule the user asked for.
    if (rule.remoteAddress.empty()) {
        SetError(error,
                 L"the remote address must be \"*\" or an address, list, or "
                 L"CIDR range; an empty field is not the same as any");
        return false;
    }
    if (rule.localAddress.empty()) {
        SetError(error,
                 L"the local address must be \"*\" or an address, list, or CIDR range");
        return false;
    }
    if (rule.profiles <= 0 ||
        (rule.profiles != kAllProfiles &&
         (rule.profiles & ~kSelectableProfiles) != 0)) {
        SetError(error, L"profiles must include Domain, Private, or Public");
        return false;
    }

    // An empty port field is not "*" for the same reason.
    if (rule.localPorts.empty() || rule.remotePorts.empty()) {
        SetError(error,
                 L"a port field must be \"*\" or a port list; an empty field "
                 L"is not the same as any");
        return false;
    }

    // The process path becomes the rule's ApplicationName. It has to be a
    // path: a bare program name is resolved against a working directory this
    // tool does not control, which is how "block chrome" ends up blocking a
    // different program that happens to live in the service's cwd.
    if (!rule.processPath.empty()) {
        if (rule.processPath.find(L'\\') == std::wstring::npos) {
            SetError(error,
                     L"a process rule needs the full image path, not a bare "
                     L"program name: the firewall resolves a bare name "
                     L"against a working directory this tool does not control");
            return false;
        }
        if (!IsLabelSafe(rule.processPath)) {
            SetError(error,
                     L"the process path contains characters the firewall "
                     L"refuses in an application name");
            return false;
        }
    }

    // The name cap is the firewall's, and kMaxRuleNameChars is what is enforced.
    const std::wstring name = BuildFwRuleName(rule);
    if (name.size() > kMaxRuleNameChars) {
        SetError(error, L"the rule name would be " +
                            std::to_wstring(name.size()) +
                            L" characters, over the " +
                            std::to_wstring(kMaxRuleNameChars) +
                            L" the firewall allows; shorten the label");
        return false;
    }
    return true;
}

std::wstring BuildFwRuleName(const FwRule& rule) {
    std::wstring name = wintcp::kRuleNamePrefix;
    name += rule.inbound ? L"in" : L"out";
    name += L"-";
    name += rule.allow ? L"allow" : L"block";
    name += L"-";
    name += (rule.protocol == 0)   ? L"any"
             : (rule.protocol == 6) ? L"tcp"
                                    : L"udp";
    name += L"-";
    name += FwRuleNameToken(rule.remoteAddress);
    if (rule.localAddress != L"*") {
        name += L"-local-";
        name += FwRuleNameToken(rule.localAddress);
    }
    name += L"-";
    name += FwRuleNameToken(rule.localPorts);
    name += L"-";
    name += FwRuleNameToken(rule.remotePorts);
    name += L"-";
    name += FwRuleNameToken(rule.processPath);
    if (!rule.service.empty()) {
        name += L"-";
        name += FwRuleNameToken(rule.service);
    }
    if (rule.profiles != kAllProfiles) {
        name += L"-profile-";
        name += std::to_wstring(rule.profiles);
    }
    if (name.size() >= kMaxRuleNameChars) {
        return name;   // identity preserved; the label is what is dropped
    }
    if (!rule.label.empty()) {
        const size_t room = kMaxRuleNameChars - name.size() - 1;
        const std::wstring label =
            rule.label.substr(0, (std::min)(room, rule.label.size()));
        if (!label.empty()) {
            name += L"-";
            name += label;
        }
    }
    return name;
}

FwRuleOutcome AddFwRule(const FwRule& rule, std::wstring* name,
                        std::wstring* error) {
    if (name != nullptr) {
        name->clear();
    }
    std::wstring why;
    if (!ValidateFwRule(rule, &why)) {
        SetError(error, why);
        return FwRuleOutcome::kFailed;
    }

    const std::wstring ruleName = BuildFwRuleName(rule);
    std::unique_ptr<BStr> procGuard;
    std::unique_ptr<BStr> svcGuard;

    FwSession session;
    if (!session.Open(error)) {
        return FwRuleOutcome::kFailed;
    }
    INetFwRules* rules = session.rules();

    // An identity that already exists is not an error: the rule the user asked
    // for is already in place. Reported distinctly so a caller can say "already
    // blocked" the way BlockConnection already does.
    {
        ComPtr<INetFwRule> existing;
        BStr bname(ruleName);
        if (bname.valid() && SUCCEEDED(rules->Item(bname, existing.receive())) &&
            existing) {
            if (name != nullptr) {
                *name = ruleName;
            }
            // The rule is already in the firewall; make sure we own a ledger
            // entry for it too, so it can be inventoried and removed.
            LedgerRememberRule(ruleName);
            return FwRuleOutcome::kAlreadyPresent;
        }
    }

    BStr bname(ruleName);
    BStr baddr(rule.remoteAddress);
    BStr blocaddr(rule.localAddress);
    BStr blp(rule.localPorts);
    BStr brp(rule.remotePorts);
    if (!rule.processPath.empty()) {
        procGuard.reset(new BStr(rule.processPath));
        if (!procGuard->valid()) {
            SetError(error, L"out of memory allocating the process path");
            return FwRuleOutcome::kFailed;
        }
    }
    if (!rule.service.empty()) {
        svcGuard.reset(new BStr(rule.service));
        if (!svcGuard->valid()) {
            SetError(error, L"out of memory allocating the service name");
            return FwRuleOutcome::kFailed;
        }
    }
    if (!bname.valid() || !baddr.valid() || !blocaddr.valid() ||
        !blp.valid() || !brp.valid()) {
        SetError(error, L"out of memory allocating rule strings");
        return FwRuleOutcome::kFailed;
    }

    ComPtr<INetFwRule> fwRule;
    HRESULT hr = ::CoCreateInstance(kClsidRule, nullptr, CLSCTX_INPROC_SERVER,
                                    kIidRule,
                                    reinterpret_cast<void**>(fwRule.receive()));
    if (FAILED(hr) || !fwRule) {
        SetError(error,
                 L"CoCreateInstance(CLSID_NetFwRule) failed: " + FormatHresult(hr));
        return FwRuleOutcome::kFailed;
    }

    const NET_FW_RULE_DIRECTION dir =
        rule.inbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT;
    const NET_FW_ACTION action = rule.allow ? NET_FW_ACTION_ALLOW
                                            : NET_FW_ACTION_BLOCK;

    struct Prop {
        const wchar_t* what;
        HRESULT hr;
    };
    // The description carries the netsh incantation, the same as
    // EnsureRule's, so a user who reads the rule in WF.msc knows how to remove
    // it by hand without this tool.
    std::wstring desc = L"Created by WinTCP. ";
    desc += rule.allow ? L"Allow" : L"Block";
    desc += rule.inbound ? L" inbound from " : L" outbound to ";
    desc += rule.remoteAddress;
    desc += L". Delete via WinTCP or 'netsh advfirewall firewall delete rule "
            L"name=\"";
    desc += ruleName;
    desc += L"\"'.";
    BStr bdesc(desc);
    if (!bdesc.valid()) {
        SetError(error, L"out of memory allocating the rule description");
        return FwRuleOutcome::kFailed;
    }

    const Prop props[] = {
        { L"Name", fwRule.get()->put_Name(bname) },
        { L"Description", fwRule.get()->put_Description(bdesc) },
        { L"Protocol", fwRule.get()->put_Protocol(rule.protocol) },
        { L"LocalPorts", fwRule.get()->put_LocalPorts(blp) },
        { L"RemotePorts", fwRule.get()->put_RemotePorts(brp) },
        { L"RemoteAddresses", fwRule.get()->put_RemoteAddresses(baddr) },
        { L"LocalAddresses", fwRule.get()->put_LocalAddresses(blocaddr) },
        { L"Direction", fwRule.get()->put_Direction(dir) },
        { L"Action", fwRule.get()->put_Action(action) },
        { L"Profiles", fwRule.get()->put_Profiles(rule.profiles) },
        { L"Enabled", fwRule.get()->put_Enabled(VARIANT_TRUE) },
        { L"EdgeTraversal", fwRule.get()->put_EdgeTraversal(VARIANT_FALSE) },
        // An empty ApplicationName would mean "any program"; a null BSTR is
        // what passes "any" through.
        { L"ApplicationName",
          procGuard ? fwRule.get()->put_ApplicationName(*procGuard)
                    : fwRule.get()->put_ApplicationName(nullptr) },
        { L"ServiceName",
          svcGuard ? fwRule.get()->put_ServiceName(*svcGuard)
                   : fwRule.get()->put_ServiceName(nullptr) },
    };
    for (const Prop& p : props) {
        if (FAILED(p.hr)) {
            SetError(error, std::wstring(L"setting rule ") + p.what + L" failed: " +
                                FormatHresult(p.hr));
            return FwRuleOutcome::kFailed;
        }
    }

    hr = rules->Add(fwRule.get());
    if (FAILED(hr)) {
        SetError(error, L"INetFwRules::Add failed: " + FormatHresult(hr));
        return FwRuleOutcome::kFailed;
    }

    // Read it back, the same guarantee EnsureRule gives: Add can succeed while
    // the rule is not retrievable, and a rule that exists but cannot be found
    // is worse than one that failed - the user believes the peer is blocked.
    {
        ComPtr<INetFwRule> readBack;
        BStr probe(ruleName);
        const HRESULT item = rules->Item(probe, readBack.receive());
        if (FAILED(item) || !readBack) {
            SetError(error, L"INetFwRules::Add reported success but the rule \"" +
                                ruleName + L"\" is not retrievable (" +
                                FormatHresult(item) +
                                L"); Windows Firewall is not accepting new rules "
                                L"from this process - check that another "
                                L"firewall product is not enforcing its own "
                                L"policy");
            rules->Remove(probe);
            return FwRuleOutcome::kFailed;
        }
    }

    if (name != nullptr) {
        *name = ruleName;
    }
    // Record ownership so the rule can be inventoried and removed later.
    // This runs for both newly created and already-present rules; the helper
    // is idempotent.
    LedgerRememberRule(ruleName);
    return FwRuleOutcome::kCreated;
}

// --- layer 1: connection teardown -------------------------------------------

namespace {

// Enumerate the IPv4 TCP table and hand each row to 'fn' along with its index.
bool ForEachIpv4TcpRow(bool (*fn)(const MIB_TCPROW&, void*), void* ctx,
                       std::wstring* error) {
    ULONG size = 0;
    DWORD rc = ::GetTcpTable(nullptr, &size, FALSE);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        SetError(error, L"GetTcpTable size query failed: " + FormatWin32(rc));
        return false;
    }
    std::vector<BYTE> buffer(size);
    rc = ::GetTcpTable(reinterpret_cast<PMIB_TCPTABLE>(buffer.data()), &size, FALSE);
    if (rc != NO_ERROR) {
        SetError(error, L"GetTcpTable failed: " + FormatWin32(rc));
        return false;
    }
    PMIB_TCPTABLE table = reinterpret_cast<PMIB_TCPTABLE>(buffer.data());
    if (table == nullptr) {
        SetError(error, L"GetTcpTable returned a null table");
        return false;
    }
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        if (!fn(table->table[i], ctx)) {
            return false;
        }
    }
    return true;
}

bool PortHostToNetwork(uint16_t port, DWORD* out) {
    *out = static_cast<DWORD>(::htons(static_cast<u_short>(port)));
    return true;
}

bool Addr4ToDword(const unsigned char* raw, DWORD* out) {
    // The four raw bytes are already in network order, which is exactly the
    // in_addr.s_addr layout MIB_TCPROW wants - no ntohl anywhere.
    *out = (static_cast<DWORD>(raw[0]) << 24) | (static_cast<DWORD>(raw[1]) << 16) |
           (static_cast<DWORD>(raw[2]) << 8) | static_cast<DWORD>(raw[3]);
    return true;
}

struct KillCtx {
    DWORD remoteAddr = 0;
    DWORD localPort = 0;
    DWORD remotePort = 0;
    int killed = 0;
    std::wstring lastError;
};

bool KillVisitor(const MIB_TCPROW& row, void* rawCtx) {
    KillCtx* ctx = static_cast<KillCtx*>(rawCtx);
    if (row.dwRemoteAddr != ctx->remoteAddr ||
        row.dwLocalPort != ctx->localPort || row.dwRemotePort != ctx->remotePort) {
        return true;  // not our row; keep scanning
    }
    if (row.dwState == MIB_TCP_STATE_DELETE_TCB) {
        return true;  // already gone
    }
    MIB_TCPROW victim = row;
    victim.dwState = MIB_TCP_STATE_DELETE_TCB;
    const DWORD rc = ::SetTcpEntry(&victim);
    if (rc != NO_ERROR) {
        ctx->lastError = L"SetTcpEntry failed: " + FormatWin32(rc);
        if (rc == ERROR_ACCESS_DENIED) {
            ctx->lastError +=
                L" (tearing down another process' connection requires "
                L"administrator rights)";
        }
        return false;
    }
    ++ctx->killed;
    return true;
}

// Tear down every live IPv4 TCP connection matching (remoteAddr, localPort,
// remotePort), whichever local address it is bound to. Matching the whole set
// rather than a single row is deliberate: a "block this connection" that left
// a sibling socket on another local address standing would look like it had
// worked while the connection lived on.
bool KillMatchingIpv4(const unsigned char* remoteAddr, uint16_t localPort,
                      uint16_t remotePort, int* killed, std::wstring* error) {
    *killed = 0;
    KillCtx ctx;
    if (!Addr4ToDword(remoteAddr, &ctx.remoteAddr) ||
        !PortHostToNetwork(localPort, &ctx.localPort) ||
        !PortHostToNetwork(remotePort, &ctx.remotePort)) {
        SetError(error, L"invalid IPv4 address or port");
        return false;
    }
    if (!ForEachIpv4TcpRow(&KillVisitor, &ctx, error)) {
        if (!ctx.lastError.empty()) {
            *error = ctx.lastError;
        }
        return false;
    }
    *killed = ctx.killed;
    return true;
}

}  // namespace

// --- public API -------------------------------------------------------------

const wchar_t* BlockOutcomeToString(BlockOutcome o) {
    switch (o) {
        case BlockOutcome::kBlocked:        return L"kBlocked";
        case BlockOutcome::kRulesOnly:      return L"kRulesOnly";
        case BlockOutcome::kKilledOnly:     return L"kKilledOnly";
        case BlockOutcome::kFailed:         return L"kFailed";
        case BlockOutcome::kAlreadyBlocked: return L"kAlreadyBlocked";
    }
    return L"kFailed";
}

bool SetIpv4Teardown(const unsigned char* remoteAddr, uint16_t localPort,
                     uint16_t remotePort, std::wstring* error) {
    if (error != nullptr) {
        error->clear();
    }
    if (remoteAddr == nullptr) {
        SetError(error, L"null remote address");
        return false;
    }
    if (localPort == 0 || remotePort == 0) {
        SetError(error, L"port 0 is not a usable TCP endpoint");
        return false;
    }
    if (IsAllZero(remoteAddr, 4)) {
        SetError(error, L"remote address is unspecified");
        return false;
    }

    int killed = 0;
    if (!KillMatchingIpv4(remoteAddr, localPort, remotePort, &killed, error)) {
        return false;
    }
    if (killed == 0) {
        SetError(error,
                 L"no matching IPv4 TCP connection was found - it may already "
                 L"have closed");
        return false;
    }
    return true;
}

BlockOutcome BlockConnection(const BlockRequest& req, std::wstring* error) {
    if (error != nullptr) {
        error->clear();
    }
    if (!ValidateRequest(req, error)) {
        return BlockOutcome::kFailed;
    }

    FwSession session;
    if (!session.Open(error)) {
        return BlockOutcome::kFailed;
    }
    INetFwRules* rules = session.rules();

    // Layer 1: kill the live connection, before the rules go in. Doing it in
    // this order closes the socket first and only then prevents it returning;
    // the reverse order would leave a window in which the owning process could
    // reconnect before the firewall was watching.
    bool killed = false;
    std::wstring killError;
    if (req.ipv6) {
        // Reported truthfully rather than faked; see the note in BlockConn.h.
        // The rules still stop the endpoint coming back, so the caller gets
        // kRulesOnly, not a failure.
        killError =
            L"IPv6 connections cannot be torn down individually: Windows "
            L"exposes no supported public API for it (SetTcpEntry accepts an "
            L"MIB_TCPROW only, and there is no IPv6 equivalent). The firewall "
            L"rules are in place, so this endpoint cannot reconnect.";
    } else {
        std::wstring teardownError;
        killed = SetIpv4Teardown(req.remoteAddr, req.localPort, req.remotePort,
                                 &teardownError);
        if (!killed) {
            killError = teardownError;
        }
    }

    // Layer 2: two outbound block rules.
    const std::wstring addrText = FormatAddress(req.remoteAddr, req.ipv6);
    const std::wstring description = BuildDescription(req);
    const std::wstring endpointName = BuildRuleName(req, L"endpoint");
    const std::wstring portsName = BuildRuleName(req, L"ports");
    const std::wstring localPortText = std::to_wstring(static_cast<unsigned>(req.localPort));
    const std::wstring remotePortText = std::to_wstring(static_cast<unsigned>(req.remotePort));

    bool madeEndpoint = false;
    bool madePorts = false;
    std::wstring ruleError;

    // Rule 1 blocks the remote endpoint for every program and every protocol,
    // regardless of port. "*" is the firewall's "any port" token.
    if (!EnsureRule(rules, endpointName, description, addrText, L"*", L"*",
                    &madeEndpoint, &ruleError)) {
        SetError(error, ruleError);
        return killed ? BlockOutcome::kKilledOnly : BlockOutcome::kFailed;
    }

    // Rule 2 pins the local/remote port pair. This is the rule that actually
    // stops the owning application from dialling the same endpoint again on a
    // fresh ephemeral local port, which the endpoint rule alone would not -
    // an app that reconnects from a different local port is a different
    // connection but the same conversation.
    if (!EnsureRule(rules, portsName, description, L"*", localPortText,
                    remotePortText, &madePorts, &ruleError)) {
        // Never leave half a block: if this rule is new, drop the other one.
        if (madeEndpoint) {
            RemoveRuleQuiet(rules, endpointName);
        }
        SetError(error, ruleError);
        return killed ? BlockOutcome::kKilledOnly : BlockOutcome::kFailed;
    }

    // Record the pair in the ledger. Done unconditionally (not just when the
    // rules were newly created) because a block that was already installed by
    // an earlier session still has to be removable by this one, and the
    // enumerator cannot be used to rediscover it. See the ledger note above.
    // Record ownership even when both rules were already present: the ledger is
    // what lets a later session find and remove them.
    LedgerRemember(req);

    if (killed) {
        SetError(error, killError);  // empty when the kill genuinely succeeded
        return BlockOutcome::kBlocked;
    }
    if (!madeEndpoint && !madePorts) {
        // Both rules were already present: nothing was created, and the
        // connection is (still) blocked. Distinct from kFailed so a repeated
        // "block" click is not reported as an error.
        SetError(error, killError.empty() ? std::wstring()
                                          : L"Already blocked. " + killError);
        return BlockOutcome::kAlreadyBlocked;
    }
    SetError(error, killError.empty() ? std::wstring()
                                      : L"Blocked (rules only). " + killError);
    return BlockOutcome::kRulesOnly;
}

bool UnblockConnection(const BlockRequest& req, std::wstring* error) {
    if (error != nullptr) {
        error->clear();
    }
    FwSession session;
    if (!session.Open(error)) {
        return false;
    }
    INetFwRules* rules = session.rules();

    const std::wstring endpointName = BuildRuleName(req, L"endpoint");
    const std::wstring portsName = BuildRuleName(req, L"ports");

    bool ok = true;
    std::wstring firstError;
    const std::wstring names[] = {endpointName, portsName};
    for (const std::wstring& name : names) {
        BStr bname(name);
        if (!bname.valid()) {
            SetError(error, L"out of memory allocating rule name");
            return false;
        }
        ComPtr<INetFwRule> existing;
        const HRESULT hr = rules->Item(bname, existing.receive());
        if (IsMissingFirewallRuleResult(hr)) {
            continue;  // already absent: nothing to do, and not an error
        }
        if (FAILED(hr)) {
            SetError(error, L"could not inspect firewall rule \"" + name +
                                L"\": " + FormatHresult(hr));
            return false;
        }
        const HRESULT del = rules->Remove(bname);
        if (FAILED(del)) {
            ok = false;
            if (firstError.empty()) {
                firstError = L"INetFwRules::Remove(\"" + name + L"\") failed: " +
                             FormatHresult(del);
            }
        }
    }
    if (!ok) {
        // Only forget on success: if a rule survived, the ledger entry must
        // stay so a later RemoveAllWinTcpRules can still find and remove it.
        SetError(error, firstError);
        return false;
    }
    LedgerForget(req);
    return true;
}

bool IsConnectionBlocked(const BlockRequest& req) {
    FwSession session;
    std::wstring ignored;
    if (!session.Open(&ignored)) {
        return false;
    }
    INetFwRules* rules = session.rules();

    const std::wstring names[] = {BuildRuleName(req, L"endpoint"),
                                  BuildRuleName(req, L"ports")};
    for (const std::wstring& name : names) {
        bool found = false;
        bool enabled = false;
        bool isBlock = false;
        std::wstring err;
        if (!QueryRule(rules, name, &found, &enabled, &isBlock, &err)) {
            return false;
        }
        if (!found || !enabled || !isBlock) {
            return false;  // a missing, disabled or non-blocking rule is no block
        }
    }
    return true;
}
// ---------------------------------------------------------------------------
// The block ledger
// ---------------------------------------------------------------------------
//
// Why a ledger exists, and why enumeration cannot be used instead. Measured
// on this machine: a rule created through INetFwRules::Add is immediately
// retrievable with INetFwRules::Item and is reported correctly by
// `netsh advfirewall firewall show rule name=<name>` (RemoteIP 203.0.113.7/32,
// Protocol TCP, Action Block) - but it is ABSENT from the IEnumVARIANT
// enumeration in the same process. The rule genuinely enforces; only the
// enumerator is incomplete.
//
// An enumeration-based count therefore reported 0 for a rule that really
// existed, and RemoveAllWinTcpRules would have silently left it behind. A
// block the user cannot undo is the one failure mode this feature must never
// have, so neither function may depend on the enumerator.
//
// So every block is written to a small registry ledger. That also solves the
// cross-session problem enumeration could not: rules outlive the process, so
// without a ledger a new run would have no way to know what it left behind.

std::wstring LedgerKey() {
    // Two changes, both needed.
    //
    // The buffer is grown to MAX_PATH * 2, which is what CrashDump.cpp already
    // uses for the same variable - a deep %APPDATA% is the only way to reach
    // MAX_PATH here, and growing is cheaper than handling it.
    //
    // And the return value is checked PROPERLY. `== 0` tested for failure, but
    // GetEnvironmentVariableW reports a too-small buffer as the REQUIRED size
    // and leaves the buffer EMPTY (measured: a 400-char variable into an 8-char
    // buffer returns 401 with the buffer untouched). So the old check passed,
    // std::wstring(path) was "", and the ledger path became L"\\WinTCP\\blocked.txt"
    // - RELATIVE, resolved against whatever directory the user ran from. Rules
    // the user had every reason to believe were persisted would quietly go to
    // the wrong place. See bufferWasTooSmall in Utils.h for the measurements.
    wchar_t path[MAX_PATH * 2] = {0};
    const DWORD n = ::GetEnvironmentVariableW(L"APPDATA", path, MAX_PATH * 2);
    if (bufferWasTooSmall(n, MAX_PATH * 2)) {
        return std::wstring();
    }
    return std::wstring(path) + L"\\WinTCP\\blocked.txt";
}

// One line per rule: the two rule names, tab-separated, base64-free because
// they are already restricted to [0-9A-F] and "-". A tab cannot appear in a
// name, so the format needs no escaping.
std::mutex g_ledgerLock;

// Caps. kLedgerMaxLineBytes lives in BlockConn.h so the selftest that pins
// the boundary cannot drift from the parser. A real ledger is one short line
// per blocked peer, so tens of rules is a few KB. 4 MiB is tens of thousands
// of such lines - far past any plausible use, and a hard bound on what a
// corrupt or planted file can make this process allocate. Previously the read
// was an append loop with no bound at all.
constexpr size_t kLedgerMaxFileBytes = 4u * 1024u * 1024u;

// Strict UTF-8 -> UTF-16, which Utf8ToWide() (Utils.cpp) is NOT. It calls
// MultiByteToWideChar with flags 0, and with CP_UTF8 that makes the function
// substitute U+FFFD for a bad byte and report SUCCESS. That is fine for
// display and wrong here: a corrupted line would silently become a rule name
// nobody wrote, and RemoveAllWinTcpRules would ask the firewall to remove a
// name built out of replacement characters. MB_ERR_INVALID_CHARS makes it fail
// instead, which is the only behaviour this ledger needs.
//
// Returns an empty string with *ok false on invalid input. 'needed' is only 0
// for invalid input or an empty string, and the empty case returns above, so
// the error code does not have to be consulted.
std::wstring Utf8ToWideStrict(const std::string& s, bool* ok) {
    *ok = true;
    if (s.empty()) return std::wstring();
    const int needed =
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                              static_cast<int>(s.size()), nullptr, 0);
    if (needed == 0) {
        *ok = false;
        return std::wstring();
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                              static_cast<int>(s.size()), out.data(),
                              needed) <= 0) {
        *ok = false;
        return std::wstring();
    }
    return out;
}

bool ParseLedgerBytes(const char* data, size_t len,
                      std::vector<std::wstring>* out, std::wstring* error) {
    if (error != nullptr) error->clear();
    std::vector<std::wstring> pairs;
    size_t start = 0;
    size_t lineNo = 0;
    while (start < len) {
        size_t nl = len;
        // memchr, not a byte-at-a-time scan: on a ledger with many short lines
        // the linear inner search made the whole parse O(n^2).
        const void* hit = std::memchr(data + start, '\n', len - start);
        if (hit != nullptr)
            nl = static_cast<size_t>(static_cast<const char*>(hit) - data);
        const size_t rawLen = nl - start;
        ++lineNo;
        if (rawLen > kLedgerMaxLineBytes) {
            SetError(error,
                     L"block ledger line " + std::to_wstring(lineNo) + L" is " +
                         std::to_wstring(rawLen) + L" bytes, over the " +
                         std::to_wstring(kLedgerMaxLineBytes) +
                         L"-byte limit; refusing the whole ledger rather than "
                         L"skipping a line whose rule names are unknown.");
            return false;
        }
        std::string line(data + start, rawLen);
        start = nl + 1;
        // Trim CR from CRLF.
        std::string trimmed = line;
        while (!trimmed.empty() &&
               (trimmed.back() == '\r' || trimmed.back() == ' '))
            trimmed.pop_back();
        if (trimmed.empty()) continue;   // blank line: not a pair, skip
        // A NUL cannot be produced by WideToUtf8 of a rule name, and a wstring
        // holding one would be truncated when handed to the firewall as a
        // BSTR - so the name silently loses its tail. Refuse instead.
        if (trimmed.find('\0') != std::string::npos) {
            SetError(error,
                     L"block ledger line " + std::to_wstring(lineNo) +
                         L" contains a NUL byte, which this file never writes; "
                         L"refusing the whole ledger.");
            return false;
        }
        bool ok = false;
        const std::wstring wide = Utf8ToWideStrict(trimmed, &ok);
        if (!ok) {
            SetError(error,
                     L"block ledger line " + std::to_wstring(lineNo) +
                         L" is not valid UTF-8; refusing the whole ledger "
                         L"rather than guessing at a rule name.");
            return false;
        }
        pairs.push_back(wide);
    }
    if (out != nullptr) *out = std::move(pairs);
    return true;
}

// Reads the ledger. An ABSENT file is an empty ledger (no error). A file
// that exists but cannot be trusted - over the size cap, or a line the parser
// refuses - returns an EMPTY vector and sets *error. Callers must treat a
// non-empty *error as "do not write": writing an empty ledger over a real one
// would erase the record of every rule it still owns, which is precisely what
// RemoveAllWinTcpRules exists to undo.
std::vector<std::wstring> ReadLedger(std::wstring* error) {
    std::vector<std::wstring> pairs;
    if (error != nullptr) error->clear();
    const std::wstring path = LedgerKey();
    if (path.empty()) return pairs;
    HANDLE f = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        if (err != ERROR_FILE_NOT_FOUND) {
            SetError(error, L"cannot open the block ledger " + path + L": " +
                                FormatSystemError(err));
        }
        return pairs;
    }
    // Bound the read before allocating anything. The old loop appended
    // until ReadFile returned 0, so a corrupt or planted multi-gigabyte file
    // was unbounded memory growth in a process that only ever wanted a few KB.
    LARGE_INTEGER fileSize = {};
    if (!::GetFileSizeEx(f, &fileSize)) {
        const DWORD err = ::GetLastError();
        ::CloseHandle(f);
        SetError(error, L"cannot read the size of the block ledger " + path +
                             L": " + FormatSystemError(err));
        return pairs;
    }
    if (fileSize.QuadPart < 0 ||
        static_cast<unsigned long long>(fileSize.QuadPart) >
            static_cast<unsigned long long>(kLedgerMaxFileBytes)) {
        const unsigned long long got =
            static_cast<unsigned long long>(fileSize.QuadPart);
        ::CloseHandle(f);
        SetError(error, L"the block ledger " + path + L" is " +
                             std::to_wstring(got) + L" bytes, over the " +
                             std::to_wstring(kLedgerMaxFileBytes) +
                             L"-byte limit; refusing to load it. A real ledger "
                             L"holds one short line per blocked peer.");
        return pairs;
    }
    std::string text;
    text.resize(static_cast<size_t>(fileSize.QuadPart));
    DWORD got = 0;
    bool readOk = true;
    if (!text.empty())
        readOk = ::ReadFile(f, &text[0], static_cast<DWORD>(text.size()), &got,
                            nullptr) != FALSE;
    const DWORD readErr = ::GetLastError();
    ::CloseHandle(f);
    if (!readOk) {
        SetError(error, L"cannot read the block ledger " + path + L": " +
                             FormatSystemError(readErr));
        return pairs;
    }
    text.resize(got);
    std::wstring parseErr;
    if (!ParseLedgerBytes(text.data(), text.size(), &pairs, &parseErr)) {
        if (error != nullptr) *error = parseErr;
        pairs.clear();
        return pairs;
    }
    return pairs;
}

bool WriteLedger(const std::vector<std::wstring>& pairs) {
    const std::wstring path = LedgerKey();
    if (path.empty()) return false;
    // Create the parent directory. It is derived by cutting the FINAL
    // separator, not by walking back over every backslash in turn - the first
    // version of this created %APPDATA%\WinTCP as a DIRECTORY named
    // "blocked.txt" (it cut at the wrong index), and then CreateFile failed
    // with ERROR_ACCESS_DENIED on every write. Deriving the parent from the
    // last separator is the only part of the path that is actually needed.
    const size_t sep = path.find_last_of(L'\\');
    if (sep != std::wstring::npos) {
        const std::wstring dir = path.substr(0, sep);
        ::SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    }
    // Write to a temp file in the SAME directory, then rename over the real
    // ledger. CREATE_ALWAYS + write + close is NOT atomic: a kill mid-write
    // leaves a truncated ledger, and RemoveAllWinTcpRules then cannot see
    // which rules it owns. A same-name MoveFileExW(REPLACE_EXISTING) is a
    // rename on NTFS - atomic, so a crash leaves either the old file or the
    // new one, never a half-written one.
    const std::wstring tmp = path + L".tmp";
    HANDLE f = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    std::string text;
    for (const std::wstring& p : pairs) {
        text += WideToUtf8(p);
        text += "\r\n";
    }
    DWORD written = 0;
    const BOOL writeOk = ::WriteFile(f, text.data(),
                                    static_cast<DWORD>(text.size()), &written,
                                    nullptr);
    ::FlushFileBuffers(f);
    ::CloseHandle(f);
    if (!writeOk || written != static_cast<DWORD>(text.size())) {
        ::DeleteFileW(tmp.c_str());
        return false;
    }
    if (!::MoveFileExW(tmp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ::DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

// Add (or re-add) a block's rule-name pair to the ledger. Idempotent.
void LedgerRemember(const BlockRequest& req) {
    const std::wstring pair =
        BuildRuleName(req, L"endpoint") + L"\t" + BuildRuleName(req, L"ports");
    std::lock_guard<std::mutex> lock(g_ledgerLock);
    std::wstring readErr;
    std::vector<std::wstring> pairs = ReadLedger(&readErr);
    // Never write over a ledger we could not read. Doing so would replace
    // a file this app still depends on with one short line, losing the record
    // of every other rule it owns. Same handling as a failed WriteLedger
    // below, which has always been ignored here: the block itself is installed
    // and enforcing either way, so refusing to record it degrades "remove all"
    // rather than unblocking anything.
    if (!readErr.empty()) return;
    if (std::find(pairs.begin(), pairs.end(), pair) != pairs.end()) {
        return;   // already recorded
    }
    pairs.push_back(pair);
    WriteLedger(pairs);
}

// Drop a block's pair from the ledger, so a later session does not try to
// remove a rule that is already gone.
void LedgerForget(const BlockRequest& req) {
    const std::wstring pair =
        BuildRuleName(req, L"endpoint") + L"\t" + BuildRuleName(req, L"ports");
    std::lock_guard<std::mutex> lock(g_ledgerLock);
    std::wstring readErr;
    std::vector<std::wstring> pairs = ReadLedger(&readErr);
    if (!readErr.empty()) return;   // as above - never rewrite what we cannot read
    const auto it = std::find(pairs.begin(), pairs.end(), pair);
    if (it == pairs.end()) return;
    pairs.erase(it);
    WriteLedger(pairs);
}

// Record one general firewall rule in the ledger, so the inventory and
// remove-all paths can find it. A single-name line is the shape
// SplitLedgerNames/RemoveBlockedRule already understand.
void LedgerRememberRule(const std::wstring& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_ledgerLock);
    std::wstring readErr;
    std::vector<std::wstring> pairs = ReadLedger(&readErr);
    if (!readErr.empty()) return;
    for (const std::wstring& line : pairs) {
        for (const std::wstring& existing : SplitLedgerNames(line)) {
            if (existing == name) return;   // already recorded
        }
    }
    pairs.push_back(name);
    WriteLedger(pairs);
}

int CountWinTcpRules(std::wstring* error) {
    if (error != nullptr) error->clear();
    FwSession session;
    std::wstring ignored;
    if (!session.Open(&ignored)) {
        // A firewall we cannot open is a count we cannot make, not a count of
        // zero - the same distinction made about the ledger. Reported on
        // the error channel so `blocks` can say so.
        SetError(error, L"cannot open the Windows Firewall policy: " + ignored);
        return 0;
    }
    INetFwRules* rules = session.rules();

    std::lock_guard<std::mutex> lock(g_ledgerLock);
    int count = 0;
    // A ledger we could not read counts as 0, and that is honest rather
    // than a silent wrong answer - the caller is "how many WinTCP rules are
    // installed", and RemoveAllWinTcpRules, which shares this ledger, will
    // surface the read failure by name if the user goes on to remove them.
    std::wstring readErr;
    const std::vector<std::wstring> pairs = ReadLedger(&readErr);
    if (!readErr.empty()) {
        SetError(error, readErr);
        return 0;
    }
    for (const std::wstring& pair : pairs) {
        const std::wstring name = LedgerPeerName(pair);
        if (name.empty()) continue;
        ComPtr<INetFwRule> found;
        BStr bname(name);
        if (!bname.valid()) {
            SetError(error, L"out of memory allocating firewall rule name");
            return 0;
        }
        const HRESULT lookup = rules->Item(bname, found.receive());
        if (SUCCEEDED(lookup) && found.get() != nullptr) {
            ++count;   // only rules the firewall still reports
        } else if (!IsMissingFirewallRuleResult(lookup)) {
            SetError(error, L"could not inspect firewall rule \"" + name +
                                 L"\": " + FormatHresult(lookup));
            return 0;
        }
    }
    return count;
}

bool RemoveAllWinTcpRules(std::wstring* error) {
    if (error != nullptr) {
        error->clear();
    }
    FwSession session;
    if (!session.Open(error)) {
        return false;
    }
    INetFwRules* rules = session.rules();

    std::lock_guard<std::mutex> lock(g_ledgerLock);
    std::wstring pairsErr;
    std::vector<std::wstring> pairs = ReadLedger(&pairsErr);
    if (!pairsErr.empty()) {
        // A ledger we could not read with confidence. Returning false here
        // is the whole point of the error channel: the loop below would find
        // nothing, report success, and then WriteLedger({}) - erasing the
        // record of every rule still installed in the firewall, which is the
        // one outcome "remove all blocks" must never produce.
        SetError(error, pairsErr);
        return false;
    }

    bool ok = true;
    std::wstring firstError;
    for (const std::wstring& name : CollectLedgerRuleNames(pairs)) {
        BStr bname(name);
        if (!bname.valid()) {
            if (ok) {
                ok = false;
                firstError = L"out of memory allocating firewall rule name";
            }
            continue;
        }
        ComPtr<INetFwRule> found;
        const HRESULT lookup = rules->Item(bname, found.receive());
        if (IsMissingFirewallRuleResult(lookup)) {
            continue;   // already gone: nothing to do, and not an error
        }
        if (FAILED(lookup) || found.get() == nullptr) {
            if (ok) {
                ok = false;
                firstError = L"could not inspect \"" + name + L"\": " +
                             FormatHresult(lookup);
            }
            continue;
        }
        const HRESULT del = rules->Remove(bname);
        if (FAILED(del) && ok) {
            ok = false;
            firstError = L"could not remove \"" + name + L"\": " +
                         FormatHresult(del);
            continue;
        }
        if (SUCCEEDED(del)) {
            ComPtr<INetFwRule> remaining;
            const HRESULT verify = rules->Item(bname, remaining.receive());
            if (!IsMissingFirewallRuleResult(verify) && ok) {
                ok = false;
                firstError = SUCCEEDED(verify) && remaining.get() != nullptr
                    ? L"Windows Firewall still reports \"" + name + L"\" after removal"
                    : L"could not verify removal of \"" + name +
                          L"\": " + FormatHresult(verify);
            }
        }
    }
    // The ledger is rewritten unconditionally on success so a rule the user
    // deleted by hand does not linger in it and block a future re-add.
    if (ok) {
        if (!WriteLedger({})) {
            SetError(error, L"the firewall rules were removed, but the WinTCP rule ledger could not be cleared");
            return false;
        }
    } else {
        SetError(error, firstError);
    }
    return ok;
}

std::vector<std::wstring> SplitLedgerNames(const std::wstring& line) {
    std::vector<std::wstring> names;
    size_t start = 0;
    while (start <= line.size()) {
        const size_t tab = line.find(L'\t', start);
        const size_t len = tab == std::wstring::npos ? std::wstring::npos
                                                     : tab - start;
        const std::wstring name = line.substr(start, len);
        if (!name.empty()) {
            names.push_back(name);
        }
        if (tab == std::wstring::npos) break;
        start = tab + 1;
    }
    return names;
}

std::vector<std::wstring> CollectLedgerRuleNames(
    const std::vector<std::wstring>& lines) {
    std::vector<std::wstring> names;
    for (const std::wstring& line : lines) {
        std::vector<std::wstring> fields = SplitLedgerNames(line);
        names.insert(names.end(), fields.begin(), fields.end());
    }
    return names;
}

std::wstring LedgerPeerName(const std::wstring& line) {
    const size_t tab = line.find(L'\t');
    return line.substr(0, tab);
}

bool IsMissingFirewallRuleResult(HRESULT result) {
    return result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
           result == HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

bool BlankLedgerName(const std::wstring& line, const std::wstring& name,
                     std::wstring* out) {
    if (out == nullptr || name.empty()) return false;
    std::wstring work(line);
    bool touched = false;
    size_t start = 0;
    while (start <= work.size()) {
        const size_t tab = work.find(L'\t', start);
        const size_t len = tab == std::wstring::npos ? std::wstring::npos
                                                     : tab - start;
        if (work.compare(start, len, name) == 0) {
            work.replace(start, len, std::wstring());
            touched = true;
        }
        if (tab == std::wstring::npos) break;
        start = tab + 1;
    }
    if (touched) {
        *out = work;
    }
    return touched;
}

// ---- the firewall viewer's engine half --------------------------------------
//
// Everything the viewer shows comes from the rule itself once it is in hand -
// enabled, direction, action, addresses and ports - so a rule the user edited
// in netsh or WF.msc reads as it actually is. The LEDGER's only job here is to
// supply the names, because the enumerator cannot (see the note on
// CountWinTcpRules).

// Read one BSTR property off a rule, tolerating a null return (which several
// INetFwRule getters produce for "any" rather than for "empty").
std::wstring ReadBstrProp(HRESULT (STDMETHODCALLTYPE INetFwRule::*get)(BSTR*),
                          INetFwRule* rule) {
    BSTR raw = nullptr;
    const HRESULT hr = (rule->*get)(&raw);
    if (FAILED(hr) || raw == nullptr) {
        if (raw != nullptr) ::SysFreeString(raw);
        return std::wstring();
    }
    std::wstring out(raw, ::SysStringLen(raw));
    ::SysFreeString(raw);
    return out;
}

bool ReadBstrProp(HRESULT (STDMETHODCALLTYPE INetFwRule::*get)(BSTR*),
                  INetFwRule* rule, std::wstring* out) {
    if (rule == nullptr || out == nullptr) return false;
    BSTR raw = nullptr;
    const HRESULT hr = (rule->*get)(&raw);
    if (FAILED(hr)) {
        if (raw != nullptr) ::SysFreeString(raw);
        return false;
    }
    if (raw == nullptr) {
        *out = L"*";
        return true;
    }
    out->assign(raw, ::SysStringLen(raw));
    ::SysFreeString(raw);
    return true;
}

bool ReadLongProp(HRESULT (STDMETHODCALLTYPE INetFwRule::*get)(LONG*),
                  INetFwRule* rule, LONG* out) {
    return rule != nullptr && out != nullptr && SUCCEEDED((rule->*get)(out));
}

bool ReadFirewallRule(INetFwRule* rule, bool owned, BlockedRule* entry) {
    if (rule == nullptr || entry == nullptr) return false;
    entry->wintcpOwned = owned;
    BSTR rawName = nullptr;
    if (FAILED(rule->get_Name(&rawName)) || rawName == nullptr) {
        if (rawName != nullptr) ::SysFreeString(rawName);
        return false;
    }
    entry->name.assign(rawName, ::SysStringLen(rawName));
    ::SysFreeString(rawName);

    VARIANT_BOOL enabled = VARIANT_FALSE;
    if (SUCCEEDED(rule->get_Enabled(&enabled))) {
        entry->enabled = enabled != VARIANT_FALSE;
        entry->enabledKnown = true;
    }
    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
    if (SUCCEEDED(rule->get_Direction(&direction))) {
        entry->direction = static_cast<LONG>(direction);
        entry->directionKnown = true;
    }
    NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
    if (SUCCEEDED(rule->get_Action(&action))) {
        entry->action = static_cast<LONG>(action);
        entry->actionKnown = true;
    }
    entry->protocolKnown = ReadLongProp(&INetFwRule::get_Protocol, rule,
                                        &entry->protocol);
    entry->profilesKnown = ReadLongProp(&INetFwRule::get_Profiles, rule,
                                        &entry->profiles);
    entry->blockingKnown = entry->directionKnown && entry->actionKnown;
    if (entry->blockingKnown) {
        entry->isBlocking = entry->direction == NET_FW_RULE_DIR_OUT &&
                            entry->action == NET_FW_ACTION_BLOCK;
    }
    entry->remoteAddrsKnown = ReadBstrProp(
        &INetFwRule::get_RemoteAddresses, rule, &entry->remoteAddrs);
    entry->localAddrsKnown = ReadBstrProp(
        &INetFwRule::get_LocalAddresses, rule, &entry->localAddrs);
    entry->localPortsKnown = ReadBstrProp(
        &INetFwRule::get_LocalPorts, rule, &entry->localPorts);
    entry->remotePortsKnown = ReadBstrProp(
        &INetFwRule::get_RemotePorts, rule, &entry->remotePorts);
    entry->applicationKnown = ReadBstrProp(
        &INetFwRule::get_ApplicationName, rule, &entry->application);
    entry->serviceKnown = ReadBstrProp(
        &INetFwRule::get_ServiceName, rule, &entry->service);
    return true;
}

bool ListBlockedRules(std::vector<BlockedRule>* out, std::wstring* error) {
    if (out == nullptr) {
        SetError(error, L"internal error: no output for ListBlockedRules");
        return false;
    }
    out->clear();
    if (error != nullptr) {
        error->clear();
    }
    FwSession session;
    if (!session.Open(error)) {
        return false;
    }
    INetFwRules* rules = session.rules();

    std::lock_guard<std::mutex> lock(g_ledgerLock);
    std::wstring readErr;
    const std::vector<std::wstring> pairs = ReadLedger(&readErr);
    if (!readErr.empty()) {
        SetError(error, readErr);
        return false;
    }

    for (const std::wstring& pair : pairs) {
        // One ledger line can hold up to two names: "endpoint\tports".
        // Both are listed, because both are rules the user can delete and
        // both are what RemoveAllWinTcpRules is supposed to clean up.
        for (const std::wstring& name : SplitLedgerNames(pair)) {
            BlockedRule entry;
            entry.name = name;
            BStr bname(name);
            if (!bname.valid()) {
                out->clear();
                SetError(error, L"out of memory allocating firewall rule name");
                return false;
            }
            ComPtr<INetFwRule> rule;
            const HRESULT lookup = rules->Item(bname, rule.receive());
            if (IsMissingFirewallRuleResult(lookup)) continue;
            if (FAILED(lookup) || rule.get() == nullptr) {
                out->clear();
                SetError(error, L"could not inspect firewall rule \"" + name +
                                    L"\": " + FormatHresult(lookup));
                return false;
            }
            {
                VARIANT_BOOL vb = VARIANT_FALSE;
                if (SUCCEEDED(rule.get()->get_Enabled(&vb))) {
                    entry.enabled = (vb != VARIANT_FALSE);
                    entry.enabledKnown = true;
                }
                NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;
                const HRESULT directionResult = rule.get()->get_Direction(&dir);
                NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
                const HRESULT actionResult = rule.get()->get_Action(&action);
                entry.blockingKnown = SUCCEEDED(directionResult) &&
                                      SUCCEEDED(actionResult);
                if (entry.blockingKnown) {
                    entry.isBlocking = (dir == NET_FW_RULE_DIR_OUT) &&
                                       (action == NET_FW_ACTION_BLOCK);
                }
                entry.remoteAddrsKnown = ReadBstrProp(
                    &INetFwRule::get_RemoteAddresses, rule.get(),
                    &entry.remoteAddrs);
                entry.localPortsKnown = ReadBstrProp(
                    &INetFwRule::get_LocalPorts, rule.get(), &entry.localPorts);
                entry.remotePortsKnown = ReadBstrProp(
                    &INetFwRule::get_RemotePorts, rule.get(),
                    &entry.remotePorts);
                out->push_back(std::move(entry));
            }
        }
    }
    return true;
}

bool ListFirewallInventory(std::vector<BlockedRule>* out, std::wstring* error,
                           std::wstring* warning, long* activeProfileTypes,
                           bool* activeProfileKnown) {
    if (out == nullptr) {
        SetError(error, L"internal error: no output for ListFirewallInventory");
        return false;
    }
    out->clear();
    if (error != nullptr) error->clear();
    if (warning != nullptr) warning->clear();
    if (activeProfileTypes != nullptr) *activeProfileTypes = 0;
    if (activeProfileKnown != nullptr) *activeProfileKnown = false;
    FwSession session;
    if (!session.Open(error)) return false;

    std::vector<std::wstring> ledgerNames;
    {
        std::lock_guard<std::mutex> lock(g_ledgerLock);
        std::wstring ledgerError;
        const std::vector<std::wstring> pairs = ReadLedger(&ledgerError);
        if (!ledgerError.empty()) {
            if (warning != nullptr) *warning = ledgerError;
        } else {
            for (const std::wstring& pair : pairs) {
                for (const std::wstring& name : SplitLedgerNames(pair))
                    if (!name.empty()) ledgerNames.push_back(name);
            }
        }
    }
    auto sameName = [](const std::wstring& left, const std::wstring& right) {
        return ::CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()),
                                      right.c_str(), static_cast<int>(right.size()),
                                      TRUE) == CSTR_EQUAL;
    };
    auto appendWarning = [&](const std::wstring& message) {
        if (warning == nullptr || message.empty()) return;
        if (!warning->empty()) *warning += L" ";
        *warning += message;
    };
    if (activeProfileTypes != nullptr || activeProfileKnown != nullptr) {
        long profileTypes = 0;
        const HRESULT profileResult = session.CurrentProfileTypes(&profileTypes);
        if (SUCCEEDED(profileResult)) {
            if (activeProfileTypes != nullptr) *activeProfileTypes = profileTypes;
            if (activeProfileKnown != nullptr) *activeProfileKnown = true;
        } else {
            appendWarning(L"The active Windows Firewall profile is unavailable: " +
                          FormatHresult(profileResult));
        }
    }
    std::vector<std::wstring> enumeratedNames;
    IUnknown* rawEnumerator = nullptr;
    HRESULT hr = session.rules()->get__NewEnum(&rawEnumerator);
    if (FAILED(hr) || rawEnumerator == nullptr) {
        appendWarning(L"Windows Firewall rule enumeration is unavailable: " +
                      FormatHresult(hr));
    } else {
        ComPtr<IUnknown> enumeratorOwner;
        enumeratorOwner.p = rawEnumerator;
        ComPtr<IEnumVARIANT> enumerator;
        hr = enumeratorOwner->QueryInterface(IID_IEnumVARIANT,
                                             reinterpret_cast<void**>(enumerator.receive()));
        if (FAILED(hr) || !enumerator) {
            appendWarning(L"Windows Firewall rule enumerator is unavailable: " +
                          FormatHresult(hr));
        } else {
            for (;;) {
                VARIANT item;
                ::VariantInit(&item);
                ULONG fetched = 0;
                hr = enumerator->Next(1, &item, &fetched);
                if (hr == S_FALSE || fetched == 0) {
                    ::VariantClear(&item);
                    break;
                }
                if (FAILED(hr)) {
                    ::VariantClear(&item);
                    appendWarning(L"Windows Firewall rule enumeration stopped early: " +
                                  FormatHresult(hr));
                    break;
                }
                IUnknown* unknown = nullptr;
                if (item.vt == VT_DISPATCH && item.pdispVal != nullptr)
                    unknown = item.pdispVal;
                else if (item.vt == VT_UNKNOWN)
                    unknown = item.punkVal;
                ComPtr<INetFwRule> rule;
                if (unknown != nullptr)
                    (void)unknown->QueryInterface(kIidRule,
                                                  reinterpret_cast<void**>(rule.receive()));
                BlockedRule entry;
                if (rule && ReadFirewallRule(rule.get(), false, &entry)) {
                    const bool owned = std::any_of(ledgerNames.begin(), ledgerNames.end(),
                        [&](const std::wstring& name) { return sameName(name, entry.name); });
                    entry.wintcpOwned = entry.wintcpOwned || owned;
                    enumeratedNames.push_back(entry.name);
                    out->push_back(std::move(entry));
                }
                ::VariantClear(&item);
            }
        }
    }

    for (const std::wstring& name : ledgerNames) {
        const bool alreadyEnumerated = std::any_of(
            enumeratedNames.begin(), enumeratedNames.end(),
            [&](const std::wstring& candidate) { return sameName(name, candidate); });
        if (alreadyEnumerated) continue;
        BStr bname(name);
        if (!bname.valid()) {
            appendWarning(L"A WinTCP-owned firewall rule could not be retrieved because its name could not be allocated.");
            continue;
        }
        ComPtr<INetFwRule> rule;
        const HRESULT lookup = session.rules()->Item(bname, rule.receive());
        if (IsMissingFirewallRuleResult(lookup))
            continue;
        if (FAILED(lookup) || !rule) {
            appendWarning(L"The WinTCP-owned firewall rule \"" + name +
                          L"\" could not be read: " + FormatHresult(lookup));
            continue;
        }
        BlockedRule entry;
        if (ReadFirewallRule(rule.get(), true, &entry)) {
            enumeratedNames.push_back(entry.name);
            out->push_back(std::move(entry));
        } else {
            appendWarning(L"The WinTCP-owned firewall rule \"" + name +
                          L"\" could not be decoded.");
        }
    }
    return true;
}

bool RemoveBlockedRule(const std::wstring& name, std::wstring* error) {
    if (error != nullptr) {
        error->clear();
    }
    if (name.empty()) {
        SetError(error, L"internal error: no rule name to remove");
        return false;
    }
    FwSession session;
    if (!session.Open(error)) {
        return false;
    }
    INetFwRules* rules = session.rules();

    BStr bname(name);
    if (!bname.valid()) {
        SetError(error, L"out of memory allocating rule name");
        return false;
    }
    ComPtr<INetFwRule> found;
    const HRESULT lookup = rules->Item(bname, found.receive());
    if (FAILED(lookup)) {
        if (!IsMissingFirewallRuleResult(lookup)) {
            SetError(error, L"could not inspect \"" + name + L"\": " +
                                FormatHresult(lookup));
            return false;
        }
        // Already gone. The ledger still needs repairing below, so this is
        // success rather than an error - same shape as
        // RemoveAllWinTcpRules, which skips an absent rule silently.
        found = ComPtr<INetFwRule>();
    } else if (found.get() == nullptr) {
        SetError(error, L"Windows Firewall returned no rule object for \"" +
                            name + L"\"");
        return false;
    }
    if (found.get() != nullptr) {
        const HRESULT del = rules->Remove(bname);
        if (FAILED(del)) {
            SetError(error, L"could not remove \"" + name + L"\": " +
                                FormatHresult(del));
            return false;
        }
        ComPtr<INetFwRule> remaining;
        const HRESULT verify = rules->Item(bname, remaining.receive());
        if (!IsMissingFirewallRuleResult(verify)) {
            SetError(error, SUCCEEDED(verify) && remaining.get() != nullptr
                                ? L"Windows Firewall still reports \"" + name + L"\" after removal"
                                : L"could not verify removal of \"" + name +
                                      L"\": " + FormatHresult(verify));
            return false;
        }
    }

    std::lock_guard<std::mutex> lock(g_ledgerLock);
    std::wstring readErr;
    std::vector<std::wstring> pairs = ReadLedger(&readErr);
    if (!readErr.empty()) {
        // The rule IS out of the firewall, so report that; the ledger will be
        // repaired the next time a clean rewrite happens.
        SetError(error, readErr);
        return false;
    }
    bool touched = false;
    for (std::wstring& pair : pairs) {
        std::wstring blanked;
        if (BlankLedgerName(pair, name, &blanked)) {
            pair = blanked;
            touched = true;
        }
    }
    // Only rewrite when something actually matched, so a caller passing a
    // name that was never ours does not churn the file.
    if (touched) {
        std::vector<std::wstring> kept;
        kept.reserve(pairs.size());
        for (const std::wstring& p : pairs) {
            if (p.empty()) continue;   // both halves gone
            kept.push_back(p);
        }
        if (!WriteLedger(kept)) {
            SetError(error, L"the firewall rule was removed, but the WinTCP rule ledger could not be updated");
            return false;
        }
    }
    return true;
}

bool SetBlockedRuleEnabled(const std::wstring& name, bool enabled,
                           std::wstring* error) {
    if (error != nullptr) {
        error->clear();
    }
    if (name.empty()) {
        SetError(error, L"internal error: no rule name to enable/disable");
        return false;
    }
    FwSession session;
    if (!session.Open(error)) {
        return false;
    }
    INetFwRules* rules = session.rules();

    BStr bname(name);
    if (!bname.valid()) {
        SetError(error, L"out of memory allocating rule name");
        return false;
    }
    ComPtr<INetFwRule> rule;
    const HRESULT found = rules->Item(bname, rule.receive());
    if (FAILED(found) || rule.get() == nullptr) {
        // 0x80070490 is how a missing rule surfaces. Disabling something that
        // is already gone is not an error - the state the caller wants is the
        // state the firewall is in.
        if (IsMissingFirewallRuleResult(found)) {
            return true;
        }
        SetError(error, L"could not read the rule \"" + name + L"\": " +
                            FormatHresult(found));
        return false;
    }

    const HRESULT hr = rule.get()->put_Enabled(
        enabled ? VARIANT_TRUE : VARIANT_FALSE);
    if (FAILED(hr)) {
        SetError(error, L"could not set Enabled on \"" + name + L"\": " +
                            FormatHresult(hr));
        return false;
    }

    // Read it back. put_Enabled is the one property where a silent no-op would
    // be invisible: the manager would show "enabled" while the firewall held
    // "disabled", and the user would believe they had turned a block back on.
    VARIANT_BOOL now = VARIANT_FALSE;
    if (FAILED(rule.get()->get_Enabled(&now))) {
        SetError(error, L"could not read back Enabled on \"" + name + L"\"");
        return false;
    }
    if ((now != VARIANT_FALSE) != enabled) {
        SetError(error, L"the firewall accepted the change to \"" + name +
                            L"\" but Enabled reads back the other way");
        return false;
    }
    return true;
}

}  // namespace wintcp

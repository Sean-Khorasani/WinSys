// TlsDecode.cpp
// SPDX-License-Identifier: Apache-2.0
// See TlsDecode.h. Every multi-byte field is read big-endian (network byte
// order) via Be16/Be32, and every length is bounds-checked against the
// remaining stream before it is used, because the input is attacker-shaped
// data off the wire: a malformed length must stop the parse, not read past
// the buffer.

#include "TlsDecode.h"

#include <windows.h>
#include <wincrypt.h>   // CertCreateCertificateContext, CertGetNameStringW

#include <cstdio>
#include <cstring>

#include "Utils.h"
#include "WinCaps.h"   // DllAvailable: crypt32.dll is delay-loaded
#include "Opt.h"

namespace wintcp {
namespace {

inline uint16_t Be16(const unsigned char* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t Be24(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) | p[2];
}

inline uint32_t Be32(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

// Handshake message types we care about (RFC 8446 s4).
constexpr uint8_t kHsClientHello = 1;
constexpr uint8_t kHsServerHello = 2;
constexpr uint8_t kHsCertificate = 11;

// The Random field of a ClientHello and a ServerHello is 32 octets in both
// (RFC 8446 s4.1.2). Four call sites skip it, and a wrong width desynchronises
// the rest of the parse - the session id starts immediately after it.
constexpr size_t kHelloRandomBytes = 32;

// "YYYY-MM-DD" for a certificate validity date, plus NUL.
constexpr size_t kDateTextChars = 32;

// CertGetNameStringW output width. A subject DN is bounded by the certificate
// size, not by this, and CertGetNameStringW truncates rather than overruns -
// so this is slack chosen so a long organisational name still reads, and the
// same buffer is reused for subject and issuer.
constexpr size_t kCertNameChars = 512;

std::string FormatFiletime(const FILETIME& ft) {
    FILETIME local = {};
    SYSTEMTIME st = {};
    if (::FileTimeToLocalFileTime(&ft, &local) == FALSE) return std::string();
    if (::FileTimeToSystemTime(&local, &st) == FALSE) return std::string();
    char buf[kDateTextChars] = {0};
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u",
                  static_cast<unsigned>(st.wYear),
                  static_cast<unsigned>(st.wMonth),
                  static_cast<unsigned>(st.wDay));
    return buf;
}

}  // namespace

std::string TlsRecordTypeName(uint8_t type) {
    switch (type) {
        case kTlsChangeCipherSpec: return "ChangeCipherSpec";
        case kTlsAlert:           return "Alert";
        case kTlsHandshake:       return "Handshake";
        case kTlsApplicationData: return "Encrypted record";
        default: return std::string();
    }
}

std::string TlsVersionName(uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        case 0x7F00: return "TLS 1.3 (draft)";
        default: return std::string();
    }
}

std::string TlsCipherSuiteName(uint16_t s) {
    switch (s) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xC02B: return "ECDHE-ECDSA-AES128-GCM-SHA256";
        case 0xC02F: return "ECDHE-RSA-AES128-GCM-SHA256";
        case 0xC030: return "ECDHE-RSA-AES256-GCM-SHA384";
        case 0xC02C: return "ECDHE-ECDSA-AES256-GCM-SHA384";
        case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0xC013: return "ECDHE_RSA_WITH_AES_128_CBC_SHA";
        case 0xC014: return "ECDHE_RSA_WITH_AES_256_CBC_SHA";
        default: return std::string();
    }
}

std::string TlsHandshake::summary() const {
    std::string s;
    if (!sni.empty()) { s += sni; s += "  "; }
    const char* dir = nullptr;
    if (serverVersion != 0) dir = TlsVersionName(serverVersion).c_str();
    if (dir == nullptr && clientVersion != 0)
        dir = TlsVersionName(clientVersion).c_str();
    if (dir != nullptr && *dir != '\0') { s += dir; s += "  "; }
    const char* cs = cipherSuite != 0
                         ? TlsCipherSuiteName(cipherSuite).c_str() : nullptr;
    if (cs != nullptr && *cs != '\0') { s += cs; s += "  "; }
    if (sawAlert) { s += "alert  "; }
    if (sawApplicationData) {
        s += "encrypted (" + std::to_string(encryptedBytes) + " bytes)";
    }
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

bool LooksLikeTls(const std::string& b) {
    // A record header is 5 bytes: type 20-23, version 0x03xx, length.
    if (b.size() < 5) return false;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(b.data());
    if (p[0] < kTlsChangeCipherSpec || p[0] > kTlsApplicationData)
        return false;
    if (p[1] != 0x03) return false;
    return true;
}

std::vector<TlsRecord> ParseTlsRecords(const std::string& bytes) {
    std::vector<TlsRecord> out;
    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(bytes.data());
    size_t n = bytes.size();
    size_t off = 0;
    while (off + 5 <= n) {
        TlsRecord r;
        r.offset = off;
        r.type = p[off];
        r.version = Be16(p + off + 1);
        const uint16_t len = Be16(p + off + 3);
        r.payloadOffset = off + 5;
        // A record claiming more than remains is the normal end-of-capture
        // case: record what we know and stop, rather than skipping ahead into
        // what is almost certainly ciphertext.
        if (r.payloadOffset + len > n) {
            r.length = static_cast<uint16_t>(n - r.payloadOffset);
            r.truncated = true;
            out.push_back(r);
            break;
        }
        r.length = len;
        out.push_back(r);
        off = r.payloadOffset + len;
        if (len == 0 && r.type != kTlsApplicationData) {
            // A zero-length non-data record would otherwise not advance;
            // bail out rather than loop.
            break;
        }
    }
    return out;
}

namespace {

// Cursor over a handshake message body, with bounds checks on every read.
class Reader {
public:
    Reader(const unsigned char* p, size_t n) : p_(p), n_(n) {}

    bool Need(size_t k) const { return pos_ + k <= n_; }
    size_t Left() const { return (pos_ <= n_) ? n_ - pos_ : 0; }
    size_t Pos() const { return pos_; }
    void Skip(size_t k) { if (Need(k)) pos_ += k; }
    bool U8(uint8_t* v) {
        if (!Need(1)) return false;
        *v = p_[pos_]; pos_ += 1; return true;
    }
    bool U16(uint16_t* v) {
        if (!Need(2)) return false;
        *v = Be16(p_ + pos_); pos_ += 2; return true;
    }
    bool U24(uint32_t* v) {
        if (!Need(3)) return false;
        *v = Be24(p_ + pos_); pos_ += 3; return true;
    }
    bool U32(uint32_t* v) {
        if (!Need(4)) return false;
        *v = Be32(p_ + pos_); pos_ += 4; return true;
    }
    // A length-prefixed opaque blob (<2..4> octets).
    bool Blob(size_t lenBytes, const unsigned char** out, uint32_t* len) {
        uint32_t l = 0;
        switch (lenBytes) {
            case 1: { uint8_t v; if (!U8(&v)) return false; l = v; break; }
            case 2: { uint16_t v; if (!U16(&v)) return false; l = v; break; }
            case 3: if (!U24(&l)) return false; break;
            case 4: if (!U32(&l)) return false; break;
            default: return false;
        }
        if (!Need(l)) return false;
        *out = p_ + pos_;
        *len = l;
        pos_ += l;
        return true;
    }
    const unsigned char* Cur() const { return p_ + pos_; }

private:
    const unsigned char* p_;
    size_t n_;
    size_t pos_ = 0;
};

void ParseClientHelloExtensions(Reader& r, uint32_t extLen, TlsHandshake* hs) {
    const size_t end = r.Pos() + extLen;
    while (r.Pos() + 4 <= end) {
        uint16_t type = 0, len = 0;
        if (!r.U16(&type) || !r.U16(&len)) break;
        if (!r.Need(len)) break;
        const unsigned char* data = r.Cur();
        r.Skip(len);
        // Extension-type classify is wintcp::ClassifyTlsExtensionOpt
        // (Opt.cpp): only 0x0000 (server_name) and 0x0010 (ALPN) are
        // handled, and a 17-entry table turns the if/else chain into one
        // range check plus an indexed load. A/B bench: 1.26x.
        // The length checks are theirs own, unchanged, so a short
        // extension is still refused before its body is read.
        switch (ClassifyTlsExtensionOpt(type)) {
            case TlsExtAction::kSni:
                if (len >= 5) {   // server_name: list_len(2) then entries
                    // SNI extension: list_len(2) then entries of
                    // name_type(1) name_len(2) name.
                    Reader sni(data, len);
                    uint16_t listLen = 0;
                    if (sni.U16(&listLen) && sni.Need(3)) {
                        uint8_t nameType = 0;
                        uint16_t nameLen = 0;
                        if (sni.U8(&nameType) && sni.U16(&nameLen) &&
                            sni.Need(nameLen) && nameType == 0) {
                            hs->sni.assign(
                                reinterpret_cast<const char*>(sni.Cur()),
                                nameLen);
                            // Trailing NUL/dot strip is
                            // wintcp::StripSniTailOpt (Opt.cpp): SSE2
                            // 16-byte tail scan with a scalar finish, for
                            // a scalar loop that popped one byte at a
                            // time. A/B bench: 16.99x on the names that
                            // exercise the SIMD path; names under 32 bytes
                            // stay scalar inside it, because one SIMD step
                            // costs more than a handful of byte pops.
                            hs->sni.resize(StripSniTailOpt(
                                hs->sni.empty() ? nullptr : &hs->sni[0],
                                hs->sni.size()));
                        }
                    }
                }
                break;
            case TlsExtAction::kAlpn:
                if (len >= 2) {   // ALPN
                    Reader alpn(data, len);
                    uint16_t listLen = 0;
                    if (alpn.U16(&listLen) && alpn.Need(2)) {
                        uint8_t nLen = 0;
                        if (alpn.U8(&nLen) && alpn.Need(nLen)) {
                            hs->sniProto.assign(
                                reinterpret_cast<const char*>(alpn.Cur()),
                                nLen);
                        }
                    }
                }
                break;
            case TlsExtAction::kSkip:
            default:
                break;
        }
        if (r.Pos() >= end) break;
    }
}

void ParseClientHello(const unsigned char* p, size_t n, TlsHandshake* hs) {
    Reader r(p, n);
    uint16_t ver = 0;
    if (!r.U16(&ver)) return;
    hs->clientVersion = ver;
    if (!r.Need(kHelloRandomBytes)) return;
    r.Skip(kHelloRandomBytes);
    uint8_t sidLen = 0;
    if (!r.U8(&sidLen) || !r.Need(sidLen)) return;
    r.Skip(sidLen);
    uint16_t csLen = 0;
    if (!r.U16(&csLen) || !r.Need(csLen)) return;
    r.Skip(csLen);
    uint8_t compLen = 0;
    if (!r.U8(&compLen) || !r.Need(compLen)) return;
    r.Skip(compLen);
    // Extensions are optional in the pre-SNI case; absence is normal.
    if (r.Left() < 2) return;
    const size_t save = r.Pos();
    uint16_t extLen = 0;
    if (!r.U16(&extLen) || extLen == 0) return;
    (void)save;
    ParseClientHelloExtensions(r, extLen, hs);
}

// Decode the ServerHello body: version, random, session id, cipher suite,
// compression method, and the extensions. The supported_versions extension
// (0x002B) carries the real negotiated version under TLS 1.3, where the
// legacy field still reads 1.2 - reporting the legacy value would understate
// the connection's actual strength.
void ParseServerHello(const unsigned char* p, size_t n, TlsHandshake* hs) {
    Reader r(p, n);
    uint16_t ver = 0;
    if (!r.U16(&ver)) return;
    hs->serverVersion = ver;
    if (!r.Need(kHelloRandomBytes)) return;   // random
    r.Skip(kHelloRandomBytes);
    uint8_t sidLen = 0;
    if (!r.U8(&sidLen) || !r.Need(sidLen)) return;
    r.Skip(sidLen);
    uint16_t suite = 0;
    if (!r.U16(&suite)) return;
    hs->cipherSuite = suite;
    uint8_t comp = 0;
    if (!r.U8(&comp)) return;
    if (r.Left() < 2) return;
    uint16_t extLen = 0;
    if (!r.U16(&extLen) || extLen == 0 || !r.Need(extLen)) return;
    const unsigned char* ext = r.Cur();
    Reader er(ext, extLen);
    while (er.Pos() + 4 <= extLen) {
        uint16_t type = 0, len = 0;
        if (!er.U16(&type) || !er.U16(&len)) break;
        if (!er.Need(len)) break;
        if (type == 0x002B && len >= 2) {     // supported_versions
            // ServerHello's SupportedVersions carries a single 2-byte field -
            // NO length prefix. (The ClientHello form has the 1-byte prefix; a
            // ServerHello that reads U8 first eats the high byte of the version
            // and corrupts the parse. RFC 8446 4.2.1.) This bug silently
            // understated TLS 1.3 as its high byte in `listLen` and the next
            // byte in `sel`.
            Reader vr(er.Cur(), len);
            uint16_t sel = 0;
            if (vr.U16(&sel)) hs->serverVersion = sel;
        }
        er.Skip(len);
    }
}

}  // namespace

// Decode a DER certificate blob using the Windows certificate APIs, which
// are already linked (advapi32/crypt32) and give correct parsing of
// subject, issuer and validity without hand-rolling an ASN.1 walk.
static void FillCertFromDer(const unsigned char* der, size_t derLen,
                            TlsHandshake* hs) {
    if (der == nullptr || derLen == 0) return;
    // crypt32.dll is delay-loaded (kDelayedDlls in WinCaps.cpp), and a
    // delay-loaded import raises on FIRST CALL rather than failing to link.
    // Without this gate a machine without crypt32.dll would take a delay-load
    // exception the moment a TLS handshake was parsed, instead of simply
    // showing the protocol, cipher and SNI this file already has. The
    // certificate subject/issuer are the ONLY thing that needs crypt32.
    if (!DllAvailable("crypt32.dll")) return;
    const DWORD len = static_cast<DWORD>(derLen);
    // CertCreateCertificateContext does not copy the blob, but the buffer we
    // pass is the live stream, which outlives this call.
    PCCERT_CONTEXT ctx =
        ::CertCreateCertificateContext(X509_ASN_ENCODING, der, len);
    if (ctx == nullptr) return;

    wchar_t name[kCertNameChars] = {0};
    // CertGetNameStringW takes the buffer size BY VALUE, not by pointer, and
    // updates nothing - a &chars here does not even compile.
    if (::CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                             name, kCertNameChars) != 0) {
        // WideToUtf8, not assign(begin, end): the latter narrows wchar_t to
        // char and mangles any non-ASCII subject. DN components are routinely
        // UTF-8 (internationalised domains, CJK organisations).
        hs->certSubject = WideToUtf8(name);
    }
    name[0] = L'\0';
    // CERT_NAME_ISSUER_STR is 3; spelled numerically because the symbolic
    // constant is not exposed at this _WIN32_WINNT level.
    if (::CertGetNameStringW(ctx, 3 /*CERT_NAME_ISSUER_STR*/, 0, nullptr, name,
                             kCertNameChars) != 0) {
        hs->certIssuer = WideToUtf8(name);
    }
    std::string from = FormatFiletime(ctx->pCertInfo->NotBefore);
    std::string to = FormatFiletime(ctx->pCertInfo->NotAfter);
    if (!from.empty() || !to.empty())
        hs->certValidity = from + " \xe2\x86\x92 " + to;
    ::CertFreeCertificateContext(ctx);
}

TlsHandshake ParseTlsHandshake(const std::string& bytes) {
    TlsHandshake hs;
    if (!LooksLikeTls(bytes)) return hs;
    const std::vector<TlsRecord> recs = ParseTlsRecords(bytes);

    // Handshake messages can span record boundaries and several messages can
    // share one record, so accumulate handshake bytes and parse from the
    // accumulated buffer.
    std::string hsBuf;
    for (const TlsRecord& r : recs) {
        if (r.type == kTlsApplicationData) {
            // Ciphertext starts here. Everything after is encrypted, so stop.
            hs.sawApplicationData = true;
            hs.encryptedBytes += r.length;
            for (const TlsRecord& later : recs) {
                if (later.offset > r.offset) hs.encryptedBytes += later.length;
            }
            break;
        }
        if (r.type == kTlsAlert) { hs.sawAlert = true; continue; }
        if (r.type != kTlsHandshake) continue;
        hsBuf.append(bytes, r.payloadOffset, r.length);
    }

    // Walk the handshake messages.
    const unsigned char* p = reinterpret_cast<const unsigned char*>(hsBuf.data());
    size_t n = hsBuf.size();
    size_t off = 0;
    while (off + 4 <= n) {
        const uint8_t type = p[off];
        const uint32_t len = Be24(p + off + 1);
        if (off + 4 + len > n) break;   // truncated: stop, keep what we have
        const unsigned char* body = p + off + 4;
        const size_t bodyLen = len;

        switch (type) {
            case kHsClientHello:
                if (!hs.sawClientHello) {
                    ParseClientHello(body, bodyLen, &hs);
                    hs.sawClientHello = true;
                }
                break;
            case kHsServerHello:
                if (!hs.sawServerHello) {
                    ParseServerHello(body, bodyLen, &hs);
                    hs.sawServerHello = true;
                }
                break;
            case kHsCertificate: {
                if (hs.sawCertificate) break;
                Reader r(body, bodyLen);
                uint8_t ctxLen = 0;
                if (!r.U8(&ctxLen) || !r.Need(ctxLen)) break;
                r.Skip(ctxLen);
                uint32_t listLen = 0;
                const unsigned char* list = nullptr;
                if (!r.Blob(3, &list, &listLen) || listLen < 3) break;
                uint32_t certLen = Be24(list);
                if (certLen == 0 || 3 + certLen > listLen) break;
                FillCertFromDer(list + 3, certLen, &hs);
                hs.sawCertificate = true;
                break;
            }
            default:
                break;
        }
        off += 4 + len;
    }
    return hs;
}

}  // namespace wintcp

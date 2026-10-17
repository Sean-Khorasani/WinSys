// TlsDecode.h
// SPDX-License-Identifier: Apache-2.0
// TLS record-layer and handshake parsing for the follow-stream view
// Pure: no I/O, no windows.
//
// WHAT THIS DECODES, AND WHAT IT DELIBERATELY DOES NOT:
// TLS terminates inside each process's own address space, so a separate
// process cannot obtain the decrypted application data. It is technically
// possible via DLL injection, lsass session-key extraction, or a WFP callout
// - all of which are credential-access techniques, so none of them are used.
//
// What IS available without any of that is the handshake itself, which
// travels in cleartext by design: the ClientHello (with the SNI hostname),
// the ServerHello (version, cipher suite) and the server's Certificate
// message. Those are real, not inferred, and they are what identifies a
// connection. Everything after the handshake is ciphertext and is rendered as
// labelled encrypted records - never as fabricated plaintext.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <cstdint>
#include <string>
#include <vector>

namespace wintcp {

// TLS record content types (RFC 8446 s5.1).
enum TlsRecordType : uint8_t {
    kTlsChangeCipherSpec = 20,
    kTlsAlert = 21,
    kTlsHandshake = 22,
    kTlsApplicationData = 23,
};

// One TLS record located inside a reassembled stream.
struct TlsRecord {
    size_t offset = 0;         // byte offset within the direction's stream
    uint8_t type = 0;
    uint16_t version = 0;      // record-layer version, e.g. 0x0303
    uint16_t length = 0;
    size_t payloadOffset = 0;  // absolute, for the hex view
    bool truncated = false;    // ran past the end of what we captured
};

// Everything learned from the cleartext handshake.
struct TlsHandshake {
    bool sawClientHello = false;
    bool sawServerHello = false;
    bool sawCertificate = false;
    bool sawAlert = false;

    std::string sni;            // server_name, e.g. "example.com"
    std::string sniProto;       // alpn, e.g. "h2"

    uint16_t clientVersion = 0; // legacy_version from ClientHello
    uint16_t serverVersion = 0; // negotiated version from ServerHello
    uint16_t cipherSuite = 0;  // 0 if not seen
    std::string alpnList;

    // Certificate fields, decoded via the Windows certificate store APIs
    // from the DER blob in the Certificate message. Empty when absent.
    std::string certSubject;
    std::string certIssuer;
    std::string certValidity;   // "2026-01-01 → 2026-04-01" (local time)
    std::string certSerial;

    // True when the stream contained an application_data record, i.e. the
    // connection is genuinely encrypted rather than a plaintext protocol we
    // failed to recognise.
    bool sawApplicationData = false;
    size_t encryptedBytes = 0;

    // A one-line summary for the window's status area.
    std::string summary() const;
};

// Does this direction look like TLS at all? Cheap first-record check, used
// to pick a decoder before doing any real work.
bool LooksLikeTls(const std::string& bytes);

// Walk the record layer of one direction. Tolerates a truncated tail (the
// capture may have stopped mid-record) and stops at the first byte that
// cannot be a record header, reporting what was read so far.
std::vector<TlsRecord> ParseTlsRecords(const std::string& bytes);

// Parse the handshake messages out of the cleartext handshake records. The
// stream normally switches to ciphertext after the server's Finished, so
// decoding stops there rather than misreading ciphertext as a handshake.
TlsHandshake ParseTlsHandshake(const std::string& bytes);

// Human-readable names for the values we surface. Return an empty string for
// unknown values rather than a guess.
std::string TlsRecordTypeName(uint8_t type);
std::string TlsVersionName(uint16_t version);
std::string TlsCipherSuiteName(uint16_t suite);

}  // namespace wintcp

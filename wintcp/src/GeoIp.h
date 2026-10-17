// File: wintcp/src/GeoIp.h (c-header)
// SPDX-License-Identifier: Apache-2.0
// GeoIp.h
// A read-only MaxMind DB (.mmdb) reader: address -> ISO 3166-1 alpha-2
// country code, for the Country column.
//
// WHY IT IS HERE RATHER THAN A LIBRARY: the published libmaxminddb is C, and
// the .mmdb file is the only input we have (the user drops one in). Parsing
// it in-tree keeps the build dependency-free and the failure mode under our
// control - the file is untrusted input, so every read in the implementation
// is bounds-checked against the loaded buffer.
//
// The file is read once into memory and kept there for the object's life.
// These are 1-500 MB files; a real map is not worth the lifetime rules here
// when the reader is owned by one object with an explicit Close().
//
// Nothing in this header throws. Load() reports through a return value and an
// out-parameter because the file is user-supplied and can be absent,
// truncated, or not a database at all - none of which are exceptional.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT
#endif

#include <cstdint>
#include <string>
#include <vector>

namespace wintcp {

// One autonomous-system answer: the number, and the organisation that owns it.
//
// WHY A STRUCT AND NOT A STRING: the two halves are used differently and must
// be filterable differently. `asn:15169` is a NUMBER comparison, and an org
// name is a substring comparison - "Google LLC" is not a threshold. Formatting
// them into one string here would force every filter to re-parse it and would
// make a numeric range impossible to express.
//
// number == 0 means "no answer", which is the honest reading of "not in the
// database", "this database has no ASN records" (a Country database) and "the
// record carried an organisation but no number". It is not an error and it is
// never printed as a number.
struct AsnInfo {
    uint32_t number = 0;
    std::wstring org;

    bool Known() const { return number != 0; }
    // "AS15169 Google LLC", "AS15169", "Google LLC", or "" - assembled from
    // whichever halves are present, so a record with only one half still says
    // something useful. The "AS" prefix is always upper case because that is
    // how the number is written everywhere it appears, and because matching it
    // case-insensitively is what `asn:` does anyway.
    std::wstring Display() const;
};

class GeoIpDatabase {
public:
    GeoIpDatabase() = default;
    ~GeoIpDatabase();

    // Move-only: the instance owns a multi-hundred-megabyte buffer, and
    // silently duplicating that would be a footgun rather than a convenience.
    GeoIpDatabase(GeoIpDatabase&& other) noexcept;
    GeoIpDatabase& operator=(GeoIpDatabase&& other) noexcept;

    GeoIpDatabase(const GeoIpDatabase&) = delete;
    GeoIpDatabase& operator=(const GeoIpDatabase&) = delete;

    // Read and validate the whole file. Returns false and sets *error (if
    // non-null) on any failure, including a file that is not an MMDB or is
    // too small to hold a search tree. 'error' is cleared on success.
    // 'path' is UTF-16; the code point limit is enforced by the OS, so no
    // wide/narrow conversion is needed or attempted here.
    bool Load(const std::wstring& path, std::wstring* error);

    // Release the buffer. Safe at any time, including when nothing is loaded.
    void Close();

    bool Loaded() const { return dataSectionSize_ != 0; }

    // The path Load() was given, so the GUI can persist it. Empty when
    // nothing has been loaded; not a separate "has been loaded" flag, because
    // Loaded() answers that and this is only ever read alongside it.
    const std::wstring& SourcePath() const { return sourcePath_; }

    // Look up an address. Returns an ISO 3166-1 alpha-2 code (L"US"), or an
    // empty string when the address is absent from the database, has no
    // country record, or the database is not loaded.
    //
    // 'hostOrderAddr' is the dotted-quad address in host byte order, i.e. the
    // same value you would compare against INADDR_NONE. The tree is walked
    // in network order internally.
    //
    // Addresses that are not globally routable return empty WITHOUT touching
    // the tree. They are not "country unknown", they are "not a country at
    // all", and printing a code for a loopback or RFC1918 peer would be a
    // lie; registry data is full of rows for ranges that will never be a
    // remote endpoint.
    std::wstring LookupV4(uint32_t hostOrderAddr) const;

    // 'addr' is the 16 address bytes in network order, as stored in
    // IN6_ADDR / SOCKADDR_IN6.
    std::wstring LookupV6(const unsigned char addr[16]) const;

    // The same two lookups against an ASN database (GeoLite2-ASN.mmdb).
    //
    // A Country database has no ASN records, so these return an unknown AsnInfo
    // against one - that is not a failure, it is the honest answer, and it is
    // why the two databases are loaded separately and named separately rather
    // than sniffed apart by database_type. Likewise a record that carries only
    // an organisation returns number 0 with a non-empty org.
    AsnInfo LookupAsnV4(uint32_t hostOrderAddr) const;
    AsnInfo LookupAsnV6(const unsigned char addr[16]) const;

    // Metadata, for the About box. All are empty/zero unless the metadata
    // section parsed, which is a valid state: a database that answers lookups
    // is still usable, so nothing here is load-bearing.
    std::wstring DatabaseVersion() const;
    uint64_t RecordCount() const;
    uint64_t NodeCount() const;
    size_t FileSize() const { return fileSize_; }

private:
    void MoveFrom(GeoIpDatabase& other) noexcept;
    // Walk the tree for 'bitCount' address bits taken from the front of
    // 'bits' (network order), starting at 'startNode', then resolve the record
    // found there.
    //
    // The start node is a parameter rather than something this reads off the
    // object, because the correct answer depends on the ADDRESS FAMILY, not on
    // the database: an IPv6 walk always starts at the root, while an IPv4 walk
    // in an IPv6 tree starts inside the IPv4 half. Deriving it from a single
    // stored flag (as this used to) sent one of the two families to the wrong
    // place whichever way the flag was read.
    std::wstring LookupBits(const unsigned char bits[16], unsigned bitCount,
                            size_t startNode) const;
    // Resolve an address to a DATA-SECTION OFFSET, or false when the walk finds
    // no record for it. Split out of LookupBits so the country and ASN lookups
    // share ONE tree walk instead of each walking it: the tree is the expensive
    // part (up to 128 NodeRecord reassemblies), and a caller that wants both
    // answers from one database would otherwise pay twice.
    bool ResolveOffset(const unsigned char bits[16], unsigned bitCount,
                       size_t startNode, size_t* out) const;
    // An IPv4 host-order address as the 16 network-order bits the walk expects.
    // Shared by the country and ASN lookups so the byte order is spelled once -
    // getting it wrong answers for a different address rather than failing.
    static void AddressBitsV4(uint32_t hostOrderAddr, unsigned char bits[16]);
    // Resolve a data-section offset to a country code, or empty.
    std::wstring CountryAt(size_t dataOffset) const;
    // Resolve a data-section offset to an autonomous system, or an unknown
    // AsnInfo. The record keys sit at the TOP level of the map, not under a
    // wrapper: GeoLite2-ASN records are {autonomous_system_number,
    // autonomous_system_organization} with no nesting, unlike a country record.
    AsnInfo AsnAt(size_t dataOffset) const;
    // Read one of a node's two child records. False when the node or the read
    // itself falls outside the mapped tree. Shared by the tree walk and by
    // Load's search for the IPv4 start node, so the 28-bit reassembly - the
    // one layout that does not divide into whole bytes - is written once.
    bool NodeRecord(size_t node, unsigned half, size_t* out) const;

    // The loaded database as a memory-mapped view of the file, not a heap
    // copy. A City database is ~70 MB and ISP-level files run to ~450 MB;
    // reading that into a std::vector at startup allocates it, blocks on the
    // read, and pins it - CreateFileMappingW + MapViewOfFile makes it
    // demand-paged work instead, and Load returns in microseconds. The view
    // is released in Close().
    const unsigned char* mappedView_ = nullptr;
    size_t fileSize_ = 0;

    // The data section starts after the tree and the 16-byte separator, and
    // runs from there to the end of the file. Its start is where it starts -
    // NOT an offset that pointers get added to: the spec defines a data pointer
    // as already relative to this start, and a reader that added it produced a
    // file-absolute address that its own bounds check then rejected.
    size_t dataSectionBase_ = 0;
    size_t dataSectionSize_ = 0;

    // The path Load() was given, so the GUI can persist it across
    // restarts. Empty when nothing has been loaded; never read alongside
    // Loaded() being false.
    std::wstring sourcePath_;

    // ip_version from the metadata, 4 or 6 only. In a v6 tree the IPv4 half
    // sits behind 96 bits of zeros, so an IPv4 lookup would otherwise walk 32
    // more hops through a subtree every real database aliases anyway;
    // ipv4_start_node from the metadata jumps straight to it.
    bool ipv6Tree_ = false;
    size_t v4StartNode_ = 0;

    // Node geometry, from node_count and record_size. A node is two records
    // of recordBytes_ bytes, so nodes are nodeByteSize_ bytes apart, and the
    // tree occupies treeSize_ bytes. None of this is stored in the file: it
    // is all derived, and derived values are the only ones trusted.
    // record28_ is set for a 28-bit record size, the one layout that is not a
    // whole number of bytes per record: its node is 7 bytes and the two records
    // share the nibbles in the middle byte, so it needs reassembling.
    size_t recordBytes_ = 0;
    bool record28_ = false;
    size_t nodeByteSize_ = 0;
    size_t treeSize_ = 0;

    uint64_t recordCount_ = 0;
    uint64_t nodeCount_ = 0;
    std::wstring version_;
};

// True for addresses that are not globally routable and should never get a
// country: loopback, link-local, multicast, broadcast, unspecified, the
// RFC1918 private ranges, and the rest of the non-forwardable blocks
// (0.0.0.0/8, 192.0.0/24, 100.64/10, 198.18/15, 240.0.0.0/4 and friends).
// Public so the caller can skip the lookup entirely.
bool IsGlobalUnicastV4(uint32_t hostOrderAddr);
bool IsGlobalUnicastV6(const unsigned char addr[16]);

// The same question, named for what a FILTER means by it. `local:private`
// is "is this endpoint on a non-routable range", which is the same set GeoIP
// refuses to assign a country - so the two share one implementation rather than
// keeping two lists of ranges that could drift apart.
bool IsPrivateAddrV4(uint32_t hostOrderAddr);
bool IsPrivateAddrV6(const unsigned char addr[16]);

}  // namespace wintcp

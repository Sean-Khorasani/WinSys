// GeoIp.cpp
// See GeoIp.h. Parses the MaxMind DB file format 2.0:
//   [search tree][16-byte separator][data section][marker][metadata]
// The tree is a binary search tree over the address bits; a node holds two
// big-endian records, and a record is either the next node number, the node
// count (meaning "no data for this address"), or a data-section pointer.
//
// The data section is a stream of typed values. This reader only needs maps,
// strings and integers out of it, because the record it cares about is
//   {"country": {"iso_code": "US", "names": {"en": "United States"}}}
// Every other type decodes to an opaque skip, so an unexpected field is
// stepped over rather than mis-parsed.
//
// The file is untrusted input - a truncated download, a file still being
// copied, or a hand-crafted one - hence the read helpers return bool and only
// write their value on success, and every walk checks that it stayed inside
// the section it is reading before touching the next byte.

#include "GeoIp.h"

#include <algorithm>
#include <cstring>
#include <limits>

#include "Opt.h"   // IsGlobalUnicastV4Opt / IsGlobalUnicastV6Opt

// Only for the file mapping in Load() (CreateFileW, CreateFileMappingW,
// MapViewOfFile). Deliberately not in
// the header: the rest of the program can use this reader without dragging in
// windows.h and its macros.
#include <windows.h>

namespace wintcp {
namespace {

// ---------------------------------------------------------------------------
// Format constants
// ---------------------------------------------------------------------------

// The metadata map is found by scanning back from the end of the file for this
// marker; everything after it is that map. The trailing text is "MaxMind.com"
// with no space in it, which is worth spelling out because the obvious guess
// puts one there.
constexpr unsigned char kMetaMarker[14] = {0xAB, 0xCD, 0xEF, 'M', 'a', 'x',
                                           'M', 'i', 'n', 'd', '.', 'c', 'o',
                                           'm'};

constexpr size_t kSeparatorLen = 16;

// A data pointer's control byte is 001SSVVV: bits 4-3 hold the size code and
// the low three bits are the top of the value. The size codes and the offset
// each one implies are the spec's, and the two larger forms deliberately do
// not start at zero - that is what keeps a size-1 pointer from colliding with
// a size-0 one.
constexpr uint8_t kPtrSizeShift = 3;
constexpr uint8_t kPtrSizeMask = 0x3;
constexpr uint64_t kPtr2Base = 2048;     // size 1
constexpr uint64_t kPtr3Base = 526336;   // size 2

constexpr int kMaxPointerFollows = 16;  // bounds a hostile pointer cycle

// Data value types, from the top 3 bits of a control byte.
constexpr uint8_t kTypeExtended = 0;
constexpr uint8_t kTypePointer = 1;
constexpr uint8_t kTypeUtf8 = 2;
constexpr uint8_t kTypeUint16 = 5;
constexpr uint8_t kTypeUint32 = 6;
constexpr uint8_t kTypeMap = 7;
constexpr uint8_t kTypeUint64 = 9;
constexpr uint8_t kTypeUint128 = 10;
constexpr uint8_t kTypeArray = 11;
constexpr uint8_t kTypeBool = 14;

// A 5-bit size of 29/30/31 means the size continues in the next 1/2/3 bytes.
constexpr uint8_t kSizeExtended29 = 29;
// Named so PayloadSize can test against it the same way it tests 29. The
// neighbouring bases below are the spec's; a bare 30 here would be the one
// case whose spelling did not match the constant that documents it.
constexpr uint8_t kSizeExtended30 = 30;
// The spec's two larger extended forms: a 2-byte size adds to 285, a 3-byte
// size adds to 65821. Both numbers are arbitrary-looking but they are the
// spec's, not ours, and the arithmetic is checked against them - a reader that
// invented its own base here would silently mis-size every long value.
constexpr uint32_t kSizeExtended30Base = 285;
constexpr uint32_t kSizeExtended31Base = 65821;
// Bytes an extra size digit occupies for those two forms.
constexpr size_t kSizeExtraBytes30 = 2;
constexpr size_t kSizeExtraBytes31 = 3;

// The three record sizes the spec permits, in bits. 28 is the awkward one: not
// a whole number of bytes, so a node is 7 of them rather than 2x3.
constexpr uint64_t kRecordBits24 = 24;
constexpr uint64_t kRecordBits28 = 28;
constexpr uint64_t kRecordBits32 = 32;
// Bytes per node for the awkward case (two records sharing the middle byte).
constexpr size_t kNodeBytes28 = 7;
// Bytes per record for the two whole-byte cases.
constexpr size_t kBytes24BitRecord = 3;
constexpr size_t kBytes32BitRecord = 4;
// The widest integer this reader will accept from metadata: 4 bytes, so 32
// bits. Anything wider is a corrupt file, not a count.
constexpr uint32_t kMaxMetadataCountBytes = 4;

// Address bit counts, for LookupBits. The walk is over bits, and the two
// callers differ only here - 32 for IPv4, 128 for IPv6.
constexpr unsigned kIpv4BitCount = 32;
constexpr unsigned kIpv6BitCount = 128;

// An IPv6 tree contains the whole IPv4 space at a fixed place: ::/96, i.e. 96
// zero bits from the root, which writers also alias at ::ffff:0:0/96. This is
// how the IPv4 half is located when metadata does not say (and shipped
// databases do not say - ipv4_start_node is not in the format's known-key
// list, so no MaxMind database carries it).
constexpr unsigned kIpv4InV6PrefixBits = 96;

// No country key, ISO code or name this reader looks at comes close to this,
// so a size field beyond it is a corrupt file rather than a long string.
constexpr size_t kMaxStringBytes = 1024;

bool AddOvf(size_t a, size_t b, size_t* out) {
    if (a > (std::numeric_limits<size_t>::max)() - b) return false;
    *out = a + b;
    return true;
}

uint32_t ReadU32BE(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint64_t ReadU64BE(const unsigned char* p) {
    return (static_cast<uint64_t>(ReadU32BE(p)) << 32) | ReadU32BE(p + 4);
}

bool ReadBytes(const unsigned char* p, size_t n, uint64_t* out) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    *out = v;
    return true;
}

// ---------------------------------------------------------------------------
// Data section
// ---------------------------------------------------------------------------

// A located data-section value. A string is a view into the file buffer rather
// than a copy: the buffer is owned by the database and untouched after Load(),
// so it outlives every use of these, and a country code is read once per row.
struct Value {
    enum class Type { kOpaque, kMap, kArray, kString, kUint };

    Type type = Type::kOpaque;
    size_t start = 0;  // map/array: first entry; string: first byte
    size_t count = 0;  // entry count (key/value pairs) or byte count
    uint64_t uval = 0;  // kUint only
};

// Decodes values inside a byte range that is already known to be a
// self-contained section: the data section, or the metadata map. Pointers
// inside a section are relative to that section's own start, so the base is
// passed in rather than assumed - the spec has metadata pointers starting at
// the beginning of the metadata section, not the beginning of the data.
class DataReader {
public:
    // No base is carried. 'data' IS the start of the section being read and
    // the spec makes pointer values relative to that section - the data
    // section for data pointers, the metadata section for metadata ones - so a
    // resolved target is already usable as an index into 'data'. Adding a file
    // offset here (which is what the third parameter used to be) produced an
    // absolute address that Resolve() then rejected as past the end.
    DataReader(const unsigned char* data, size_t size)
        : data_(data), size_(size) {}

    const unsigned char* data() const { return data_; }
    size_t size() const { return size_; }

    // Resolve 'off' (relative to this range) and decode the value there.
    // False means the offset is outside the range or the value is malformed;
    // either way nothing was read out of bounds.
    bool Decode(size_t off, Value* out) const {
        size_t real = 0;
        if (!Resolve(off, &real)) return false;

        unsigned char ctrl = data_[real];
        size_t pos = real + 1;
        uint8_t type = static_cast<uint8_t>(ctrl >> 5);
        if (type == kTypeExtended) {
            // A zero type means the real type number is in the next byte,
            // minus 7. This is how the rarely used types are spelled - signed
            // int32, uint128, array, cache container, end marker, boolean,
            // float - and array matters, because it is not in the top three
            // bits and cannot be assumed away.
            if (pos >= size_) return false;
            type = static_cast<uint8_t>(data_[pos] + 7);
            if (type < 8) return false;  // wrapped into a type already read
            pos += 1;
        }
        if (type == kTypePointer) return false;  // Resolve() followed them all

        uint32_t size = 0;
        if (!PayloadSize(ctrl, &pos, &size)) return false;
        if (type == kTypeBool) {
            // A boolean's five size bits are its VALUE (0 or 1), not a payload
            // length - see SkipValue() for the damage reading them as a length
            // caused.
            size = 0;
        }

        size_t payload = 0;
        if (!AddOvf(size, pos, &payload)) return false;
        if (payload > size_) return false;  // the value runs past the section

        switch (type) {
        case kTypeMap:
        case kTypeArray:
            out->type = (type == kTypeMap) ? Value::Type::kMap : Value::Type::kArray;
            out->start = pos;
            out->count = size;
            return true;

        case kTypeUtf8:
            if (size > kMaxStringBytes) return false;  // not a key we would use
            out->type = Value::Type::kString;
            out->start = pos;
            out->count = size;
            return true;

        case kTypeUint16:
        case kTypeUint32:
        case kTypeUint64:
        case kTypeUint128: {
            const size_t width = (type == kTypeUint16)   ? 2u
                                 : (type == kTypeUint32) ? 4u
                                                          : 8u;
            if (size > width) return false;  // not an integer of that type
            out->type = Value::Type::kUint;
            out->uval = 0;
            ReadBytes(data_ + pos, size, &out->uval);
            out->count = size;
            return true;
        }

        default:
            // Double, signed int32, float, bytes, the cache container, the
            // end marker, boolean: none carries a length this reader needs,
            // and none can appear inside a country record. They occupy 'size'
            // bytes, which is all the skip path wants to know.
            return true;
        }
    }

    // The offset just past the value stored at 'off'. A walk over a container
    // needs this to reach the next entry, so it has to account for both an
    // extended type byte and an extended size.
    //
    // For a map or an array the payload is a run of entries, NOT 'size' bytes,
    // so the only way to find where the container really ends is to walk it.
    // Adding 'size' to the position (which is what this used to do) lands
    // INSIDE the container, and since every real database carries a
    // 'description' map and a 'languages' array, the walk silently derailed
    // from there on and the keys after it were never found.
    bool ValueEnd(size_t off, size_t* end) const {
        return SkipValue(off, 0, end);
    }

    // Step over the value at 'off' without interpreting it - how a field we do
    // not care about is skipped. It goes through the same bounds checks as
    // Decode(), so a skip can fail just like a read.
    bool Skip(size_t off) const {
        size_t end = 0;
        return ValueEnd(off, &end);
    }

    // The value that follows the key at 'keyPos', whatever the key is. A
    // caller walking a map needs this to advance past an entry whose key it
    // did not recognise, and the arithmetic has to account for a key length
    // that needed an extended size byte.
    bool ValueAfterKey(size_t keyPos, size_t* valPos) const {
        if (keyPos >= size_) return false;
        const unsigned char ctrl = data_[keyPos];

        // A key is usually an inline UTF-8 string, but it is very often a
        // POINTER: writers dedup the sub-keys every country record repeats,
        // so "continent" in the record at data offset 441 is literally a
        // 2-byte pointer to the "continent" string that the record at offset 0
        // already contains. This used to demand a UTF-8 control byte here and
        // returned false, which MapFind reads as "no such key" - so one shared
        // key on the FIRST entry made the whole lookup fail, and since the
        // first key of a country record is always shared, no country was ever
        // extracted from a real database.
        //
        // The key's extent is the pointer's own bytes; KeyIs() needs no change,
        // because Decode() already follows a pointer to reach the string.
        if (static_cast<uint8_t>(ctrl >> 5) == kTypePointer) {
            const size_t payload =
                static_cast<size_t>((ctrl >> kPtrSizeShift) & kPtrSizeMask) + 1;
            if (keyPos + 1 + payload > size_) return false;
            return AddOvf(keyPos, 1 + payload, valPos);
        }

        if (static_cast<uint8_t>(ctrl >> 5) != kTypeUtf8) return false;

        size_t pos = keyPos + 1;
        uint32_t len = 0;
        if (!PayloadSize(ctrl, &pos, &len)) return false;
        return AddOvf(pos, len, valPos);
    }

    // True if the key at 'keyPos' is exactly 'want'.
    bool KeyIs(size_t keyPos, const char* want) const {
        Value k;
        if (!Decode(keyPos, &k) || k.type != Value::Type::kString) return false;
        const size_t n = std::strlen(want);
        return k.count == n && std::memcmp(data_ + k.start, want, n) == 0;
    }

    // False if the value at 'off' is not an integer, or is wider than the 32
    // bits a metadata count can legitimately occupy.
    bool ReadUint(size_t off, uint64_t* out) const {
        Value v;
        if (!Decode(off, &v)) return false;
        if (v.type != Value::Type::kUint || v.count > kMaxMetadataCountBytes)
            return false;
        *out = v.uval;
        return true;
    }

private:
    // Walk the value at 'off' and report the offset just past it. Recurses for
    // map/array payloads; 'depth' is the same bound Resolve() applies to a
    // pointer chain, and stops a file that nests containers into each other.
    bool SkipValue(size_t off, int depth, size_t* end) const {
        if (depth > kMaxPointerFollows) return false;
        if (off >= size_) return false;

        // A pointer is FOUR facts, but a skip only needs one of them: how many
        // bytes it occupies HERE. 1 control byte plus (size code + 1) payload.
        //
        // This branch has to come BEFORE Resolve(), because Resolve() exists to
        // throw the pointer away and report where it POINTS. Following it here
        // made ValueEnd() return the end of the TARGET, and the container walk
        // then resumed at that target instead of just past the pointer - a
        // jump backwards into the middle of an unrelated value. Every real
        // database has a 'languages' array of pointers, so metadata walking
        // derailed there and node_count was never reached.
        const unsigned char here = data_[off];
        if (static_cast<uint8_t>(here >> 5) == kTypePointer) {
            const size_t payload =
                static_cast<size_t>((here >> kPtrSizeShift) & kPtrSizeMask) + 1;
            if (off + 1 + payload > size_) return false;
            *end = off + 1 + payload;
            return true;
        }

        size_t real = 0;
        if (!Resolve(off, &real)) return false;

        const unsigned char ctrl = data_[real];
        size_t pos = real + 1;
        uint8_t type = static_cast<uint8_t>(ctrl >> 5);
        if (type == kTypeExtended) {
            if (pos >= size_) return false;
            type = static_cast<uint8_t>(data_[pos] + 7);
            if (type < 8) return false;
            pos += 1;
        }
        if (type == kTypePointer) return false;

        uint32_t size = 0;
        if (!PayloadSize(ctrl, &pos, &size)) return false;
        if (type == kTypeBool) {
            // boolean - 14: "The length information for a boolean type will
            // always be 0 or 1, indicating the value. There is no payload for
            // this field." The five size bits in the control byte are the
            // VALUE, so treating them as a payload length - which this did -
            // stepped exactly one byte into the NEXT field.
            //
            // That one byte is all it takes to lose a record: a country record
            // carrying 'is_in_european_union' is followed by 'iso_code', and
            // resuming one byte late meant the key was read from the middle of
            // the boolean itself, ValueAfterKey() refused it, MapFind() gave up
            // on the whole map, and the row printed no country. The records
            // without that flag worked, which is what made it look like only
            // some countries were broken. (end marker - 13 needs no special
            // case: its size is always 0, so the generic path already lands
            // right after it.)
            size = 0;
        }

        if (type == kTypeMap || type == kTypeArray) {
            for (uint32_t i = 0; i < size; ++i) {
                if (type == kTypeMap) {
                    // Each entry is a key, then a value.
                    size_t next = 0;
                    if (!SkipValue(pos, depth + 1, &next)) return false;
                    pos = next;
                }
                size_t next = 0;
                if (!SkipValue(pos, depth + 1, &next)) return false;
                pos = next;
            }
            *end = pos;
            return true;
        }
        // Everything else is a fixed-width payload of 'size' bytes, which
        // Decode() has already checked fits inside the section.
        return AddOvf(pos, size, end);
    }

    // The 5-bit size, extended if it is 29/30/31. Advances 'pos' past whatever
    // the size needed.
    //
    // The size lives in the low 5 bits of the CONTROL byte - including for an
    // extended type, where that byte is 0x00|type<<5|size and the real type
    // follows it. The four cases, per the spec's read_size:
    //   under 29  - the value is inline
    //   29        - the next byte, plus 29
    //   30        - 285 plus the next 2 bytes
    //   31        - 65821 plus the next 3 bytes
    // The old code took the 29 case as a bare byte and read 31 as 285 + 2
    // bytes, so any string of 29+ characters or integer of 285+ shifted the
    // whole parse - which is every real database.
    bool PayloadSize(unsigned char ctrl, size_t* pos, uint32_t* size) const {
        const uint32_t s = ctrl & 0x1Fu;
        if (s < kSizeExtended29) {
            *size = s;
            return true;
        }
        if (s == kSizeExtended29) {
            if (*pos >= size_) return false;
            *size = kSizeExtended29 + static_cast<uint32_t>(data_[*pos]);
            *pos += 1;
            return true;
        }
        // 30 -> 2 bytes added to 285; 31 -> 3 bytes added to 65821.
        const size_t extra = (s == kSizeExtended30) ? kSizeExtraBytes30 : kSizeExtraBytes31;
        if (*pos + extra > size_) return false;
        uint64_t v = 0;
        ReadBytes(data_ + *pos, extra, &v);
        *size = static_cast<uint32_t>((s == kSizeExtended30 ? kSizeExtended30Base : kSizeExtended31Base) + v);
        *pos += extra;
        return true;
    }

    // Follow a data pointer to the control byte it designates, rejecting a
    // file whose pointers form a cycle.
    bool Resolve(size_t off, size_t* realOff) const {
        int depth = 0;
        while (depth <= kMaxPointerFollows) {
            if (off >= size_) return false;
            const unsigned char ctrl = data_[off];
            if (static_cast<uint8_t>(ctrl >> 5) != kTypePointer) {
                *realOff = off;
                return true;
            }
            size_t target = 0;
            if (!ReadPointer(ctrl, off + 1, &target)) return false;
            off = target;
            ++depth;
        }
        return false;
    }

    // Spec readPointer(). 'pos' is the first byte after the control byte.
    //
    // A size code S stands for S+1 payload bytes, so the value is assembled
    // from S+1 bytes - and the previous version of this function got that wrong
    // three separate ways at once. That is not a rounding error: it is why no
    // real MaxMind database could ever be opened by this program, while every
    // self-test passed, because the synthetic database contains no pointers at
    // all and this code was therefore never executed by a single test:
    //
    //   * it read S bytes rather than S+1, so a size-0 pointer - by far the
    //     common case - consumed NO payload byte and the offset came out as
    //     whatever the control bits alone described;
    //   * ReadBytes() ASSIGNS its result, so seeding 'v' with the control
    //     byte's low three bits and then calling it threw those three bits
    //     away, contradicting the comment that used to sit right here;
    //   * it added dataBase_ to a value the spec already defines relative to
    //     the section, handing Resolve() a file-absolute offset that its own
    //     'off >= size_' bound then rejected.
    //
    // Every real database carries a 'languages' array whose elements are
    // pointers, so Load() derailed while skipping that array and reported the
    // unrelated "metadata is missing node_count or record_size".
    //
    // Size 3 is the 4-byte form, where the payload is a plain 32-bit offset and
    // the control byte's low three bits are IGNORED. It used to be refused
    // outright as unimplemented; all four
    // forms are implemented now, and the two larger ones keep their spec bases
    // (2048 = 2^11, past every 11-bit size-0 value; 526336 = 2^19 + 2048, past
    // every 19-bit size-1 value) so the ranges cannot overlap.
    bool ReadPointer(unsigned char ctrl, size_t pos, size_t* out) const {
        const uint8_t size = static_cast<uint8_t>((ctrl >> kPtrSizeShift) &
                                                 kPtrSizeMask);
        const size_t payload = static_cast<size_t>(size) + 1;
        if (pos + payload > size_) return false;

        uint64_t v = 0;
        ReadBytes(data_ + pos, payload, &v);
        if (size != 3) {
            // ReadBytes() replaced 'v', so the control byte's three bits go on
            // top of the payload now - they are the value's MOST significant
            // bits, which is what the (8 * payload) shift expresses.
            v |= (static_cast<uint64_t>(ctrl) & 0x7u) << (8 * payload);
            if (size == 1) v += kPtr2Base;
            else if (size == 2) v += kPtr3Base;
        }

        *out = static_cast<size_t>(v);
        return true;
    }

    const unsigned char* data_;
    size_t size_;
};

// Find 'key' in the map described by 'map' and leave its value's offset in
// 'valPos'. Returns false if the key is absent or the map is malformed.
bool MapFind(const DataReader& r, const Value& map, const char* key,
             size_t* valPos) {
    if (map.type != Value::Type::kMap) return false;
    size_t pos = map.start;
    for (size_t i = 0; i < map.count; ++i) {
        size_t val = 0;
        if (!r.ValueAfterKey(pos, &val)) return false;
        if (r.KeyIs(pos, key)) {
            *valPos = val;
            return true;
        }
        size_t next = 0;
        if (!r.ValueEnd(val, &next)) return false;
        pos = next;
    }
    return false;
}

// A well-formed MMDB string is UTF-8. The ISO codes this reader prefers are two
// ASCII letters, but a fallback name may not be, and a bad byte must never
// become a bad wchar_t - so each unit is validated and anything malformed
// becomes U+FFFD. Strings are only ever widened through here.
void AppendUtf8(std::wstring* dst, const unsigned char* p, size_t n) {
    size_t i = 0;
    while (i < n) {
        const unsigned char lead = p[i];
        if (lead < 0x80) {
            dst->push_back(static_cast<wchar_t>(lead));
            ++i;
            continue;
        }
        uint32_t cp = 0xFFFD;
        size_t used = 1;
        if (lead >= 0xC2 && lead < 0xE0) {
            cp = lead & 0x1Fu;
        } else if (lead >= 0xE0 && lead < 0xF0) {
            cp = lead & 0x0Fu;
        } else {
            cp = 0xFFFD;  // stray continuation byte, overlong lead, or 4-byte
        }
        if (lead >= 0xC2 && lead < 0xF0 && i + 1 < n &&
            (p[i + 1] & 0xC0) == 0x80) {
            cp = (cp << 6) | (p[i + 1] & 0x3Fu);
            used = 2;
            if (lead >= 0xE0 && i + 2 < n && (p[i + 2] & 0xC0) == 0x80) {
                cp = (cp << 6) | (p[i + 2] & 0x3Fu);
                used = 3;
            }
        }
        if (cp > 0xFFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
        dst->push_back(static_cast<wchar_t>(cp));
        i += used;
    }
}

std::wstring Widen(const DataReader& r, const Value& v) {
    std::wstring s;
    s.reserve(v.count);
    AppendUtf8(&s, r.data() + v.start, v.count);
    return s;
}

// The country column is a few characters wide, so a two-letter uppercase code
// is the only thing that belongs in it. A record whose iso_code is anything
// else is corrupt and falls through to the name rather than printing junk.
bool LooksLikeIsoCode(const std::wstring& s) {
    return s.size() == 2 && s[0] >= L'A' && s[0] <= L'Z' && s[1] >= L'A' &&
           s[1] <= L'Z';
}

}  // namespace

// ---------------------------------------------------------------------------
// GeoIpDatabase
// ---------------------------------------------------------------------------

GeoIpDatabase::~GeoIpDatabase() { Close(); }

GeoIpDatabase::GeoIpDatabase(GeoIpDatabase&& other) noexcept {
    MoveFrom(other);
}

GeoIpDatabase& GeoIpDatabase::operator=(GeoIpDatabase&& other) noexcept {
    if (this != &other) {
        Close();
        MoveFrom(other);
    }
    return *this;
}

void GeoIpDatabase::MoveFrom(GeoIpDatabase& other) noexcept {
    mappedView_ = other.mappedView_;
    fileSize_ = other.fileSize_;
    dataSectionBase_ = other.dataSectionBase_;
    dataSectionSize_ = other.dataSectionSize_;
    ipv6Tree_ = other.ipv6Tree_;
    v4StartNode_ = other.v4StartNode_;
    recordBytes_ = other.recordBytes_;
    record28_ = other.record28_;
    nodeByteSize_ = other.nodeByteSize_;
    treeSize_ = other.treeSize_;
    recordCount_ = other.recordCount_;
    nodeCount_ = other.nodeCount_;
    version_ = std::move(other.version_);
    sourcePath_ = std::move(other.sourcePath_);

    other.mappedView_ = nullptr;
    other.fileSize_ = 0;
    other.dataSectionBase_ = 0;
    other.dataSectionSize_ = 0;
    other.ipv6Tree_ = false;
    other.v4StartNode_ = 0;
    other.recordBytes_ = 0;
    other.record28_ = false;
    other.nodeByteSize_ = 0;
    other.treeSize_ = 0;
    other.recordCount_ = 0;
    other.nodeCount_ = 0;
    other.version_.clear();
    other.sourcePath_.clear();
}

void GeoIpDatabase::Close() {
    if (mappedView_ != nullptr) ::UnmapViewOfFile(mappedView_);
    mappedView_ = nullptr;
    fileSize_ = 0;
    dataSectionBase_ = 0;
    dataSectionSize_ = 0;
    ipv6Tree_ = false;
    v4StartNode_ = 0;
    recordBytes_ = 0;
    nodeByteSize_ = 0;
    treeSize_ = 0;
    recordCount_ = 0;
    nodeCount_ = 0;
    version_.clear();
}

std::wstring GeoIpDatabase::DatabaseVersion() const { return version_; }
uint64_t GeoIpDatabase::RecordCount() const { return recordCount_; }
uint64_t GeoIpDatabase::NodeCount() const { return nodeCount_; }

bool GeoIpDatabase::Load(const std::wstring& path, std::wstring* error) {
    // Stays const wchar_t*: widening it to std::wstring would make all fifteen
    // literal call sites below build a temporary string on an error path, for
    // no benefit - the one message that needs a value in it builds its own
    // string and hands over .c_str(), which is copied before it goes out of
    // scope.
    const auto fail = [error, this](const wchar_t* what) {
        if (error != nullptr) *error = what;
        // Release any partial mapping on failure. On an early failure
        // mappedView_ is still null, so Close() is a clean no-op.
        Close();
        return false;
    };
    if (error != nullptr) error->clear();

    // Remember the path so the caller can persist it. Set BEFORE the
    // success/fail branches, so a failed load still records what was tried -
    // a stale path is the honest thing to hand back, and the only reader
    // (MainWindow) asks Loaded() first and persists "" when it is false.
    sourcePath_ = path;

    // A failed reload must leave the object empty rather than holding the
    // previous file, so the caller cannot mix results from two databases.
    Close();

    if (path.empty()) {
        return fail(L"No GeoIP database path was given.");
    }

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return fail(L"The GeoIP database could not be opened.");
    }

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(h, &fileSize)) {
        CloseHandle(h);
        return fail(L"The GeoIP database size could not be read.");
    }
    const size_t minSize = kSeparatorLen + sizeof(kMetaMarker);
    if (fileSize.QuadPart < static_cast<LONGLONG>(minSize)) {
        CloseHandle(h);
        return fail(L"The file is too small to be a GeoIP database.");
    }
    // The size has to fit in a size_t, but the file API already reports it as a
    // signed 64-bit count, so on a 64-bit build the only case left to reject is
    // negative - which cannot happen for a real file, and is checked anyway so
    // a weird filesystem cannot turn it into a huge size_t.
    if (fileSize.QuadPart < 0) {
        CloseHandle(h);
        return fail(L"The GeoIP database size could not be read.");
    }

    const size_t total = static_cast<size_t>(fileSize.QuadPart);

    // A real database is 70-500 MB. A full ReadFile into a heap buffer used to
    // allocate it and block startup. Map it instead: CreateFileMappingW +
    // MapViewOfFile gives us a view of the file with demand paging, Load
    // returns immediately, and cold pages are the OS's problem, not this
    // process's commit charge. The file and mapping handles are closed after
    // the view is open; the view alone keeps the underlying pages alive.
    const HANDLE hMap = ::CreateFileMappingW(
        h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (hMap == nullptr) {
        ::CloseHandle(h);
        return fail(L"Could not create a file mapping for the GeoIP database.");
    }
    const void* view = ::MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, total);
    ::CloseHandle(hMap);
    ::CloseHandle(h);
    if (view == nullptr) {
        return fail(L"Could not map the GeoIP database into memory.");
    }

    mappedView_ = static_cast<const unsigned char*>(view);
    fileSize_ = total;

    // --- metadata ------------------------------------------------------------
    // Found by searching backwards from the END OF THE FILE for the marker. The
    // spec asks for the LAST occurrence, because arbitrary binary in the data
    // section can contain the same 14 bytes. Searching the whole tail (rather
    // than from a data-section offset) is deliberate: the offset is not known
    // yet — it depends on the tree size, which comes out of this metadata.
    size_t metaStart = 0;
    bool haveMeta = false;
    for (size_t back = sizeof(kMetaMarker); back <= total; ++back) {
        const size_t off = total - back;
        if (std::memcmp(mappedView_ + off, kMetaMarker, sizeof(kMetaMarker)) == 0) {
            metaStart = off + sizeof(kMetaMarker);
            haveMeta = true;
            break;
        }
    }
    if (!haveMeta) {
        return fail(L"This file is not a GeoIP database (no metadata).");
    }

    // The metadata is read as its own section, so a pointer in it cannot walk
    // back into the data section and be mistaken for a record. The section's
    // start is only the DATA pointer, not an offset to add: pointer values
    // inside this section are already relative to it.
    const DataReader meta(mappedView_ + metaStart, total - metaStart);
    Value metaMap;
    if (!meta.Decode(0, &metaMap) || metaMap.type != Value::Type::kMap) {
        return fail(L"The GeoIP database metadata is malformed.");
    }

    // --- node geometry -------------------------------------------------------
    // The tree size is derived rather than read: node_count nodes of two
    // records of record_size bits each. That is the only reason a stored length
    // never has to be trusted.
    size_t pos = 0;
    uint64_t nodeCount = 0;
    uint64_t recordBits = 0;
    if (!MapFind(meta, metaMap, "node_count", &pos) ||
        !meta.ReadUint(pos, &nodeCount) ||
        !MapFind(meta, metaMap, "record_size", &pos) ||
        !meta.ReadUint(pos, &recordBits)) {
        return fail(L"The GeoIP database metadata is missing node_count or record_size.");
    }
    // Two DISTINCT faults, reported separately: a file with no tree at all and
    // a file whose records this reader cannot address have different causes and
    // different fixes, and collapsing them into one sentence is what made both
    // reach the user as an unactionable "cannot load database".
    if (nodeCount == 0) {
        return fail(L"The GeoIP database declares node_count = 0, so it contains "
                    L"no search tree.");
    }
    // The spec allows exactly three record sizes: 24, 28 and 32 bits. 28 is not
    // a whole number of bytes - a node is 7 of them, with the two records'
    // overflow nibbles sharing the middle byte - so the old "whole bytes only"
    // check rejected it, and 28 is what essentially every real MaxMind database
    // uses. Rejecting it meant no real database could ever load.
    //
    // The message carries the value that was REFUSED. record_size = 4 is the
    // case reported as a silent rejection: 4 is the size in bytes, and 4 bytes
    // is the 32 bits already accepted - one unit away from loadable, which a
    // bare "impossible search tree" does not hint at. Nothing here trusts the
    // file, but neither does it hide what the file said.
    if (recordBits != kRecordBits24 && recordBits != kRecordBits28 &&
        recordBits != kRecordBits32) {
        std::wstring msg =
            L"The GeoIP database declares record_size = " +
            std::to_wstring(recordBits) +
            L", which is not one of the sizes this reader supports "
            L"(24, 28 or 32 bits).";
        // Exact comparisons against literals, deliberately: recordBits comes
        // straight out of an untrusted file, so nothing is COMPUTED from it -
        // a value that does not match either falls through with the plain
        // message above rather than reaching a multiplication.
        if (recordBits == 4) {
            msg += L" 4 is a size in bytes; 4 bytes is 32 bits, so this file may "
                   L"be stating the record size in bytes rather than bits.";
        } else if (recordBits == 3) {
            msg += L" 3 is a size in bytes; 3 bytes is 24 bits, so this file may "
                   L"be stating the record size in bytes rather than bits.";
        }
        // 'msg' outlives this call: fail() copies what it is given, and it
        // only ever runs on a path that is about to return false.
        return fail(msg.c_str());
    }
    const bool record28 = (recordBits == kRecordBits28);
    const size_t recordBytes = static_cast<size_t>(
        recordBits == kRecordBits32 ? kBytes32BitRecord : kBytes24BitRecord);
    // 24 and 32 bit records are two whole records per node; a 28 bit node is 7
    // bytes, because the two records share the nibbles in the middle byte.
    const size_t nodeBytes = record28 ? kNodeBytes28 : 2u * recordBytes;
    const size_t maxNodes = (std::numeric_limits<size_t>::max)() / nodeBytes;
    if (nodeCount > static_cast<uint64_t>(maxNodes)) {
        return fail(L"The GeoIP database search tree is impossibly large.");
    }
    const size_t treeSize = static_cast<size_t>(nodeCount) * nodeBytes;

    // --- data section ------------------------------------------------------
    // The layout is fixed: [tree][16-byte separator][data][metadata marker]
    // [metadata], so the section starts at treeSize + 16. It is DERIVED rather
    // than read out of the separator's last 8 bytes, because the separator only
    // sits at that offset once the tree size is known - which is exactly what
    // the metadata gives us here. (Reading it before the geometry was known
    // meant reading tree bytes, so every database with a non-empty tree was
    // rejected as "not a GeoIP database" - the country column could never work.)
    // Derived is also the only value worth trusting, per the same rule the tree
    // size itself follows: nothing stored in the file is taken on faith.
    if (treeSize + kSeparatorLen >= total) {
        return fail(L"This file is not a GeoIP database (bad data section).");
    }
    const size_t base = treeSize + kSeparatorLen;
    // The section runs to the end of the file: the format puts nothing after it
    // except the metadata marker, which is not part of the section.
    const size_t dataSize = total - base;

    // record_count is only ever shown, never used to index, so a value larger
    // than the section could hold is a lie and is dropped rather than printed.
    uint64_t recordCount = 0;
    if (MapFind(meta, metaMap, "record_count", &pos)) {
        (void)meta.ReadUint(pos, &recordCount);
    }
    if (recordCount > static_cast<uint64_t>(dataSize)) recordCount = 0;

    // ip_version decides whether the tree has an IPv4 half of its own, and
    // where it starts. A v6 tree puts IPv4 at ::/96 - 96 zero bits down from
    // the root - and the metadata MAY confirm that as ipv4_start_node.
    //
    // It usually does not: the key is not in the format's known-key list, so no
    // shipped MaxMind database carries it. When it was missing this did
    // nothing, leaving IPv4 walks to start at the ROOT, on the stated reasoning
    // that "those 96 zero bits lead there anyway". They do not lead there - they
    // lead to a node 96 hops down - so a 32-bit walk from the top searched the
    // upper reaches of the IPv6 space and never reached IPv4 data at all. Every
    // IPv4 row came back empty against a real database, which is why this went
    // unnoticed: the self-test's synthetic database is ip_version 4, has no
    // such half, and passed. The node is therefore DERIVED when unnamed, by
    // following 96 zero-bit branches.
    bool ipv6Tree = false;
    size_t v4Start = 0;
    bool haveV4Start = false;
    uint64_t ipVersion = 0;
    if (MapFind(meta, metaMap, "ip_version", &pos) &&
        meta.ReadUint(pos, &ipVersion) && ipVersion == 6) {
        ipv6Tree = true;
        uint64_t start = 0;
        if (MapFind(meta, metaMap, "ipv4_start_node", &pos) &&
            meta.ReadUint(pos, &start)) {
            if (start >= nodeCount) {
                return fail(L"The GeoIP database points at a node that does not exist.");
            }
            v4Start = static_cast<size_t>(start);
            haveV4Start = true;
        }
        // When the key is absent the node is derived further down, once the
        // tree geometry has been written to this object: the derivation reads
        // the tree through NodeRecord, which reads those members, so running it
        // here would have seen them still at their reset values, concluded on
        // step one that no IPv4 half exists, and recorded that as fact.
    }

    // Everything checked out, so take ownership of the buffer.
    // Everything checked out; the buffer is not copied, so there is nothing
    // more to take ownership of here. Ownership already transferred when
    // mappedView_ was set right after MapViewOfFile.
    dataSectionBase_ = base;
    dataSectionSize_ = dataSize;
    ipv6Tree_ = ipv6Tree;
    recordBytes_ = recordBytes;
    record28_ = record28;
    nodeByteSize_ = nodeBytes;
    treeSize_ = treeSize;
    nodeCount_ = nodeCount;
    recordCount_ = recordCount;

    // Derive the IPv4 half's root node when metadata did not name it. This runs
    // AFTER the geometry above, because NodeRecord reads nodeByteSize_,
    // treeSize_, record28_, recordBytes_ and nodeCount_ - every one of which is
    // still a reset value earlier in Load.
    //
    // Only a full 96-step descent is accepted. A tree that branches to data on
    // the way has no separate IPv4 half to find, and stopping partway down
    // would misalign the remaining 32 bits, so the root is used instead - the
    // pre-existing behaviour, and no worse than walking a subtree nothing leads
    // to. This is not a reason to reject a file whose metadata and geometry
    // already checked out.
    if (ipv6Tree && !haveV4Start) {
        size_t node = 0;
        bool reached = true;
        for (unsigned step = 0; step < kIpv4InV6PrefixBits; ++step) {
            size_t child = 0;
            if (!NodeRecord(node, 0, &child) ||
                child >= static_cast<size_t>(nodeCount)) {
                reached = false;
                break;
            }
            node = child;
        }
        v4Start = reached ? node : 0;
    }
    v4StartNode_ = v4Start;

    // The version string is cosmetic: a database that answers lookups is still
    // usable if this one field is missing or odd.
    if (MapFind(meta, metaMap, "database_type", &pos)) {
        Value t;
        if (meta.Decode(pos, &t) && t.type == Value::Type::kString) {
            version_ = Widen(meta, t);
        }
    }
    return true;
}

bool GeoIpDatabase::NodeRecord(size_t node, unsigned half, size_t* out) const {
    if (nodeByteSize_ == 0 || treeSize_ == 0) return false;
    if (node >= static_cast<size_t>(nodeCount_)) return false;
    const size_t recPos = node * nodeByteSize_;
    if (recPos + nodeByteSize_ > treeSize_) return false;

    if (record28_) {
        // A 28-bit record keeps the top four bits of both halves in the
        // middle byte of the node, so a 28-bit file has to be reassembled
        // from both halves rather than read straight out. This is the
        // layout nearly every real database uses.
        const unsigned char* p = mappedView_ + recPos;
        if (half == 0) {
            *out = (static_cast<size_t>(p[3] >> 4) << 24) |
                   (static_cast<size_t>(p[0]) << 16) |
                   (static_cast<size_t>(p[1]) << 8) |
                   static_cast<size_t>(p[2]);
        } else {
            *out = (static_cast<size_t>(p[3] & 0x0Fu) << 24) |
                   (static_cast<size_t>(p[4]) << 16) |
                   (static_cast<size_t>(p[5]) << 8) |
                   static_cast<size_t>(p[6]);
        }
        return true;
    }
    if (recordBytes_ == 4) {
        *out = ReadU32BE(mappedView_ + recPos);
        return true;
    }
    if (recordBytes_ == 3) {
        // A 3-byte record is the 3 bytes of the node starting at the half this
        // bit selects: bytes 0-2 for the left record, 3-5 for the right.
        // Reading the same window for both (which is what this used to do)
        // meant the right record was a copy of the left, so every walk stepped
        // down the left half and found nothing. The 4-byte read at offset 3
        // reaches one byte past this node, which is why the data-section
        // geometry is checked before any walk runs.
        *out = (ReadU32BE(mappedView_ + recPos + (half ? 3u : 0u)) >> 8) &
               0x00FFFFFFu;
        return true;
    }
    // Unreachable: recordBytes_ is derived as (32-bit ? 4 : 3) and a 28-bit
    // record is caught above. It is a refusal rather than a fall-through so a
    // future record size cannot quietly read as one of the others.
    return false;
}

std::wstring GeoIpDatabase::LookupBits(const unsigned char bits[16],
                                       unsigned bitCount,
                                       size_t startNode) const {
    size_t offset = 0;
    if (!ResolveOffset(bits, bitCount, startNode, &offset)) return std::wstring();
    return CountryAt(offset);
}

bool GeoIpDatabase::ResolveOffset(const unsigned char bits[16],
                                  unsigned bitCount,
                                  size_t startNode,
                                  size_t* out) const {

    if (!Loaded() || nodeCount_ == 0 || recordBytes_ == 0) return false;

    const size_t nodeCount = static_cast<size_t>(nodeCount_);
    size_t node = startNode;

    for (unsigned depth = 0; depth < bitCount; ++depth) {
        const unsigned bit = (bits[depth / 8] >> (7 - (depth % 8))) & 1u;
        size_t record = 0;

// SPDX-License-Identifier: Apache-2.0
        if (!NodeRecord(node, bit, &record)) return false;

        // Three cases: below the node count it is a node number; equal to it
        // the database has no data here; and node_count + 16 or above it is a
        // data pointer, where offset_in_file = (record - node_count) +
        // tree_bytes, and tree_bytes + 16 is where the data section starts -
        // so the subtraction below lands on an offset inside that section.
        //
        // The boundary is >=, not >: node_count + 16 is EXACTLY offset 0, and
        // offset 0 is the data section's first byte, which is a real record.
        // Real databases do put one there - the record a whole IPv4 range in
        // the test database resolves to sits at offset 0 - and reading that
        // value as "no data", which this did, made the one country stored
        // there unfindable while every other country in the same file worked.
        // Records strictly between node_count and node_count + 16 would be
        // offsets below the section's start, so they are unassigned and fall
        // through to the no-data branch.
        if (record < nodeCount) {
            node = record;
        } else if (record >= nodeCount + kSeparatorLen) {
            const size_t offset = record - nodeCount - kSeparatorLen;
            if (offset >= dataSectionSize_) return false;
            *out = offset;
            return true;
        } else {
            return false;
        }
    }

    // Every address bit was consumed and the walk still stands on an internal
    // node, so the address simply has no record. 'node' is a NODE NUMBER - it
    // is only ever assigned when a record came back below node_count - so
    // handing it to the decoder would read search-tree bytes as if they were a
    // data record, naming a country (or an ASN) for an address that has none
    // (and, now that data offset 0 is a reachable record, naming whatever sits
    // there for every address with no data at all).
    return false;
}

void GeoIpDatabase::AddressBitsV4(uint32_t hostOrderAddr,
                                  unsigned char bits[16]) {
    // The tree is indexed in network order, so hand it the address that way:
    // the most significant octet of a host-order value is the LAST octet of the
    // address, so the two pairs swap. Swapping the wrong way round (which is
    // what this used to do) turns 8.8.4.4 into 4.4.8.8 and quietly answers for
    // a completely different address - in every caller, not just this one.
    const uint32_t be = ((hostOrderAddr & 0xFF000000u) >> 24) |
                        ((hostOrderAddr & 0x00FF0000u) >> 8)  |
                        ((hostOrderAddr & 0x0000FF00u) << 8)  |
                        ((hostOrderAddr & 0x000000FFu) << 24);
    // 'be' is the address in network order, which on this little-endian build
    // means octet 0 sits in the LEAST significant byte. The tree is walked
    // address byte 0 first, so the bytes have to come out low byte first:
    // reading be >> 24 first walked the tree in reverse octet order and
    // answered for 4.4.8.8 when asked about 8.8.4.4 - a wrong answer, not an
    // error, in every caller (list --db, the country: filter, the GUI).
    for (int i = 0; i < 16; ++i) bits[i] = 0;
    bits[0] = static_cast<unsigned char>(be & 0xFFu);
    bits[1] = static_cast<unsigned char>((be >> 8) & 0xFFu);
    bits[2] = static_cast<unsigned char>((be >> 16) & 0xFFu);
    bits[3] = static_cast<unsigned char>((be >> 24) & 0xFFu);
}

std::wstring GeoIpDatabase::LookupV4(uint32_t hostOrderAddr) const {
    if (!IsGlobalUnicastV4(hostOrderAddr)) return std::wstring();
    if (!Loaded()) return std::wstring();

    unsigned char bits[16] = {0};
    AddressBitsV4(hostOrderAddr, bits);
    // In an IPv6 tree the IPv4 space is a SUBTREE - the 96-zero-bit one - so an
    // IPv4 walk starts there rather than at the root. v4StartNode_ is 0 for a
    // plain IPv4 tree, where the root is the correct start anyway.
    return LookupBits(bits, kIpv4BitCount, ipv6Tree_ ? v4StartNode_ : 0);
}

AsnInfo GeoIpDatabase::LookupAsnV4(uint32_t hostOrderAddr) const {
    if (!IsGlobalUnicastV4(hostOrderAddr)) return AsnInfo();
    if (!Loaded()) return AsnInfo();

    unsigned char bits[16] = {0};
    AddressBitsV4(hostOrderAddr, bits);
    size_t offset = 0;
    if (!ResolveOffset(bits, kIpv4BitCount, ipv6Tree_ ? v4StartNode_ : 0,
                       &offset)) {
        return AsnInfo();
    }
    return AsnAt(offset);
}

AsnInfo GeoIpDatabase::LookupAsnV6(const unsigned char addr[16]) const {
    if (!IsGlobalUnicastV6(addr)) return AsnInfo();
    if (!Loaded()) return AsnInfo();
    // Always the root, for the same reason LookupV6 does: a 128-bit walk lands
    // in the IPv4 subtree of a v6 tree on its own.
    size_t offset = 0;
    if (!ResolveOffset(addr, kIpv6BitCount, 0, &offset)) return AsnInfo();
    return AsnAt(offset);
}

std::wstring GeoIpDatabase::LookupV6(const unsigned char addr[16]) const {
    if (!IsGlobalUnicastV6(addr)) return std::wstring();
    if (!Loaded()) return std::wstring();
    // No special case for ::ffff:a.b.c.d: a 128-bit walk lands in the IPv4
    // subtree of a v6 tree on its own, which is where the data is.
    // Always the root: the IPv6 half IS the tree. Passing v4StartNode_ here as
    // well (which one stored flag and two identical call sites invited) walked
    // 128 bits from inside the IPv4 half, where no IPv6 address leads.
    return LookupBits(addr, kIpv6BitCount, 0);
}

std::wstring GeoIpDatabase::CountryAt(size_t dataOffset) const {
    // Offset 0 is NOT "no data" - it is the data section's first byte, and real
    // databases store a country there. Excluding it was half of why the
    // country at offset 0 could never be read, the other half being the
    // tree-walk boundary. dataSectionSize_ only means "not loaded".
    if (dataSectionSize_ == 0) return std::wstring();
    const DataReader r(mappedView_ + dataSectionBase_, dataSectionSize_);

    Value rec;
    if (!r.Decode(dataOffset, &rec) || rec.type != Value::Type::kMap) {
        return std::wstring();
    }

    // "country" is where the address itself is located; "registered_country" is
    // who owns the network, which is a reasonable second best and is what many
    // records carry when the first key is absent.
    static const char* const kKeys[] = {"country", "registered_country"};
    for (const char* key : kKeys) {
        size_t pos = 0;
        if (!MapFind(r, rec, key, &pos)) continue;
        Value c;
        if (!r.Decode(pos, &c) || c.type != Value::Type::kMap) continue;

        // iso_code first: short, stable, and unambiguous in a narrow column.
        size_t field = 0;
        if (MapFind(r, c, "iso_code", &field)) {
            Value v;
            if (r.Decode(field, &v) && v.type == Value::Type::kString) {
                const std::wstring code = Widen(r, v);
                if (LooksLikeIsoCode(code)) return code;
            }
        }
        // Only if there is no usable code: the name is a column-width gamble.
        if (MapFind(r, c, "names", &field)) {
            Value names;
            if (r.Decode(field, &names) && names.type == Value::Type::kMap &&
                MapFind(r, names, "en", &field)) {
                Value v;
                if (r.Decode(field, &v) && v.type == Value::Type::kString) {
                    const std::wstring name = Widen(r, v);
                    if (!name.empty()) return name;
                }
            }
        }
    }
    return std::wstring();
}

// ---------------------------------------------------------------------------
// ASN
// ---------------------------------------------------------------------------

std::wstring AsnInfo::Display() const {
    if (number == 0 && org.empty()) return std::wstring();
    std::wstring s;
    if (number != 0) {
        s = L"AS";
        s += std::to_wstring(number);
    }
    if (!org.empty()) {
        if (!s.empty()) s += L' ';
        s += org;
    }
    return s;
}

AsnInfo GeoIpDatabase::AsnAt(size_t dataOffset) const {
    // Same offset-0 rule as CountryAt: offset 0 is a real record, not "no data".
    if (dataSectionSize_ == 0) return AsnInfo();
    const DataReader r(mappedView_ + dataSectionBase_, dataSectionSize_);

    Value rec;
    if (!r.Decode(dataOffset, &rec) || rec.type != Value::Type::kMap) {
        return AsnInfo();
    }

    // Unlike a country record, these two keys sit at the TOP level of the map.
    // GeoLite2-ASN has no wrapper object - the record IS the autonomous system,
    // so looking for a nested "autonomous_system" key (which it does not have)
    // finds nothing and every address reads as unknown.
    //
    // The two halves are read independently rather than as a pair, because a
    // record that has only one of them is still worth reporting: some entries
    // carry an organisation with no number. Reading them as a pair would throw
    // that away.
    AsnInfo out;
    size_t pos = 0;
    if (MapFind(r, rec, "autonomous_system_number", &pos)) {
        Value v;
        if (r.Decode(pos, &v) && v.type == Value::Type::kUint) {
            // 0 is not a real ASN, and Decode cannot produce it from a
            // non-empty field (a zero-length uint reads as 0), so an explicit
            // check keeps "the record says zero" from printing as "AS0".
            if (v.uval != 0 && v.uval <= 0xFFFFFFFFull) {
                out.number = static_cast<uint32_t>(v.uval);
            }
        }
    }
    if (MapFind(r, rec, "autonomous_system_organization", &pos)) {
        Value v;
        if (r.Decode(pos, &v) && v.type == Value::Type::kString) {
            out.org = Widen(r, v);
        }
    }
    return out;
}

// Deliberately wider than RFC1918: a connection to a CGNAT address, a
// benchmarking range or a documentation block is just as much not a country as
// a connection to 10.0.0.1, and the registry has rows for some of them. The
// first-octet tests come first because they decide the overwhelming majority
// of addresses in a single comparison.
// Is this v4 address globally routable? The host-order form, and the ranges
// are spelled per-octet because the answer has to be readable against the
// IANA registry. The body is wintcp::IsGlobalUnicastV4Opt (Opt.cpp), which
// uses an octet table and two u64 tails for the trailing cases: 1.24x on the
// A/B bench, and this is called once per resolvable address per lookup.
bool IsGlobalUnicastV4(uint32_t a) {
    return IsGlobalUnicastV4Opt(a);
}

bool IsGlobalUnicastV6(const unsigned char a[16]) {
    return IsGlobalUnicastV6Opt(a);
}

// `local:private` and `remote:private`. Defined as the exact inverse of
// the GeoIP predicate, so the two can never disagree: an address the Country
// layer refuses to name is the same address a filter calls private.
bool IsPrivateAddrV4(uint32_t a) { return !IsGlobalUnicastV4(a); }
bool IsPrivateAddrV6(const unsigned char a[16]) {
    return !IsGlobalUnicastV6(a);
}

}  // namespace wintcp
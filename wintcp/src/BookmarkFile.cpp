// BookmarkFile.cpp
// SPDX-License-Identifier: Apache-2.0
// See BookmarkFile.h.

#include "BookmarkFile.h"

#include <cstdio>
#include <cstring>

#include "Opt.h"      // JsonEscapeOpt
#include "Utils.h"    // NormalizeAddress lives next to MakeBookmarkKey

namespace wintcp {
namespace {

// --- a tiny, strict JSON reader ----------------------------------------------
//
// Not a general JSON parser: it recognises the one shape this module accepts,
// and refuses everything else. Recursion depth is bounded because the schema is
// bounded - a document nested deeper than this is not a bookmark file, and
// accepting it would be accepting an input nobody defined.
constexpr int kMaxDepth = 16;

struct Cursor {
    const char* base = nullptr;   // document start, for byte offsets in errors
    const char* p = nullptr;      // current position
    const char* end = nullptr;
    std::wstring error;
};

// Records the FIRST failure only, so the caller sees the reason the parse
// actually died rather than whatever the unwinding tripped over next.
void FailAt(Cursor* c, const std::string& why) {
    if (c->error.empty()) {
        const size_t at =
            (c->p != nullptr && c->base != nullptr && c->p >= c->base)
                ? static_cast<size_t>(c->p - c->base)
                : 0;
        c->error = std::wstring(L"bookmark file: ") +
                   std::wstring(why.begin(), why.end()) +
                   L" at byte " +
                   std::to_wstring(static_cast<unsigned long long>(at));
    }
}

void SkipWs(Cursor* c) {
    while (c->p < c->end) {
        const char ch = *c->p;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
            ++c->p;
        } else {
            break;
        }
    }
}

bool ParseString(Cursor* c, std::string* out);
bool ParseValue(Cursor* c, int depth);

// A JSON string, including escapes. \uXXXX is decoded to UTF-8, and a
// surrogate PAIR is required for a code point above U+FFFF: a lone surrogate
// is refused, because it has no UTF-8 encoding and a bookmark address
// carrying one would be a value nothing else in the tool can round-trip.
bool ParseString(Cursor* c, std::string* out) {
    if (c->p >= c->end || *c->p != '"') {
        FailAt(c, "expected a string");
        return false;
    }
    ++c->p;
    out->clear();
    while (c->p < c->end) {
        const unsigned char ch = static_cast<unsigned char>(*c->p);
        if (ch == '"') {
            ++c->p;
            return true;
        }
        if (ch < 0x20) {
            FailAt(c, "control character inside a string");
            return false;
        }
        if (ch != '\\') {
            out->push_back(static_cast<char>(ch));
            ++c->p;
            continue;
        }
        ++c->p;
        if (c->p >= c->end) {
            FailAt(c, "unterminated escape");
            return false;
        }
        const char esc = *c->p++;
        switch (esc) {
            case '"': out->push_back('"'); break;
            case '\\': out->push_back('\\'); break;
            case '/': out->push_back('/'); break;
            case 'b': out->push_back('\b'); break;
            case 'f': out->push_back('\f'); break;
            case 'n': out->push_back('\n'); break;
            case 'r': out->push_back('\r'); break;
            case 't': out->push_back('\t'); break;
            case 'u': {
                auto hex4 = [&c](unsigned* value) {
                    if (c->end - c->p < 4) {
                        FailAt(c, "truncated \\u escape");
                        return false;
                    }
                    unsigned v = 0;
                    for (int i = 0; i < 4; ++i) {
                        const char h = c->p[i];
                        v <<= 4;
                        if (h >= '0' && h <= '9') {
                            v |= static_cast<unsigned>(h - '0');
                        } else if (h >= 'a' && h <= 'f') {
                            v |= static_cast<unsigned>(h - 'a' + 10);
                        } else if (h >= 'A' && h <= 'F') {
                            v |= static_cast<unsigned>(h - 'A' + 10);
                        } else {
                            FailAt(c, "bad hex digit in \\u escape");
                            return false;
                        }
                    }
                    c->p += 4;
                    *value = v;
                    return true;
                };
                unsigned cp = 0;
                if (!hex4(&cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    // High surrogate: a low one must follow.
                    if (c->end - c->p < 6 || c->p[0] != '\\' || c->p[1] != 'u') {
                        FailAt(c, "unpaired high surrogate");
                        return false;
                    }
                    c->p += 2;
                    unsigned lo = 0;
                    if (!hex4(&lo)) return false;
                    if (lo < 0xDC00 || lo > 0xDFFF) {
                        FailAt(c, "unpaired high surrogate");
                        return false;
                    }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    FailAt(c, "unpaired low surrogate");
                    return false;
                }
                // UTF-8 encode.
                if (cp < 0x80) {
                    out->push_back(static_cast<char>(cp));
                } else if (cp < 0x800) {
                    out->push_back(static_cast<char>(0xC0 | (cp >> 6)));
                    out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    out->push_back(static_cast<char>(0xE0 | (cp >> 12)));
                    out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                } else {
                    out->push_back(static_cast<char>(0xF0 | (cp >> 18)));
                    out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                    out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                    out->push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default:
                FailAt(c, "unknown escape");
                return false;
        }
    }
    FailAt(c, "unterminated string");
    return false;
}

bool ParseNumber(Cursor* c, long long* out) {
    const char* start = c->p;
    if (c->p < c->end && (*c->p == '-' || *c->p == '+')) ++c->p;
    bool any = false;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        ++c->p;
        any = true;
    }
    if (!any) {
        FailAt(c, "expected a number");
        return false;
    }
    // A fractional part is refused: the schema holds integers only, and a
    // tag of 1.5 is not a colour.
    if (c->p < c->end && (*c->p == '.' || *c->p == 'e' || *c->p == 'E')) {
        FailAt(c, "a fractional or exponent number is not valid here");
        return false;
    }
    std::string text(start, static_cast<size_t>(c->p - start));
    *out = std::strtoll(text.c_str(), nullptr, 10);
    return true;
}

bool ParseLiteral(Cursor* c, const char* word) {
    const size_t n = std::strlen(word);
    if (static_cast<size_t>(c->end - c->p) < n ||
        std::memcmp(c->p, word, n) != 0) {
        FailAt(c, "unrecognised token");
        return false;
    }
    c->p += n;
    return true;
}

// Skips a value the schema does not care about. It still has to be VALID JSON,
// because "version 1 with an unknown extra key" is a file this reader should
// accept while "version 1 with a stray brace" is not.
bool SkipValue(Cursor* c, int depth);

bool SkipString(Cursor* c) {
    std::string ignored;
    return ParseString(c, &ignored);
}

bool SkipValue(Cursor* c, int depth) {
    if (depth > kMaxDepth) {
        FailAt(c, "nested too deeply to be a bookmark file");
        return false;
    }
    SkipWs(c);
    if (c->p >= c->end) {
        FailAt(c, "unexpected end of document");
        return false;
    }
    switch (*c->p) {
        case '"': return SkipString(c);
        case '{':
        case '[': {
            const char open = *c->p;
            const char close = (open == '{') ? '}' : ']';
            ++c->p;
            SkipWs(c);
            if (c->p < c->end && *c->p == close) {
                ++c->p;
                return true;
            }
            for (;;) {
                SkipWs(c);
                if (open == '{') {
                    if (!SkipString(c)) return false;
                    SkipWs(c);
                    if (c->p >= c->end || *c->p != ':') {
                        FailAt(c, "expected ':'");
                        return false;
                    }
                    ++c->p;
                }
                if (!SkipValue(c, depth + 1)) return false;
                SkipWs(c);
                if (c->p < c->end && *c->p == ',') {
                    ++c->p;
                    continue;
                }
                if (c->p < c->end && *c->p == close) {
                    ++c->p;
                    return true;
                }
                FailAt(c, open == '{' ? "expected ',' or '}'" : "expected ',' or ']'");
                return false;
            }
        }
        default:
            if (std::memcmp(c->p, "true", 4) == 0 || c->p[0] == 't') {
                return ParseLiteral(c, "true");
            }
            if (std::memcmp(c->p, "false", 5) == 0 || c->p[0] == 'f') {
                return ParseLiteral(c, "false");
            }
            if (std::memcmp(c->p, "null", 4) == 0 || c->p[0] == 'n') {
                return ParseLiteral(c, "null");
            }
            {
                long long ignored = 0;
                return ParseNumber(c, &ignored);
            }
    }
}

// One record's fields. Everything the reader needs, filled by ReadRecord.
struct Record {
    std::string address;
    bool hasAddress = false;
    long long port = 0;
    bool hasPort = false;
    long long tag = 0;
    bool hasTag = false;
    std::string note;
    bool hasNote = false;
    long long when = 0;
    bool hasWhen = false;
};

bool ReadRecord(Cursor* c, Record* rec) {
    if (c->p >= c->end || *c->p != '{') {
        FailAt(c, "a bookmark record must be a JSON object");
        return false;
    }
    ++c->p;
    SkipWs(c);
    if (c->p < c->end && *c->p == '}') {
        ++c->p;
        return true;
    }
    for (;;) {
        SkipWs(c);
        std::string key;
        if (!ParseString(c, &key)) return false;
        SkipWs(c);
        if (c->p >= c->end || *c->p != ':') {
            FailAt(c, "expected ':' after a key");
            return false;
        }
        ++c->p;
        SkipWs(c);
        if (key == "address") {
            if (!ParseString(c, &rec->address)) return false;
            rec->hasAddress = true;
        } else if (key == "port" || key == "tag" || key == "when") {
            long long value = 0;
            if (!ParseNumber(c, &value)) return false;
            if (key == "port") {
                rec->port = value;
                rec->hasPort = true;
            } else if (key == "tag") {
                rec->tag = value;
                rec->hasTag = true;
            } else {
                rec->when = value;
                rec->hasWhen = true;
            }
        } else if (key == "note") {
            if (!ParseString(c, &rec->note)) return false;
            rec->hasNote = true;
        } else {
            // An unknown key is skipped, but must still be JSON.
            if (!SkipValue(c, 0)) return false;
        }
        SkipWs(c);
        if (c->p < c->end && *c->p == ',') {
            ++c->p;
            continue;
        }
        if (c->p < c->end && *c->p == '}') {
            ++c->p;
            return true;
        }
        FailAt(c, "expected ',' or '}'");
        return false;
    }
}

}  // namespace

void SerialiseBookmarks(const std::vector<Bookmark>& items, std::string* out) {
    if (out == nullptr) return;
    out->clear();
    out->reserve(64 + items.size() * 96);
    const std::string nl = "\r\n";
    const std::string q = "\"";
    out->append("{" + nl);
    out->append("  " + q + "schema" + q + ": " + q + "wintcp-bookmarks" + q +
                "," + nl);
    out->append("  " + q + "version" + q + ": " +
                std::to_string(kBookmarkFileVersion) + "," + nl);
    out->append("  " + q + "count" + q + ": " + std::to_string(items.size()) +
                "," + nl);
    out->append("  " + q + "bookmarks" + q + ": [");
    for (size_t i = 0; i < items.size(); ++i) {
        const Bookmark& b = items[i];
        if (i != 0) out->append(",");
        out->append(nl + "    {");
        // address and note are already wide, so the escaper takes them as
        // they are - there is no UTF-8 round trip here to get wrong.
        out->append(q + "address" + q + ":" + q + JsonEscapeOpt(b.address) +
                    q + ",");
        out->append(q + "port" + q + ":" + std::to_string(b.port) + ",");
        out->append(q + "tag" + q + ":" + std::to_string(b.tag) + ",");
        out->append(q + "note" + q + ":" + q + JsonEscapeOpt(b.note) + q + ",");
        out->append(q + "when" + q + ":" + std::to_string(b.when));
        out->append("}");
    }
    if (!items.empty()) out->append(nl + "  ");
    out->append("]" + nl + "}" + nl);
}

bool ParseBookmarks(const std::string& text, std::vector<Bookmark>* out,
                    std::wstring* error) {
    if (out == nullptr) {
        if (error != nullptr) *error = L"internal error: no output for ParseBookmarks";
        return false;
    }
    out->clear();
    if (error != nullptr) error->clear();

    if (text.size() > kBookmarkFileMaxBytes) {
        if (error != nullptr) {
            *error = L"bookmark file is " +
                     std::to_wstring(text.size()) +
                     L" bytes, over the " +
                     std::to_wstring(kBookmarkFileMaxBytes) +
                     L"-byte limit; refusing to load it. A real file holds one "
                     L"short record per pinned peer.";
        }
        return false;
    }

    Cursor c;
    c.base = text.data();
    c.p = text.data();
    c.end = text.data() + text.size();
    SkipWs(&c);
    if (c.p >= c.end || *c.p != '{') {
        FailAt(&c, "the document must be a JSON object");
        if (error != nullptr) *error = c.error;
        return false;
    }
    ++c.p;

    int version = -1;
    bool haveVersion = false;
    std::vector<Record> records;
    bool haveArray = false;

    SkipWs(&c);
    if (c.p < c.end && *c.p == '}') {
        ++c.p;
    } else {
        for (;;) {
            SkipWs(&c);
            std::string key;
            if (!ParseString(&c, &key)) {
                if (error != nullptr) *error = c.error;
                return false;
            }
            SkipWs(&c);
            if (c.p >= c.end || *c.p != ':') {
                FailAt(&c, "expected ':' after a key");
                if (error != nullptr) *error = c.error;
                return false;
            }
            ++c.p;
            SkipWs(&c);
            if (key == "version") {
                long long value = 0;
                if (!ParseNumber(&c, &value)) {
                    if (error != nullptr) *error = c.error;
                    return false;
                }
                version = static_cast<int>(value);
                haveVersion = true;
            } else if (key == "bookmarks") {
                haveArray = true;
                if (c.p >= c.end || *c.p != '[') {
                    FailAt(&c, "the bookmarks field must be an array");
                    if (error != nullptr) *error = c.error;
                    return false;
                }
                ++c.p;
                SkipWs(&c);
                if (c.p < c.end && *c.p == ']') {
                    ++c.p;
                } else {
                    for (;;) {
                        SkipWs(&c);
                        Record rec;
                        if (!ReadRecord(&c, &rec)) {
                            if (error != nullptr) *error = c.error;
                            return false;
                        }
                        records.push_back(rec);
                        if (records.size() > kBookmarkFileMaxRecords) {
                            if (error != nullptr) {
                                *error = L"bookmark file holds more than " +
                                         std::to_wstring(kBookmarkFileMaxRecords) +
                                         L" records; refusing to load it.";
                            }
                            return false;
                        }
                        SkipWs(&c);
                        if (c.p < c.end && *c.p == ',') {
                            ++c.p;
                            continue;
                        }
                        if (c.p < c.end && *c.p == ']') {
                            ++c.p;
                            break;
                        }
                        FailAt(&c, "expected ',' or ']'");
                        if (error != nullptr) *error = c.error;
                        return false;
                    }
                }
            } else {
                // "schema" and "count" are informational; an unknown key is
                // skipped but must still be JSON.
                if (!SkipValue(&c, 0)) {
                    if (error != nullptr) *error = c.error;
                    return false;
                }
            }
            SkipWs(&c);
            if (c.p < c.end && *c.p == ',') {
                ++c.p;
                continue;
            }
            if (c.p < c.end && *c.p == '}') {
                ++c.p;
                break;
            }
            FailAt(&c, "expected ',' or '}'");
            if (error != nullptr) *error = c.error;
            return false;
        }
    }

    SkipWs(&c);
    if (c.p != c.end) {
        FailAt(&c, "trailing content after the document");
        if (error != nullptr) *error = c.error;
        return false;
    }

    // The version is the one thing that cannot be guessed. A missing version
    // is refused rather than assumed to be 1: a format that guesses about its
    // own schema is a format that will one day guess wrong.
    if (!haveVersion) {
        if (error != nullptr) *error = L"bookmark file has no \"version\" field";
        return false;
    }
    if (version != kBookmarkFileVersion) {
        if (error != nullptr) {
            *error = L"bookmark file is schema version " +
                     std::to_wstring(version) + L", this build reads " +
                     std::to_wstring(kBookmarkFileVersion);
        }
        return false;
    }
    if (!haveArray) {
        if (error != nullptr) *error = L"bookmark file has no \"bookmarks\" array";
        return false;
    }

    std::vector<Bookmark> parsed;
    parsed.reserve(records.size());
    for (size_t i = 0; i < records.size(); ++i) {
        const Record& r = records[i];
        if (!r.hasAddress || !r.hasPort || !r.hasTag || !r.hasNote) {
            if (error != nullptr) {
                *error = L"bookmark record " + std::to_wstring(i + 1) +
                         L" is missing a required field (address, port, tag, "
                         L"note); the whole file is refused rather than "
                         L"loaded in part";
            }
            return false;
        }
        if (r.port < 0 || r.port > 65535) {
            if (error != nullptr) {
                *error = L"bookmark record " + std::to_wstring(i + 1) +
                         L" has a port outside 0..65535";
            }
            return false;
        }
        if (r.note.size() > Bookmarks::kMaxNoteChars) {
            if (error != nullptr) {
                *error = L"bookmark record " + std::to_wstring(i + 1) +
                         L" has a note over " +
                         std::to_wstring(Bookmarks::kMaxNoteChars) +
                         L" characters";
            }
            return false;
        }
        Bookmark b;
        // The JSON reader hands back UTF-8 bytes; Bookmark holds wide. The
        // conversion is the one place a wide/narrow mix-up could hide, so it
        // happens here and nowhere else.
        b.address = Utf8ToWide(r.address.c_str());
        b.port = static_cast<UINT>(r.port);
        b.tag = static_cast<unsigned>(r.tag);
        b.note = Utf8ToWide(r.note.c_str());
        b.when = (r.hasWhen && r.when > 0)
                     ? static_cast<std::uint64_t>(r.when)
                     : 0;
        // The address must be one the rest of the tool agrees on. Importing a
        // bookmark whose key differs from the key the GUI would compute is
        // importing a bookmark that can never be found again.
        const std::wstring wide = Utf8ToWide(r.address.c_str());
        const std::wstring normalised = NormalizeAddress(wide);
        if (normalised.empty() || normalised != wide) {
            if (error != nullptr) {
                *error = L"bookmark record " + std::to_wstring(i + 1) +
                         L" has an address that does not normalise (" +
                         wide + L")";
            }
            return false;
        }
        parsed.push_back(b);
    }

    *out = std::move(parsed);
    return true;
}

}  // namespace wintcp

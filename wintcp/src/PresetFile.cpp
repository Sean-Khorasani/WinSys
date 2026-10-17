// PresetFile.cpp
// SPDX-License-Identifier: Apache-2.0
// See PresetFile.h.

#include "PresetFile.h"

#include <cstring>

#include "Columns.h"   // COL_COUNT
#include "Opt.h"       // JsonEscapeOpt
#include "Presets.h"   // IsValidName, kMaxPresetNameChars
#include "Utils.h"

namespace wintcp {
namespace {

// A deliberately small, strict reader. See the header for why this is not a
// general JSON parser: a preset that loads half is a view the user never
// saved, and it is believed.
//
// Rather than a second hand-rolled parser, this recognises the one shape the
// preset file uses and refuses everything else. The file is flat by design:
// an array of objects whose values are strings and small integers, so the
// reader is small and the refusals are easy to state exactly.
struct Cursor {
    const char* base = nullptr;
    const char* p = nullptr;
    const char* end = nullptr;
    std::wstring error;
};

void FailAt(Cursor* c, const std::string& why) {
    if (c->error.empty()) {
        const size_t at =
            (c->p != nullptr && c->base != nullptr && c->p >= c->base)
                ? static_cast<size_t>(c->p - c->base)
                : 0;
        c->error = std::wstring(L"preset file: ") +
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
    if (c->p < c->end && (*c->p == '.' || *c->p == 'e' || *c->p == 'E')) {
        FailAt(c, "a fractional or exponent number is not valid here");
        return false;
    }
    const std::string text(start, static_cast<size_t>(c->p - start));
    *out = std::strtoll(text.c_str(), nullptr, 10);
    return true;
}

bool ParseBool(Cursor* c, bool* out) {
    if (c->end - c->p >= 4 && std::memcmp(c->p, "true", 4) == 0) {
        c->p += 4;
        *out = true;
        return true;
    }
    if (c->end - c->p >= 5 && std::memcmp(c->p, "false", 5) == 0) {
        c->p += 5;
        *out = false;
        return true;
    }
    FailAt(c, "expected true or false");
    return false;
}

// Skip a value the schema does not use. It must still be valid JSON, so an
// unknown extra key is accepted while a stray brace is not.
bool SkipValue(Cursor* c, int depth);

bool SkipString(Cursor* c) {
    std::string ignored;
    return ParseString(c, &ignored);
}

bool SkipValue(Cursor* c, int depth) {
    constexpr int kMaxDepth = 16;
    if (depth > kMaxDepth) {
        FailAt(c, "nested too deeply to be a preset file");
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
        case 't': {
            bool ignored = false;
            return ParseBool(c, &ignored);
        }
        case 'f': {
            bool ignored = false;
            return ParseBool(c, &ignored);
        }
        default: {
            long long ignored = 0;
            return ParseNumber(c, &ignored);
        }
    }
}

struct RawRecord {
    std::string name;
    bool hasName = false;
    std::string filter;
    bool hasFilter = false;
    ViewState view;
};

// Read one record. Every field is required; the version and array are the only
// optional ones and are handled by the caller.
bool ReadRecord(Cursor* c, RawRecord* rec) {
    if (c->p >= c->end || *c->p != '{') {
        FailAt(c, "a preset record must be a JSON object");
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
        // ViewState's axes, in the order ViewState.h declares them.
        if (key == "name") {
            if (!ParseString(c, &rec->name)) return false;
            rec->hasName = true;
        } else if (key == "filter") {
            if (!ParseString(c, &rec->filter)) return false;
            rec->hasFilter = true;
        } else if (key == "protoMask" || key == "stateFilter" ||
                   key == "sortColumn" || key == "colVisible" ||
                   key == "sources") {
            long long value = 0;
            if (!ParseNumber(c, &value)) return false;
            if (key == "protoMask") {
                rec->view.protoMask = static_cast<unsigned>(value);
            } else if (key == "stateFilter") {
                rec->view.stateFilter = static_cast<DWORD>(value);
            } else if (key == "sortColumn") {
                rec->view.sortColumn = static_cast<int>(value);
            } else if (key == "colVisible") {
                rec->view.colVisible = static_cast<UINT32>(value);
            } else {
                rec->view.sources = static_cast<unsigned>(value);
            }
        } else if (key == "sortAsc" || key == "grouped" || key == "frozen" ||
                   key == "preserveSelection") {
            bool value = false;
            if (!ParseBool(c, &value)) return false;
            if (key == "sortAsc") {
                rec->view.sortAsc = value;
            } else if (key == "grouped") {
                rec->view.grouped = value;
            } else if (key == "frozen") {
                rec->view.frozen = value;
            } else {
                rec->view.preserveSelection = value;
            }
        } else if (key == "frozenAtMs") {
            long long value = 0;
            if (!ParseNumber(c, &value)) return false;
            rec->view.frozenAtMs = static_cast<ULONGLONG>(value);
        } else {
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

void SerialisePresets(const std::vector<PresetRecord>& items,
                      std::string* out) {
    if (out == nullptr) return;
    out->clear();
    out->reserve(64 + items.size() * 128);
    const std::string nl = "\r\n";
    const std::string q = "\"";
    out->append("{" + nl);
    out->append("  " + q + "schema" + q + ": " + q + "wintcp-presets" + q +
                "," + nl);
    out->append("  " + q + "version" + q + ": " +
                std::to_string(kPresetFileVersion) + "," + nl);
    out->append("  " + q + "count" + q + ": " + std::to_string(items.size()) +
                "," + nl);
    out->append("  " + q + "presets" + q + ": [");
    for (size_t i = 0; i < items.size(); ++i) {
        const PresetRecord& r = items[i];
        const ViewState& v = r.view;
        if (i != 0) out->append(",");
        out->append(nl + "    {");
        // name and filter are already wide, so the escaper takes them as they
        // are - no UTF-8 round trip to get wrong.
        out->append(q + "name" + q + ":" + q + JsonEscapeOpt(r.name) + q + ",");
        out->append(q + "filter" + q + ":" + q + JsonEscapeOpt(v.filter) + q +
                    ",");
        out->append(q + "protoMask" + q + ":" +
                    std::to_string(v.protoMask) + ",");
        out->append(q + "stateFilter" + q + ":" +
                    std::to_string(v.stateFilter) + ",");
        out->append(q + "sortColumn" + q + ":" +
                    std::to_string(v.sortColumn) + ",");
        out->append(q + "sortAsc" + q + ":" +
                    std::string(v.sortAsc ? "true" : "false") + ",");
        out->append(q + "grouped" + q + ":" +
                    std::string(v.grouped ? "true" : "false") + ",");
        out->append(q + "frozen" + q + ":" +
                    std::string(v.frozen ? "true" : "false") + ",");
        out->append(q + "frozenAtMs" + q + ":" +
                    std::to_string(v.frozenAtMs) + ",");
        out->append(q + "preserveSelection" + q + ":" +
                    std::string(v.preserveSelection ? "true" : "false") + ",");
        out->append(q + "colVisible" + q + ":" +
                    std::to_string(v.colVisible) + ",");
        out->append(q + "sources" + q + ":" + std::to_string(v.sources));
        out->append("}");
    }
    if (!items.empty()) out->append(nl + "  ");
    out->append("]" + nl + "}" + nl);
}

bool ParsePresets(const std::string& text, std::vector<PresetRecord>* out,
                  std::wstring* error) {
    if (out == nullptr) {
        if (error != nullptr) {
            *error = L"internal error: no output for ParsePresets";
        }
        return false;
    }
    out->clear();
    if (error != nullptr) error->clear();

    if (text.size() > kPresetFileMaxBytes) {
        if (error != nullptr) {
            *error = L"preset file is " + std::to_wstring(text.size()) +
                     L" bytes, over the " +
                     std::to_wstring(kPresetFileMaxBytes) +
                     L"-byte limit; refusing to load it.";
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
    std::vector<RawRecord> records;
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
            } else if (key == "presets") {
                haveArray = true;
                if (c.p >= c.end || *c.p != '[') {
                    FailAt(&c, "the presets field must be an array");
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
                        RawRecord rec;
                        if (!ReadRecord(&c, &rec)) {
                            if (error != nullptr) *error = c.error;
                            return false;
                        }
                        records.push_back(rec);
                        if (records.size() > kPresetFileMaxRecords) {
                            if (error != nullptr) {
                                *error = L"preset file holds more than " +
                                         std::to_wstring(kPresetFileMaxRecords) +
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

    if (!haveVersion) {
        if (error != nullptr) *error = L"preset file has no \"version\" field";
        return false;
    }
    if (version != kPresetFileVersion) {
        if (error != nullptr) {
            *error = L"preset file is schema version " +
                     std::to_wstring(version) + L", this build reads " +
                     std::to_wstring(kPresetFileVersion);
        }
        return false;
    }
    if (!haveArray) {
        if (error != nullptr) *error = L"preset file has no \"presets\" array";
        return false;
    }

    std::vector<PresetRecord> parsed;
    parsed.reserve(records.size());
    for (size_t i = 0; i < records.size(); ++i) {
        const RawRecord& r = records[i];
        if (!r.hasName || !r.hasFilter) {
            if (error != nullptr) {
                *error = L"preset record " + std::to_wstring(i + 1) +
                         L" is missing a required field (name, filter); the "
                         L"whole file is refused rather than loaded in part";
            }
            return false;
        }
        // The name must be one the storage layer would accept, decided by
        // Presets::IsValidName rather than a second spelling of the rule here.
        const std::wstring wideName = Utf8ToWide(r.name.c_str());
        if (!Presets::IsValidName(wideName)) {
            if (error != nullptr) {
                *error = L"preset record " + std::to_wstring(i + 1) +
                         L" has a name that is not usable (" + wideName + L")";
            }
            return false;
        }
        if (r.filter.size() > kMaxPresetFilterChars) {
            if (error != nullptr) {
                *error = L"preset record " + std::to_wstring(i + 1) +
                         L" has a filter over " +
                         std::to_wstring(kMaxPresetFilterChars) +
                         L" characters";
            }
            return false;
        }
        // A column mask or sort column outside the table's range is a view the
        // renderer could not draw, so it is refused rather than clamped.
        if (r.view.sortColumn < 0 ||
            r.view.sortColumn >= static_cast<int>(COL_COUNT)) {
            if (error != nullptr) {
                *error = L"preset record " + std::to_wstring(i + 1) +
                         L" sorts on column " +
                         std::to_wstring(r.view.sortColumn) +
                         L", which is not a column";
            }
            return false;
        }
        PresetRecord rec;
        rec.name = wideName;
        rec.view = r.view;
        rec.view.filter = Utf8ToWide(r.filter.c_str());
        // A frozen view without its frozen-at time cannot be unfrozen
        // correctly, so it is refused rather than half-loaded.
        if (rec.view.frozen && rec.view.frozenAtMs == 0) {
            if (error != nullptr) {
                *error = L"preset record " + std::to_wstring(i + 1) +
                         L" is frozen with no frozen-at time";
            }
            return false;
        }
        parsed.push_back(std::move(rec));
    }

    *out = std::move(parsed);
    return true;
}

}  // namespace wintcp

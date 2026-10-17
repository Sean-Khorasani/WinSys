// IniFile.cpp
// SPDX-License-Identifier: Apache-2.0
// See IniFile.h.

#include "IniFile.h"

#include <cctype>
#include <cstdlib>

namespace wintcp {
namespace {

constexpr size_t kMaxIniBytes = 64u * 1024u;   // the file is hand-written
constexpr size_t kMaxIniValues = 256u;
constexpr size_t kMaxValueChars = 256u;

void Trim(std::string* s) {
    const char* ws = " \t\r\n";
    const size_t first = s->find_first_not_of(ws);
    if (first == std::string::npos) {
        s->clear();
        return;
    }
    const size_t last = s->find_last_not_of(ws);
    *s = s->substr(first, last - first + 1);
}

}  // namespace

bool IsKnownIniKey(const std::string& key) {
    return key == "interval" || key == "autoRefresh" ||
           key == "resolveHosts" || key == "topMost" ||
           key == "trayEnabled" || key == "trafficEnabled";
}

std::vector<IniValue> ParseIniSection(const std::string& text,
                                     const std::string& section,
                                     std::string* error) {
    std::vector<IniValue> out;
    if (error != nullptr) error->clear();

    if (text.size() > kMaxIniBytes) {
        if (error != nullptr) {
            *error = "wintcp.ini is " + std::to_string(text.size()) +
                     " bytes, over the " + std::to_string(kMaxIniBytes) +
                     "-byte limit; this file is meant to be hand-written, so "
                     "it is refused whole rather than read in part";
        }
        return out;
    }

    bool inSection = false;
    size_t lineNo = 0;
    size_t pos = 0;
    const size_t n = text.size();
    while (pos <= n) {
        ++lineNo;
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = n;
        std::string line = text.substr(pos, eol - pos);
        pos = eol + 1;

        // Strip a trailing CR so a CRLF file parses, and a trailing comment.
        // A '#' or ';' only starts a comment at the start of a token or after
        // whitespace, so a value containing one survives.
        const size_t comment = line.find_first_of(";#");
        if (comment != std::string::npos &&
            (comment == 0 || line[comment - 1] == ' ' || line[comment - 1] == '\t')) {
            line = line.substr(0, comment);
        }
        Trim(&line);
        if (line.empty()) {
            if (pos > n) break;
            continue;
        }

        if (line.front() == '[') {
            if (line.back() != ']' || line.size() < 3) {
                if (error != nullptr) {
                    *error = "wintcp.ini line " + std::to_string(lineNo) +
                             ": a section header must be [name]";
                }
                out.clear();
                return out;
            }
            const std::string name = line.substr(1, line.size() - 2);
            // Section names are compared case-insensitively, the way every
            // ini reader on Windows does.
            std::string lowerName = name;
            for (char& c : lowerName) c = static_cast<char>(::tolower(c));
            std::string want = section;
            for (char& c : want) c = static_cast<char>(::tolower(c));
            inSection = (lowerName == want);
            if (!inSection) {
                // A different tool's section is skipped, not an error.
                if (pos > n) break;
                continue;
            }
            if (pos > n) break;
            continue;
        }

        if (!inSection) {
            if (pos > n) break;
            continue;
        }

        const size_t eq = line.find('=');
        if (eq == std::string::npos) {
            if (error != nullptr) {
                *error = "wintcp.ini line " + std::to_string(lineNo) +
                         ": expected key = value, got \"" + line + "\"";
            }
            out.clear();
            return out;
        }
        IniValue kv;
        kv.key = line.substr(0, eq);
        kv.value = line.substr(eq + 1);
        Trim(&kv.key);
        Trim(&kv.value);
        if (kv.key.empty()) {
            if (error != nullptr) {
                *error = "wintcp.ini line " + std::to_string(lineNo) +
                         ": a line with no key before '='";
            }
            out.clear();
            return out;
        }
        if (kv.value.size() > kMaxValueChars) {
            if (error != nullptr) {
                *error = "wintcp.ini line " + std::to_string(lineNo) +
                         ": value over " + std::to_string(kMaxValueChars) +
                         " characters";
            }
            out.clear();
            return out;
        }
        // A repeated key: the LAST one wins, which is what every ini reader
        // does and what a user editing by hand expects.
        bool replaced = false;
        for (IniValue& existing : out) {
            if (existing.key == kv.key) {
                existing.value = kv.value;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            out.push_back(kv);
            if (out.size() > kMaxIniValues) {
                if (error != nullptr) {
                    *error = "wintcp.ini holds over " +
                             std::to_string(kMaxIniValues) +
                             " values; this file is meant to be hand-written";
                }
                out.clear();
                return out;
            }
        }
        if (pos > n) break;
    }
    return out;
}

}  // namespace wintcp

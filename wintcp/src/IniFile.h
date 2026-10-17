// IniFile.h
// SPDX-License-Identifier: Apache-2.0
// the portable `wintcp.ini` beside the executable.
//
// WHAT THIS IS FOR. Settings live in HKCU, which is per user and per machine -
// so a copy of wintcp.exe on a USB stick carries no preferences with it. A
// `wintcp.ini` placed beside the exe is how the preferences travel.
//
// THE DESIGN DECISION, and it is the one that keeps this from being a trap.
// The ini supplies DEFAULTS only: it is applied BEFORE the registry is read,
// so an existing user's saved settings always win. The alternative - the ini
// overriding the registry - means a user who changes a setting in the GUI sees
// it silently revert on the next launch, which is the sort of bug that gets
// reported as "the app forgets my settings". With this ordering the ini is
// exactly "what to use on a machine I have never run this on", and a fresh
// install on a new machine picks it up while an existing install does not.
//
// A second decision: only the BEHAVIOUR preferences are in scope, not the
// whole Settings struct. Window placement, column widths and the column
// order are per-monitor, per-machine facts whose values mean nothing
// elsewhere - a window rectangle from a 4K display is wrong on a 1366x768
// laptop, and a column mask persisted with a different column count is a
// migration problem. Interval, auto-refresh, hostname resolution, always-on-
// top, tray and traffic-on are the ones that genuinely describe how someone
// wants the tool to behave.
//
// A STRICT reader, for the same reason as the bookmark and preset files: an
// ini that is accepted half is a preference that is half set. Pure over a
// string, so it is pinned by tests with no disk and no registry.

#pragma once

#include <string>
#include <vector>

namespace wintcp {

// One parsed key. Values are kept as text: whether "1" is a boolean or "5000"
// is a millisecond is the caller's business, decided by the key's name, so a
// second meaning cannot be invented here.
struct IniValue {
    std::string key;
    std::string value;
};

// The keys, in file order, from the [wintcp] section. An unrecognised section
// is SKIPPED rather than refused - a file that also carries another tool's
// section is a file that has been handed to the wrong place, and refusing the
// whole thing is not the reader's call. Unrecognised KEYS inside [wintcp] are
// likewise kept, so a future key does not make an older reader refuse.
std::vector<IniValue> ParseIniSection(const std::string& text,
                                      const std::string& section,
                                      std::string* error);

// The behaviour keys this build understands, so a caller can distinguish
// "not in the file" from "in the file with a value this build does not know".
// Kept beside the parser so the two are read together.
bool IsKnownIniKey(const std::string& key);

}  // namespace wintcp

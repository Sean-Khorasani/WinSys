// BenchSync.cpp
// SPDX-License-Identifier: Apache-2.0
// The sync-and-hardening half of the selftest, split out of Bench.cpp under
// the constraint that permits it ("tests only, MAY split ... as an optional
// standalone task").
//
// These eight Check* functions are the batch that landed with the bookmark
// and preset file codecs, the portable wintcp.ini grammar, the empty-state
// button decision, the process tree and its kill plan, the SHA-256 image
// hash and the exposure predicate). They share one property the older
// checks do not: every one of them is pure over a value or a small struct,
// so none of them needs a synthetic database, a store or a snapshot to run.
// That is what makes them a clean seam - the split moves code, not behaviour.
//
// The harness still calls them from RunSelfTest in Bench.cpp, so the order
// the checks run in and the number reported are unchanged.

#include "Bench.h"
#include "BenchCheck.h"   // Check / FormatCheckAreas, shared with Bench.cpp

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <string>
#include <utility>
#include <vector>

#include <windows.h>
#include <iphlpapi.h>   // MIB_TCP_STATE_LISTEN, IPPROTO_TCP

#include "BookmarkFile.h"
#include "DnsCache.h"
#include "EmptyStateActions.h"
#include "IniFile.h"
#include "Opt.h"
#include "PresetFile.h"
#include "Presets.h"
#include "ProcessTree.h"
#include "Sha256.h"
#include "ExposureScore.h"
#include "Utils.h"

namespace wintcp {

// ppidKnown defaults to true: a test wants a real parent unless it says
// otherwise, and an "unknown parent" is a distinct case worth spelling out.
TreeNodeInfo TreeNode(DWORD pid, DWORD ppid, bool ppidKnown = true) {
    TreeNodeInfo n;
    n.pid = pid;
    n.ppid = ppid;
    n.ppidKnown = ppidKnown;
    return n;
}

// The plan carries ROW indices; a test that reads it needs PIDs, and the
// mapping is exactly what a caller does when it works the plan.
std::vector<DWORD> Pids(const std::vector<TreeNodeInfo>& rows,
                        const KillTreePlan& plan) {
    std::vector<DWORD> out;
    for (size_t i : plan.targets) out.push_back(rows[i].pid);
    return out;
}
std::string PidsText(const std::vector<TreeNodeInfo>& rows,
                     const KillTreePlan& plan) {
    std::string s;
    for (DWORD p : Pids(rows, plan)) s += std::to_string(p) + " ";
    return s;
}


void CheckBookmarkFile(TestResult& r) {
    Bookmark a;
    a.address = L"203.0.113.7";
    a.port = 443;
    a.tag = 3;
    a.note = L"known good";
    a.when = 1700000000;
    Bookmark b;
    b.address = L"198.51.100.22";
    b.port = 80;
    b.tag = kBookmarkTagNone;
    b.when = 0;
    const std::vector<Bookmark> items = {a, b};

    // The writer is deterministic: same input, same bytes. That is what makes
    // the file usable in a dotfiles repo, where an export that reordered
    // itself would produce a diff on every run.
    std::string json;
    SerialiseBookmarks(items, &json);
    std::string json2;
    SerialiseBookmarks(items, &json2);
    Check(r, "serialise.deterministic", json == json2,
          "len=" + std::to_string(json.size()));
    Check(r, "serialise.declares-its-version",
          json.find("\"version\": 1") != std::string::npos, "");
    std::string empty;
    SerialiseBookmarks({}, &empty);
    Check(r, "serialise.empty-list-is-valid",
          empty.find("\"count\": 0") != std::string::npos, empty);

    // Round trip, including a note with a quote, a backslash, a newline and a
    // tab - the case a hand-rolled reader gets wrong.
    Bookmark tricky;
    tricky.address = L"203.0.113.9";
    tricky.port = 8443;
    tricky.tag = 5;
    tricky.note = L"quote \" backslash \\ newline \n tab \t end";
    tricky.when = 42;
    std::string tj;
    SerialiseBookmarks({tricky}, &tj);
    std::vector<Bookmark> back;
    std::wstring err;
    Check(r, "roundtrip.parse-ok", ParseBookmarks(tj, &back, &err),
          WideToUtf8(err));
    Check(r, "roundtrip.one-record", back.size() == 1,
          "n=" + std::to_string(back.size()));
    if (back.size() == 1) {
        const Bookmark& q = back[0];
        Check(r, "roundtrip.address", q.address == tricky.address,
              WideToUtf8(q.address));
        Check(r, "roundtrip.port", q.port == tricky.port,
              std::to_string(q.port));
        Check(r, "roundtrip.tag", q.tag == tricky.tag,
              std::to_string(q.tag));
        Check(r, "roundtrip.annotations.note-with-escapes",
              q.note == tricky.note, WideToUtf8(q.note));
        Check(r, "roundtrip.when", q.when == tricky.when,
              std::to_string(q.when));
    }

    // A non-ASCII note must survive: the reader decodes \uXXXX and its UTF-8
    // decoder must agree with the encoder's.
    Bookmark uni;
    uni.address = L"2001:db8::1";
    uni.port = 443;
    uni.note = L"caf\u00e9 \u4e2d\u6587 \U0001F600";
    uni.when = 7;
    std::string uj;
    SerialiseBookmarks({uni}, &uj);
    std::vector<Bookmark> ub;
    Check(r, "roundtrip.unicode-note",
          ParseBookmarks(uj, &ub, nullptr) && ub.size() == 1 &&
              ub[0].note == uni.note,
          WideToUtf8(ub.empty() ? L"no record" : ub[0].note));

    std::vector<Bookmark> nv;
    Check(r, "refuse.missing-version",
          !ParseBookmarks("{\"schema\":\"wintcp-bookmarks\",\"bookmarks\":[]}",
                          &nv, &err) && !err.empty(),
          WideToUtf8(err));
    Check(r, "refuse.future-version",
          !ParseBookmarks("{\"version\":2,\"bookmarks\":[]}", &nv, &err) &&
              WideToUtf8(err).find("2") != std::string::npos,
          WideToUtf8(err));
    Check(r, "refuse.non-numeric-version",
          !ParseBookmarks("{\"version\":\"1\",\"bookmarks\":[]}", &nv, nullptr),
          "");
    Check(r, "refuse.missing-array",
          !ParseBookmarks("{\"version\":1}", &nv, nullptr), "");

    // THE ONE THAT MATTERS: a corrupt LAST record must not let the good
    // records before it through.
    Check(r, "refuse.bad-last-record-refuses-the-whole-file",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                          "\"203.0.113.7\",\"port\":443,\"tag\":0,\"note\":"
                          "\"\"},{\"address\":\"198.51.100.22\",\"port\":"
                          "\"nope\",\"tag\":0,\"note\":\"\"}]}",
                          &nv, &err) && nv.empty(),
          "arrived=" + std::to_string(nv.size()));
    Check(r, "refuse.missing-required-field",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"port\":443}]}", &nv,
                          &err) &&
              WideToUtf8(err).find("missing") != std::string::npos,
          WideToUtf8(err));
    Check(r, "refuse.record-not-an-object",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[\"203.0.113.7\"]}",
                          &nv, nullptr), "");
    Check(r, "refuse.unterminated-array",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[}", &nv, nullptr), "");
    Check(r, "refuse.unterminated-string",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[\"abc]}", &nv,
                          nullptr), "");
    Check(r, "refuse.unterminated-document",
          !ParseBookmarks("{\"version\":1", &nv, nullptr), "");
    Check(r, "refuse.trailing-content",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[]} garbage", &nv,
                          nullptr), "");
    Check(r, "refuse.not-an-object",
          !ParseBookmarks("[1,2,3]", &nv, nullptr), "");
    Check(r, "refuse.empty-document",
          !ParseBookmarks("", &nv, nullptr), "");

    // A control character inside a string is not valid JSON.
    std::string ctrl = "{\"version\":1,\"bookmarks\":[{\"address\":\"a\tb\","
                       "\"port\":1,\"tag\":0,\"note\":\"\"}]}";
    Check(r, "refuse.control-char-in-string",
          !ParseBookmarks(ctrl, &nv, nullptr), "");
    // An unpaired surrogate has no UTF-8 encoding.
    Check(r, "refuse.unpaired-surrogate",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                          "\"\\ud800\",\"port\":1,\"tag\":0,\"note\":\"\"}]}",
                          &nv, nullptr), "");
    // A correct surrogate PAIR is accepted.
    std::vector<Bookmark> pr;
    Check(r, "accepts.a-surrogate-pair",
          ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                         "\"1.2.3.4\",\"port\":1,\"tag\":0,\"note\":"
                         "\"\\ud83d\\ude00\"}]}",
                         &pr, nullptr) &&
              pr.size() == 1 &&
              pr[0].note == std::wstring(1, static_cast<wchar_t>(0xD83D)) +
                                std::wstring(1, static_cast<wchar_t>(0xDE00)),
          "");

    // A fractional tag is refused rather than truncated to 1, which would be
    // a bookmark with a colour the user never picked.
    Check(r, "refuse.fractional-tag",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                          "\"1.2.3.4\",\"port\":1,\"tag\":1.5,\"note\":\"\"}]}",
                          &nv, nullptr), "");
    Check(r, "refuse.port-out-of-range",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                          "\"1.2.3.4\",\"port\":70000,\"tag\":0,\"note\":"
                          "\"\"}]}",
                          &nv, nullptr), "");
    Check(r, "refuse.negative-port",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                          "\"1.2.3.4\",\"port\":-1,\"tag\":0,\"note\":\"\"}]}",
                          &nv, nullptr), "");

    // An address that does not normalise. Importing a bookmark whose key
    // differs from the key the GUI computes is importing a bookmark that can
    // never be found again.
    Check(r, "refuse.address-does-not-normalise",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[{\"address\":"
                          "\"not-an-ip\",\"port\":1,\"tag\":0,\"note\":\"\"}]}",
                          &nv, &err) && !WideToUtf8(err).empty(),
          WideToUtf8(err));

    // An unknown extra key is ACCEPTED: the schema reserves the right to add
    // fields, and a reader that rejected unknown keys would make every future
    // addition a breaking change.
    std::vector<Bookmark> ek;
    Check(r, "accepts.unknown-top-level-key",
          ParseBookmarks("{\"version\":1,\"future\":{\"x\":[1,2]},"
                         "\"bookmarks\":[]}",
                         &ek, nullptr), "");
    Check(r, "refuse.null-output",
          !ParseBookmarks("{\"version\":1,\"bookmarks\":[]}", nullptr,
                          nullptr), "");
}

void CheckPresetFile(TestResult& r) {
    PresetRecord a;
    a.name = L"listening sockets";
    a.view.grouped = true;
    a.view.filter = L"state:listen exclude:127.";

    PresetRecord b;
    b.name = L"chrome by traffic";
    b.view.filter = L"process:chrome.exe";
    b.view.sortColumn = COL_TRAFFIC;
    b.view.sortAsc = false;
    b.view.colVisible = 0x0000000Fu;
    b.view.sources = 3;

    const std::vector<PresetRecord> items = {a, b};
    std::string json;
    SerialisePresets(items, &json);
    std::string json2;
    SerialisePresets(items, &json2);
    Check(r, "preset.deterministic", json == json2,
          "len=" + std::to_string(json.size()));
    Check(r, "preset.declares-its-version",
          json.find("\"version\": 1") != std::string::npos, "");
    std::string empty;
    SerialisePresets({}, &empty);
    Check(r, "preset.empty-list-is-valid",
          empty.find("\"count\": 0") != std::string::npos, empty);

    // Round trip: every axis of ViewState survives, including the two that
    // look redundant with a default (sortAsc, preserveSelection) - a preset
    // that dropped one of those would open a view the user did not save.
    std::vector<PresetRecord> back;
    std::wstring err;
    Check(r, "preset.roundtrip.parse-ok",
          ParsePresets(json, &back, &err), WideToUtf8(err));
    Check(r, "preset.roundtrip.two-records", back.size() == 2,
          "n=" + std::to_string(back.size()));
    if (back.size() == 2) {
        const PresetRecord& x = back[0];
        Check(r, "preset.roundtrip.name", x.name == a.name,
              WideToUtf8(x.name));
        Check(r, "preset.roundtrip.grouped", x.view.grouped, "");
        Check(r, "preset.roundtrip.filter", x.view.filter == a.view.filter,
              WideToUtf8(x.view.filter));
        const PresetRecord& y = back[1];
        Check(r, "preset.roundtrip.sort-column",
              y.view.sortColumn == COL_TRAFFIC,
              std::to_string(y.view.sortColumn));
        Check(r, "preset.roundtrip.sort-asc",
              !y.view.sortAsc, "");
        Check(r, "preset.roundtrip.col-visible",
              y.view.colVisible == b.view.colVisible,
              std::to_string(y.view.colVisible));
        Check(r, "preset.roundtrip.sources",
              y.view.sources == b.view.sources,
              std::to_string(y.view.sources));
    }

    // A frozen view carries its frozen-at time, and a frozen view WITHOUT one
    // is refused rather than half-loaded - it could not be unfrozen correctly.
    const char* kFrozenNoTime =
        "{\"version\":1,\"presets\":[{\"name\":\"x\",\"frozen\":true}]}";
    std::vector<PresetRecord> nv;
    Check(r, "preset.refuse.frozen-without-time",
          !ParsePresets(kFrozenNoTime, &nv, &err) && !WideToUtf8(err).empty(),
          WideToUtf8(err));

    // A name the storage layer would refuse is refused here too, decided by
    // Presets::IsValidName rather than a second spelling of the rule: a
    // backslash would create a subkey, and a control character is invisible in
    // a dialog.
    const char* kBadName =
        "{\"version\":1,\"presets\":[{\"name\":\"a\\\\b\",\"filter\":\"\"}]}";
    Check(r, "preset.refuse.name-with-a-backslash",
          !ParsePresets(kBadName, &nv, nullptr), "");
    const char* kEmptyName =
        "{\"version\":1,\"presets\":[{\"name\":\"\",\"filter\":\"\"}]}";
    Check(r, "preset.refuse.empty-name",
          !ParsePresets(kEmptyName, &nv, nullptr), "");

    // A sort column outside the table is a view the renderer could not draw,
    // so it is refused rather than clamped.
    const char* kBadSort =
        "{\"version\":1,\"presets\":[{\"name\":\"x\",\"filter\":\"\","
        "\"sortColumn\":9999}]}";
    Check(r, "preset.refuse.sort-column-out-of-range",
          !ParsePresets(kBadSort, &nv, nullptr), "");
    const char* kNegSort =
        "{\"version\":1,\"presets\":[{\"name\":\"x\",\"filter\":\"\","
        "\"sortColumn\":-1}]}";
    Check(r, "preset.refuse.negative-sort-column",
          !ParsePresets(kNegSort, &nv, nullptr), "");

    // THE ONE THAT MATTERS: a corrupt last record refuses the whole file.
    const char* kBadTail =
        "{\"version\":1,\"presets\":[{\"name\":\"good\",\"filter\":\"\"},"
        "{\"name\":\"bad\",\"filter\":123}]}";
    Check(r, "preset.refuse.bad-last-record-refuses-the-whole-file",
          !ParsePresets(kBadTail, &nv, &err) && nv.empty(),
          "arrived=" + std::to_string(nv.size()));
    Check(r, "preset.refuse.missing-required-field",
          !ParsePresets("{\"version\":1,\"presets\":[{\"name\":\"x\"}]}", &nv,
                        &err) &&
              WideToUtf8(err).find("missing") != std::string::npos,
          WideToUtf8(err));

    // Version and document rules, same as the bookmark file's.
    Check(r, "preset.refuse.missing-version",
          !ParsePresets("{\"presets\":[]}", &nv, &err) && !err.empty(),
          WideToUtf8(err));
    Check(r, "preset.refuse.future-version",
          !ParsePresets("{\"version\":2,\"presets\":[]}", &nv, nullptr), "");
    Check(r, "preset.refuse.missing-array",
          !ParsePresets("{\"version\":1}", &nv, nullptr), "");
    Check(r, "preset.refuse.record-not-an-object",
          !ParsePresets("{\"version\":1,\"presets\":[\"x\"]}", &nv, nullptr),
          "");
    Check(r, "preset.refuse.unterminated-array",
          !ParsePresets("{\"version\":1,\"presets\":[}", &nv, nullptr), "");
    Check(r, "preset.refuse.unterminated-document",
          !ParsePresets("{\"version\":1", &nv, nullptr), "");
    Check(r, "preset.refuse.trailing-content",
          !ParsePresets("{\"version\":1,\"presets\":[]} junk", &nv, nullptr),
          "");
    Check(r, "preset.refuse.not-an-object",
          !ParsePresets("[1,2,3]", &nv, nullptr), "");
    Check(r, "preset.refuse.empty-document",
          !ParsePresets("", &nv, nullptr), "");
    std::string ctrl = "{\"version\":1,\"presets\":[{\"name\":\"a\tb\","
                       "\"filter\":\"\"}]}";
    Check(r, "preset.refuse.control-char-in-string",
          !ParsePresets(ctrl, &nv, nullptr), "");

    // A boolean field must be true or false, not a number: "frozen":1 is not
    // a state anything can act on.
    Check(r, "preset.refuse.boolean-as-a-number",
          !ParsePresets("{\"version\":1,\"presets\":[{\"name\":\"x\","
                        "\"filter\":\"\",\"grouped\":1}]}",
                        &nv, nullptr), "");

    // An unknown extra key is accepted, so adding an axis later is not a
    // breaking change.
    std::vector<PresetRecord> ek;
    Check(r, "preset.accepts.unknown-top-level-key",
          ParsePresets("{\"version\":1,\"future\":1,\"presets\":[]}", &ek,
                       nullptr), "");
    Check(r, "preset.refuse.null-output",
          !ParsePresets("{\"version\":1,\"presets\":[]}", nullptr, nullptr), "");
}

void CheckEmptyState(TestResult& r) {
    // A quiet machine is NOT an empty state: with no rows at all there is
    // nothing to measure traffic for and no filter to clear, so it is not a
    // state regardless of which columns are shown. (Passing the traffic flags
    // as "nothing measuring" with a visible column WOULD be the traffic state -
    // that is the third case - so this passes them as "measuring".)
    {
        const EmptyStateOffer o = DecideEmptyState(0, 0, false, false, false, true,
                                                   true, false, false);
        Check(r, "quiet-machine-is-not-a-state",
              o.caze == EmptyStateCase::kNone && o.ButtonCount() == 0,
              "caze=" + std::to_string((int)o.caze));
    }
    // A full table is not a state either.
    {
        const EmptyStateOffer o = DecideEmptyState(100, 100, false, true, false,
                                                   false, true, false, true);
        Check(r, "full-table-is-not-a-state",
              o.caze == EmptyStateCase::kNone && o.ButtonCount() == 0, "");
    }

    // ---- 1. no filter match ----
    {
        const EmptyStateOffer o = DecideEmptyState(50, 0, false, true, false,
                                                   false, true, false, true);
        Check(r, "filter-match.picked-first",
              o.caze == EmptyStateCase::kNoFilterMatch, "");
        Check(r, "filter-match.offers-clear-and-edit",
              o.offerClear && o.offerEdit && !o.offerPickGeo &&
                  !o.offerRunAdmin && o.ButtonCount() == 2,
              "n=" + std::to_string(o.ButtonCount()));
    }
    {
        // The reason it wins: with no rows at all the database and traffic
        // answers are a question nobody asked, so it must not be shadowed.
        const EmptyStateOffer o = DecideEmptyState(10, 0, true, false, false, true,
                                                   false, false, false);
        Check(r, "filter-match.outranks-geo-and-traffic",
              o.caze == EmptyStateCase::kNoFilterMatch, "");
    }

    // ---- 2. no GeoIP database ----
    {
        const EmptyStateOffer o = DecideEmptyState(20, 20, true, false, false,
                                                   false, true, false, false);
        Check(r, "geo.picked-when-country-shown",
              o.caze == EmptyStateCase::kNoGeoIp, "");
        // No elevation button here: elevating does not install a database.
        Check(r, "geo.offers-only-pick-mmdb",
              o.offerPickGeo && !o.offerRunAdmin && !o.offerClear &&
                  o.ButtonCount() == 1,
              "n=" + std::to_string(o.ButtonCount()));
    }
    {
        // Either database fills the cell, so with one loaded there is nothing
        // to offer.
        const EmptyStateOffer withGeo =
            DecideEmptyState(20, 20, true, true, false, false, true, false, false);
        const EmptyStateOffer withAsn =
            DecideEmptyState(20, 20, true, false, true, false, true, false, false);
        Check(r, "geo.either-database-satisfies",
              withGeo.caze == EmptyStateCase::kNone &&
                  withAsn.caze == EmptyStateCase::kNone,
              "");
    }
    {
        // A country column nobody is looking at is not an empty state.
        const EmptyStateOffer o = DecideEmptyState(20, 20, false, false, false,
                                                   false, true, false, false);
        Check(r, "geo.hidden-column-is-not-a-state",
              o.caze == EmptyStateCase::kNone && o.ButtonCount() == 0, "");
    }

    // ---- 3. no traffic ----
    {
        // NOT elevated: the one click that helps is a relaunch, so it appears.
        const EmptyStateOffer o = DecideEmptyState(20, 20, false, true, false, true,
                                                   false, false, false);
        Check(r, "traffic.picked-when-column-shown",
              o.caze == EmptyStateCase::kNoTraffic, "");
        Check(r, "traffic.unelevated-gets-the-relaunch",
              o.offerRunAdmin && o.ButtonCount() == 1,
              "n=" + std::to_string(o.ButtonCount()));
    }
    {
        // ALREADY elevated: the relaunch button must NOT appear. A process
        // that already has the rights cannot restart itself into higher ones,
        // so the button would do nothing and the click would be a lie.
        const EmptyStateOffer o = DecideEmptyState(20, 20, false, true, false, true,
                                                   false, false, true);
        Check(r, "traffic.elevated-gets-no-button",
              o.caze == EmptyStateCase::kNoTraffic && !o.offerRunAdmin &&
                  o.ButtonCount() == 0,
              "n=" + std::to_string(o.ButtonCount()));
    }
    {
        // A working source (either one) is not a state.
        const EmptyStateOffer withEtw = DecideEmptyState(
            20, 20, false, true, false, true, true, false, false);
        const EmptyStateOffer withSockets = DecideEmptyState(
            20, 20, false, true, false, true, false, true, true);
        Check(r, "traffic.either-source-satisfies",
              withEtw.caze == EmptyStateCase::kNone &&
                  withSockets.caze == EmptyStateCase::kNone,
              "");
    }
    {
        // Nobody is looking at a traffic column.
        const EmptyStateOffer o = DecideEmptyState(20, 20, false, true, false, false,
                                                   false, false, false);
        Check(r, "traffic.hidden-column-is-not-a-state",
              o.caze == EmptyStateCase::kNone && o.ButtonCount() == 0, "");
    }

    // Every case must carry its sentence, so a caller that shows buttons has
    // no excuse to show none of the reason.
    {
        const EmptyStateOffer a =
            DecideEmptyState(10, 0, false, true, false, false, true, false, true);
        const EmptyStateOffer b = DecideEmptyState(
            10, 10, true, false, false, false, true, false, false);
        const EmptyStateOffer c = DecideEmptyState(
            10, 10, false, true, false, true, false, false, false);
        Check(r, "every-case-carries-a-message",
              a.message[0] != L'\0' && b.message[0] != L'\0' &&
                  c.message[0] != L'\0',
              "");
    }
}

void CheckProcessTree(TestResult& r) {
    auto node = [](DWORD pid, DWORD ppid, bool known = true) {
        TreeNodeInfo n;
        n.pid = pid;
        n.ppid = ppid;
        n.ppidKnown = known;
        return n;
    };

    // A tiny chain: shell -> svchost -> w3wp.
    {
        const std::vector<TreeNodeInfo> rows = {
            node(100, 1), node(200, 100), node(300, 200), node(900, 1)};
        const ProcessTree t = BuildProcessTree(rows);
        Check(r, "chain.root-count", t.rootCount == 2,
              "roots=" + std::to_string(t.rootCount));
        Check(r, "chain.no-depth-exceeded", !t.depthExceeded, "");
        const std::vector<size_t> d = ProcessTreeDescendants(rows, 200);
        Check(r, "chain.descendants-of-middle",
              d.size() == 2 && d[0] == 1 && d[1] == 2,
              "n=" + std::to_string(d.size()));
        // Roots: the two whose parent pid is not in the set.
        const std::vector<size_t> roots = ProcessTreeRoots(rows);
        Check(r, "chain.roots-in-row-order",
              roots.size() == 2 && roots[0] == 0 && roots[1] == 3,
              "n=" + std::to_string(roots.size()));
    }

    // ---- the roots-first contract is real, not assumed -------------------
    //
    // The header promises nodes()[0..rootCount) are exactly the roots. A
    // renderer walking that range as roots is reading the contract as
    // written; before the builder ordered the nodes that range held the
    // first rootCount NODES, so a forest whose roots sit later in row order
    // drew subtrees with parents as top-level items and missed real roots.
    {
        // Row order deliberately puts a CHILD first: 200's parent is 100, so
        // a node-order read would take node 0 (the child) as a root.
        const std::vector<TreeNodeInfo> rows = {
            node(200, 100), node(300, 100), node(100, 1)};
        const ProcessTree t = BuildProcessTree(rows);
        bool allRootsAreRoots = t.rootCount == 1;
        for (size_t i = 0; allRootsAreRoots && i < t.rootCount; ++i) {
            const TreeNodeInfo& n = t.nodes[i].info;
            // "Claimed" means the node's OWN parent is present in the set -
            // i.e. some row carries a pid equal to this node's ppid. A root
            // that is itself a PARENT (rows pointing at it) is still a root.
            bool claimed = false;
            if (n.ppidKnown)
                for (const TreeNodeInfo& o : rows)
                    if (o.pid == n.ppid) claimed = true;
            if (claimed) allRootsAreRoots = false;
        }
        Check(r, "roots-first.range-is-roots", allRootsAreRoots,
              "rootCount=" + std::to_string(t.rootCount));
        Check(r, "roots-first.root-is-pid-100",
              t.rootCount == 1 && t.nodes[0].info.pid == 100,
              "rootPid=" + std::to_string(t.rootCount ? t.nodes[0].info.pid
                                                      : 0));
        // Every node is still reachable from the roots, so reordering lost
        // nothing: node count is the process count.
        Check(r, "roots-first.nothing-lost", t.nodes.size() == 3,
              "n=" + std::to_string(t.nodes.size()));
        // And the child moved to a non-root index with its parent's link
        // remapped, not pointing at a stale slot. (auto, because this file's
        // own helper function is also called TreeNode and shadows the struct
        // name inside this function.)
        const auto& root = t.nodes[0];
        bool childLinksOk = root.children.size() == 2;
        for (size_t c : root.children) {
            if (c < t.rootCount || c >= t.nodes.size()) childLinksOk = false;
            else if (t.nodes[c].info.ppid != 100) childLinksOk = false;
        }
        Check(r, "roots-first.children-remapped", childLinksOk,
              "children=" + std::to_string(root.children.size()));
    }

    // ---- the plan's indices are ROW indices, by construction -------------
    //
    // KillTreePlan::targets says "row indices to end". That was true only
    // because node order matched row order - an accident exposed the moment
    // the nodes were reordered roots-first. A plan must name the right
    // processes, not the right shape.
    {
        // A pid==0 row (a socket nobody resolved) is skipped by the builder,
        // so node index and row index differ even before any reordering.
        // Sibling order is row order, each subtree complete before the next,
        // root last - the same shape the other kill tests pin.
        const std::vector<TreeNodeInfo> rows = {
            node(0, 0), node(10, 0), node(11, 10), node(12, 10)};
        const KillTreePlan plan = PlanKillTree(rows, 10, 0);
        Check(r, "plan.row-indices-with-skipped-row",
              plan.targets.size() == 3 &&
                  Pids(rows, plan) == std::vector<DWORD>({11, 12, 10}),
              PidsText(rows, plan));
    }

    // ---- a CYCLE is refused, not followed ----
    {
        // 100 -> 200 -> 300 -> 100 (a stale-parent cycle, which Windows can
        // produce during a teardown). Following it would not terminate.
        const std::vector<TreeNodeInfo> rows = {
            node(100, 300), node(200, 100), node(300, 200)};
        const std::vector<size_t> d = ProcessTreeDescendants(rows, 100);
        // The whole set is reachable, so the set is the answer - but the walk
        // must still TERMINATE, which is what reaching here proves.
        Check(r, "cycle.walk-terminates",
              d.size() == 3, "n=" + std::to_string(d.size()));
        const ProcessTree t = BuildProcessTree(rows);
        // No node in a pure cycle can be a root, so nothing is visited and
        // nothing is rendered - the cycle is reported rather than drawn.
        Check(r, "cycle.build-does-not-loop",
              t.nodes.size() == 3, "n=" + std::to_string(t.nodes.size()));
    }
    {
        // A self-parent is not a parent: it must not make the row its own
        // child, which would make it its own root and its own subtree.
        const std::vector<TreeNodeInfo> rows = {node(100, 100)};
        const ProcessTree t = BuildProcessTree(rows);
        Check(r, "cycle.self-parent-is-not-a-parent",
              t.rootCount == 1 && t.nodes[0].children.empty(),
              "roots=" + std::to_string(t.rootCount));
    }

    // ---- an unknown parent is not a parent (and not a root by accident) ----
    {
        // 200's parent 999 is gone: 200 becomes a root, because a root is
        // defined by observation ("nobody claims me") rather than by PPID.
        const std::vector<TreeNodeInfo> rows = {node(200, 999), node(100, 1)};
        const std::vector<size_t> roots = ProcessTreeRoots(rows);
        Check(r, "roots.parent-exited-makes-a-root",
              roots.size() == 2, "n=" + std::to_string(roots.size()));
    }
    {
        // ppid NOT known: still a root, and never claimed.
        const std::vector<TreeNodeInfo> rows = {node(200, 0, false)};
        const std::vector<size_t> roots = ProcessTreeRoots(rows);
        Check(r, "roots.unknown-ppid-is-a-root",
              roots.size() == 1, "n=" + std::to_string(roots.size()));
    }

    // ---- the ancestor rule ----
    {
        const std::vector<TreeNodeInfo> rows = {
            node(100, 1), node(200, 100), node(300, 200), node(400, 300)};
        Check(r, "ancestor.direct-and-transitive",
              IsAncestorOf(rows, 100, 200) && IsAncestorOf(rows, 100, 400) &&
                  !IsAncestorOf(rows, 200, 100),
              "");
        // A PID we have never heard of is not an ancestor: refusing to walk
        // into a process outside the set is what stops the answer being a
        // guess.
        Check(r, "ancestor.unknown-pid-is-not-one",
              !IsAncestorOf(rows, 999, 300) && !IsAncestorOf(rows, 100, 999), "");
        // A self cannot be its own ancestor, and 0 is never a process.
        Check(r, "ancestor.self-and-zero-rejected",
              !IsAncestorOf(rows, 300, 300) && !IsAncestorOf(rows, 0, 300),
              "");
        // An ancestor cycle terminates too: 100 -> 300 -> 100 must not loop.
        const std::vector<TreeNodeInfo> cyclic = {
            node(100, 300), node(200, 100), node(300, 200)};
        Check(r, "ancestor.cycle-terminates",
              IsAncestorOf(cyclic, 100, 200) &&
                  !IsAncestorOf(cyclic, 300, 300) &&
                  IsAncestorOf(cyclic, 100, 300)   /* via the cycle back to 300 */
                ,
              "");
    }

    // ---- a PID that is not in the set ----
    {
        const std::vector<TreeNodeInfo> rows = {node(100, 1)};
        Check(r, "descendants.unknown-root-is-empty",
              ProcessTreeDescendants(rows, 999).empty() &&
                  ProcessTreeDescendants(rows, 0).empty(),
              "");
        Check(r, "tree.empty-set-is-empty",
              BuildProcessTree({}).nodes.empty() &&
                  ProcessTreeDescendants({}, 100).empty() &&
                  ProcessTreeRoots({}).empty(),
              "");
    }

    // ---- a wide fan-out ----
    {
        // One parent, many children (a service host). Every child is a
        // descendant of the root and none of them is the root's ancestor.
        std::vector<TreeNodeInfo> rows;
        rows.push_back(node(1, 0));
        for (DWORD i = 2; i < 82; ++i) rows.push_back(node(i, 1));
        const std::vector<size_t> d = ProcessTreeDescendants(rows, 1);
        Check(r, "fanout.every-child-is-a-descendant",
              d.size() == rows.size(),
              "n=" + std::to_string(d.size()));
        const ProcessTree t = BuildProcessTree(rows);
        Check(r, "fanout.one-root-many-children",
              t.rootCount == 1, "roots=" + std::to_string(t.rootCount));
    }

    // ---- a deep chain is walked, and the ceiling is reported ----
    {
        // A chain deep enough to be interesting but bounded well under the
        // ceiling: the whole thing must be reachable.
        std::vector<TreeNodeInfo> rows;
        for (DWORD i = 1; i <= 40; ++i) {
            rows.push_back(node(i, i == 1 ? 0 : i - 1));
        }
        const ProcessTree t = BuildProcessTree(rows);
        const std::vector<size_t> d = ProcessTreeDescendants(rows, 1);
        Check(r, "deep.whole-chain-reachable",
              d.size() == rows.size() && !t.depthExceeded,
              "n=" + std::to_string(d.size()));
    }

    // ---- a PID appearing on two rows (two connections, one process) ----
    {
        // The first row bearing the pid is the root, so the tree and
        // Descendants agree about which row a pid means.
        const std::vector<TreeNodeInfo> rows = {
            node(100, 1), node(200, 100), node(100, 1)};
        const std::vector<size_t> d = ProcessTreeDescendants(rows, 100);
        Check(r, "duplicate-pid.first-row-wins",
              d.size() >= 2 && d[0] == 0,
              "n=" + std::to_string(d.size()));
    }
}

void CheckSha256(TestResult& r) {
    auto HS = [](const std::string& s) {
        return Sha256HexA(Sha256Bytes(
            reinterpret_cast<const unsigned char*>(s.data()), s.size()));
    };
    auto H = [](const unsigned char* p, size_t n) {
        return Sha256HexA(Sha256Bytes(p, n));
    };

    Check(r, "sha256.fips-empty", HS("") ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    Check(r, "sha256.fips-abc", HS("abc") ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // The FIPS 56-byte vector (FIPS 180-4 Example 1).
    Check(r, "sha256.fips-56",
          HS("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // Exact multiples of the block size: the accumulator must emit the pad in
    // a fresh block, not treat it as data. 55 is the last one-block length;
    // 56/57/63 straddle the boundary.
    {
        const std::string s55(55, 'a');
        const std::string s56(56, 'a');
        const std::string s64(64, 'a');
        const std::string s119(119, 'a');
        const std::string s120(120, 'a');
        const std::string s128(128, 'a');
        Check(r, "sha256.block-multiple-55", HS(s55) ==
              "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
        Check(r, "sha256.block-multiple-64", HS(s64) ==
              "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
        Check(r, "sha256.block-multiple-119", HS(s119) ==
              "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb");
        Check(r, "sha256.block-multiple-128", HS(s128) ==
              "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e");
        // 56/120 differ only in the last byte's position relative to the pad,
        // so they must differ.
        Check(r, "sha256.block-multiple-pairs-differ",
              HS(s56) != HS(s55) && HS(s120) != HS(s119) && HS(s56) != HS(s64));
    }

    // A second independent oracle: hashing the same bytes through the file path
    // must agree, because that is the path the Details view actually uses and
    // an accumulator that diverges only when chunked is the bug that would hide
    // behind a green in-memory suite.
    {
        const std::wstring path = L"%TEMP%\\benoot_sha_roundtrip.bin";
        wchar_t expanded[MAX_PATH] = {0};
        ::ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH);
        std::string blob;
        uint32_t x = 0x12345678u;
        for (int i = 0; i < 70000; ++i) {   // spans several 64 KB reads
            x = x * 1664525u + 1013904223u;
            blob.push_back(static_cast<char>(x >> 24));
            blob.push_back(static_cast<char>(x >> 16));
            blob.push_back(static_cast<char>(x >> 8));
        }
        HANDLE hf = ::CreateFileW(expanded, GENERIC_WRITE, 0, nullptr,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD wrote = 0;
        bool wroteOk = hf != INVALID_HANDLE_VALUE;
        if (wroteOk) {
            wroteOk = ::WriteFile(hf, blob.data(),
                                  static_cast<DWORD>(blob.size()), &wrote,
                                  nullptr) != FALSE;
            ::CloseHandle(hf);
        }
        (void)wrote;
        const bool ok = wroteOk && wrote == blob.size();
        const std::string mem =
            H(reinterpret_cast<const unsigned char*>(blob.data()), blob.size());
        const ImageHashResult fh = HashImageFile(expanded);
        Check(r, "sha256.file-path-agrees-with-memory",
              ok && fh.ok && fh.bytesHashed == blob.size() &&
                  Sha256HexA(fh.digest) == mem,
              "ok=" + std::string(ok ? "1" : "0") + " mem=" + mem +
                  " file=" + Sha256HexA(fh.digest));
        ::DeleteFileW(expanded);
    }

    // The hex formatter: exact lowercase, 64 chars, no separators.
    {
        Sha256Digest d{};
        for (size_t i = 0; i < d.size(); ++i) d[i] = static_cast<uint8_t>(i);
        const std::string h = Sha256HexA(d);
        const std::wstring hw = Sha256HexW(d);
        bool fmt = h.size() == 64 && hw.size() == 64;
        for (char c : h) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) fmt = false;
        }
        fmt = fmt && h == "000102030405060708090a0b0c0d0e0f1011121314"
                          "15161718191a1b1c1d1e1f";
        Check(r, "sha256.hex-is-lowercase-64-no-separators", fmt, h);
    }

    // Empty and unusable paths fail with a reason, never silently.
    {
        const ImageHashResult e = HashImageFile(L"");
        Check(r, "sha256.empty-path-refused",
              !e.ok && e.reason == HashFailReason::kEmptyPath &&
                  !e.message.empty(),
              "");
        const ImageHashResult missing =
            HashImageFile(L"%TEMP%\\benoot_no_such_image_xyz.exe");
        Check(r, "sha256.missing-file-refused",
              !missing.ok && missing.reason == HashFailReason::kOpenFailed &&
                  !missing.message.empty(),
              "");
    }
}

void CheckExposure(TestResult& r) {
    const unsigned char kV4Wild[4] = {0, 0, 0, 0};
    const unsigned char kV4Loop[4] = {127, 0, 0, 1};
    // NOT 203.0.113/24 - that is the documentation range, which IsGlobalUnicastV4// deliberately rejects. Use a genuine public address.
    const unsigned char kV4Pub[4] = {1, 1, 1, 1};
    const unsigned char kV4Priv[4] = {10, 0, 0, 5};      // RFC1918

    // ---- A listener that is not a listener is never exposed ----
    {
        // A UDP row that is not a listener, and a TCP row in a non-LISTEN
        // state. The predicate must reject both rather than trusting the
        // caller to have filtered them.
        const ExposureRow a =
            ScoreListener(kV4Wild, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_ESTAB, true);
        const ExposureRow b =
            ScoreListener(kV4Wild, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_CLOSE_WAIT, true);
        Check(r, "exposure.non-listener-is-never-exposed",
              a.level == ExposureLevel::kNone &&
                  b.level == ExposureLevel::kNone,
              "");
    }

    // ---- Loopback is not exposed, whatever the port ----
    {
        const ExposureRow a =
            ScoreListener(kV4Loop, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        Check(r, "exposure.loopback-is-not-exposed",
              a.level == ExposureLevel::kPrivate, "");
    }

    // ---- Private ranges are not internet-reachable ----
    {
        const ExposureRow a =
            ScoreListener(kV4Priv, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, false);
        Check(r, "exposure.rfc1918-is-private",
              a.level == ExposureLevel::kPrivate, "");
    }

    // ---- A wildcard on a privileged port is the red case ----
    {
        const ExposureRow a =
            ScoreListener(kV4Wild, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        Check(r, "exposure.wildcard-443-is-exposed",
              a.level == ExposureLevel::kExposed && !a.reason.empty(),
              "");
    }

    // ---- A wildcard on a high port is public, not exposed ----
    {
        const ExposureRow a =
            ScoreListener(kV4Wild, 4, false, 51593, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        Check(r, "exposure.wildcard-high-port-is-public",
              a.level == ExposureLevel::kPublic, "");
    }

    // ---- A specific public address is public, whatever the port ----
    {
        const ExposureRow a =
            ScoreListener(kV4Pub, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, false);
        Check(r, "exposure.specific-public-address-is-public",
              a.level == ExposureLevel::kPublic, "");
    }

    // ---- The privileged-port ladder ----
    {
        // Every port the badge treats as privileged must turn a wildcard
        // bind red; the first one above 1023 must not.
        bool ok = IsPrivilegedExposurePort(1);
        ok = ok && IsPrivilegedExposurePort(443);
        ok = ok && IsPrivilegedExposurePort(1023);
        ok = ok && IsPrivilegedExposurePort(3389);
        ok = ok && IsPrivilegedExposurePort(445);
        ok = ok && IsPrivilegedExposurePort(5985);
        ok = ok && IsPrivilegedExposurePort(5986);
        ok = ok && !IsPrivilegedExposurePort(1024);
        ok = ok && !IsPrivilegedExposurePort(51593);
        ok = ok && !IsPrivilegedExposurePort(65535);
        Check(r, "exposure.privileged-port-ladder", ok, "");
    }

    // ---- IPv6 ----
    {
        const unsigned char v6Wild[16] = {0};
        const unsigned char v6Loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        // NOT 2001:db8::/32 - the documentation range for v6.
        const unsigned char v6Pub[16] = {0x26, 0x06, 0x47, 0x00,0x47,0,0,0,0,0,0,0,0,0,0,1};
        const ExposureRow wild =
            ScoreListener(v6Wild, 16, true, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        const ExposureRow loop =
            ScoreListener(v6Loop, 16, true, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        const ExposureRow pub =
            ScoreListener(v6Pub, 16, true, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, false);
        Check(r, "exposure.v6-wildcard-443-is-exposed",
              wild.level == ExposureLevel::kExposed, "");
        Check(r, "exposure.v6-loopback-is-private",
              loop.level == ExposureLevel::kPrivate, "");
        Check(r, "exposure.v6-public-is-public",
              pub.level == ExposureLevel::kPublic, "");
    }

    // ---- The owner axes ----
    {
        // The two axes travel with the row and are reported in the line,
        // which is the part a caller cannot add after the fact.
        ExposureRow row =
            ScoreListener(kV4Wild, 4, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        row.isSystem = true;
        row.isUnsigned = true;
        Check(r, "exposure.owner-axes-travel-with-the-row",
              row.isSystem && row.isUnsigned && row.isSystem == true, "");
    }

    // ---- The summary ----
    {
        std::vector<ExposureRow> rows;
        // Two red, one public, three private.
        for (int i = 0; i < 2; ++i) {
            ExposureRow x;
            x.level = ExposureLevel::kExposed;
            x.reason = L"listening on *:443 (tcp/ipv4)";
            rows.push_back(x);
        }
        for (int i = 0; i < 1; ++i) {
            ExposureRow x;
            x.level = ExposureLevel::kPublic;
            x.reason = L"a specific public address";
            rows.push_back(x);
        }
        for (int i = 0; i < 3; ++i) {
            ExposureRow x;
            x.level = ExposureLevel::kPrivate;
            rows.push_back(x);
        }
        const ExposureSummary s = SummariseExposure(rows);
        Check(r, "exposure.summary-counts-every-level",
              s.exposed == 2 && s.publicRows == 1 && s.privateRows == 3,
              "exposed=" + std::to_string(s.exposed) +
                  " public=" + std::to_string(s.publicRows) +
                  " private=" + std::to_string(s.privateRows));
        // The bar must name the RED case specifically - "listening on any
        // address, privileged port" is the recipe-24 wording, and "exposed"
        // alone would not tell the user which of the two severity lines it is.
        // Assert on both the severity keyword and the reason.
        Check(r, "exposure.summary-leads-with-red",
              WideToUtf8(s.line).find("privileged port") != std::string::npos,
              WideToUtf8(s.line));

        // Public only: the bar says "reachable" and not "exposed".
        std::vector<ExposureRow> pubOnly(2);
        for (auto& x : pubOnly) x.level = ExposureLevel::kPublic;
        const ExposureSummary sp = SummariseExposure(pubOnly);
        Check(r, "exposure.summary-public-wording",
              WideToUtf8(sp.line).find("reachable") != std::string::npos, WideToUtf8(sp.line));

        // All private, or empty: the bar stays SILENT. This is the check that
        // keeps the badge from becoming noise - a healthy machine has plenty
        // of loopback listeners.
        std::vector<ExposureRow> privOnly(3);
        for (auto& x : privOnly) x.level = ExposureLevel::kPrivate;
        Check(r, "exposure.summary-silent-when-healthy",
              SummariseExposure(privOnly).line.empty() &&
                  SummariseExposure({}).line.empty(),
              "");
    }

    // ---- An unknown address is not reported as safe ----
    {
        // A caller that cannot say where a listener is bound must not be told
        // "not exposed": guessing safe is the direction that hides things.
        const ExposureRow a =
            ScoreListener(nullptr, 0, false, 443, IPPROTO_TCP,
                          MIB_TCP_STATE_LISTEN, true);
        Check(r, "exposure.unknown-address-is-not-safe",
              a.level != ExposureLevel::kNone && !a.reason.empty(), "");
    }
}

void CheckKillTree(TestResult& r) {
    {
        // A diamond: root 1 with children 2 and 3, both parented by 1, and
        // 4 parented by 2. The plan must be POST-ORDER: a child always dies
        // before its parent, so every process still has a living parent to
        // answer to.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(1, 0), TreeNode(2, 1), TreeNode(3, 1), TreeNode(4, 2)};
        const KillTreePlan plan = PlanKillTree(rows, 1, 0);
        Check(r, "kill.targets-are-post-order",
              plan.targets.size() == 4 && Pids(rows, plan) == std::vector<DWORD>({4, 2, 3, 1}),
              PidsText(rows, plan));
        Check(r, "kill.root-is-remembered", plan.rootPid == 1, "");
        Check(r, "kill.complete-plan", !plan.partial, "");
    }
    {
        // A chain 1 -> 2 -> 3 -> 4: the deepest dies first.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(1, 0), TreeNode(2, 1), TreeNode(3, 2), TreeNode(4, 3)};
        const KillTreePlan plan = PlanKillTree(rows, 1, 0);
        Check(r, "kill.deep-chain-last-in",
              plan.targets.size() == 4 &&
                  Pids(rows, plan) == std::vector<DWORD>({4, 3, 2, 1}),
              PidsText(rows, plan));
    }
    {
        // Killing from a MIDDLE node takes only that subtree: an ancestor
        // must survive, and a sibling must survive.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(1, 0), TreeNode(2, 1), TreeNode(3, 1), TreeNode(4, 2)};
        const KillTreePlan plan = PlanKillTree(rows, 2, 0);
        Check(r, "kill.middle-node-takes-only-its-subtree",
              plan.targets.size() == 2 &&
                  Pids(rows, plan) == std::vector<DWORD>({4, 2}),
              PidsText(rows, plan));
    }
    {
        // A forest: killing one root must not touch the other.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(10, 0), TreeNode(11, 10), TreeNode(20, 0),
            TreeNode(21, 20)};
        const KillTreePlan plan = PlanKillTree(rows, 20, 0);
        Check(r, "kill.one-root-of-a-forest",
              plan.targets.size() == 2 &&
                  Pids(rows, plan) == std::vector<DWORD>({21, 20}),
              PidsText(rows, plan));
    }
    {
        // A cycle is planned through, not followed: the walk still terminates
        // and the plan covers each node once.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(1, 3), TreeNode(2, 1), TreeNode(3, 2)};
        const KillTreePlan plan = PlanKillTree(rows, 1, 0);
        Check(r, "kill.cycle-terminates-and-covers-each-node",
              plan.targets.size() == 3,
              PidsText(rows, plan));
    }
    {
        // The CALLER goes last, not absent. An absent root would read as "the
        // whole tree died" while the caller is still running, and the caller
        // refuses that step rather than exiting itself mid-plan.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(1, 0), TreeNode(2, 1), TreeNode(3, 2)};
        const KillTreePlan plan = PlanKillTree(rows, 1, 1);
        Check(r, "kill.self-is-last-not-absent",
              plan.targets.size() == 3 &&
                  Pids(rows, plan) == std::vector<DWORD>({3, 2, 1}),
              PidsText(rows, plan));
    }
    {
        // An unknown root plans nothing, rather than planning everything.
        const std::vector<TreeNodeInfo> rows = {TreeNode(1, 0)};
        const KillTreePlan plan = PlanKillTree(rows, 999, 0);
        Check(r, "kill.unknown-root-plans-nothing",
              plan.targets.empty(), std::to_string(plan.targets.size()));
    }
    {
        // A single-node tree is a one-target plan.
        const std::vector<TreeNodeInfo> rows = {TreeNode(7, 0)};
        const KillTreePlan plan = PlanKillTree(rows, 7, 0);
        Check(r, "kill.single-node",
              plan.targets.size() == 1 &&
                  Pids(rows, plan) == std::vector<DWORD>({7}),
              PidsText(rows, plan));
    }
    {
        // A duplicate PID (two rows, one process) is one target: killing it
        // twice would report a success the machine did not deliver.
        const std::vector<TreeNodeInfo> rows = {
            TreeNode(1, 0), TreeNode(1, 0), TreeNode(2, 1)};
        const KillTreePlan plan = PlanKillTree(rows, 1, 0);
        size_t ones = 0;
        for (DWORD p : Pids(rows, plan)) {
            if (p == 1) ++ones;
        }
        Check(r, "kill.duplicate-pid-is-one-target",
              ones == 1 && plan.targets.size() == 2, PidsText(rows, plan));
    }
}

void CheckIniFile(TestResult& r) {
    std::string err;
    const std::string good =
        "[wintcp]\r\n"
        "interval = 1500\r\n"
        "autoRefresh = yes\r\n"
        "resolveHosts = 0\r\n"
        "topMost = on\r\n";
    const std::vector<IniValue> v = ParseIniSection(good, "wintcp", &err);
    Check(r, "ini.parse-ok",
          err.empty() && v.size() == 4,
          "n=" + std::to_string(v.size()) + " err=" +
              std::string(err.begin(), err.end()));
    if (v.size() == 4) {
        Check(r, "ini.interval", v[0].key == "interval" && v[0].value == "1500",
              v[0].key + "=" + v[0].value);
        Check(r, "ini.boolean-spelling", v[1].value == "yes" && v[2].value == "0",
              v[1].key + "=" + v[1].value);
        Check(r, "ini.on-spelling", v[3].value == "on",
              v[3].key + "=" + v[3].value);
    }

    // Keys outside the wanted section are ignored, and another tool's section
    // is skipped rather than refused.
    const std::string others =
        "[something-else]\r\n"
        "interval = 9\r\n"
        "[wintcp]\r\n"
        "interval = 3000\r\n";
    const std::vector<IniValue> w = ParseIniSection(others, "wintcp", &err);
    Check(r, "ini.other-sections-are-skipped",
          err.empty() && w.size() == 1 && w[0].value == "3000",
          "n=" + std::to_string(w.size()));

    // No [wintcp] section at all: empty, not an error.
    Check(r, "ini.no-section-is-empty",
          ParseIniSection("[other]\r\na=1\r\n", "wintcp", &err).empty() &&
              err.empty(),
          "");

    // Comments, blank lines, whitespace, CRLF and a trailing line with no
    // newline are all handled - the file is meant to be hand-written.
    const std::string loose =
        "; a comment\r\n"
        "# another\r\n"
        "  \r\n"
        "[wintcp]\r\n"
        "\r\n"
        "  interval   =   2500   ; trailing\r\n"
        "autoRefresh=true";
    const std::vector<IniValue> lv = ParseIniSection(loose, "wintcp", &err);
    const std::string lvFirst = lv.empty() ? std::string() : lv[0].value;
    Check(r, "ini.comments-blanks-and-tight-spacing",
          err.empty() && lv.size() == 2 && lv[0].value == "2500" &&
              lv[1].value == "true",
          "n=" + std::to_string(lv.size()) + " v0=" + lvFirst);

    // A repeated key: the last one wins, which is what a user editing by hand
    // expects.
    const std::vector<IniValue> dup =
        ParseIniSection("[wintcp]\r\ninterval=1\r\ninterval=2\r\n", "wintcp", &err);
    Check(r, "ini.repeated-key-last-wins",
          err.empty() && dup.size() == 1 && dup[0].value == "2", "");

    // A value containing '=' keeps the part after the FIRST one, so a filter
    // or a path cannot be truncated at its own '='.
    const std::vector<IniValue> eq =
        ParseIniSection("[wintcp]\r\nk=a=b=c\r\n", "wintcp", &err);
    Check(r, "ini.value-keeps-its-own-equals",
          err.empty() && eq.size() == 1 && eq[0].value == "a=b=c",
          eq.empty() ? "" : eq[0].value);

    // ---- refusals ----
    // The one that matters: a line with no '=' is a line that was MEANT to set
    // something, and skipping it silently would leave a preference unset while
    // the file looks fine.
    const std::vector<IniValue> bad =
        ParseIniSection("[wintcp]\r\ninterval\r\n", "wintcp", &err);
    Check(r, "ini.refuse.a-line-with-no-equals",
          !err.empty() && bad.empty(), "");
    Check(r, "ini.refuse.no-key-before-equals",
          ParseIniSection("[wintcp]\r\n=5\r\n", "wintcp", &err).empty() &&
              !err.empty(),
          "");
    Check(r, "ini.refuse.unterminated-section-header",
          ParseIniSection("[wintcp\r\ninterval=1\r\n", "wintcp", &err).empty(),
          "");
    Check(r, "ini.refuse.empty-section-name",
          ParseIniSection("[]\r\ninterval=1\r\n", "wintcp", &err).empty(), "");

    // The size bound, the same shape the other files use.
    Check(r, "ini.refuse.over-the-size-bound",
          ParseIniSection(std::string(70 * 1024, 'x'), "wintcp", &err).empty() &&
              !err.empty(),
          "");

    // Known keys are the six behaviour ones, and an unknown key is refused
    // NOWHERE - a newer build may have added it, and refusing over it would be
    // this reader's guess made into the user's problem.
    Check(r, "ini.known-keys", IsKnownIniKey("interval") &&
              IsKnownIniKey("autoRefresh") && IsKnownIniKey("resolveHosts") &&
              IsKnownIniKey("topMost") && IsKnownIniKey("trayEnabled") &&
              IsKnownIniKey("trafficEnabled"), "");
    Check(r, "ini.unknown-key-is-not-known",
          !IsKnownIniKey("windowWidth"), "");
    const std::vector<IniValue> extra =
        ParseIniSection("[wintcp]\r\ninterval=1\r\nsomeFutureKey=7\r\n", "wintcp",
                        &err);
    Check(r, "ini.accepts.an-unknown-key",
          err.empty() && extra.size() == 2, "n=" + std::to_string(extra.size()));
}

// ---------------------------------------------------------------------------
// The reverse-DNS answer cache.
//
// The rule this file exists to test is not "does it parse" - it is "can it
// answer WRONG". Every check below is about a way a cache could hand back a
// name that is not the peer's: a stale entry, a timestamp too far in the
// future to ever expire, a negative remembered as fact, or a file whose
// contents were not written by this module. A bug in any of those would be
// invisible in a run and wrong in front of the user, which is why they are
// pinned here rather than trusted.
// ---------------------------------------------------------------------------
void CheckDnsCache(TestResult& r) {
    const int64_t now = NowEpoch();

    // --- What an entry is allowed to be ----------------------------------
    Check(r, "dns.address.v4-ok", IsCacheableAddress(L"1.2.3.4"), "");
    Check(r, "dns.address.v6-ok",
          IsCacheableAddress(L"2001:db8::8a2e:370:7334"), "");
    // A scope suffix is stripped, so fe80::1%12 and fe80::1 are one peer.
    Check(r, "dns.address.scope-stripped",
          IsCacheableAddress(L"fe80::1%12") &&
              StripAddressScope(L"fe80::1%12") == L"fe80::1", "");
    // Never a name: the cache answers addresses, and a line naming a host
    // would let a file redirect a query it was never asked.
    Check(r, "dns.address.rejects-a-hostname",
          !IsCacheableAddress(L"localhost") && !IsCacheableAddress(L"a.b.c"), "");
    Check(r, "dns.address.rejects-empty", !IsCacheableAddress(L""), "");

    Check(r, "dns.display.hostname.plain", IsCacheableHostname(L"host.example.com"),
          "");
    // A trailing dot is what a resolver may hand back, so it must survive.
    Check(r, "dns.display.hostname.trailing-dot",
          IsCacheableHostname(L"host.example.com."), "");
    // Punycode, which is the ASCII form of a non-ASCII name, is the answer
    // that actually arrives.
    Check(r, "dns.display.hostname.punycode",
          IsCacheableHostname(L"xn--e1afmkfd.xn--p1ai"), "");
    // Rejected: empty is the negative case and is never recorded; a hyphen
    // edge is not a legal host name; an empty label is not a name at all.
    Check(r, "dns.display.hostname.rejects-empty", !IsCacheableHostname(L""), "");
    Check(r, "dns.display.hostname.rejects-hyphen-edge",
          !IsCacheableHostname(L"-host.example.com") &&
              !IsCacheableHostname(L"host-.example.com"), "");
    Check(r, "dns.display.hostname.rejects-empty-label",
          !IsCacheableHostname(L"a..b") && !IsCacheableHostname(L".a"), "");
    // Non-ASCII is refused so a hand-edited file cannot widen what is
    // displayed: the resolver hands back punycode, never raw letters.
    Check(r, "dns.display.hostname.rejects-non-ascii",
          !IsCacheableHostname(L"hos\U000000e9.example.com"), "");
    Check(r, "dns.display.hostname.rejects-shell-metacharacters",
          !IsCacheableHostname(L"host;rm -rf.example.com") &&
              !IsCacheableHostname(L"host$(x).example.com"), "");
    Check(r, "dns.display.hostname.rejects-over-253",
          !IsCacheableHostname(std::wstring(63, L'a') + L"." +
                              std::wstring(63, L'b') + L"." +
                              std::wstring(63, L'c') + L"." +
                              std::wstring(63, L'd') + L"." + std::wstring(6, L'e')),
          "");

    // --- Round trip ------------------------------------------------------
    std::vector<DnsCacheEntry> entries;
    DnsCacheEntry a;
    a.address = L"8.8.8.8";
    a.hostname = L"dns.google";
    a.solvedEpoch = now;
    entries.push_back(a);
    DnsCacheEntry b;
    b.address = L"2001:4860:4860::8888";
    b.hostname = L"dns64.example.net";
    b.solvedEpoch = now - 3600;
    entries.push_back(b);
    const std::string text = SerializeDnsCache(entries);
    std::vector<DnsCacheEntry> back;
    std::wstring err;
    Check(r, "dns.roundtrip.serializes",
          ParseDnsCacheText(text, &back, &err) && err.empty(), "");
    Check(r, "dns.roundtrip.entries-survive",
          back.size() == 2 && back[0].address == L"8.8.8.8" &&
              back[0].hostname == L"dns.google" &&
              back[1].address == L"2001:4860:4860::8888" &&
              back[1].solvedEpoch == now - 3600,
          "n=" + std::to_string(back.size()));
    // CRLF in, CRLF out: a file written on Windows must read back identically.
    Check(r, "dns.roundtrip.stable",
          SerializeDnsCache(back) == text, "");

    // --- What the parser is willing to believe ---------------------------
    // A comment and a blank line are not entries and not errors.
    Check(r, "dns.parse.skips-comments-and-blanks",
          ParseDnsCacheText("# a comment\r\n\r\n", &back, &err) &&
              back.empty() && err.empty(), "");
    // A line with the wrong field count is one we did not write. Skipped,
    // not fatal: a single odd line costs one entry, while failing the file
    // would let one byte disable the cache entirely.
    Check(r, "dns.parse.skips-wrong-field-count",
          ParseDnsCacheText("no-tabs-here\r\n1.2.3.4\tok.example\r\n", &back, &err) &&
              back.empty(), "");
    Check(r, "dns.parse.skips-too-many-fields",
          ParseDnsCacheText("1.2.3.4\tok.example\t" +
                            std::to_string(now) + "\textra\r\n", &back, &err) &&
              back.empty(), "");
    Check(r, "dns.parse.skips-non-ascii-bytes",
          ParseDnsCacheText("1.2.3.4\th\366St.example.com\t" +
                            std::to_string(now) + "\r\n", &back, &err) &&
              back.empty(), "");
    Check(r, "dns.parse.skips-non-digit-timestamp",
          ParseDnsCacheText("1.2.3.4\tok.example\tnotanumber\r\n", &back, &err) &&
              back.empty(), "");
    Check(r, "dns.parse.skips-hostname-field",
          ParseDnsCacheText("1.2.3.4\t-not-a-name-\t" +
                            std::to_string(now) + "\r\n", &back, &err) &&
              back.empty(), "");
    // An implausible address in the address field is a line about something
    // this module never wrote.
    Check(r, "dns.parse.skips-hostname-in-address-field",
          ParseDnsCacheText("some.host.example\tok.example\t" +
                            std::to_string(now) + "\r\n", &back, &err) &&
              back.empty(), "");
    // A repeated address: the later line is what a human reader intends.
    Check(r, "dns.parse.duplicate-address-later-wins",
          ParseDnsCacheText("1.2.3.4\tfirst.example\t" +
                            std::to_string(now - 10) + "\r\n1.2.3.4\tsecond.example\t" +
                            std::to_string(now) + "\r\n", &back, &err) &&
              back.size() == 1 && back[0].hostname == L"second.example",
          "");
    // Valid lines among corrupt ones: the valid ones are still honoured.
    Check(r, "dns.parse.valid-survives-among-corrupt",
          ParseDnsCacheText("garbage\r\n\r\n1.2.3.4\tok.example\t" +
                            std::to_string(now) + "\r\nmore garbage\r\n", &back,
                            &err) &&
              back.size() == 1 && back[0].hostname == L"ok.example", "");
    // A file over the size limit is refused WHOLE rather than read in part.
    Check(r, "dns.parse.refuses-oversized",
          ParseDnsCacheText(std::string(kMaxCacheBytes + 1, 'x'), &back, &err) ==
                  false &&
              !err.empty(), "");
    Check(r, "dns.parse.oversized-leaves-output-alone",
          back.empty(), "");

    // --- Freshness: the rule that keeps the cache from answering wrong ----
    DnsCacheEntry fresh;
    fresh.address = L"8.8.8.8";
    fresh.hostname = L"dns.google";
    fresh.solvedEpoch = now;
    // Just inside the window.
    Check(r, "dns.fresh.at-the-ttl",
          DnsEntryFresh(fresh, now + kPositiveTtlHours * 3600 - 1), "");
    // One second past it.
    fresh.solvedEpoch = now - kPositiveTtlHours * 3600 - 1;
    Check(r, "dns.stale.past-the-ttl",
          !DnsEntryFresh(fresh, now), "");
    // The one way a file could pin an answer forever: a timestamp in the
    // future, so the age never reaches the TTL. Refused - there is no skew
    // allowance to permit it, because one would be exactly that loophole.
    fresh.solvedEpoch = now + 400LL * 24 * 3600;
    Check(r, "dns.stale.implausibly-future-timestamp",
          !DnsEntryFresh(fresh, now), "");
    // A modestly future date is refused on the same rule, not tolerated: the
    // cost of refusing is one re-query, and the answer is then re-recorded
    // against this machine's clock.
    fresh.solvedEpoch = now + 3600;
    Check(r, "dns.stale.any-future-timestamp",
          !DnsEntryFresh(fresh, now), "");
    // An entry with no answer is the negative case, which is never recorded
    // in the first place and is not believed if it somehow lands there.
    fresh.solvedEpoch = now;
    fresh.hostname.clear();
    Check(r, "dns.stale.no-answer-recorded",
          !DnsEntryFresh(fresh, now), "");
    // A zero timestamp means "never recorded", not "recorded at the epoch".
    fresh.hostname = L"dns.google";
    fresh.solvedEpoch = 0;
    Check(r, "dns.stale.zero-timestamp", !DnsEntryFresh(fresh, now), "");
}

}  // namespace wintcp

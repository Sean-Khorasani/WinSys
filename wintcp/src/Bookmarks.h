// Bookmarks.h
// SPDX-License-Identifier: Apache-2.0
// Bookmarked connections: a colour tag, a free-text note and a timestamp for
// each remote endpoint the user has marked, persisted under
// HKCU\Software\WinTCP\Bookmarks.
//
// A bookmark's identity is the REMOTE address plus the REMOTE port, and that
// choice is the whole design of this module - the reasoning is on
// NormalizeAddress() below.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

// winsock2.h must precede windows.h, or the winsock declarations are lost
// behind the older winsock.h that windows.h pulls in.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wintcp {

// Colour tags. The same values Connection.h gives RowTag, declared here as
// constants rather than by including Connection.h (which this header has no
// need of) so a row tag and a bookmark tag cannot disagree about what "amber"
// means. Kept in step by a static_assert in Bookmarks.cpp.
constexpr unsigned kBookmarkTagNone  = 0;
constexpr unsigned kBookmarkTagRed   = 1;
constexpr unsigned kBookmarkTagAmber = 2;
constexpr unsigned kBookmarkTagBlue  = 3;
constexpr unsigned kBookmarkTagGreen = 4;
constexpr unsigned kBookmarkTagCount = 5;

constexpr bool IsValidBookmarkTag(unsigned tag) {
    return tag < kBookmarkTagCount;
}

const wchar_t* BookmarkTagLabel(unsigned tag);

// A bookmark as stored. 'when' is UTC seconds since the Unix epoch (the same
// convention the filesystem uses), so a caller can format or compare it
// without parsing a string.
struct Bookmark {
    std::wstring address;    // normalised literal: L"1.2.3.4", L"fe80::1%12"
    UINT port = 0;           // remote port, host byte order
    unsigned tag = kBookmarkTagNone;
    std::wstring note;
    std::uint64_t when = 0;  // 0 = unknown

    // The subkey this bookmark lives under, e.g. L"1.2.3.4:443" or
    // L"[fe80::1%12]:443". Displayed in the details pane, and useful when
    // diagnosing a registry by hand.
    std::wstring Key() const;
};

std::uint64_t FileTimeToUnixSeconds(const FILETIME& ft);
FILETIME UnixSecondsToFileTime(std::uint64_t seconds);

// --- Identity ---------------------------------------------------------------
//
// WHY remote address + remote port, and not the local port. The local port is
// chosen by the stack per connection: it is a different ephemeral number on
// every reconnect, and often a different one again per interface. A bookmark
// keyed on the 4-tuple would therefore be a bookmark that matches exactly
// once and is orphaned the moment the connection drops - the user bookmarks
// something "interesting" and it vanishes from their own list. Remote address
// + remote port is the conversation: it is what the user recognised and
// clicked on, and it is what survives the reconnect, the process restart and
// the app restart. The cost is the deliberate one that two sockets to the
// same peer on the same port share a bookmark - which is the behaviour a
// user marking "the connection to 1.2.3.4:443" actually wants.
//
// WHY THE KEY IS A STRING AND NOT A HASH. addr:port is a valid registry
// subkey name, so the entries are enumerable, individually addressable,
// and deletable with a single RegDeleteKey. A hash of the same would need
// its own index to be listable at all.

// NORMALISATION - the single definition of an address's identity in this
// program, and every path below goes through it. It is public precisely so
// that nothing can grow a second copy: Add, Remove, Get, SetNote, SetColour
// and IsBookmarked all call it, and a divergence between two of them is
// exactly the bug that stores a bookmark the program can never find again.
//
// It accepts a bare literal, with an optional "%<scope>" suffix, optionally
// wrapped in "[...]" with an optional ":port", and returns L"" for anything
// unparseable or unspecified. A std::wstring carries no family, so
// InetPtonW is tried as AF_INET6 first - it also accepts "1.2.3.4", and it
// accepts the v4-mapped form that Windows hands out for a dual-stack socket
// talking to an IPv4 peer, which is the whole reason the mapped case is
// collapsed rather than stored verbatim.
//
//   * "1.2.3.4"        -> L"1.2.3.4"
//   * "::ffff:1.2.3.4" -> L"1.2.3.4"   (v4-mapped collapsed to dotted form)
//   * "::FFFF:1.2.3.4" -> L"1.2.3.4"   (and the v4 tail lowercased, so an
//                                      upper-case spelling is not a second
//                                      bookmark)
//   * "[::ffff:1.2.3.4]:443" -> L"1.2.3.4"   (bracketed, port discarded)
//   * "fe80::1%12"     -> L"fe80::1%12"  (a link-local address keeps its
//                                          scope, because dropping it would
//                                          merge the same address on two
//                                          interfaces into one bookmark)
//   * "fe80::1"        -> L"fe80::1%1"    (see the scope rule below)
//   * "2001:db8::1"    -> L"2001:db8::1"  (a global address is unambiguous,
//                                          so a scope is neither required
//                                          nor invented)
//   * "::" / "0.0.0.0" -> L""             (the placeholder a listening row
//                                          shows; not an endpoint)
//   * "1.2.3.4:80"     -> L""             (a bare port is not an address;
//                                          the port is the other half of the
//                                          identity and swallowing it would
//                                          make "1.2.3.4:80" collide with
//                                          "1.2.3.4")
//   * "not-an-address" -> L""
//
// THE SCOPE RULE. A scope id is kept exactly as given and is never invented,
// because adding one is as much a change of identity as removing one - with
// one exception: a link-local address (fe00::/8 per RFC 4291, whose
// 0xFE00::/9 covers link-local and the deprecated site-local range; wider
// than the fe80::/10 the display code applies, because dropping a scope is a
// silent identity change whereas keeping one the UI never printed is only
// untidy) written WITHOUT a scope is completed with a default interface
// index, so that the unscoped spelling and the scoped spelling of the same
// link-local address resolve to the same bookmark instead of two. The index
// is a NUMBER, never a zone name: "eth0" does not mean the same interface on
// two machines, so a name-keyed identity cannot be compared across them.
// A non-numeric scope is rejected outright rather than dropped, for the same
// reason it is not silently discarded on any other address.
std::wstring NormalizeAddress(const std::wstring& address);

// "addr:port", IPv6 bracketed - the subkey name for one bookmark.
std::wstring MakeBookmarkKey(const std::wstring& normalizedAddress, UINT port);

struct Bookmarks {
    // Note length cap. A note is a one-line annotation typed into a dialog,
    // not a document; the cap stops one bookmark from turning the registry
    // into a file store, and gives the read path a bound to check against.
    static constexpr size_t kMaxNoteChars = 1024;

    // Add a bookmark for (address, port) with 'note' and 'tag'.
    //
    // 'tag' and 'note' are used only when the bookmark is NEW. Re-adding an
    // existing bookmark refreshes its timestamp and nothing else, so a
    // refresh can never quietly discard a note the user typed; SetNote and
    // SetColour are how those change. Refused (nothing written) for an
    // address that does not normalise, an unspecified address, a port above
    // 65535, an unknown tag, or a note over the cap.
    static bool Add(const std::wstring& address, UINT port,
                    unsigned tag = kBookmarkTagNone,
                    const std::wstring& note = std::wstring());

    // Remove one bookmark. Returns true when nothing of that identity is
    // stored afterwards, which includes the case where it never was:
    // removing something that is not there is not an error.
    static bool Remove(const std::wstring& address, UINT port);

    // Every readable bookmark, sorted by address then port, so the order
    // cannot depend on registry enumeration order. Entries whose stored
    // values are corrupt or of the wrong type are skipped, and counted in
    // 'unreadable' (optional) rather than being silently passed off as
    // "the user has no bookmark" - which would hide a bug and let a later
    // Remove claim success on data it never read.
    static std::vector<Bookmark> List(size_t* unreadable = nullptr);

    // One bookmark. Strict: every stored value must be present, of the right
    // type and the right size, or Get fails and '*out' is left untouched.
    static bool Get(const std::wstring& address, UINT port, Bookmark* out);

    static bool IsBookmarked(const std::wstring& address, UINT port);

    // Notes and colours. Both fail for a bookmark that is not stored (a
    // bookmark that does not exist cannot be re-coloured) and for corrupt or
    // missing data; they leave everything else about the entry alone.
    static bool SetNote(const std::wstring& address, UINT port,
                        const std::wstring& note);
    static bool GetNote(const std::wstring& address, UINT port,
                        std::wstring* out);
    static bool SetColour(const std::wstring& address, UINT port, unsigned tag);

    // UTC time of the most recent Add, or 0 when nothing is stored.
    static std::uint64_t LastChangeUnixSeconds();
};

}  // namespace wintcp

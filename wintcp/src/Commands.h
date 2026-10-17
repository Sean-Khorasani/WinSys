// Commands.h
// SPDX-License-Identifier: Apache-2.0
// Abstract command layer: every feature as a pure function over
// (ConnectionStore, SnapshotSource, ViewState, args). No HWND here and none
// may be added. Both the CLI and the GUI call these; the GUI only gathers
// args from widgets and renders the returned strings/models.

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
#include <tcpmib.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "BlockConn.h"
#include "Connection.h"
#include "ConnectionStore.h"
#include "DetailModel.h"
#include "ProcessTree.h"   // CmdKillTree's plan
#include "Snapshot.h"
#include "SysStats.h"
#include "TcpReasm.h"
#include "ViewState.h"

namespace wintcp {

// Exit codes shared by CLI and scripts:
//   0 success (or --quiet matched), 1 failure/empty, 2 bad args, 3 refused.
constexpr int kExitOk = 0;
constexpr int kExitFail = 1;
constexpr int kExitArgs = 2;
constexpr int kExitRefused = 3;   // mutating command without --yes
//
// THE CONTRACT ACROSS FRONT ENDS, which used to be unstated and partly
// colliding. Only the CLI's four are a published interface - they are what a
// script tests - and the other two front ends reuse their values without
// sharing the meaning:
//
//   CLI    0/1/2/3 exactly as above. RunCli returns these and nothing else.
//   GUI    0 after the message loop; 1 for each of its three startup
//          failures (WSAStartup, RegisterClassEx, window Create). So the GUI's
//          1 means "never got a window", NOT the CLI's "failed" - and no
//          script can observe it, because the CLI is the only front end a
//          script runs.
//   bench  0 all green, 1 any check failed. Again not the CLI's 1.
//
// The collision is harmless precisely because it is unobservable, and it is
// written down here so that "which 1 is this?" is answerable rather than a
// thing a reader has to infer from wmain. main.cpp returns its own literals
// rather than these constants, and that is deliberate: naming them kExitFail
// would assert that "the window did not open" and "the command failed" are the
// same thing, which is the confusion this comment exists to prevent.
struct FrontEndExitCodes {};   // documentation only; never instantiated

// CLI validation ranges (A4). One home for the numbers the parser enforces,
// the executor re-clamps, and the error strings print — owned here (not in
// CliCommands.cpp) so the in-process selftest can also assert on them, and so
// a future second front end cannot invent a second set. The `help` prose
// states the same ranges as literals (a `const char*` table cannot compute
// them); each prose line carries a keep-in-step comment, and golden asserts
// the prose, so either side drifting fails loudly somewhere.
constexpr unsigned kWatchMinSec = 1;
constexpr unsigned kWatchMaxSec = 3600;
constexpr unsigned kCaptureSecsMin = 1;
constexpr unsigned kCaptureSecsMax = 60;
constexpr unsigned kCaptureSecsDefault = 5;
constexpr unsigned kMinPort = 1;
constexpr unsigned kMaxPort = 65535;
constexpr unsigned kMinTag = 0;
constexpr unsigned kMaxTag = 4;
constexpr unsigned kMinCount = 1;

// One command invocation. Text is UTF-8, ready to print; the CLI writes out
// and err to stdout/stderr, the GUI renders them into dialogs/status.
//
// TWO RULES about these two strings, both previously only followed in practice.
//
// 1. LINE ENDINGS ARE PER-CHANNEL, and the split is not arbitrary.
//    `err` is human prose for a terminal, so every message ends "\r\n". `out`
//    is a DATA FEED, so it uses whatever the chosen format specifies: JSON,
//    JSON-lines and CSV all use a bare "\n" separator and terminator, because
//    that is what those formats are defined to use and a conforming parser
//    handles either. Measured across Commands.cpp: 134 "\r\n" and 22 bare
//    "\n", and all 22 are in the JSON/CSV renderers. None is in `err`.
//
// 2. `err` IS ASSIGNED, NOT APPENDED, EXCEPT WHERE YOU ARE ADDING A WHOLE
//    NEW MESSAGE. Assignment owns the whole string, so an `err = ` inside a
//    conditional silently discards whatever an earlier branch wrote. There is
//    exactly ONE place in Commands.cpp that appends - the advisory merge in the
//    list path - and it is guarded on emptiness, which is what keeps the
//    separator honest. Two messages that both end in a newline need no
//    separator work at all, which is why `err` messages all end in "\r\n":
//    that is what makes append safe by construction.
//
// A message that does NOT end in a newline breaks both rules at once: appending
// runs it into the next message, and printing it leaves the cursor mid-line.
struct CommandResult {
    int exitCode = kExitOk;
    std::string out;
    std::string err;
};

// Write straight to stdout WHILE a command is still running (the CLI's
// streaming path: the table's fixed header goes out before the slow
// enrichment joins, the rows follow in CommandResult.out when they are
// ready). Defined in Utils.cpp next to the writers it wraps - NOT in
// CliCommands.cpp, because this header is included by Commands.cpp, which the
// GUI links without CliCommands.cpp, and a symbol defined in a TU the GUI
// does not link is an LNK2019 waiting for the first Debug build. A verb
// only calls it when its own options opt in (ListOptions::streamHeader), so
// in-process callers (selftest, GUI) never see a mid-render write.
void StreamOut(const std::string& s);

// ---- cooperative cancellation ----------------------------------------------
// A long enrichment pass has to be interruptible: `list --dns --limit 5000`
// spends seconds inside blocking reverse lookups, and until this existed a
// Ctrl+C set the front end's own stop flag and then the join kept going,
// because the join never asked. The front end's console handler calls
// RequestCancellation(); the joins poll CancellationRequested() between items
// and stop early, KEEPING whatever they already resolved - a partial answer
// beats a process that will not exit. ResetCancellation() clears it before a
// new run (the CLI calls it where it resets its own stop flag).
void RequestCancellation();
bool CancellationRequested();
void ResetCancellation();

// ---- snapshot --------------------------------------------------------------
// Fill 'store' with one enriched pass. procStats/dns/geoIp are opt-in so a
// fast `list` pays for nothing it does not show.
bool BuildStoreSnapshot(SnapshotSource& source, ConnectionStore& store,
                        bool procStats, bool resolveDns, bool geoIp,
                        const wchar_t* geoIpPath, std::wstring* error);

// the process-lifetime traffic sampler, or nullptr if no --traffic verb
// has created one yet. Lets a caller REPORT what the scan could not measure
// without creating a sampler to ask - creating one would probe SIO_TCP_INFO
// (a loopback connect) and would answer about a different object than the one
// the traffic columns came from.
class SocketTrafficSampler;
SocketTrafficSampler* ActiveTrafficSampler();
// ---- list (conn) -----------------------------------------------------------
struct ListOptions {
    std::wstring filter;          // filter-box grammar, "" = all
    unsigned protoMask = kProtoMaskAll;
    DWORD stateFilter = kAllStates;
    int sortColumn = COL_PID;
    bool sortAsc = true;
    bool grouped = false;
    size_t limit = 0;             // 0 = no limit
    // Output shape: "table" (aligned columns for humans), "csv",
    // "tsv" (raw tabs, the machine shape table used to be) or "json".
    // There is deliberately no "jsonl" VALUE here: --format jsonl is this
    // same "json" with jsonLines set, so every rule keyed on the format -
    // "json prints no header line", the grouped-column refusal, the
    // --changes shape check - already applies to it unchanged, and the two
    // can only differ where they are meant to differ: the renderer.
    std::string format = "table";
    // --format jsonl: emit NDJSON instead of a JSON array - one object per
    // line, every line terminated, no enclosing brackets. An array has to be
    // read to its closing bracket before any of it is usable; a line at a
    // time is consumable the moment it lands, which is what a SIEM pipe or
    // `jq -c` reading a --watch stream needs. Off by default.
    bool jsonLines = false;
    // Column ids for delimited output; empty = frozen default set.
    std::vector<int> columns;
    // Quiet: print nothing; exit 0 when the view is non-empty, else 1.
    // For scripts: `list --filter ... --quiet && ...`.
    bool quiet = false;
    // Opt-in enrichment (each costs time; all off by default):
    //   traffic: per-PID byte totals via the bounded socket sampler
    //   dns:     blocking reverse-DNS for the printed rows (use --limit!)
    //   geoIpPath: load this .mmdb and join country codes ("" = off)
    //   signatures: verify each distinct process image ("" = off)
    bool traffic = false;
    bool dns = false;
    // per-lookup budget (ms) for the CLI --dns one-shot join. A lookup
    // that exceeds it is shown as `host: pending` instead of stalling the run;
    // the count of such stalls is reported on stderr. 0 = DnsResolver default.
    unsigned dnsTimeoutMs = 0;
    std::wstring geoIpPath;
    // the ASN database, which is a SEPARATE file from the country one.
    // GeoLite2-Country and GeoLite2-ASN are different products with different
    // record shapes, so one --db cannot supply both; "" = off.
    std::wstring asnIpPath;
    // verify each distinct process image with WinVerifyTrust, so the
    // Signature column and the `signed:` filter have something to report.
    // Opt-in because the trust provider is far too slow to run per pass by
    // default; cached per image path, so the cost is once per binary.
    bool signatures = false;
    // changes: with --watch/--count, print only APPEAR/DISAPPEAR/STATE
    // deltas between polls instead of full snapshots.
    bool changes = false;
    // Stream the fixed column header to stdout as soon as the snapshot is
    // built - before the (potentially multi-second) enrichment joins - and
    // send the rows along in CommandResult.out afterwards. The CLI's
    // list verb sets it; json has no header line, --quiet prints nothing,
    // and in-process callers leave it false so their CommandResult.out stays
    // a complete, self-contained rendering.
    bool streamHeader = false;
    // Internal Web UI API fields. Ordinary CLI parsing never sets this, so
    // the published JSON shape remains unchanged for existing scripts.
    bool webMetadata = false;
};

CommandResult CmdList(SnapshotSource& source, const ListOptions& opt);

// One `list` snapshot pass into a CALLER-owned store. CmdList owns a
// throwaway one; the watch loop keeps a store across ticks so per-row
// lifetime state (Duration) accumulates instead of restarting at 0s.
CommandResult CmdListInto(SnapshotSource& source, ConnectionStore& store,
                          const ListOptions& opt);

// True when a detached socket-traffic scan may still be running. `list
// --traffic` and friends start one, and a detached thread keeps the process
// alive at exit, so a one-shot CLI verb that has already written its output
// must not simply return: the caller exits hard instead. False when no scan
// was ever started (every other verb), so the normal `return` applies.
bool CliScanThreadMayBeLive();

// ---- ps / top --------------------------------------------------------------
// One aggregated row per process (like ps/lsof): pid, name, connections,
// cpu %, working set, disk I/O totals. Sorted by cpu desc by default.
struct PsOptions {
    std::wstring filter;          // matched against connection rows first
    std::string format = "table"; // table | csv | json
    size_t limit = 0;
    // Sort key: cpu (default, hottest first), mem, disk, conns, pid, process.
    // Unknown-valued readings always sort last.
    std::string sortBy = "cpu";
    bool quiet = false;           // print nothing; 0 = any process, else 1
};

// Pure render over an already-filled store: apply the view, format, honour
// quiet/limit. No snapshot, no network, no registry - this is what
// --selftest drives with synthetic rows.
//
// skipHeader: the caller already streamed the header (CmdListInto with
// streamHeader), so the body must come back WITHOUT it - concatenating
// StreamOut(header) and this body reproduces the unstreamed rendering byte
// for byte. Default false = the complete output every other caller wants.
CommandResult RenderList(ConnectionStore& store, const ListOptions& opt,
                         bool skipHeader = false);
CommandResult RenderPs(ConnectionStore& store, const PsOptions& opt);

// Filter analysis for the enrichment pre-pass (see Commands.cpp). A clause on
// a joined column (tx/rx/net, country, host) cannot be evaluated before its
// join, so those clauses are held back until the join has filled the values.
// Exposed because they are pure functions of the filter string - exactly the
// decision --selftest can pin without a snapshot or a network.
bool DependsOnEnrichment(FilterField f);
bool HasEnrichmentClause(const std::wstring& filter);
std::vector<FilterClause> PreJoinClauses(const std::wstring& filter);
// The stderr advice naming the switch an enrichment clause is missing
// (host: -> --dns, country: -> --db, rx/tx/net: -> --traffic), so an
// unanswerable filter says so instead of printing an empty table. Empty when
// nothing is missing or --quiet is set. Pure: no snapshot, no network.
std::string MissingEnrichmentAdvice(const ListOptions& opt);

// the FILTER half of that advice - no quiet gate, no column half.
// The CLI refuses a `--quiet` run whose filter needs a switch that is off
// (exit 2) and calls this to see exactly what the advisory path suppresses.
// Only filter clauses qualify: `--quiet`'s exit code answers "does the
// filter match", and a requested column cannot change that answer.
std::string FilterEnrichmentAdvice(const ListOptions& opt);
// View-scoped enrichment for list/export: DNS + GeoIP + traffic over the
// printed rows only. False + err when the GeoIP database fails. 'advice'
// (optional) receives advisory hints - the missing-switch note above and the
// unenrichable-window hint - never fatal, never on stdout. When the filter
// holds an enrichment clause the view is (re)applied here, AFTER the joins,
// so the caller renders - and the hint inspects - the rows the joins actually
// filled (an export otherwise wrote a silent 0-row file).
bool EnrichViewForList(ConnectionStore& store, const ListOptions& opt,
                       std::wstring* err, std::string* advice = nullptr);

CommandResult CmdPs(SnapshotSource& source, const PsOptions& opt);

// ---- details ---------------------------------------------------------------
// What to enrich a details snapshot with. All off except procStats by
// default; each extra source costs time, so the CLI asks explicitly.
struct EnrichOptions {
    bool procStats = true;
    bool traffic = false;
    bool dns = false;
    // per-lookup budget for --dns (ms). 0 = resolver default.
    unsigned dnsTimeoutMs = 0;
    std::wstring geoIpPath;
    // the ASN database, which is a SEPARATE file from the country one.
    // GeoLite2-Country and GeoLite2-ASN are different products with different
    // record shapes, so one --db cannot supply both; "" = off.
    std::wstring asnIpPath;
    // for `details`, which shares this shape with `list`.
    bool signatures = false;
};

// Build the Details model for the single row matching 'select' (filter
// grammar, must resolve to exactly one live row) and render plain text.
CommandResult CmdDetails(SnapshotSource& source, const std::wstring& select,
                         const EnrichOptions& eo);

// Pure builder lifted out of MainWindow::BuildDetails: the GUI calls this
// with its live store, the CLI with a one-shot store. Needs the store for
// the per-PID connection list.
//
// 'threadsMayBlock' is the one behavioural difference between the two callers,
// and it is forced by the measurement in ProcessInfo.h. Enumerating a
// process's threads costs ~48 ms, which the GUI must never pay inline (it
// rebuilds this model on every refresh tick) and a one-shot command must pay
// or it never sees the result at all. Default false, so the safe case is the
// default and the caller that knows better has to say so.
// POST the current snapshot (or a test event) to a webhook URL.
CommandResult CmdWebhook(const std::wstring& url, bool test);

DetailModel BuildDetailModel(const Connection& c, const ConnectionStore& store,
                            bool threadsMayBlock = false);

// ---- view / preset helpers -------------------------------------------------
// Non-widget core of MainWindow::CurrentPresetView / ApplyPresetView.
ViewState CurrentPresetViewFor(const std::wstring& filter, UINT32 colVisible,
                               int sortColumn, bool sortAsc, unsigned sources);
void ApplyPresetViewToStore(const ViewState& v, ConnectionStore& store,
                            std::vector<FilterClause>* out = nullptr);

// ---- kill / close ----------------------------------------------------------
// Core used by both CmdKill (which enumerates for the create time) and the
// GUI (which already holds the row). Takes the row's identity directly so
// neither caller re-derives it.
struct MutateOptions {
    bool yes = false;             // confirmed
    bool dryRun = false;          // print plan, change nothing
    // how `kill` ends the process. Neither set = the documented
    // hybrid (WM_CLOSE, wait kKillGraceMs, then TerminateProcess).
    bool closeOnly = false;       // WM_CLOSE + wait only; never terminate
    bool forceNow = false;        // terminate immediately; no WM_CLOSE
};

// Can this process be ended, and if not, why.
//
// A pure function on purpose: the decision belongs to the abstract layer
// so the GUI's context menu, the GUI's handler and the CLI all apply ONE rule,
// and so the rule can be pinned by a selftest with no window and no real
// process. "Can it be ended" sounds like a property of the process, but it is
// really a property of *who is asking* - the answer differs for wintcp.exe
// depending on the caller - so both PIDs are parameters rather than one being
// read out of global state.
enum class PidVerdict {
    Ok,             // may be ended
    IsSelf,         // it is wintcp.exe itself
    Pseudo,         // PID 0 / System: no real process to end
    NotPermitted,   // exists, but this token cannot end it
};

// 'selfPid' is the caller's own PID. 'rowPid' is the row's. 'exists' is
// whether the row's process was still resolvable (PID 0 rows are not).
PidVerdict PidKillVerdict(DWORD rowPid, DWORD selfPid, bool exists);

// The user-facing refusal, or an empty string when PidKillVerdict() is Ok.
// One string per verdict so the menu tooltip, the handler's message and the
// CLI's error can never word the same refusal differently.
const wchar_t* PidKillRefusal(PidVerdict v);

CommandResult KillPid(DWORD pid, const FILETIME& create, bool createKnown,
                      const std::wstring& label, const MutateOptions& mo);
// Resolve --select to exactly one live row and kill its PID. The "find by
// port/name, kill exactly that" flow taskkill cannot do.
CommandResult CmdKillSelect(SnapshotSource& source, const std::wstring& select,
                            const MutateOptions& mo);
CommandResult CloseRow(const Connection& c, const MutateOptions& mo);
CommandResult BlockNow(const BlockRequest& req, const MutateOptions& mo);

// ---- shared serializers ----------------------------------------------------
// The same row->text used by CmdList/CmdExport AND by the GUI export and
// copy paths, so the two front ends cannot drift. 'cols' is any ColumnId
// list (usually the visible columns in display order, or a CLI column set).
// includeHeader=false suppresses the title line so the streaming CLI can
// print it first; the default keeps the historical one-shot output.
std::string RenderDelimitedRows(const std::vector<Connection>& rows,
                                const std::vector<int>& cols, char delim,
                                bool rfcCsv, bool includeHeader = true);
// 'extraHostname' appends the hostname field the GUI's export schema has
// always carried; the CLI's frozen --json schema passes false.
// 'lines' renders NDJSON rather than a JSON array (see ListOptions::
// jsonLines); the default keeps the array every existing caller expects.
std::string RenderJsonRows(const std::vector<Connection>& rows,
                           const std::vector<int>& cols, bool extraHostname,
                           bool lines = false, bool webMetadata = false);

// The frozen ten-column default shared by every delimited/JSON export.
std::vector<int> DefaultExportColumns();

CommandResult CmdKill(SnapshotSource& source, DWORD pid,
                       const MutateOptions& mo);
// kill a process and everything under it. Best-effort by contract -
// it ends what it can and reports what survived, where `kill` is
// all-or-nothing. The plan's shape lives in ProcessTree (pure, tested); this
// builds it from the snapshot and works it deepest-first, re-checking the
// PID-reuse guard per target because the machine moves between steps.
CommandResult CmdKillTree(SnapshotSource& source, DWORD pid,
                          const MutateOptions& mo);
CommandResult CmdClose(SnapshotSource& source, const std::wstring& select,
                       const MutateOptions& mo);

// ---- block -----------------------------------------------------------------
CommandResult CmdBlock(SnapshotSource& source, const std::wstring& select,
                       const MutateOptions& mo);
CommandResult CmdUnblock(const std::wstring& address, UINT port,
                         const MutateOptions& mo);
// `blocks`: the count by default. With 'listRules' the rules themselves are
// listed instead, in 'format' (table, csv or json). The listing path never
// calls CountWinTcpRules, so looking cannot change the number the count
// prints - that is the property that has to be preserved.
CommandResult CmdBlocks(bool listRules = false,
                        const std::string& format = "table");

// Map a connection row onto a firewall request (binary remote address, not
// the display string that carries the port). False when the row cannot be
// blocked (UDP, listening, unspecified peer).
bool ConnectionToBlockRequest(const Connection& c, BlockRequest* out,
                              std::wstring* whyNot);

// ---- a stated policy rule --------------------------------------------
// What `block --rule` sends to the engine. Deliberately the CLI's shape rather
// than FwRule itself: the CLI speaks in words ("tcp", "any") and the engine in
// the firewall's own constants, and that one mapping is easier to review in one
// place than to keep honest at every call site.
struct RuleRequest {
    bool inbound = false;
    bool allow = false;
    std::wstring proto = L"tcp";   // "tcp" | "udp" | "any"
    std::wstring address;          // required: "*" or an address / list / CIDR
    std::wstring localPorts;       // empty = "*"
    std::wstring remotePorts;      // empty = "*"
    std::wstring process;          // empty = any program
    std::wstring label;
};

// Writes one rule. Follows the same refusal contract as every other act verb:
// 0 done, 2 a bad rule (refused by ValidateFwRule before anything is written),
// 3 no --yes. `--dry-run` prints the rule it would create and writes nothing,
// so the exact name is visible before it exists.
CommandResult CmdRule(const RuleRequest& req, bool dryRun, bool yes);

// ---- bookmark --------------------------------------------------------------
CommandResult CmdBookmarkList(const std::string& format);

// the bookmark file. Export writes every bookmark as a Version=1 JSON
// document; import reads one and adds what it holds, refusing the WHOLE file
// when the codec refuses it (so a partial import cannot happen).
//
// Both follow the act-verb contract: 2 for a bad argument, 3 for no --yes,
// 0 when done, 1 when the target could not be read. Import parses and plans
// before anything is written, so a file that will not parse leaves the
// bookmarks that were there alone.
CommandResult CmdBookmarkExport(const std::wstring& outPath,
                                bool forceOverwrite);
CommandResult CmdBookmarkImport(const std::wstring& inPath, bool yes);
CommandResult CmdBookmarkAdd(const std::wstring& address, UINT port,
                             unsigned tag, const std::wstring& note);
CommandResult CmdBookmarkRemove(const std::wstring& address, UINT port);
CommandResult CmdBookmarkNote(const std::wstring& address, UINT port,
                              const std::wstring& note);
CommandResult CmdBookmarkColour(const std::wstring& address, UINT port,
                                unsigned tag);

// ---- preset ----------------------------------------------------------------
CommandResult CmdPresetList(const std::string& format);

// the preset file. Same codec shape and the same all-or-nothing rule as
// the bookmark one - a preset that loads half is a view the user never saved,
// and unlike a bookmark the failure is subtle, because it is believed.
CommandResult CmdPresetExport(const std::wstring& outPath,
                              bool forceOverwrite);
CommandResult CmdPresetImport(const std::wstring& inPath, bool yes);

CommandResult CmdPresetSave(const std::wstring& name, const ViewState& view,
                            bool overwrite);
CommandResult CmdPresetShow(const std::wstring& name);
CommandResult CmdPresetDelete(const std::wstring& name);
// 'overrides' carries the switches the USER typed on the command line
// (--limit, --columns, --sort, --asc/--desc, --format, --traffic, --dns,
// --db). They are layered over the SAVED view, so `preset apply --name web
// --limit 5` means "the web view, five rows" rather than silently ignoring
// --limit - which is what it did before (measured: 27 rows, rc 0).
CommandResult CmdPresetApply(SnapshotSource& source, const std::wstring& name,
                             ListOptions* appliedView,
                             const ListOptions* overrides = nullptr);

// ---- export ----------------------------------------------------------------
// 'forceOverwrite' is R4. The write underneath is CREATE_ALWAYS, so without it
// an export aimed at an existing path destroys that file's contents with no
// warning and no way to tell afterwards - silent data loss, which this codebase
// treats as the failure rather than as a trade-off. The house convention is
// Presets::Save, which reports kExists and leaves the caller to authorise the
// overwrite; a non-interactive CLI cannot ask, so the authorisation arrives as
// a switch instead. The GUI passes true, because it asks the user first.
CommandResult CmdExport(SnapshotSource& source, const ListOptions& opt,
                        const std::wstring& outPath,
                        bool forceOverwrite = false);

// R4. True when `path` exists and the caller did not authorise replacing it, with
// the reason written to `err`. Declared here rather than left file-local so the
// selftest can drive it against a real file: the failure mode being fixed is a
// SILENT one, and a test that only checked an exit code would pass even if the
// refusal arrived after the write had already destroyed the file.
bool RefuseExistingOutput(const wchar_t* verb, const std::wstring& path,
                          bool forceOverwrite, std::wstring* err);

// ---- geoip -----------------------------------------------------------------
CommandResult CmdGeoIpLookup(SnapshotSource& source,
                             const std::wstring& geoIpPath,
                             const std::wstring& ip);
CommandResult CmdGeoIpInfo(SnapshotSource& source,
                           const std::wstring& geoIpPath);

// ---- doctor (environment diagnostics) ---------------------------------------
// `version` shows the build + capability state; `doctor` adds the run-local
// diagnostics a script or a support call needs to know whether a missing
// feature is "this build" vs "this machine" vs "this invocation": GeoIP DB, the
// WinTCP firewall-rule ledger, and capture availability (tools + elevation).
// Text here reuses AboutText/BuildSummary so `version` and `doctor` can never
// disagree about process state.
// Every field is tri-state: -1 or unset means "leave alone", so a
// caller can change one switch without restating the whole configuration.
// Values are in the domain the engine applies them in, so rates are bytes/sec.
struct AlertFlags {
    bool enableSet = false;
    bool enable = false;
    long long bpsWarn = -1;
    long long bpsCritical = -1;
    long long connWarn = -1;
    bool onListenerSet = false, onListener = false;
    bool onConnectionSet = false, onConnection = false;
    bool onRstSet = false, onRst = false;
    bool onClosedSet = false, onClosed = false;
    std::string format;
};

// Rule sub-commands: `alert rule add/list/remove`. add is the only one that
// carries a rule; the rest identify one by name.
struct AlertRuleFlags {
    std::wstring name;
    std::wstring address;
    std::wstring process;
    bool onNew = false;        // "tell me when it appears" - the default for a
                               // hand-built rule too, and set explicitly here so
    bool onClose = false;      // `add --on-close` is the opt-in, not the default
    bool onThreshold = false;
    bool onNewSet = false;
    bool onCloseSet = false;
    std::string format;
};

CommandResult CmdAlertRule(const std::wstring& action, AlertRuleFlags f);
CommandResult CmdAlert(AlertFlags f);
CommandResult CmdDoctor(bool verbose, const std::wstring& geoDbPath,
                        const std::wstring& asnDbPath, const std::string& format);

// ---- capture (follow stream) -----------------------------------------------
//
// `capture` grew from "print some counters" into the command-line replacement
// for the GUI's Follow TCP stream, which was removed 2026-10-05.
// The three switches below are that replacement, and the reasons they are
// switches rather than defaults are worth keeping:
//
//   text  - the payload was already in memory and was being thrown away. On the
//           command line, printing it costs nothing extra and makes the verb
//           worth running without piping into anything.
//   out   - the capture file was deleted immediately after parsing. Saving it is
//           the difference between "here are the bytes" and "here is the
//           capture, open it in Wireshark".
//   dir   - a stream has two halves and most questions are about one of them.
//           Default is both, because guessing for the user is worse than
//           printing twice.
struct CaptureOptions {
    // Print the reassembled stream to stdout as a hex dump, one block per
    // direction (or just the one --dir selects).
    bool text = false;
    // Dump the raw reassembled stream bytes to outPath (binary, no hex/pcapng
    // framing). Requires outPath; mutually exclusive with text.
    bool bin = false;
    // Save the capture as pcapng here. Empty = do not keep it.
    std::wstring outPath;
    // R4: the pcapng write is CREATE_ALWAYS, so an existing file at outPath
    // would be destroyed silently. Same convention as export: refuse without
    // this, and the CLI's --force is what sets it.
    bool forceOverwrite = false;
    // Which half --text prints. Parsed by ParseCaptureDir.
    std::wstring dir = L"both";
    // pktmon `start --flags N` mask (SYN/FIN/RST). 0 = record everything
    // (the default and the only mode that fully reassembles). Parsed by
    // ParseCaptureFlags. Named constant lives in StreamCapture.h; the struct
    // default stays a literal 0 so this header does not need to include it.
    unsigned eventFlags = 0;

    // an extra `pktmon filter add -i <ip>` address pin, passed through
    // verbatim. Empty = do not add one, keeping the default single-connection
    // filter pktmon derives from the selected row. Validated as an IP in
    // CmdCapture, so the executor never ships a malformed token to pktmon.
    std::wstring filter;
};

CommandResult CmdCapture(SnapshotSource& source, const std::wstring& select,
                         const MutateOptions& mo,
                         unsigned secs = kCaptureSecsDefault,
                         const CaptureOptions& co = CaptureOptions());

// ---- stat (system CPU/mem/disk/net) ----------------------------------------
CommandResult CmdStat(SystemStatsSampler& sampler, const std::string& format);

// ---- column specs ----------------------------------------------------------
// Resolve a --columns value: a set name (default | minimal | full | wide) or
// an explicit comma list (proto,local,lport,...). Returns false (leaving
// 'out' untouched) when nothing in the spec names a column.
bool ResolveColumnSpec(const std::wstring& spec, std::vector<int>& out);

// ColumnId for a single column name, or -1 when unknown.
int ColumnIdForName(const std::wstring& name);

// `help columns` / `help filters` text, generated from the same tables
// (ColumnTitle, JsonKeyFor, ColumnIsPerConnectionOnly, kColumnSet*) the parser
// uses, so the reference can never drift from accepted spellings.
std::string HelpColumnsText();
std::string HelpFiltersText();

// ---- change events ---------------------------------------------------------
// Format drained RowChange events as text lines or JSON lines. 'prog'
// (nullptr = no filter) keeps only events whose row matches, so
// `list --watch --changes --filter ...` watches a subset.
//
// 'eventMask' selects which kinds are printed, as a bitmask of RowChangeKind
// (1<<kChangeAppear | 1<<kChangeDisappear | 1<<kChangeState). It is applied
// BEFORE the row filter, so asking for APPEAR only costs nothing and shows
// nothing else. kAllChangeKinds is the default and reproduces the old
// behaviour exactly. This is what answers "what opened while I was away" - the
// single most valuable question for an event feed - which was previously not
// expressible at all.
constexpr unsigned kAllChangeKinds =
    (1u << kChangeAppear) | (1u << kChangeDisappear) | (1u << kChangeState);

std::string FormatChangeEvents(const std::vector<RowChange>& events,
                               const std::string& format,
                               const std::wstring& stamp,
                               const std::vector<FilterClause>* prog,
                               unsigned eventMask = kAllChangeKinds);

// ---- script execution -------------------------------------------------------
// Script execution engine for batch automation. The script command parses and
// executes a script file or inline script containing CLI commands with control
// flow (loops, conditionals), variables, and timing functions.
//
// Grammar (line-oriented, # comments, ; statement separator):
//   set VAR = EXPR          ; variable assignment with math/string ops
//   sleep SECONDS           ; pause execution
//   while COND { ... }      ; loop while condition is true
//   for VAR = START to END { ... }  ; numeric range loop
//   if COND { ... } [else { ... }]  ; conditional
//   CMD [args...]           ; execute any CLI command (list, ps, kill, etc.)
//   break / continue        ; loop control
//   return [CODE]           ; exit script with code
//
// Expressions support: + - * / % ( ), string concat with +, comparisons
//   == != < > <= >=, logical && || !, variables $VAR or ${VAR}.
struct ScriptOptions {
    std::wstring filePath;       // script file path (empty = inline)
    std::wstring inlineScript;   // inline script text
    bool inlineProvided = false; // distinguishes an empty inline script from no source
    bool dryRun = false;         // parse only, don't execute
    bool trace = false;          // print each command before execution
    std::map<std::wstring, std::wstring> initialVars;  // -DVAR=value
};

CommandResult CmdScript(const ScriptOptions& opt);

// ---- misc ------------------------------------------------------------------
std::string ViewStateToJson(const ViewState& v);
bool ViewStateFromPreset(const PresetView& v, ViewState* out);
std::string FormatSystemStatsLine(const SystemStats& s);
std::string SystemStatsToJson(const SystemStats& s);

// ---- the TLS report capture prints -----------------------------------------
//
// Declared here, and not left as a private helper in Commands.cpp, for one
// reason: it is pure formatting over two reassembled directions, and the
// repository's convention is that pure logic gets tested rather than trusted
// (see SocketTraffic.h's "split out for --selftest"). The test drives the real
// captured ClientHello that Bench.cpp already carries.
//
// It is here, and only here, because it is the only place a TLS session can be
// reported at all. Windows has no socket-level TLS ioctl - no SIO_TLS_INFO
// exists in the SDK, and TCP_INFO_v0 carries no TLS field - so the handshake
// bytes are the only source, and they are readable only for a connection the
// user chose to capture. The `tls` column therefore stays unpopulated; see the
// TlsInfo comment in Connection.h.
std::string TlsCaptureLines(const ReasmResult& toServer,
                            const ReasmResult& toClient,
                            const std::wstring& dir1Label,
                            const std::wstring& dir2Label);

}  // namespace wintcp

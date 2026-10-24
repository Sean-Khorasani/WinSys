// MainWindow.h
// SPDX-License-Identifier: Apache-2.0
// Main application window: control bar + virtual ListView (LVS_OWNERDATA)
// + status bar. Owns the RefreshEngine worker, the ConnectionStore model,
// filter/sort/export logic, selection preservation, and column layout.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>   // SelectedCopy: "no selection" and "a row" as one value
#include <set>
#include <string>
#include <vector>

#include "Alerts.h"
#include "AlertMonitor.h"
#include "BlockConn.h"
#include "ConnectionStore.h"
#include "ChartsWindow.h"
#include "DetailModel.h"
#include "DetailsDialog.h"
#include "DnsResolver.h"
#include "Elevate.h"
#include "EtwTraffic.h"
#include "GeoIp.h"
#include "ExposureScore.h"   // the exposure badge
#include "RefreshEngine.h"
#include "Settings.h"
#include "Presets.h"
#include "Bookmarks.h"
#include "ViewPresets.h"    // the save/load/delete preset dialogs
#include "BookmarkActions.h"   // the bookmark dialogs + row actions
#include "ChangeLogWindow.h"
#include "ProcessTreeView.h"   // the process-tree view mode's fill
#include "TypeToJump.h"
#include "SocketTraffic.h"
#include "TrayIcon.h"          // the notification-area icon
#include "WorkerSink.h"        // the mailbox the worker threads post into
#include "RowEnrichment.h"     // DNS / country / ASN
#include "ListViewColumns.h"   // column geometry: mask, widths, order
#include "ConnectionsList.h"   // the list control, its text, its selection

namespace wintcp {

// The worker -> UI message ids and the mailbox itself are in WorkerSink.h:
// the refresh worker and the enrichment subsystem both post through them.
//
// Posted to self when a header drag starts, so the resulting order is read
// back AFTER the drag has finished. Posting rather than reading
// inside LVN_BEGINDRAG is deliberate: at that point the header still holds
// the OLD order, and there is no end-of-drag notification to hook.
constexpr UINT WM_APP_COLUMNORDER_SYNC = WM_APP + 4;

class MainWindow : public ConnectionsListSink {
public:
    MainWindow() = default;
    ~MainWindow();
    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    // Register the window class (call once at startup).
    static bool RegisterClass(HINSTANCE hInstance);

    // Create the top-level window. Returns nullptr on failure.
    HWND Create(HINSTANCE hInstance, int nCmdShow);

    HWND Handle() const { return hwnd_; }

    // In-process UI harness. See UiHarness.cpp.
    //
    // Everything the harness needs is already reachable through
    // HandleMessage() - the same entry point the real WndProc uses - so the
    // harness drives the production WndProc, not a parallel copy of it. What
    // it cannot see is the resulting STATE, because every field is private and
    // friend would not survive: this exists so a test can ask the window
    // itself what it did, rather than reading the controls back from another
    // process and guessing.
    //
    // Returns a pointer to static storage valid until the next call, or
    // nullptr if the op name is not recognised.
    //
    // Declared here, DEFINED IN UiProbe.cpp, AND NOT LINKED INTO wintcp.exe.
    // The one caller in this repository is wintcp/tests/UiHarness.cpp; nothing
    // in the product calls this or can reach it. That is what makes the split
    // possible: the declaration stays where the harness can see it, the
    // definition sits in its own file, and the product link line never
    // mentions that file - so the shipped binary contains no probe code and no
    // path to any. See the header comment in UiProbe.cpp for why it moved.
    const wchar_t* UiProbe(const wchar_t* op, const wchar_t* arg) const;
    const wchar_t* UiProbeAction(const wchar_t* op);

    // direct access to the change-log window for the UI harness.
    //
    // Not a UiProbe op, because UiProbe is deliberately a string-keyed READ
    // interface: it answers questions about state and performs no actions. The
    // harness needs to SET the event mask and push synthetic events, which is
    // exactly what that interface is shaped to prevent. This is one typed
    // accessor for one test, which is a smaller concession than widening UiProbe
    // into a general command channel.
    ChangeLogWindow* ChangeLogForTest() { return &changeLog_; }

private:
    static const wchar_t* kClassName;
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    // The list's own proc, installed with SetWindowSubclass: WM_GETOBJECT for
    // a child control never reaches the parent, so the per-row accessible
    // object can only be served here. 'refData' is this - the list's
    // GWLP_USERDATA belongs to the subclass chain.
    static LRESULT CALLBACK ListSubclassProc(HWND hwnd, UINT msg,
                                             WPARAM wParam, LPARAM lParam,
                                             UINT_PTR id, DWORD_PTR refData);

    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCreate();
    void OnSize(int cx, int cy);
    void OnCommand(WORD id, WORD notifyCode, HWND ctl);
    void OnNotify(NMHDR* hdr, LPARAM lParam);
    void SyncColumnOrderFromHeader();   // persist header drag-reorder
    bool OnTypeJumpChar(wchar_t ch);    // type-a-few-letters navigation
    void OnTimer(UINT_PTR timerId);
    // R8: refresh watchdog, run from the 1 s status tick. Declares the view
    // stale and restarts the worker past the threshold, switches auto-refresh
    // off past the restart cap. Pure policy lives in RefreshWatchdogNext
    // (RefreshEngine.h, selftested); this only executes the verdict.
    void CheckRefreshWatchdog();
    void OnContextMenu(HWND target, int x, int y);
    void OnDestroy();

    void OnRefreshResult(RefreshResult* payload);   // takes ownership if registered
    void OnDnsResult(DnsResolver::Result* payload); // takes ownership if registered

    void CreateControls();
    void LayoutControls(int cx, int cy);
    void InitTooltips();                // control-bar tooltips + accNames
// Column geometry lives in ListViewColumns; these are the window's half of
// it - the dialogs, the side effects, the persistence and the repaint.
void RebuildColumns();                 // apply visibility + widths
void HarvestColumnWidths();            // physical -> logical (96-dpi) units
void SyncGroupHeader();                // grouped label + live group count
void UpdateSortIndicator();
void ToggleColumn(int columnId);
void SyncColumnMenuChecks();           // View > Columns ticks trace the mask
void InitFilterControls();
    void StartWorker();                    
    void StartDnsWorker();                 

    // DPI: logical layout units are 96-dpi pixels; S() scales them.
    int S(int px96) const { return ::MulDiv(px96, static_cast<int>(dpi_), 96); }
    void RecreateFont();                   // Segoe UI 9pt at current DPI
    void ApplyFontToChildren();


    // Close connection.
    void CloseSelectedConnection();

    // Theming: the app has no theme of its own and follows the system one,
    // so "dark mode" as a setting is gone. High contrast (WO_HC_ACTIVE) is
    // picked up from the system automatically - see RefreshSystemColors().
    bool HighContrastActive() const;
    bool ThemeIsDark() const;      // system theme is dark (for highlights)
    void RefreshSystemColors();    // WM_THEMECHANGED / WM_SYSCOLORCHANGE

    // The notification-area icon. The icon's own plumbing (add/remove/tip/
    // balloon/menu) is TrayIcon's; what is left here is WHEN: the remembered
    // first-minimize choice and the prompt that asks for it.
    TrayIcon tray_;
    // Add the icon now when settings say it should be there; remove it when
    // they say it should not. One call, both directions, so the menu check and
    // the icon cannot disagree.
    void SyncTray();

    // on the first minimize while the tray icon is OFF, offer the user a
    // one-shot choice - minimize-to-tray (enable the tray icon) or exit. The
    // choice is remembered in settings_.trayMinimizeChoice so the prompt never
    // returns.
    enum class MinimizeTarget { kTaskbar, kTray, kExit };
    MinimizeTarget ResolveMinimize();

    // Reverse-DNS plumbing.
    void OfferDnsForAllRows();
    void OfferGeoIpForAllRows();           // fill Country from the MMDB
    void LoadGeoIpDatabase();              // pick a .mmdb, load, refresh
    void OfferAsnForAllRows();             // fill the ASN half of Country
    void LoadAsnDatabase();                // pick a GeoLite2-ASN .mmdb
    // column profiles and quick filters. Both are one-click named
    // sets, so both live here as a pair of apply-and-sync helpers rather than as
    // five and six near-identical command handlers.
    void ApplyColumnProfile(int profileId);
    UINT32 ColumnProfileMask(int profileId) const;   // profile id -> column mask
    void ApplyQuickFilter(int filterId);
    void SyncColumnProfileChecks();        // View > Column profile ticks
    void SyncQuickFilterChecks();          // Filter menu ticks
    void UpdateEmptyState();               // the empty-column infobar
    void ShowEmptyStateActions();          // ...with buttons for it
    void RunAlerts();                    // evaluate + balloon
    void RaiseAlert(const wintcp::Alert& a);   // one balloon per alert
    // Filter + sort + repaint the virtual list, preserving selection/scroll.
    void ApplyView();                      // captures selection from current view
    // The funnel behind ApplyView: a caller that has already captured the
    // selection (or wants to preserve a specific one) calls this with it, and
    // every other path - a refresh, a column toggle, a preset, a GeoIP pick,
    // a freeze - ends here.
    void ApplyViewWith(const std::vector<std::uint64_t>& ids,
                       std::uint64_t focusedId, int topIdx);
    void UpdateStatusBar(const std::wstring& errorText);
    void UpdateCaption();               // the state-carrying title
    void UpdateExposure();              // the exposure badge
    void UpdateTrayTip();               // rows/frozen/grouped/alerts tip
    void UpdateStatusTips();            // every status pane gets a tooltip
    void ResetLayout();                 // defaults + persist + rebuild
    // the process-tree view mode. Toggle swaps the tree control in
    // where the list view is; RebuildTree refills it from the store's rows
    // (the same rows the list would show, by value).
    void ToggleTreeMode();
    void RebuildTree();
    // The selection pane's text while tree mode is on: the process/connection
    // counts of the last rebuild. The list's own summary is meaningless
    // there, because the list is hidden and cannot be selected.
    std::wstring TreeSummary() const { return treeSummary_; }
    // Select the first VIEW row owned by the captured process in the (hidden) list and
    // return true, so every command handler - Details, Copy, Export, Block,
    // Close, End process, Open file location - runs against the tree's node
    // without any of them knowing the tree exists. One selection, one
    // answer; a second mapping inside each handler is how the two would
    // drift apart.
    bool SelectViewRowForProcess(const ProcessTreeNode& process);
    const ProcessTreeNode* TreeProcessForItemData(LPARAM itemData) const;
    // Details for a tree node: the process's first connection when it owns
    // one, and the process dossier alone when it does not. The second case
    // is why this exists - Details on a connection-less process used to do
    // nothing, which made most of the tree a dead end.
    void ShowDetailsForTreeItemData(LPARAM itemData);
    // Status-bar panes 3 and 4, factored out so the countdown stays a pure
    // function of the last refresh tick and the auto-refresh interval.
    std::wstring SelectedSummary() const;
    std::wstring RefreshAgeText() const;

    void Refresh(bool reportErrors);
    void ExportCsv();                     // -> DoExport(false)
    std::wstring SelectedRowsText(bool copyAll) const;
    void CopySelectionToClipboard(bool copyAll);
    void CopyFieldToClipboard(ConnectionsList::CopyField field);
    void CopyTextToClipboard(const std::wstring& text,
                             const std::wstring& successMessage,
                             const ClipboardApi* clipboardApi = nullptr);
    std::vector<Connection> SelectedCopyRows() const;
    void KillSelectedProcess();            // PID-reuse verification
    std::optional<Connection> SelectedProcessCopy() const;
    void ShowDetailsOfSelectedRow();       // modeless details window
    // REMOVED 2026-10-05. The capability moved to the CLI as
    // `capture --text` / `capture --out`.
    void OpenSelectedFileLocation();      // ShellExecute "explore"
    // REMOVED 2026-10-05: the `properties` shell verb cannot
    // be invoked with a bare path, so this action never worked.
    // void ShowSelectedProcessProperties(); // ShellExecute "properties"
    void BlockSelectedConnection();       // firewall block
    void RemoveAllWinTcpBlocks();         // tray - every WinTCP rule at once
    // The Export CSV path: the dialog is the window's, the text is the list's.
    void DoExport(bool selectionOnly);
    // sectioned builder + silent live-update while open.
    DetailModel BuildDetails(const Connection& c) const;
    void RefreshDetailsWindow();           // no-op unless details visible
    void ShowAboutBox();
    void ShowShortcutsSheet();

    // presets + bookmarks, wired to the File and Process menus.
    PresetView CurrentPresetView() const;
    void ApplyPresetView(const PresetView& v);
    void SavePreset();
    void LoadPreset();
    void DeletePreset();
    void ShowBookmarksList();
    void RefreshBookmarkMarks();            // registry -> row model
    void BookmarkSelectedConnection();
    void EditSelectedBookmarkNote();
    void EnsureTrafficCounters();          // ETW try + socket fallback

    // Change log: append APPEAR/DISAPPEAR/STATE lines to a CSV
    // file the user picked; persists across restarts via Settings.
    void ToggleChangeLog();
    bool OpenLogFromSettings();            // reopen at startup (best effort)
    void WriteChangeLog();                 // drains store_.TakeChangeEvents()

    // Settings: loaded in OnCreate, saved in OnDestroy.
    //
    // this used to call Settings::Save() TWICE and discard the bool both
    // times. The first call was dead work - it ran before the GeoIP path was
    // written into settings_, so the file it wrote could not have been
    // complete - and the second overwrote it. Every exit therefore did two full
    // registry writes, and a write that FAILED left the user with a silently
    // lost column layout, window position, filter and GeoIP path.
    //
    // SaveSettings is private and called only from ~MainWindow, so there is no
    // surface a user could act on between the failure and the process going
    // away - a MessageBox here would pop up during teardown. So the counts are
    // kept instead, readable through the op table, and the duplication is gone.
    // See the note on the counters: NO gate forces a Save to fail, so the
    // failure half is unexercised.
    void SaveSettings();
    // The single write path. See the definition for why every caller uses it.
    void PersistSettings(const char* why);
    // Writes attempted and writes that reported failure. Read through the
    // "settingsSaveAttempts" / "settingsSaveFailures" ops.
    //
    // NOT mutable-out-of-const in spirit: SaveSettings is called from
    // ~MainWindow, which does not need constness, so these need not be mutable
    // and are not. They are plain unsigned because every increment happens on
    // the UI thread - the column-reorder path is a control notification and
    // the shutdown path is the destructor - so there is no race to defend.
    unsigned settingsSaveAttempts_ = 0;
    unsigned settingsSaveFailures_ = 0;

    void SelectAllRows();
    void FocusFilterBox();
    void ClearFilterBox();

    std::wstring CurrentSearchText() const;
    unsigned CurrentProtoFilterMask() const;   // kProtoMask* combination
    DWORD CurrentStateFilter() const;          // kAllStates or MIB_TCP_STATE_*
    // First selected connection (nullptr when nothing is selected).
    //
    // The POINTER form. It stays for the two call sites that legitimately want
    // the live row and provably outlive it (the context-menu builder, and the
    const Connection* FirstSelectedRow() const;

    // The COPY form, for every handler that hands control to a modal loop.
    // Returns false when nothing is selected, and writes the row BY VALUE.
    //
    // Why this exists: a refresh arriving during a modal loop replaces rows_
    // and frees the row the pointer referred to, so a handler that kept
    // `const Connection* c` across a MessageBox read freed memory. This was
    // call, and the lifetime hazard is closed by construction rather than by
    // remembering a rule at each new site.
    //
    // std::optional rather than a bool + out-param because "no selection" and
    std::optional<Connection> SelectedCopy() const;
    bool SelectedRowIndices(std::vector<int>& out) const;

int VisibleToCol(int visibleIndex) const;   // -1 when out of range
int ColToVisible(int columnId) const;       // -1 when hidden
// The window's own traffic-column question, which is the column object's
// answer, kept as a method because every caller wrote the mask by hand.
bool AnyTrafficColVisible() const { return cols_.AnyTrafficVisible(); }

    // The index in the shell's system image list for a
    // Queries the shell by path, so an .exe shows its
    // The top-level window itself. Declared first because every control we
    // own is its child, and because the ConnectionsList member below is
    // constructed with *this.
    HWND hwnd_ = nullptr;
    HINSTANCE hInstance_ = nullptr;
    HWND hwndStatus_ = nullptr;
    // The shell's shared system image list, attached to the list control. The
    // window owns the ATTACHMENT, not the list - the list is the shell's, and
    // LVS_SHAREIMAGELISTS on the control is what keeps it from being destroyed
    // with the control.
    HIMAGELIST iconImageList_ = nullptr;
    HWND hwndRefreshBtn_ = nullptr;
    HWND hwndExportBtn_ = nullptr;
    HWND hwndAutoChk_ = nullptr;
    HWND hwndIntervalCbo_ = nullptr;
    HWND hwndProtoCbo_ = nullptr;
    HWND hwndStateCbo_ = nullptr;
    HWND hwndSearchEdit_ = nullptr;
    // The shell's system small-icon list, attached to the list so
    // each row can carry its process's icon. Owned by
    // CreateControls; tools are added there and never removed, because the
    // bar's children live as long as the window.
    HWND hwndTip_ = nullptr;
    // a refresh has been requested but no result has arrived yet. Set
    // in Refresh(), cleared in OnRefreshResult on every path (success,
    // error, frozen-early-out), so a slow enum/DNS stall reads as
    // "Refreshing..." instead of looking idle.
    bool refreshInFlight_ = false;
    // the first-hide balloon ("where did the window go, click to
    // restore") shows once per process, not once per minimize.
    bool trayHideBalloonShown_ = false;

    ConnectionStore store_;
    RefreshEngine engine_;
    // The reverse-DNS resolver, the country database and the ASN database.
    // All three live in RowEnrichment now - the window offers and reports,
    // and holds none of them.
    RowEnrichment enrich_;
    // per-PID traffic (ETW kernel logger). Heap-allocated and never freed,
    // for the SAME reason as socketTraffic_ below: the ProcessTrace worker can
    // be wedged in the kernel past EtwTraffic::Stop()'s bounded join, and it
    // writes its final events through `this`, so the object must outlive the
    // window. Stop() sets stopping_ and clears gEtwInstance before abandoning,
    // so a lingering docked thread does nothing; a one-object leak at process
    // exit is the smaller problem. Create it in OnCreate.
    EtwTraffic* etw_ = nullptr;
    // non-admin per-PID traffic. Heap-allocated and never freed: a
    // scan thread wedged in SIO_TCP_INFO can outlive the window, and it holds
    // a pointer to its sampler, so the sampler must outlive it too. See
    // ~SocketTrafficSampler for the reasoning; `this` is never deleted, which
    // is a deliberate one-object leak at process exit.
    SocketTrafficSampler* socketTraffic_ = nullptr;
    // Whether the socket fallback (not ETW) feeds the traffic columns.
    // Heap-owned and shared with the refresh worker: after Stop() detaches
    // the worker, a late pass may still read this, so it must not die with
    // the window. Read by the worker thread -> atomic.
    std::shared_ptr<std::atomic<bool>> fallbackFlag_ =
        std::make_shared<std::atomic<bool>>(false);
    DetailsDialog details_;
    ChartsWindow charts_;                    // performance graphs
    DWORD detailsPid_ = 0;                   // PID the details window shows
    FILETIME detailsProcessCreate_ = {};
    bool detailsProcessCreateKnown_ = false;
    DetailModel detailsModel_;               // last content shown
    bool detailsExitedNoted_ = false;        // exit note shown once
    Settings settings_;
    std::vector<FilterClause> filterProgram_;
    std::wstring filterError_;

    // change log: append-mode handle while logging is active
    HANDLE logFile_ = INVALID_HANDLE_VALUE;
    std::wstring logPath_;

    // worker -> UI payload registry. The sink itself is WorkerSink's own
    // type now (WorkerSink.h) - it is shared by the refresh worker and the
    // enrichment subsystem, so it cannot be private to this class.
    // Everything a worker-thread callback touches lives in that heap block,
    // never in the window: if Stop() detaches a worker, its late pass still
    // holds a shared_ptr to the sink, so the callback can run to completion
    // against freed-window-safe state (a PostMessage to the dead hwnd simply
    // fails and the payload is deleted). This is what makes the bounded-join
    // detach provably harmless rather than hopefully so. mutable so the const
    // UiProbe accessor can read the pending counts.
    mutable std::shared_ptr<WorkerSink> sink_;
    // Lazy owner: created on first use so a window that never starts its
    // workers still destroys cleanly.
    std::shared_ptr<WorkerSink> Sink() const;

    bool reportErrorsNextResult_ = false;
    bool dnsEnabled_ = false;              // View > Resolve hostnames
    std::wstring dnsStalledHint_;         // status-bar hint on stalls
    // Same shape and same lifetime as dnsStalledHint_ - derived from live
    // state each second, never stored across a refresh - because a stored hint
    // outlives the condition that produced it.
    std::wstring emptyStateHint_;
    // the exposure badge's one-line summary. Empty on a healthy
    // machine, so the status bar stays quiet by default. Recomputed from the
    // snapshot every pass, like every other message on this bar.
    std::wstring exposureLine_;
    // which rows the badge decided were exposed, so the reason can be
    // shown without re-walking the store. Keyed on row id.
    std::wstring exposureDetail_;
    // The alert fallback when there is no tray icon, and the count of
    // alerts currently suppressed by the engine's latch.
    std::wstring alertHint_;
    size_t suppressedAlerts_ = 0;
    // The alert engine's wiring (engine + latch + suppressed count). The engine
    // is pure and tested; this is its only production caller, and it used to be
    // inline RunAlerts, which is why a tested feature had no caller at all.
    AlertMonitor alertMonitor_;
    // The preset file dialogs (save/load/delete), wired to the window's own
    // Current/Apply. Constructed with them, so a caller cannot drive the
    // dialogs with a stale view of the window.
    ViewPresetDialogs presetDialogs_{
        hwnd_,
        [this]() { return CurrentPresetView(); },
        [this](const PresetView& v) { ApplyPresetView(v); }};
    // The bookmark dialogs and row actions, wired to the list selection and
    // the re-join-and-repaint that a change to the bookmark set means. The
    // endpoint is copied before the first prompt in every method, because a
    // prompt pumps messages and a refresh arriving there reallocates the
    // store - the access violation that reproduced roughly one run in three.
    BookmarkActions bookmarks_{
        hwnd_,
        [this]() { return list_.SelectedCopy(); },
        [this]() { RefreshBookmarkMarks(); ApplyView(); }};
    bool topMost_ = false;                 // View > Always on top
    // View > Tray icon. 'trayIconShown_' was a second truth for the same fact
    // and lived beside it; TrayIcon::IsShown() is the one that decides
    // whether the icon is actually there (Add() can fail), so only the
    // requested state remains here.
    bool trayEnabled_ = false;             // View > Tray icon
    // remembered first-minimize choice (mirrors settings_.trayMinimizeChoice).
    DWORD trayMinimizeChoice_ = 0;
    bool etwAutoAttempted_ = false;        // at most one implicit ETW start
    HBRUSH hwndBrushWindow_ = nullptr;   // WM_CTLCOLOR* backdrop (system)
    std::wstring lastError_;
    std::wstring copyFeedback_;
    ULONGLONG copyFeedbackUntil_ = 0;
    std::wstring lastRefreshTime_;
    // GetTickCount64 of the last completed snapshot; drives the status bar's
    // age and next-refresh countdown. 0 = nothing has completed yet.
    ULONGLONG lastRefreshTick_ = 0;
    std::atomic<std::uint64_t> completedRefreshCount_{0};
    // R8 liveness stamp: GetTickCount64 of the last POSTED result, success or
    // error — either proves the worker alive. lastRefreshTick_ stays
    // success-only (it drives the display age); this one drives the watchdog.
    ULONGLONG lastResultTick_ = 0;
    // Watchdog state (R8). workerStartTick_ seeds the age before the first
    // result; the rest is the restart state machine in CheckRefreshWatchdog.
    ULONGLONG workerStartTick_ = 0;
    bool watchdogRestarting_ = false;
    ULONGLONG watchdogRestartTick_ = 0;
    int watchdogRestarts_ = 0;

    // DPI
    UINT dpi_ = 96;
    HFONT font_ = nullptr;

    // Column geometry: the visible mask, the widths in 96-dpi logical units,
    // the user's order and the control's visible-index mapping. Four members
    // and ten methods that managed them became one object, because the header
    // drag path, the menu-tick path and the persistence path were each
    // reaching into a bitmask of their own.
    ListViewColumns cols_;

    // keep the selection across auto-refresh ticks. On by default -
    // a row the user is inspecting must not jump to the top of the list every
    // two seconds - but on a busy machine the tracked row can end up far down
    // the view, so it is a toggle rather than a hard-coded behaviour.
    bool preserveSelection_ = true;

    // type-to-jump state.
    TypeToJump typeToJump_;

    // freeze. When set, auto-refresh keeps sampling but the list is not
    // replaced, so the user can read a table without it changing under them.
    bool frozen_ = false;
    ULONGLONG frozenAt_ = 0;

    // group rows by process. Changes the SHAPE of the list only; the
    // underlying rows are untouched, so toggling it off restores the flat
    // list exactly.
    bool groupByProcess_ = false;

    // the process-tree VIEW MODE. Not another window - a tree
    // control where the list view is, which is what was asked for
    // and what Task Manager's Processes tab is. A separate detached window
    // answering the same question is a second answer, so the toggle swaps
    // the two controls in place instead of adding a third surface.
    bool treeMode_ = false;

    // change-log window. Fed from the SAME drain the file writer uses -
    // TakeChangeEvents is destructive, so there is exactly one drain and both
    // consumers get the batch. See WriteChangeLog().
    ChangeLogWindow changeLog_;
    std::string monitorOperationId_;

    // the tree control that REPLACES the list in tree mode, over
    // the same rows (ProcessTreeFill). Hidden until the mode is on; the
    // list is hidden while it is.
    HWND hwndTree_ = nullptr;
    // The process list the last tree fill drew. Tree item data indexes this
    // snapshot, including for processes with no connection row.
    std::vector<ProcessTreeNode> treeProcs_;
    // The summary the status bar shows in place of the selection count.
    std::wstring treeSummary_;
    // The last fill's counts: items drawn, and the processes they were drawn
    // from. A check compares the tree with the second number rather than with
    // a fresh enumeration, because the machine changes between two of those.
    size_t treeItemsAtFill_ = 0;
    size_t treeEnumeratedAtFill_ = 0;
    // The list's selection and scroll as they were when tree mode was
    // switched ON, restored when it is switched off: a view mode is a lens,
    // not a state destructor, and the person who toggled back expects to
    // find the rows they were looking at still selected and still scrolled
    // to the same place.
    std::vector<std::uint64_t> treeSavedIds_;
    std::uint64_t treeSavedFocus_ = 0;
    int treeSavedTop_ = -1;

    // GeoIP. Both databases live in RowEnrichment now - loaded lazily from
    // the user-supplied .mmdb, never downloaded. The module existed and was
    // fully tested but was never actually consulted, so the Country column
    // was permanently empty - a 778-line feature wired to nothing. The
    // window asks whether each is loaded (for the status bar, the presets
    // and the settings line) through the enrichment object, and holds
    // neither database itself.
    //
// The alert engine and the rule store both live outside the window now -
// AlertMonitor owns the engine and the latch, AlertRuleStore (Alerts.h) owns
// the rule list, and both are wired by that module. Neither was ever the
// window's business; the alert.* selftests used to be the only thing exercising
// them because nothing else called them.
wchar_t dispBuf_[kMaxColumnText] = {0};  // LVN_GETDISPINFO scratch buffer

    std::wstring filterDebounceText_;
    bool autoRefresh_ = false;
    UINT autoRefreshMs_ = kDefaultIntervalMs;

    // ---- the ConnectionsListSink implementation --------------------------
    // The list reports up; the window answers. Implemented in
    // ConnectionsListOwner.cpp, beside the other owner half of the list.
    void OnSortByColumn(int columnId, bool ascending) override;
    void OnRowActivated() override;
    void OnColumnDragStarted() override;
    int ProcessIconIndex(const std::wstring& path) const override;
    ConnectionsListSink::Painting QueryPainting() const override;

    // The one list, now an object: the control, its cell text, its painting
    // and its selection. The window's job with it is the FONT, the LAYOUT,
    // and answering what it asks for.
    ConnectionsList list_{store_, cols_, *this};
};

}  // namespace wintcp

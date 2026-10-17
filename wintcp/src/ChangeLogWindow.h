// ChangeLogWindow.h
// SPDX-License-Identifier: Apache-2.0
// Live change log window: APPEAR / DISAPPEAR / STATE events
// shown as they happen, in a virtual ListView over a capped buffer of
// pre-formatted rows.
//
// WHY IT IS FED AND DOES NOT POLL: ConnectionStore::TakeChangeEvents()
// *drains* the change queue. A window that called it would take the events
// away from MainWindow::WriteChangeLog(), and the reverse is equally true -
// whoever asks first starves the other. So the main window keeps ownership
// of the drain and hands the same batch to both consumers; this window
// never touches the store. AppendEvents() is the whole interface.
//
// WHY THE BUFFER IS CAPPED: a busy machine emits thousands of change
// events a minute, and this is a rolling view, not the archive (the CSV
// file is the archive). kMaxEvents bounds the memory for the lifetime of
// the process and keeps the ListView's virtual index space small enough
// that a repaint is always cheap. Dropped events are counted and reported
// in the status line rather than silently forgotten.
//
// WHY THE ROWS ARE PRE-FORMATTED: every event is turned into its column
// strings once, when it arrives. Painting is then a pointer read, so a
// burst of thousands of events costs one repaint rather than thousands of
// formatting passes.
//
// WHY THE SCROLL FOLLOWS THE SCROLLBAR: the newest row is the useful
// default, but a log that yanks the view back to the bottom while you are
// reading is unusable. follow_ is therefore derived from where the user
// left the scrollbar, and only events that arrive *while the user is at the
// bottom* move the view.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <commctrl.h>   // NMLVDISPINFOW (the virtual list's display request)

#include <cstddef>
#include <string>
#include <vector>

#include "ConnectionStore.h"   // RowChange

namespace wintcp {

class ChangeLogWindow {
public:
    // Column order of the report view. Exposed so a test can read a
    // specific column back without depending on the layout constants.
    enum Column {
        kColTime = 0,
        kColEvent,
        kColProto,
        kColProcess,
        kColLocal,
        kColRemote,
        kColState,
        kColumnCount
    };

    // Rolling window size. 5000 rows is roughly 20-30 minutes of history on
    // a very busy machine and about 1.5 MB of formatted text, while staying
    // a small number for a virtual ListView to repaint - only the ~20
    // visible rows are ever asked for. Anything larger is mostly scroll-back
    // nobody reads, and the change log file already holds everything.
    // Dev constant, no --history knob. The CSV file is the archive; the
    // window is a rolling view, and 5000 events is 20-30 min of history.
    static constexpr size_t kMaxEvents = 5000;

    ChangeLogWindow() = default;
    ~ChangeLogWindow();

    ChangeLogWindow(const ChangeLogWindow&) = delete;
    ChangeLogWindow& operator=(const ChangeLogWindow&) = delete;

    // Show (or reveal) the window; created on first call and reused until
    // Close(). Centred over 'owner' when first created. Re-showing returns
    // the view to the live tail but keeps the buffer.
    void Show(HWND owner, HFONT font);

    // Destroy the window. Idempotent, and safe when never created. The
    // buffer deliberately survives: the main window keeps feeding events
    // while the window is closed, and reopening should show recent history
    // rather than an empty pane.
    void Close();
    bool IsOpen() const { return hwnd_ != nullptr; }
    bool IsVisible() const;
    HWND Handle() const { return hwnd_; }
    HWND ListHandle() const { return hwndList_; }

    // Add change events. Safe to call whether or not the window is open and
    // whether or not it is paused; the cap holds in every case.
    void AppendEvents(const std::vector<RowChange>& events);

    // ---- the GUI half of `--event appear,disappear,state` ---------------------
    //
    // The CLI has had this: `--event` selects which change kinds a
    // `--changes` feed prints, applied before the row filter so the two compose.
    // The GUI's change log had no way to express it, so the two front ends
    // disagreed about what the tool could do - which is exactly the drift this
    // exists to police.
    //
    // The invariant that makes this a SURFACE and not a port: the GUI renders
    // what the store computed, it never re-derives it. So this filters the
    // kinds AppendEvents is given, and does not touch RowChange or the store.
    //
    // Default all-true, so the behaviour is unchanged for anyone who never
    // touches it. Persisted per user in HKCU alongside the rest of the window
    // state.
    void SetEventMask(bool appear, bool disappear, bool state);
    bool EventAppear() const { return evAppear_; }
    bool EventDisappear() const { return evDisappear_; }
    bool EventState() const { return evState_; }
    // True when every kind is on - i.e. the mask is not restricting anything.
    bool EventMaskIsFull() const {
        return evAppear_ && evDisappear_ && evState_;
    }

    // How many times WM_CREATE has built this window's controls. Exposed for
    // the UI harness: a visible window with a count of 0 means the controls
    // were never created, which IsVisible() reports identically to success.
    unsigned CreateCount() const { return createCount_; }

    // How many of the window's child controls currently exist. Paired with
    // CreateCount(): a non-zero create count with a zero child count means the
    // CreateWindowExW calls FAILED, which is a different fault from the handler
    // never running.
    unsigned ChildCount() const {
        return (hwndList_ != nullptr ? 1u : 0u) + (hwndPause_ != nullptr ? 1u : 0u) +
               (hwndClear_ != nullptr ? 1u : 0u) + (hwndSave_ != nullptr ? 1u : 0u) +
               (hwndCopy_ != nullptr ? 1u : 0u) + (hwndClose_ != nullptr ? 1u : 0u) +
               (hwndStatus_ != nullptr ? 1u : 0u) +
               (hwndEvAppear_ != nullptr ? 1u : 0u) +
               (hwndEvDisappear_ != nullptr ? 1u : 0u) +
               (hwndEvState_ != nullptr ? 1u : 0u);
    }

    // GetLastError() from the most recent failed child creation. OutputDebugString
    // is the wrong tool for this: the harness has no debugger attached, so the
    // message goes nowhere and the failure has to be explained by the next run
    // instead of the current one.
    DWORD LastChildError() const { return lastChildError_; }
    DWORD lastChildError_ = 0;

    // Drop every buffered event and the dropped counter, and re-sync the
    // view. Does not change the paused flag.
    void Clear();

    // Pausing keeps accepting events into the buffer but freezes the list,
    // so a row being read cannot move under the cursor; the view catches up
    // on resume, holding the same top row. That is the difference between
    // "pause" and "ignore": nothing is lost while paused.
    void SetPaused(bool paused);
    bool IsPaused() const { return paused_; }

    // True when the view is pinned to the newest row. Goes false as soon as
    // the user scrolls up, and true again when they return to the bottom.
    bool IsFollowing() const { return follow_; }

    void ApplyFont(HFONT font);        // on DPI change

    // ---- inspection, used by the self-test --------------------------------
    size_t Count() const { return events_.size(); }
    // Events pushed out of the buffer by the cap, since the last Clear().
    unsigned long long Dropped() const { return dropped_; }
    // The text the window would show in one cell, or L"" if the index is
    // outside the buffer.
    std::wstring ColumnText(size_t index, int column) const;
    // The whole buffer as CSV, in the same field order as the change log
    // file (time, event, proto, local, remote, state, old state, pid,
    // process). SaveToFile() writes exactly this.
    std::string ToCsv() const;

private:
    // One row, already split into its columns. 'stateText' is the display
    // form ("ESTABLISHED", or "OLD -> NEW" for a transition); the plain
    // old/new pair is kept beside it so the CSV stays machine-readable.
    struct Entry {
        std::wstring time;
        std::wstring kind;        // APPEAR / DISAPPEAR / STATE
        std::wstring proto;
        std::wstring process;     // "chrome.exe (1234)"
        std::wstring local;
        std::wstring remote;
        std::wstring newState;
        std::wstring oldState;    // transitions only, else empty
        std::wstring stateText;   // display column
        std::wstring pidText;     // digits, for the CSV
    };

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam,
                                       LPARAM lParam);
    // The list's own proc, installed with SetWindowSubclass: scroll and
    // keyboard input never reach the parent, so the follow rule can only be
    // evaluated here. 'refData' is this - the list's GWLP_USERDATA belongs
    // to the subclass chain.
    static LRESULT CALLBACK SubclassProc(HWND hwnd, UINT msg, WPARAM wParam,
                                         LPARAM lParam, UINT_PTR id,
                                         DWORD_PTR refData);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    // 'lParam' carries the control HWND for a notification. The
    // all-kinds-off guard has to put back the EXACT box the user clicked, and
    // identifying which one from the id alone would mean three identical
    // branches or a re-read of all three.
    void OnCommand(WORD id, LPARAM lParam = 0);
    void OnGetDispInfo(NMLVDISPINFOW* info);   // LVN_GETDISPINFO
    void Layout(int cx, int cy);
    void SetColumnWidths();
    void CenterOnOwner(HWND owner);

    void AppendFormatted(const std::vector<RowChange>& events,
                         const std::wstring& stamp);
    // The one point that touches the buffer after an append. 'evicted' is
    // how many entries fell off the front.
    void FinishAppend(size_t evicted);

    void SyncList(size_t evicted);
    void SyncCount();
    int ListTop() const;
    int ListPage() const;
    int ListCount() const;
    bool AtBottom() const;
    void ScrollToBottom();
    void ScrollToTop(int index);
    // A scroll the user performed: follow follows the scrollbar, both ways.
    void OnUserScrolled();
    // A layout or DPI change: only ever *acquires* the bottom, so resizing
    // cannot silently cancel a follow the user set.
    void MaybeFollow();

    void UpdateStatus();
    void UpdatePauseButton();
    void CopySelection();
    void SaveToFile();

    int S(int px96) const;

    HWND hwnd_ = nullptr;
    HWND hwndList_ = nullptr;
    HWND hwndPause_ = nullptr;
    HWND hwndClear_ = nullptr;
    // The three kind checkboxes. Borrowed handles, like every other child
    // here - the window owns them and this class only reads their state.
    HWND hwndEvAppear_ = nullptr;
    HWND hwndEvDisappear_ = nullptr;
    HWND hwndEvState_ = nullptr;
    HWND hwndSave_ = nullptr;
    HWND hwndCopy_ = nullptr;
    HWND hwndClose_ = nullptr;
    HWND hwndStatus_ = nullptr;

    std::vector<Entry> events_;       // capped at kMaxEvents, oldest first
    unsigned long long dropped_ = 0;  // evicted by the cap since last Clear()
    // The receipt of a fallback copy-all ("copied all N rows"). Shown
    // in the status line until new data arrives, so the count is visible
    // without a modal per copy.
    std::wstring copyNote_;

    bool paused_ = false;
    bool follow_ = true;
    // Which change kinds are displayed. All true by default, so the log
    // shows everything it always did until someone narrows it.
    bool evAppear_ = true;
    bool evDisappear_ = true;
    bool evState_ = true;
    // Incremented by the WM_CREATE handler. Zero on a visible window means the
    // controls were never built - a state IsVisible() cannot report.
    unsigned createCount_ = 0;
    // Set while the code scrolls the list itself, so the subclass can tell
    // an intended scroll from a user scroll.
    bool suppressFollow_ = false;
    // Top row to hold while paused, and to restore on resume.
    int pausedTop_ = 0;

    HFONT font_ = nullptr;            // borrowed from MainWindow, never owned

    static const wchar_t* kClassName;
};

}  // namespace wintcp

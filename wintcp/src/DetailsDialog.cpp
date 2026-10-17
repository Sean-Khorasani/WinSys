// DetailsDialog.cpp
// SPDX-License-Identifier: Apache-2.0
// Details window: registered class, a button row, and an owner-drawn body.
// No dialog template, matching the rest of the codebase's zero-dependency
// style (see DetailsDialog.h for why the body is custom-drawn).

#include "DetailsDialog.h"

#include <shellapi.h>
#include <windowsx.h>   // GET_X_LPARAM / GET_Y_LPARAM

#include <algorithm>
#include <cstring>

#include "Utils.h"
#include "FontCache.h"   // header/mono/small faces are cache entries
#include "Theme.h"       // shared dark substitutes + Mix + HC probe

namespace wintcp {
namespace {

// Control ids are local to this window, so they cannot collide with the
// main window's control ids.
const UINT IDC_DLG_COPY  = 1;
const UINT IDC_DLG_OPEN  = 2;
const UINT IDC_DLG_CLOSE = 3;
// the native body scrollbar's child id, for WM_VSCROLL routing.
const UINT IDC_DLG_SCROLL = 4;

// Logical (96 dpi) layout metrics. The renderer works in these units and
// scales once via S(), so a DPI change is one pass over the line list rather
// than a recomputation of every measurement.
constexpr int kMargin = 10;
constexpr int kBtnH = 26;
constexpr int kBtnWCpy = 90;
constexpr int kBtnWOpen = 190;
constexpr int kBtnWClose = 70;
constexpr int kTitleH = 26;         // process name
constexpr int kSubtitleH = 18;      // PID + endpoints
// One field row. It was 17 before the 2026-10-05 rework and each field was
// TWO of these (label, then value), so a section read as 34 px of stacked
// captions. Now it is one row per field, and the extra 2 px buys the vertical
// padding that makes a table legible rather than cramped.
constexpr int kLineH = 19;          // one field row: label | value on one line
constexpr int kSectionH = 24;       // section header band
constexpr int kNoteH = 16;          // dim note under a section
// Label column width, and the one number that decides whether the Details
// window looks like a table or like two columns of unrelated text.
//
// 132 -> 172, sized from the real label vocabulary rather than by eye. The
// longest labels BuildDetailModel emits are "Memory (working set)" (20 chars),
// "Certificate subject" (19) and "Certificate issuer" (18); at the 96 dpi UI
// font those measure roughly 130 px, and the label column is drawn only as far
// as ruleX - kColGap/2. With the gutter at 148 that left ~0 px of leader for the
// longest labels - the dots silently vanished on exactly the rows with the
// longest text, which is where they matter most. 172 leaves ~24 px of leader
// for the worst case and still leaves a 368 px value column at the design width
// of 560 (228 px at the 420 px minimum, enough for an address and a port).
constexpr int kLabelGutter = 172;
constexpr int kScrollBarW = 14;

// How the row is subdivided horizontally. `kColGap` is the clear space between
// the end of a label and the start of its value, which is also where the dotted
// leader is drawn - the leader is what makes the pairing read as a column
// relationship instead of two unrelated strings on one line.
constexpr int kColGap = 18;
// The leader is a run of full stops rather than a drawn line, because a dotted
// rule reads as "these belong together" while a solid one reads as a divider -
// and it costs one DrawText instead of per-pixel plotting.
constexpr int kLeaderDot = 3;
// Vertical padding inside a field row, top and bottom, in logical px.
constexpr int kRowPadY = 3;
// The hairline column rule sits this far left of the value column.
constexpr int kRuleGap = 9;

// Window geometry, authored unscaled and multiplied by the DPI ratio (S/MulDiv).
// The design size appeared TWICE - once in the CreateWindowExW call and once in
// the WM_CREATE handler - and the minimum size is a separate pair that must be
// smaller than the design size or the window can never be opened at any DPI.
// Naming all four makes those two relationships checkable.
constexpr int kDesignWidth = 560;
constexpr int kDesignHeight = 520;
constexpr int kMinWidth = 420;
constexpr int kMinHeight = 400;  // +80 for the tab strip over 320
// The DPI a design pixel is 1:1 at, and the points->pixels divisor. Same two
// numbers as MainWindow.cpp has; not shared because this window scales its own
// layout and coupling the two would tie one window's geometry to the other's.
constexpr int kDpiUnscaled = 96;
constexpr int kPointsPerInch = 72;
constexpr int kBaseFontPt = 9;
// A colour-mix weight, in percent: 10 is a faint tint, 20 a readable one.
constexpr int kTintFaint = 10;
constexpr int kTintBody = 20;
// The accent bar and the leader dots. Strong enough to be seen as marks rather
// than as a tint, weak enough not to compete with the values themselves.
constexpr int kTintAccent = 46;
// A section band under the pointer: stronger than the resting band
// (kTintBody) so hover is visible, weaker than the accent bar so it
// does not compete with it.
constexpr int kTintHover = 32;
// Indent for a field line and for the dim note under a section, in design px.
// Both sites had the same bare 12: the two are visually the same step, and a
// note that did not line up with its heading read as a layout bug.
constexpr int kIndentPx = 12;
// The scrollbar-thumb button at the right of a section row, and its width.
constexpr int kScrollThumbW = 24;
// Width of the margin gutter that holds a section header's collapse
// chevron. The header title starts one gutter in, so the chevron has
// its own column and the titles still line up across sections.
constexpr int kChevronGutter = 14;
// The tab bar lives in the fixed header. One slot per tab; the slot
// width is measured from the label so short tabs don't hoard space and the
// whole row never overflows at the design width.
constexpr int kTabH = 24;
constexpr int kTabGap = 12;           // leading space before the first tab

// Narrowest a tab slot may be, however short its label - "Notes" at any DPI is
// still a clickable target, and a slot below this is not one.
constexpr int kTabMinSlotPx = 48;

// Leader dots are a DRAWN string, so their count is bounded even though the
// from/to span arithmetic already limits it: a malformed rect must not produce
// a megabyte-long run of periods.
constexpr size_t kMaxLeaderDots = 512;

// Dark-theme substitutes live in Theme.h (kSharedDark*): this window used
// to carry its own copy of the same four values, and the charts window
// carried a third. Everything else comes from GetSysColor, so a
// high-contrast scheme wins over the substitutes automatically.

void SetChildFont(HWND hwnd, HFONT font) {
    if (font != nullptr && hwnd != nullptr) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(font),
                       MAKELPARAM(TRUE, 0));
    }
}

// The roster of tabs the model actually has content for, in
// tab-ordinal order. One derivation, shared by RebuildLayout and
// the keyboard tab switcher, so the two can never drift apart.
std::vector<DetailTab> TabRoster(const DetailModel& model) {
    std::vector<DetailTab> tabs;
    for (const DetailSection& sec : model.sections) {
        if (sec.tab != kTabSockets &&
            std::find(tabs.begin(), tabs.end(), sec.tab) == tabs.end())
            tabs.push_back(sec.tab);
    }
    if (!model.connectionLines.empty() &&
        std::find(tabs.begin(), tabs.end(), kTabSockets) == tabs.end())
        tabs.push_back(kTabSockets);
    return tabs;
}

// A small filled triangle: the collapse glyph on a section header.
// 'down' = expanded (points down), else right (collapsed). Drawn
// as a polygon so it needs no font glyph and renders identically
// in every theme.
void DrawChevron(HDC dc, int cx, int cy, int half, bool down,
                   COLORREF col) {
    POINT pts[3];
    if (down) {
        pts[0].x = cx - half;  pts[0].y = cy - half / 2;
        pts[1].x = cx + half;  pts[1].y = cy - half / 2;
        pts[2].x = cx;         pts[2].y = cy + half / 2;
    } else {
        pts[0].x = cx - half / 2; pts[0].y = cy - half;
        pts[1].x = cx - half / 2; pts[1].y = cy + half;
        pts[2].x = cx + half / 2; pts[2].y = cy;
    }
    HPEN pen = ::CreatePen(PS_SOLID, 0, col);
    HBRUSH br = ::CreateSolidBrush(col);
    HPEN oldPen = static_cast<HPEN>(::SelectObject(dc, pen));
    HBRUSH oldBr = static_cast<HBRUSH>(::SelectObject(dc, br));
    ::Polygon(dc, pts, 3);
    ::SelectObject(dc, oldPen);
    ::SelectObject(dc, oldBr);
    ::DeleteObject(pen);
    ::DeleteObject(br);
}

}  // namespace

const wchar_t* DetailsDialog::kClassName = L"WinTcpDetailsWnd";

DetailsDialog::~DetailsDialog() {
    Close();
    // header/mono/small are FontCache-borrowed - never deleted here.
    // The brushes below are still owned, one DeleteObject each.
    if (brushWindow_ != nullptr) ::DeleteObject(brushWindow_);
    if (brushAlternate_ != nullptr) ::DeleteObject(brushAlternate_);
    if (brushSection_ != nullptr) ::DeleteObject(brushSection_);
    if (brushSectionHover_ != nullptr) ::DeleteObject(brushSectionHover_);
    if (brushAccent_ != nullptr) ::DeleteObject(brushAccent_);
}

int DetailsDialog::S(int px96) const {
    const UINT dpi = QueryDpiForWindow(hwnd_);
    return ::MulDiv(px96, static_cast<int>(dpi), kDpiUnscaled);
}

void DetailsDialog::ApplyColors() {
    const auto drop = [](HBRUSH& b) {
        if (b != nullptr) { ::DeleteObject(b); b = nullptr; }
    };
    drop(brushWindow_);
    drop(brushAlternate_);
    drop(brushSection_);
    drop(brushSectionHover_);
    drop(brushAccent_);

    // Always derive from the live system colors. Under high contrast these
    // are the scheme's own values, which is exactly what we want; in a
    // normal theme they are the light palette and the dark branch below
    // substitutes its own.
    //
    // high contrast BYPASSES the dark_ flag. The dark palette is a
    // hard-coded substitute for the light one; under HC the system palette is
    // already chosen for maximum contrast, and overriding it with kDarkBg
    // (near-black) on an HC-white scheme produces unreadable text. The
    // MainWindow pattern is the same: HighContrastActive() returns
    // CDRF_DODEFAULT and the custom draw defers to the system palette.
    COLORREF bg = ::GetSysColor(COLOR_WINDOW);
    COLORREF fg = ::GetSysColor(COLOR_WINDOWTEXT);
    COLORREF dim = ::GetSysColor(COLOR_GRAYTEXT);
    COLORREF header = fg;
    if (dark_ && !HighContrastActive()) {
        bg = kSharedDarkBg;
        fg = kSharedDarkFg;
        dim = kSharedDarkDim;
        header = kSharedDarkHeader;
    }
    clrText_ = fg;
    clrDim_ = dim;
    clrHeader_ = header;
    // A hovered-but-inactive tab sits between the dim idle colour
    // and the full-strength active colour, so the three states read
    // as three distinct things.
    clrHover_ = Mix(clrDim_, clrHeader_, 128);
    brushWindow_ = ::CreateSolidBrush(bg);
    // A small shift is enough to read as a stripe without looking like a
    // different theme, and deriving it makes it work in both palettes.
    brushAlternate_ = ::CreateSolidBrush(Mix(bg, fg, kTintFaint));
    brushSection_ = ::CreateSolidBrush(Mix(bg, fg, kTintBody));
    // The section band under the pointer: brighter than the resting
    // band, so hover is visible, but short of the accent bar.
    brushSectionHover_ = ::CreateSolidBrush(Mix(bg, fg, kTintHover));
    // Stronger than the section band, because the accent bar is the thing that
    // tells the eye where one section stops and the next begins. At kTintBody
    // it was indistinguishable from the band it sat on.
    brushAccent_ = ::CreateSolidBrush(Mix(bg, fg, kTintAccent));
}

void DetailsDialog::CenterOnOwner(HWND owner) {
    if (hwnd_ == nullptr) return;
    RECT rcOwner = {};
    if (owner != nullptr && ::GetWindowRect(owner, &rcOwner)) {
        // Center over the parent window, then clamp into the
        // monitor work area so it never strands off-screen.
        RECT rcSelf = {};
        ::GetWindowRect(hwnd_, &rcSelf);
        const int w = rcSelf.right - rcSelf.left;
        const int h = rcSelf.bottom - rcSelf.top;
        int x = rcOwner.left + ((rcOwner.right - rcOwner.left) - w) / 2;
        int y = rcOwner.top + ((rcOwner.bottom - rcOwner.top) - h) / 2;
        HMONITOR mon = ::MonitorFromRect(&rcOwner, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi = {};
        mi.cbSize = sizeof(mi);
        if (::GetMonitorInfoW(mon, &mi)) {
            const RECT& wa = mi.rcWork;
            if (x + w > wa.right) x = wa.right - w;
            if (y + h > wa.bottom) y = wa.bottom - h;
            if (x < wa.left) x = wa.left;
            if (y < wa.top) y = wa.top;
        }
        ::SetWindowPos(hwnd_, nullptr, x, y, 0, 0,
                       SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

void DetailsDialog::Show(HWND owner, HFONT font, const DetailModel& model,
                         const std::wstring& filePath) {
    model_ = model;
    filePath_ = filePath;
    if (font_ != font) ApplyFont(font);

    const std::wstring caption =
        L"WinTCP - Details - " +
        (model_.title.empty() ? std::wstring(L"(none)") : model_.title);
    if (hwnd_ == nullptr) {
        // Idempotent registration (ERROR_CLASS_ALREADY_EXISTS is fine).
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = &DetailsDialog::WindowProc;
        wc.hInstance = ::GetModuleHandleW(nullptr);
        wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr;   // fully painted in OnPaint
        wc.lpszClassName = kClassName;
        if (::RegisterClassExW(&wc) == 0 &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
            return;

        // A details pane is a read-only inspector, not a document
        // window: it keeps the caption, the close button and the
        // sizing border, but no minimize/maximize boxes - every
        // other inspector window in Windows behaves this way.
        const DWORD style = WS_OVERLAPPED | WS_CAPTION |
                            WS_SYSMENU | WS_THICKFRAME |
                            WS_CLIPCHILDREN;
        hwnd_ = ::CreateWindowExW(0, kClassName, caption.c_str(), style,
                                  CW_USEDEFAULT, CW_USEDEFAULT, kDesignWidth, kDesignHeight,
                                  owner, nullptr, ::GetModuleHandleW(nullptr),
                                  this);
        if (hwnd_ == nullptr) return;
        // Scale the default size to this window's DPI so the dialog is not
        // physically small on 125/150% displays.
        const UINT dpi = QueryDpiForWindow(hwnd_);
        ::SetWindowPos(hwnd_, nullptr, 0, 0,
                       ::MulDiv(kDesignWidth, static_cast<int>(dpi), kDpiUnscaled),
                       ::MulDiv(kDesignHeight, static_cast<int>(dpi), kDpiUnscaled),
                       SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        CenterOnOwner(owner);
    } else {
        ::SetWindowTextW(hwnd_, caption.c_str());
    }

    if (hwndOpen_ != nullptr)
        ::EnableWindow(hwndOpen_, filePath_.empty() ? FALSE : TRUE);

    // A new model can have a different number of sections; keep the
    // collapse vector in step rather than indexing past its end.
    collapsed_.assign(model_.sections.size(), 0);
    RebuildLayout();
    // the body is owner-drawn pixels, so without this a screen reader
    // sees an empty window. The plain-text model is the accessible name;
    // Copy gives the same text verbatim for anyone who wants it all.
    SetAccessibleName(hwnd_, model_.ToPlainText());

    // Owned window: it hides with the owner and stays on top of it.
    if (::IsWindowVisible(hwnd_) == FALSE) ::ShowWindow(hwnd_, SW_SHOW);
    ::SetForegroundWindow(hwnd_);
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void DetailsDialog::UpdateModel(const DetailModel& model) {
    // Silent refresh while auto-refresh runs: no show, no foreground, no
    // focus steal. No-op when the window was closed meanwhile.
    if (hwnd_ == nullptr) return;
    model_ = model;
    if (collapsed_.size() != model_.sections.size())
        collapsed_.assign(model_.sections.size(), 0);
    // RebuildLayout() clamps scrollPos_ to the new content height, so a
    // live refresh that shrinks the list cannot leave the view scrolled
    // past the end.
    RebuildLayout();
    // live stats change the text every tick, so the name follows the
    // model - a stale announcement of last tick's numbers would be worse
    // than none while auto-refresh runs.
    SetAccessibleName(hwnd_, model_.ToPlainText());
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void DetailsDialog::SetDark(bool dark) {
    if (dark_ == dark) return;
    dark_ = dark;
    ApplyColors();
    if (hwnd_ != nullptr) ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void DetailsDialog::Close() {
    if (hwnd_ != nullptr && ::IsWindow(hwnd_)) ::DestroyWindow(hwnd_);
}

bool DetailsDialog::IsVisible() const {
    return hwnd_ != nullptr && ::IsWindowVisible(hwnd_) == TRUE;
}

void DetailsDialog::ApplyFont(HFONT font) {
    font_ = font;   // borrowed from MainWindow; never deleted here
    if (font_ == nullptr) return;
    if (hwnd_ != nullptr) {
        // the three derived faces are FontCache entries at fixed
        // point sizes (11 bold ~ the old 125%, 9 mono, 8 for notes),
        // resolved at this window's own DPI. The cache owns every
        // handle, so unlike the old CreateFontIndirect trio there is
        // nothing to delete on rebuild - and a DPI move re-resolves
        // instead of chasing a stale copy. Measuring (RebuildLayout,
        // below) always runs after a re-resolve, so slots and paint
        // agree on the new faces.
        const UINT dpi = QueryDpiForWindow(hwnd_);
        if (!fontsReady_ || fontDpi_ != dpi) {
            fontDpi_ = dpi;
            headerFont_ = FontCache::Get().Get(11, FW_BOLD, dpi);
            monoFont_ =
                FontCache::Get().Get(kBodyPtSize, FW_NORMAL, dpi, true);
            smallFont_ = FontCache::Get().Get(8, FW_NORMAL, dpi);
            fontsReady_ = true;
            ApplyColors();
        }
    }
    SetChildFont(hwndCopy_, font_);
    SetChildFont(hwndOpen_, font_);
    SetChildFont(hwndClose_, font_);
    if (hwnd_ != nullptr) {
        RECT rc = {};
        ::GetClientRect(hwnd_, &rc);
        Layout(rc.right, rc.bottom);
        RebuildLayout();
    }
}

int DetailsDialog::MaxScroll() const {
    // the scrollable range is the BODY (total minus the pinned
    // header) minus the viewport, all in physical pixels. The old form
    // subtracted the viewport from a total that mixed logical line
    // heights with physical pixels - and counted the pinned header as
    // scrollable besides, so the last screen of every tab was blank.
    const int over = totalContentHeight_ - headerHeight_ - viewHeight_;
    return (over > 0) ? over : 0;
}

void DetailsDialog::ScrollBy(int lines) {
    // The step is physical: scrollPos_ is compared against a physical
    // MaxScroll and subtracted from physical paint coordinates, so a
    // logical step drifted off-96dpi.
    SetScrollPosAbsolute(scrollPos_ + lines * S(kLineH));
}

void DetailsDialog::SetScrollPosAbsolute(int pos) {
    int next = pos;
    const int maxScroll = MaxScroll();
    if (next > maxScroll) next = maxScroll;
    if (next < 0) next = 0;
    if (next == scrollPos_) return;
    scrollPos_ = next;
    SyncScrollBar();
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

int DetailsDialog::PageLines() const {
    const int lineH = S(kLineH);
    if (lineH <= 0 || viewHeight_ <= 0) return 1;
    const int lines = viewHeight_ / lineH;
    return (lines > 0) ? lines : 1;
}

int DetailsDialog::ScrollBarWidth() const {
    const int metric = ::GetSystemMetrics(SM_CXVSCROLL);
    return (metric > 0) ? metric : S(kScrollBarW);
}

void DetailsDialog::SyncScrollBar() {
    // Push range/page/position into the native scrollbar, or hide it
    // when the body fits. nMax is bodyTotal - 1 because a scrollbar's
    // top position is nMax - page + 1, which must equal MaxScroll().
    if (hwndScroll_ == nullptr) return;
    const int bodyTotal = totalContentHeight_ - headerHeight_;
    if (MaxScroll() <= 0 || viewHeight_ <= 0 || bodyTotal <= 0) {
        ::ShowWindow(hwndScroll_, SW_HIDE);
        return;
    }
    ::ShowWindow(hwndScroll_, SW_SHOW);
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = bodyTotal - 1;
    si.nPage = static_cast<UINT>(viewHeight_);
    si.nPos = scrollPos_;
    ::SetScrollInfo(hwndScroll_, SB_CTL, &si, TRUE);
}

void DetailsDialog::RebuildLayout() {
    // The model is turned into a flat list of physical lines once per change;
    // painting is then a straight run of DrawText calls. Line heights are the
    // fixed logical metrics above; header slots are scaled (S()) here so the
    // pinned/header region is in physical pixels for the click and layout math.
    // A scratch DC is taken only to measure tab labels - at most kTabCount,
    // and never on the paint path.
    lines_.clear();
    lines_.reserve(64);   // ~4 screens of fields
    totalContentHeight_ = 0;
    headerHeight_ = 0;

    const auto push = [this](const Line& l) {
        lines_.push_back(l);
        // scaled here, once. Line::height is a logical metric id;
        // everything that consumes the total (MaxScroll, the thumb, the
        // paint loop) is physical, so the sum must be too.
        totalContentHeight_ += S(l.height);
    };
    const auto pushHeader = [this, &push](const Line& l) {
        push(l);
        // headerHeight_ is physical (scaled), because Layout and the click/hover
        // bounds compare it against the physical client area. totalContentHeight_
        // is physical too (see push); MaxScroll subtracts the header back out
        // because pinned lines never scroll.
        headerHeight_ += S(l.height);
    };

    if (!model_.title.empty()) {
        Line l;
        l.kind = Line::SectionHeader;
        l.text = model_.title;
        l.height = kTitleH;
        l.section = -1;
        l.pinned = true;
        pushHeader(l);
    }
    if (!model_.subtitle.empty()) {
        Line l;
        l.kind = Line::FieldValue;
        l.text = model_.subtitle;
        l.height = kSubtitleH;
        l.indent = 2;
        l.section = -1;
        l.pinned = true;
        pushHeader(l);
    }
    if (!model_.title.empty() || !model_.subtitle.empty()) {
        Line l;
        l.kind = Line::Blank;
        l.height = kMargin;
        l.section = -1;
        l.pinned = true;
        pushHeader(l);
    }

    // the tab bar is fixed in the header, one slot per tab that the
    // current model actually has content for, in tab-ordinal order. Derive
    // the roster from the sections rather than hard-coding the five, so a
    // row that has no TLS simply drops the Security tab instead of showing
    // an empty one. connectionLines (the Sockets tab) are counted too.
    // TabRoster() is the single derivation; the keyboard tab switcher
    // shares it so the two cannot drift.
    const std::vector<DetailTab> tabs = TabRoster(model_);
    // Clamp the active tab to the roster; a new model may not contain it.
    if (tabs.empty() ||
        std::find(tabs.begin(), tabs.end(), model_.activeTab) == tabs.end())
        model_.activeTab = tabs.empty() ? kTabProcess : tabs.front();

    const DetailTab active = model_.activeTab;
    const int m = S(kMargin);
    const int tabSlotH = S(kTabH);
    // Measure tab labels with the header font. A scratch DC is fine here:
    // at most kTabCount labels, and RebuildLayout is not on the paint path,
    // so GetPaintDC (which only works during WM_PAINT) is intentionally NOT
    // used. hwnd_ is valid whenever RebuildLayout runs.
    HDC hdc = hwnd_ != nullptr ? ::GetDC(hwnd_) : ::GetDC(nullptr);
    HGDIOBJ oldFont = nullptr;
    if (hdc != nullptr && headerFont_ != nullptr)
        oldFont = ::SelectObject(hdc, headerFont_);
    int tabX = m;               // running x of the next tab slot
    for (DetailTab t : tabs) {
        Line l;
        l.kind = Line::Tab;
        l.text = TabLabel(t);
        l.height = kTabH;
        l.section = static_cast<int>(t);
        l.pinned = true;
        // Layout: the strip is one row shared by all tabs. The running
        // cursor lays the slots out left to right; each slot's x origin is
        // kept on the struct through 'indent' (reused here as the origin so
        // paint, click and hover share one value), and the strip's y comes
        // from tabBarY_/tabBarH_ below - never from stacking the lines.
        l.indent = tabX;
        pushHeader(l);
        // Measure the label so the slot width tracks its content, with a
        // minimum that keeps a short tab (e.g. "Notes") clickable. The width
        // is stored back on the pushed line so OnPaint and OnMouseDown share
        // one value.
        SIZE sz = {};
        if (hdc != nullptr && !l.text.empty())
            ::GetTextExtentPoint32W(hdc, l.text.c_str(),
                                    static_cast<int>(l.text.size()), &sz);
        const int slotW = (std::max)(S(kTabMinSlotPx),
                                     static_cast<int>(sz.cx) + S(kColGap));
        lines_.back().width = slotW;
        tabX += slotW + S(kTabGap);
    }
    if (oldFont != nullptr) ::SelectObject(hdc, oldFont);
    if (hdc != nullptr) {
        if (hwnd_ != nullptr) ::ReleaseDC(hwnd_, hdc);
        else ::ReleaseDC(nullptr, hdc);
    }
    (void)tabSlotH;

    // The tabs share ONE row. The loop above pushed one line per tab, each of
    // height kTabH, but the slots paint side-by-side from their running-x
    // origins - stacking them vertically is what read as "cascaded", with
    // each tab lower and further right than the last. Only the first tab's
    // height is real layout, so the other N-1 are subtracted back out of
    // both totals: the body must start under the strip, not under N phantom
    // rows, and the scroll range must not count rows that are never drawn.
    const int tabCount = static_cast<int>(tabs.size());
    const int extraTabs = (tabCount > 1) ? tabCount - 1 : 0;
    if (extraTabs > 0) {
        totalContentHeight_ -= extraTabs * S(kTabH);
        headerHeight_ -= extraTabs * S(kTabH);
    }
    tabBarH_ = tabs.empty() ? 0 : S(kTabH);
    tabBarY_ = m + headerHeight_ - tabBarH_;

    // The body scrolls. Only the active tab's sections render (plus the
    // Sockets-tab connection list), so switching tabs collapses the body to
    // the relevant fields without a separate hide/show pass.
    for (size_t s = 0; s < model_.sections.size(); ++s) {
        const DetailSection& sec = model_.sections[s];
        if (sec.tab != active) continue;
        Line h;
        h.kind = Line::SectionHeader;
        h.text = sec.title;
        h.height = kSectionH;
        h.section = static_cast<int>(s);
        push(h);

        const bool isCollapsed =
            (s < collapsed_.size() && collapsed_[s] != 0);
        if (isCollapsed) continue;

        // ONE row per field, carrying both halves - see Line::FieldRow for why.
        for (const DetailField& f : sec.fields) {
            Line l;
            l.kind = Line::FieldRow;
            l.text = f.label;
            l.value = f.value;
            // Monospace is a property of the VALUE, not the pair: a monospace
            // label would push the value column out of alignment, because the
            // two columns are aligned by position, not by text.
            l.monospace = f.monospace;
            l.section = static_cast<int>(s);
            l.height = kLineH;
            push(l);
        }
        if (!sec.note.empty()) {
            Line n;
            n.kind = Line::SectionNote;
            n.text = sec.note;
            n.height = kNoteH;
            n.indent = kLabelGutter;
            n.section = static_cast<int>(s);
            push(n);
        }
    }

    if (active == kTabSockets && !model_.connectionLines.empty()) {
        Line h;
        h.kind = Line::SectionHeader;
        h.text = L"Connections (" + std::to_wstring(model_.connectionTotal) +
                 L")";
        h.height = kSectionH;
        h.section = -1;
        push(h);
        for (const std::wstring& c : model_.connectionLines) {
            Line l;
            l.kind = Line::Connection;
            l.text = c;
            l.monospace = true;
            l.height = kLineH;
            l.indent = kIndentPx;
            l.section = -1;
            push(l);
        }
        if (model_.connectionTotal > model_.connectionLines.size()) {
            Line n;
            n.kind = Line::SectionNote;
            n.text = L"… and " +
                     std::to_wstring(model_.connectionTotal -
                                     model_.connectionLines.size()) +
                     L" more";
            n.height = kNoteH;
            n.indent = kIndentPx;
            n.section = -1;
            push(n);
        }
    }
    const int maxScroll = MaxScroll();
    if (scrollPos_ > maxScroll) scrollPos_ = maxScroll;
    SyncScrollBar();
}

void DetailsDialog::ActivateTab(int delta) {
    const std::vector<DetailTab> tabs = TabRoster(model_);
    if (tabs.size() < 2) return;
    auto it = std::find(tabs.begin(), tabs.end(), model_.activeTab);
    int idx = (it == tabs.end())
                  ? 0
                  : static_cast<int>(it - tabs.begin());
    const int n = static_cast<int>(tabs.size());
    idx = (idx + delta + n) % n;
    const DetailTab t = tabs[static_cast<size_t>(idx)];
    if (t == model_.activeTab) return;
    model_.activeTab = t;
    scrollPos_ = 0;   // the new tab has its own body height
    RebuildLayout();
    ::InvalidateRect(hwnd_, nullptr, FALSE);
}

void DetailsDialog::Layout(int cx, int cy) {
    if (hwnd_ == nullptr) return;
    const int m = S(kMargin);
    const int btnH = S(kBtnH);
    const int btnY = cy - m - btnH;
    const int btnRowH = btnH + m;

    // The body is painted, not a child, so it only needs its height: the
    // area between the header (title + tab bar, pinned) and the button row.
    const int top = m + headerHeight_;
    viewHeight_ = cy - btnRowH - top - m;
    if (viewHeight_ < 0) viewHeight_ = 0;

    // the native scrollbar owns the body's right edge, full body
    // height. Positioned here (not painted in OnPaint), so it tracks
    // resizes exactly like the buttons do.
    if (hwndScroll_ != nullptr) {
        const int sbW = ScrollBarWidth();
        ::MoveWindow(hwndScroll_, cx - m - sbW, top, sbW,
                     (viewHeight_ > 0) ? viewHeight_ : 0, TRUE);
    }
    SyncScrollBar();

    if (hwndCopy_ != nullptr)
        ::MoveWindow(hwndCopy_, m, btnY, S(kBtnWCpy), btnH, TRUE);
    if (hwndOpen_ != nullptr)
        ::MoveWindow(hwndOpen_, m + S(kBtnWCpy) + m, btnY, S(kBtnWOpen), btnH,
                     TRUE);
    if (hwndClose_ != nullptr)
        ::MoveWindow(hwndClose_, cx - m - S(kBtnWClose), btnY,
                     S(kBtnWClose), btnH, TRUE);
}

void DetailsDialog::PaintLine(HDC mem, const Line& l, int y, int lh, int cx,
                              int m, int ruleX, bool withLeaders,
                              int textRight, int fieldInSection) {
    // Selects the right face for this row kind. Section headers and
    // tabs keep their own faces; notes and field rows differ. Field
    // rows honour the value's monospace flag separately below (the
    // label always uses the UI face).
    //
    // The Tab case is load-bearing: RebuildLayout measures every tab
    // slot with headerFont_ selected, so the slot width is the BOLD
    // face's width. Painting the label with any other face draws
    // text narrower than the slot it owns - the tabs then sit in
    // oversized, unevenly-spaced slots and the active highlight is
    // wider than its label, which reads as "mis-aligned". Measure
    // and paint must agree, so the Tab face IS headerFont_.
    const HFONT face =
        (l.kind == Line::SectionHeader) ? headerFont_
        : (l.kind == Line::Tab)          ? headerFont_
        : (l.kind == Line::SectionNote)   ? smallFont_
        : l.monospace                     ? monoFont_
                                          : font_;
    if (face != nullptr) ::SelectObject(mem, face);

    if (l.kind == Line::Tab) {
        // tab bar slot. Active tab = header colour with an accent
        // underline; inactive = dim; hover brightens the label. Layout stored
        // the slot origin in 'indent' and its measured width in 'width'.
        const bool active = (l.section == static_cast<int>(model_.activeTab));
        // Hovering the ACTIVE tab keeps the active colour (it already
        // owns the band and the underline); hovering an inactive tab
        // uses the intermediate hover colour, which is distinct from
        // both the dim idle colour and the active one - so hover no
        // longer reads as selection.
        const COLORREF tabFg = active
                                  ? clrHeader_
                                  : (l.section == hotTab_ ? clrHover_
                                                          : clrDim_);
        ::SetTextColor(mem, tabFg);
        const int slotW = l.width;
        RECT tr = {l.indent, y, l.indent + slotW, y + lh};
        if (active && brushSection_ != nullptr) ::FillRect(mem, &tr, brushSection_);
        ::DrawTextW(mem, l.text.c_str(), static_cast<int>(l.text.size()),
                    &tr, DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX |
                        DT_END_ELLIPSIS);
        if (active && brushAccent_ != nullptr) {
            RECT bar = {l.indent, y + lh - S(2), l.indent + slotW, y + lh};
            ::FillRect(mem, &bar, brushAccent_);
        }
        return;
    }

    // Alternating shading on field rows only, and a band behind every section
    // header - the same policy as before the tab bar, routed through the painter.
    if (l.kind == Line::FieldRow) {
        if ((fieldInSection % 2) == 0 && brushAlternate_ != nullptr) {
            RECT band = {0, y, cx, y + lh};
            ::FillRect(mem, &band, brushAlternate_);
        }
    } else if (l.kind == Line::SectionHeader && brushSection_ != nullptr) {
        RECT band = {0, y, cx, y + lh};
        // Hover brightens the band itself - the old code filled a
        // rect with the SAME brush the band already used, so hover
        // was invisible, and its x was a doubly-scaled S(kMargin-
        // S(2)). The hover brush is a real, derived tint now.
        const bool hovered = (l.section >= 0 && l.section == hotSection_);
        ::FillRect(mem, &band,
                       hovered && brushSectionHover_ != nullptr
                           ? brushSectionHover_ : brushSection_);
        // Accent bar on EVERY section header, not only the hovered one.
        if (brushAccent_ != nullptr) {
            RECT bar = {0, y, S(3), y + lh};
            ::FillRect(mem, &bar, brushAccent_);
        }
        // The collapse chevron. It is the ONLY affordance that a
        // section can be collapsed, so it is drawn whenever the
        // header is a real, collapsible section. The synthetic
        // "Connections" header (section == -1) is not collapsible
        // and gets none.
        if (l.section >= 0 &&
            static_cast<size_t>(l.section) < collapsed_.size()) {
            const bool isCollapsed =
                collapsed_[static_cast<size_t>(l.section)] != 0;
            DrawChevron(mem, m + S(kChevronGutter) / 2, y + lh / 2,
                            S(4), !isCollapsed, clrHeader_);
        }
    }

    if (l.kind == Line::FieldRow) {
        // ---- the two columns -------------------------------------
        // Label, in the gutter. Ellipsised, because a label that overruns
        // its column would otherwise push into the value.
        ::SetTextColor(mem, clrDim_);
        RECT labelRect = {m, y, ruleX - S(kColGap) / 2, y + lh};
        ::DrawTextW(mem, l.text.c_str(),
                    static_cast<int>(l.text.size()), &labelRect,
                    DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX |
                        DT_END_ELLIPSIS);

        // The dotted leader between them. Measured from the label that was
        // actually drawn, so it starts where the text ends rather than at a
        // guessed offset - with DT_END_ELLIPSIS the drawn label may be
        // shorter than the original string.
        //
        // the old form overwrote labelRect.right with labelRect.left
        // and then asked `want.cx < labelRect.right` - a text WIDTH against
        // an x COORDINATE, true only left of ~100 px - so leaders almost
        // never drew. The bound is the label column's width now, compared
        // before anything is overwritten; the full label must fit
        // unellipsised, so the drawn end is exactly left + want.cx.
        if (brushAccent_ != nullptr && withLeaders && !l.text.empty() &&
            !l.value.empty()) {
            const int labelColR = ruleX - S(kColGap) / 2;
            const int labelAvail = labelColR - labelRect.left;
            SIZE want = {};
            ::GetTextExtentPoint32W(
                mem, l.text.c_str(), static_cast<int>(l.text.size()), &want);
            if (want.cx > 0 && want.cx < labelAvail) {
                SIZE dotSize = {};
                ::GetTextExtentPoint32W(mem, L"..", 2, &dotSize);
                const int step = (std::max)(
                    1, static_cast<int>(dotSize.cx) / 2 + S(kLeaderDot));
                const int from =
                    (std::min)(static_cast<int>(labelRect.left + want.cx),
                               static_cast<int>(labelRect.right)) +
                    S(kColGap) / 2;
                const int to = ruleX - S(kColGap) / 2 - S(kRuleGap) / 2;
                std::wstring dots;
                for (int dx = from; dx < to; dx += step) {
                    dots.push_back(L'.');
                    if (dots.size() >= kMaxLeaderDots) break;
                }
                if (!dots.empty() && clrDim_ != 0) {
                    ::SetTextColor(mem, clrDim_);
                    RECT dotRect = {from, y, to, y + lh};
                    ::DrawTextW(mem, dots.c_str(),
                                static_cast<int>(dots.size()), &dotRect,
                                DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
                }
            }
        }

        // The hairline between the two columns, inset from the leader so it
        // never touches the value text.
        if (brushAccent_ != nullptr) {
            RECT rule = {ruleX, y + S(kRowPadY), ruleX + 1,
                         y + lh - S(kRowPadY)};
            ::FillRect(mem, &rule, brushAccent_);
        }

        // Value, starting at a fixed x so the column is aligned regardless of
        // label length. Monospace only when the field asked for it; the label
        // always uses the UI face.
        if (font_ != nullptr) ::SelectObject(mem, font_);
        ::SetTextColor(mem, clrText_);
        const HFONT valueFace = l.monospace ? monoFont_ : font_;
        if (valueFace != nullptr) ::SelectObject(mem, valueFace);
        RECT valueRect = {m + S(kLabelGutter), y, textRight, y + lh};
        ::DrawTextW(mem, l.value.c_str(),
                    static_cast<int>(l.value.size()), &valueRect,
                    DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX |
                        DT_END_ELLIPSIS);
        return;
    }

    // Single-column rows: subtitle, note, connection line.
    ::SetTextColor(mem,
                   (l.kind == Line::SectionNote)     ? clrDim_
                   : (l.kind == Line::SectionHeader) ? clrHeader_
                                                            : clrText_);
    // A section header carries a collapse chevron in the margin,
    // so its title starts one chevron gutter in - every header
    // title then lines up in its own column, clear of the glyph.
    const int left = (l.kind == Line::SectionHeader)
                         ? m + S(kChevronGutter)
                         : m + S(l.indent);
    RECT draw = {left, y, textRight, y + lh};
    ::DrawTextW(mem, l.text.c_str(), static_cast<int>(l.text.size()),
                &draw,
                DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX |
                    DT_END_ELLIPSIS);
}

void DetailsDialog::OnPaint() {
    PAINTSTRUCT ps = {};
    HDC hdc = ::BeginPaint(hwnd_, &ps);
    if (hdc == nullptr) return;

    RECT rc = {};
    ::GetClientRect(hwnd_, &rc);
    const int cx = rc.right, cy = rc.bottom;

    // Double-buffer: the body is a long run of DrawText calls, and doing
    // them straight to the window DC flickers on any redraw.
    HDC mem = ::CreateCompatibleDC(hdc);
    HBITMAP bmp = ::CreateCompatibleBitmap(hdc, cx, cy);
    HGDIOBJ oldBmp = (bmp != nullptr) ? ::SelectObject(mem, bmp) : nullptr;
    if (brushWindow_ != nullptr) ::FillRect(mem, &rc, brushWindow_);

    ::SetBkMode(mem, TRANSPARENT);

    const int m = S(kMargin);
    const int ruleX = m + S(kLabelGutter) - S(kRuleGap);

    // --- pinned header: title + subtitle block + tab bar (fixed at the top) ---
    // Painted without the scroll offset, so the process identity and the tab
    // strip stay in view as the body scrolls beneath them. The header spans
    // the full width: the scrollbar owns only the body's right edge.
    //
    // The tabs are ONE strip, not N rows: every Tab line paints at the
    // strip's own y from its measured x origin, and the cursor advances past
    // the strip once. Advancing once per tab stacked them diagonally - each
    // tab lower and further right - which was the "cascaded" report.
    int y = m;
    const int headerRight = cx - m;
    bool tabStripPainted = false;
    for (const Line& l : lines_) {
        if (!l.pinned) break;
        if (l.kind == Line::Tab) {
            if (!tabStripPainted) {
                tabStripPainted = true;
                if (tabBarY_ + tabBarH_ > 0 && tabBarY_ < cy) {
                    for (const Line& t : lines_) {
                        if (!t.pinned || t.kind != Line::Tab) continue;
                        PaintLine(mem, t, tabBarY_, S(t.height), cx, m,
                                  ruleX, false, headerRight);
                    }
                }
                y += tabBarH_;
            }
            continue;
        }
        const int lh = S(l.height);
        if (y + lh > 0 && y < cy)
            PaintLine(mem, l, y, lh, cx, m, ruleX, false, headerRight);
        y += lh;
    }
    const int headerBottom = y;   // one past the last pinned line

    // --- scrollable body: the active tab's sections + Sockets list ---------------
    //
    // The body's own bottom edge, which is ABOVE the button row. The clip used
    // to be `y <= cy` - the full client height - so the last visible fields were
    // painted behind Copy / Open File Location / Close. The buttons are child
    // windows and cover part of it; the rest showed through around them. That is
    // the "the table goes under the buttons" report, and it was a missing bound
    // rather than a layout error: Layout() already computed viewHeight_ correctly
    // and the hand-drawn scrollbar already honoured it.
    //
    // DEPENDS ON viewHeight_ BEING SET BEFORE THE FIRST PAINT, because it
    // defaults to 0 and `m + 0 == m` would clip the body to nothing - a blank
    // window rather than a wrong one, which is at least not silently plausible.
    // Two independent paths establish it: WM_CREATE calls ApplyFont, which calls
    // Layout(GetClientRect) at the end; and WM_SIZE calls Layout directly, and a
    // created window is always sent WM_SIZE before it is ever painted. So this
    // bound is safe today, but it is a landmine for anyone who adds a paint path
    // that can run before both - if you add one, call Layout() first.
    const int contentBottom = headerBottom + viewHeight_;

    // the body stops clear of the native scrollbar when one is shown,
    // instead of running under the hand-drawn thumb it replaced.
    const int bodyRight =
        cx - m - ((MaxScroll() > 0 && viewHeight_ > 0)
                      ? ScrollBarWidth() + S(4)
                      : 0);

    int fieldInSection = 0;
    y = headerBottom - scrollPos_;
    for (const Line& l : lines_) {
        if (l.pinned) continue;   // header already drawn above
        const int lh = S(l.height);
        if (l.kind == Line::FieldRow) ++fieldInSection;
        // Clipped to the BODY, not the client rect. `y < contentBottom` also
        // stops a row being drawn when only its very bottom edge is inside.
        if (y + lh > headerBottom && y < contentBottom)
            PaintLine(mem, l, y, lh, cx, m, ruleX, true, bodyRight,
                      fieldInSection);
        y += lh;
    }

    // no hand-drawn scrollbar. The native SCROLLBAR child (hwndScroll_,
    // positioned in Layout, synced in SyncScrollBar) owns this region's
    // right edge now - track, thumb, hover/press states and all.

    ::BitBlt(hdc, 0, 0, cx, cy, mem, 0, 0, SRCCOPY);
    if (oldBmp != nullptr) ::SelectObject(mem, oldBmp);
    if (bmp != nullptr) ::DeleteObject(bmp);
    ::DeleteDC(mem);
    ::EndPaint(hwnd_, &ps);
}

void DetailsDialog::OnMouseDown(int x, int y) {
    // Two interactive surfaces: the tab bar (pinned header) and the section
    // headers in the body. A click elsewhere is left alone so the window still
    // behaves like a static read-out.
    const int m = S(kMargin);

    // --- tab bar: one strip, pinned at the top, before the scroll offset ---
    // Every tab slot's rect comes from the tab Lines RebuildLayout stored
    // (origin in 'indent', width measured from the label), tested against
    // the strip's single row - so the hit test and the paint stay in
    // lockstep. The old per-line stacking only matched the first tab's row
    // and cascaded the rest, which is why all but one tab looked - and
    // were - unreachable in place.
    if (tabBarH_ > 0 && y >= tabBarY_ && y < tabBarY_ + tabBarH_) {
        for (const Line& l : lines_) {
            if (!l.pinned) break;
            if (l.kind != Line::Tab) continue;
            if (x >= l.indent && x < l.indent + l.width) {
                const DetailTab t = static_cast<DetailTab>(l.section);
                if (t != model_.activeTab) {
                    model_.activeTab = t;
                    RebuildLayout();
                    ::InvalidateRect(hwnd_, nullptr, FALSE);
                }
                return;
            }
        }
        // In the strip but on no slot: the strip owns its row, so the click
        // ends here instead of falling through to a section underneath.
        return;
    }

    // --- body: the same missing bound as the paint loop, for the same reason -
    // a click in the button row used to match a row behind it and toggle that
    // section while the user was aiming at Close.
    if (y >= m + headerHeight_ + viewHeight_) return;
    // Mirror the paint clip on the other side too: when scrolled, body lines
    // slide up under the pinned header, and without this a click on the
    // title or tab strip that missed every slot would toggle a section
    // hiding underneath it.
    if (y < m + headerHeight_) return;
    int ly = m + headerHeight_ - scrollPos_;
    for (const Line& l : lines_) {
        // Pinned lines are skipped WITHOUT advancing: the paint loop draws
        // the body from headerBottom - scrollPos_ with the header already
        // accounted for, and this cursor must start from the same origin.
        // Advancing past the header here shifted every hit test down by a
        // full header height, so
        // clicks and hover agreed with each other but not with what was
        // painted - section headers only toggled when clicked a header-height
        // below themselves.
        if (l.pinned) continue;   // header, already covered
        const int lh = S(l.height);
        if (y >= ly && y < ly + lh) {
            if (l.kind == Line::SectionHeader && l.section >= 0 &&
                static_cast<size_t>(l.section) < collapsed_.size()) {
                collapsed_[static_cast<size_t>(l.section)] ^= 1;
                RebuildLayout();
                ::InvalidateRect(hwnd_, nullptr, FALSE);
            }
            return;
        }
        ly += lh;
    }
    (void)x;
}

void DetailsDialog::CopyTextToClipboard() {
    const std::wstring text = model_.ToPlainText();
    if (text.empty()) return;
    if (!::OpenClipboard(hwnd_)) return;   // another app holds it
    ::EmptyClipboard();
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL hMem = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hMem != nullptr) {
        void* dst = ::GlobalLock(hMem);
        if (dst != nullptr) {
            ::memcpy(dst, text.c_str(), bytes);
            ::GlobalUnlock(hMem);
            if (::SetClipboardData(CF_UNICODETEXT, hMem) == nullptr)
                ::GlobalFree(hMem);
            hMem = nullptr;
        }
        if (hMem != nullptr) ::GlobalFree(hMem);
    }
    ::CloseClipboard();
}

void DetailsDialog::OnCommand(WORD id) {
    switch (id) {
        case IDC_DLG_COPY:
            CopyTextToClipboard();
            break;
        case IDC_DLG_OPEN: {
            if (filePath_.empty()) break;
            // Same implementation as the context menu
            // (Utils::ShowFileInExplorer): "explorer.exe /select,". The
            // failure is reported rather than silent - a missing file
            // otherwise looks exactly like a working button.
            std::wstring error;
            if (!ShowFileInExplorer(filePath_, &error)) {
                ::MessageBoxW(hwnd_, error.c_str(), L"Open file location",
                              MB_OK | MB_ICONWARNING);
            }
            break;
        }
        case IDC_DLG_CLOSE:
            ::ShowWindow(hwnd_, SW_HIDE);
            break;
        default:
            break;
    }
}

LRESULT CALLBACK DetailsDialog::WindowProc(HWND hwnd, UINT msg, WPARAM wParam,
                                           LPARAM lParam) {
    auto* self = reinterpret_cast<DetailsDialog*>(
        ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        self = static_cast<DetailsDialog*>(cs->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                            reinterpret_cast<LONG_PTR>(self));
        if (self != nullptr) self->hwnd_ = hwnd;
    }
    if (self != nullptr) return self->HandleMessage(msg, wParam, lParam);
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT DetailsDialog::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            const HINSTANCE inst = ::GetModuleHandleW(nullptr);
            hwndCopy_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Copy", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DLG_COPY)),
                inst, nullptr);
            hwndOpen_ = ::CreateWindowExW(
                0, L"BUTTON", L"&Open file location",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DLG_OPEN)),
                inst, nullptr);
            hwndClose_ = ::CreateWindowExW(
                0, L"BUTTON", L"C&lose",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DLG_CLOSE)),
                inst, nullptr);
            // the body's native scrollbar. Positioned in Layout, synced
            // in SyncScrollBar; hidden when the body fits, so a short tab
            // shows no chrome it does not need.
            hwndScroll_ = ::CreateWindowExW(
                0, L"SCROLLBAR", nullptr,
                WS_CHILD | WS_VISIBLE | SBS_VERT,
                0, 0, 0, 0, hwnd_,
                reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_DLG_SCROLL)),
                inst, nullptr);
            ApplyFont(font_);   // derived faces + palette + first layout
            RebuildLayout();
            return 0;
        }
        case WM_SIZE:
            Layout(LOWORD(lParam), HIWORD(lParam));
            ::InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
        case WM_GETMINMAXINFO: {
            // Never let the window shrink into a state where Layout() would
            // compute a negative view height.
            const UINT dpi = QueryDpiForWindow(hwnd_);
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x = ::MulDiv(kMinWidth, static_cast<int>(dpi), kDpiUnscaled);
            mmi->ptMinTrackSize.y = ::MulDiv(kMinHeight, static_cast<int>(dpi), kDpiUnscaled);
            return 0;
        }
        case WM_DPICHANGED: {
            const auto* suggested = reinterpret_cast<const RECT*>(lParam);
            ::SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                           suggested->right - suggested->left,
                           suggested->bottom - suggested->top,
                           SWP_NOZORDER | SWP_NOACTIVATE);
            // The derived faces are relative to font_, so rebuild them and
            // re-measure: moving to another monitor can change the scale.
            fontsReady_ = false;
            ApplyFont(font_);
            ::InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
        }
        case WM_COMMAND:
            // BN_CLICKED only: without the notification check an
            // enable/disable notification would also trigger the command.
            if (HIWORD(wParam) == BN_CLICKED) OnCommand(LOWORD(wParam));
            return 0;
        case WM_CLOSE:
            ::ShowWindow(hwnd_, SW_HIDE);   // keep it around for reuse
            return 0;
        case WM_DESTROY:
            hwnd_ = nullptr;
            hwndCopy_ = hwndOpen_ = hwndClose_ = nullptr;
            hwndScroll_ = nullptr;
            fontsReady_ = false;
            return 0;
        case WM_VSCROLL: {
            // the native scrollbar's own messages. Thumb-track drags,
            // arrows, paging and Home/End all land here with system
            // hover/press states - the hand-drawn thumb had none.
            if (reinterpret_cast<HWND>(lParam) != hwndScroll_) break;
            switch (LOWORD(wParam)) {
                case SB_LINEUP:
                    ScrollBy(-1);
                    return 0;
                case SB_LINEDOWN:
                    ScrollBy(1);
                    return 0;
                case SB_PAGEUP:
                    ScrollBy(-PageLines());
                    return 0;
                case SB_PAGEDOWN:
                    ScrollBy(PageLines());
                    return 0;
                case SB_TOP:
                    SetScrollPosAbsolute(0);
                    return 0;
                case SB_BOTTOM:
                    SetScrollPosAbsolute(MaxScroll());
                    return 0;
                case SB_THUMBTRACK:
                case SB_THUMBPOSITION: {
                    SCROLLINFO si = {};
                    si.cbSize = sizeof(si);
                    si.fMask = SIF_TRACKPOS;
                    if (::GetScrollInfo(hwndScroll_, SB_CTL, &si) != FALSE)
                        SetScrollPosAbsolute(si.nTrackPos);
                    return 0;
                }
                case SB_ENDSCROLL:
                    return 0;
                default:
                    break;
            }
            break;
        }
        case WM_MOUSEWHEEL: {
            // WHEEL_DELTA is 120 per notch; 3 lines per notch matches the
            // main list closely enough not to feel different.
            const int notches = GET_WHEEL_DELTA_WPARAM(wParam) / WHEEL_DELTA;
            ScrollBy(-notches * 3);
            return 0;
        }
        case WM_LBUTTONDOWN:
            OnMouseDown(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        case WM_MOUSEMOVE: {
            // Track two hover targets: the tab bar (pinned header) and the
            // section headers in the body. Only the pointer's own region is
            // tested, so a stray enter/leave does not flip both at once.
            const int mx = GET_X_LPARAM(lParam);
            const int my = GET_Y_LPARAM(lParam);
            const int m = S(kMargin);

            // Tab bar hover: the strip's single row, every slot tested.
            // The old per-line stacking broke out after the first tab, so
            // only tab one ever brightened - the rest of the strip was dead
            // to the pointer.
            int hotTab = -1;
            if (tabBarH_ > 0 && my >= tabBarY_ && my < tabBarY_ + tabBarH_) {
                for (const Line& l : lines_) {
                    if (!l.pinned) break;
                    if (l.kind != Line::Tab) continue;
                    if (mx >= l.indent && mx < l.indent + l.width) {
                        hotTab = l.section;
                        break;
                    }
                }
            }
            if (hotTab != hotTab_) {
                hotTab_ = hotTab;
                ::InvalidateRect(hwnd_, nullptr, FALSE);
            }

            // Section-header hover (body). Same missing bound as the paint
            // and click paths: without it, hovering the button row lit up a
            // section header hidden behind it.
            int hot = -1;
            const int headerBottom = m + headerHeight_;
            if (my >= headerBottom && my < headerBottom + viewHeight_) {
                int ly = headerBottom - scrollPos_;
                for (const Line& l : lines_) {
                    // Skipped without advancing, like the paint loop and the
                    // click path: advancing here shifted hover a full header
                    // height below the cursor (the twin of
                    // the click shift fixed above).
                    if (l.pinned) continue;
                    const int lh = S(l.height);
                    if (my >= ly && my < ly + lh) {
                        if (l.kind == Line::SectionHeader && l.section >= 0)
                            hot = l.section;
                        break;
                    }
                    ly += lh;
                }
            }
            if (hot != hotSection_) {
                hotSection_ = hot;
                ::InvalidateRect(hwnd_, nullptr, FALSE);
            }
            return 0;
        }
        case WM_PAINT:
            OnPaint();
            return 0;
        case WM_ERASEBKGND:
            return 1;   // fully painted in OnPaint
        case WM_SYSCOLORCHANGE:
        case WM_THEMECHANGED:
            // Re-derive the palette so a theme or high-contrast switch
            // takes effect without reopening the window.
            ApplyColors();
            ::InvalidateRect(hwnd_, nullptr, FALSE);
            return 0;
        case WM_CTLCOLORBTN: {
            // Buttons are the one child control that would otherwise stay
            // light-on-light in a dark theme.
            //
            // the SAME HighContrastActive() gate ApplyColors uses. Without
            // it, a dark theme under high contrast would still push kDarkBg onto
            // the button background here (dark_ is true, HighContrastActive is
            // true, and the kDarkBg branch fired anyway), producing near-black
            // text on near-black in an HC scheme the system already picked for
            // contrast. dark_ alone is not enough - HC must win, exactly as it
            // does in ApplyColors line 167.
            HDC hdc = reinterpret_cast<HDC>(wParam);
            const bool dark = dark_ && !HighContrastActive();
            ::SetTextColor(hdc, clrText_);
            ::SetBkColor(hdc, dark ? kSharedDarkBg : ::GetSysColor(COLOR_BTNFACE));
            HBRUSH btn = reinterpret_cast<HBRUSH>(
                ::GetStockObject(COLOR_BTNFACE + 1));
            if (dark && brushWindow_ != nullptr) btn = brushWindow_;
            return reinterpret_cast<LRESULT>(btn);
        }
        case WM_KEYDOWN: {
            if (wParam == VK_ESCAPE) {
                ::ShowWindow(hwnd_, SW_HIDE);
                return 0;
            }
            // the body is keyboard-scrollable, not mouse/wheel-only.
            // Up/Down step a line, PageUp/PageDown a page, Home/End jump.
            // (Tab switching below is separate: Ctrl+Tab and the Left/Right
            // arrows with focus on the window itself move tabs, these move
            // the body - Up/Down reach here regardless of focus, where no
            // button claims them.)
            switch (wParam) {
                case VK_DOWN:
                    ScrollBy(1);
                    return 0;
                case VK_UP:
                    ScrollBy(-1);
                    return 0;
                case VK_NEXT:
                    ScrollBy(PageLines());
                    return 0;
                case VK_PRIOR:
                    ScrollBy(-PageLines());
                    return 0;
                case VK_HOME:
                    SetScrollPosAbsolute(0);
                    return 0;
                case VK_END:
                    SetScrollPosAbsolute(MaxScroll());
                    return 0;
                default:
                    break;
            }
            // Tab switching. Ctrl+Tab / Ctrl+Shift+Tab always
            // move; the bare arrow keys move only when the
            // window itself (not a child button) owns the focus,
            // so they do not fight the buttons' own arrow keys.
            const bool ctrl = (::GetKeyState(VK_CONTROL) & 0x8000) != 0;
            const bool shift = (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (wParam == VK_TAB && ctrl) {
                ActivateTab(shift ? -1 : 1);
                return 0;
            }
            if ((wParam == VK_LEFT || wParam == VK_RIGHT) &&
                ::GetFocus() == hwnd_) {
                ActivateTab(wParam == VK_LEFT ? -1 : 1);
                return 0;
            }
            break;
        }
        case WM_SETCURSOR:
            // A hand over the two interactive surfaces (the tab
            // bar and the collapsible section headers); the
            // arrow everywhere else, including the read-only
            // field rows.
            if (LOWORD(lParam) == HTCLIENT &&
                (hotTab_ >= 0 || hotSection_ >= 0)) {
                ::SetCursor(::LoadCursorW(nullptr, IDC_HAND));
                return TRUE;
            }
            break;
        default:
            break;
    }
    return ::DefWindowProcW(hwnd_, msg, wParam, lParam);
}

bool DetailsDialog::HighContrastActive() {
    // one probe for the whole app (Theme.h). The body used to repeat
    // MainWindow's SystemParametersInfoW call line for line.
    return wintcp::HighContrastActive();
}

}  // namespace wintcp

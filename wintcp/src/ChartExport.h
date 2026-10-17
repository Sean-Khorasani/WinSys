// ChartExport.h
// SPDX-License-Identifier: Apache-2.0
// chart series serialisation (CSV) and per-panel zoom reset.
// Deliberately window-free: every function here is a free function over plain
// data, so the exact text a user would get on disk can be asserted by a
// test harness without creating an HWND. ChartsWindow only *feeds* this
// module the same std::vector<double> buffers it paints from, which is what
// keeps the exported numbers equal to the numbers on screen.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstddef>
#include <limits>
#include <string>
#include <vector>

namespace wintcp {

// ---------------------------------------------------------------------------
// 7.7b - zoom
// ---------------------------------------------------------------------------
// A panel's zoom is a *sample window* (kLo/kHi indices into the history
// buffer) plus a *value window* (vLo/vHi, the range the plot maps top to
// bottom). That is everything a mouse wheel can touch: a wheel can only
// address a rectangular sub-range, it cannot rotate or re-sample anything,
// so "zoomed" is fully described by these two ranges and there is no
// separate factor that could drift out of sync with what is drawn.
struct ZoomRect {
    size_t kLo = 0;    // first displayed sample index
    size_t kHi = 0;    // last displayed sample index (inclusive)
    double vLo = 0.0;  // value at the bottom of the plot
    double vHi = 0.0;  // value at the top of the plot
};

// The zoom a panel is in when the user has not touched the wheel: the full
// data range. Justification is in the "The default is the full range"
// comment block in ChartExport.cpp - reset restores that rect, never 0 and
// never 1.0x.
const ZoomRect& DefaultZoom();

// Canonical auto-scale for a panel, matching ChartsWindow::OnPaint:
//   * fixedMax > 0  -> 0 .. fixedMax  (CPU and memory are 0..100 % by
//     definition, so their axis must not wander with the data);
//   * fixedMax == 0 -> 0 .. max(all samples) * 1.2, floored at 64 KiB so
//     the byte-rate panels do not show a 40-byte spike as a full-height
//     line;
//   * all samples identical, or no samples at all -> the panel has no real
//     range, so the window is padded out to a 1-unit span centred on the
//     value. The window is never zero-height, which is what makes every
//     division downstream safe.
ZoomRect DefaultZoom(const std::vector<double>& a,
                     const std::vector<double>* b, double fixedMax);

// Fixed scale for panels whose unit is percent. Throws away 'a' and 'b',
// so the fixedMax > 0 rule above is reached on purpose rather than by
// accident.
ZoomRect DefaultZoomForFixedMax(double fixedMax);

// Every finite sample (a and b, ignoring non-finite entries) folded into
// the canonical window: the largest non-negative sample rounded *up* to a
// 1-2-5 decade step. Wheels zoom in, so the scale must not creep per tick;
// a fixed floor does that (a 0 B/s network panel would otherwise be flat at
// 0.1 B/s one second and 100 MB/s the next). Returns true when a window was
// produced (false = no finite data).
bool FitValueWindow(const std::vector<double>& a, const std::vector<double>* b,
                    ZoomRect* out);

// Clamp a requested zoom rect onto legal bounds for a series of 'n' samples
// and a canonical window 'def'. Guarantees on return:
//   def.span() > 0.0 and z.span() > 0.0, both finite
//   kLo <= kHi, kHi <= n-1 (and n == 0 or 1 collapses to a single point,
//   which is the window the charts window's own drawing code special-cases,
//   so no caller ever divides by zero samples)
//   all four fields finite, vLo <= vHi
// Callers may therefore divide by vHi - vLo without their own guards.
ZoomRect ClampZoom(const ZoomRect& z, size_t n, const ZoomRect& def);

// Wheel step. kHi < 0 means zoom out, > 0 zoom in, 0 = no change. 'anchor'
// is the value that must stay framed while the value window narrows (the
// panel's current reading); pass NaN to keep the current window's centre
// instead. Without an anchor a flat series would be zoomed straight out of
// its own panel. Never invents a range: an unknown sample is emitted as a
// NaN and stripped by ClampZoom, so "no data yet" cannot turn into a
// zero-width axis.
ZoomRect ZoomByWheel(const ZoomRect& z, size_t n, const ZoomRect& def,
                     int wheelDelta,
                     double anchor = std::numeric_limits<double>::quiet_NaN());

// Same, for a caller that has the series rather than a cached sample count
// and canonical window. This is the form a window should use: n, def and
// the anchor are derived from one place, so they cannot disagree.
ZoomRect ZoomByWheel(const ZoomRect& z, const std::vector<double>& a,
                     const std::vector<double>* b, double fixedMax,
                     int wheelDelta);

// Reset one panel to the default (full data range, canonical value window).
// A panel with no data yields a safe degenerate rect; a panel whose samples
// are all identical yields a normal rect with a non-zero span.
ZoomRect ResetPanelZoom(const std::vector<double>& a,
                        const std::vector<double>* b, double fixedMax);

// True when 'z' already equals the default for that series, so a caller
// wiring this to a button/enable can skip redundant invalidation.
bool IsDefaultZoom(const ZoomRect& z, const std::vector<double>& a,
                   const std::vector<double>* b, double fixedMax);

// Reset every panel. A zero-length vector is a no-op; panels with no data
// become a kLo == kHi == 0 degenerate rect and stay there. The three
// vectors are read independently and missing entries are treated as
// "single line" / "auto scale", so a caller that only has the first series
// of each panel can pass empty companions.
std::vector<ZoomRect> ResetAllPanelZoom(
    const std::vector<std::vector<double>>& seriesA,
    const std::vector<const std::vector<double>*>& seriesB,
    const std::vector<double>& fixedMax);

// ---------------------------------------------------------------------------
// 7.7a - CSV export
// ---------------------------------------------------------------------------
// Fixed, documented column order. The first kChartXColumns columns are the
// x axis and are the same for every panel. Then each panel contributes
// kChartColumns1 - kChartXColumns columns (one line) or
// kChartColumns2 - kChartXColumns (two lines), in this order, and the
// offsets of a panel's columns are the same on every row of the file:
enum ChartColumnId {
    kChartColSample = 0,   // 0-based index into the panel's history buffer
    kChartColTimeSec,      // seconds since the first sample of the export
    kChartColISO,          // absolute UTC stamp of the sample, if known
    kChartColValue,        // the sample as recorded, verbatim
    kChartColValueDrawn,   // the same sample as plotted (clamped to the axis)
    kChartColSeriesA,      // "<panel> (<unit>)", repeated per row
    kChartColValueB,       // second line, as recorded (two-line panels only)
    kChartColSeriesB,      // second line's name (two-line panels only)
    kChartColCount         // number of *kinds* of column, not per panel
};
const int kChartXColumns = 3;   // sample, time_sec, timestamp_iso
const int kChartColumns1 = 6;   // x axis + value, value_drawn, series_a
const int kChartColumns2 = 8;   // x axis + the above + value_b, series_b
// Cadence assumed for the 'time_sec' column when the caller supplies no
// timestamps: the charts window's 1 Hz sampler tick (kChartsIntervalMs in
// ChartsWindow.cpp). The header comment block prints the real interval
// whenever the caller supplied timestamps, so this is only ever the fallback.
const ULONGLONG kChartDefaultSampleIntervalMs = 1000;   // B4: dev constant,
// twin of kChartsIntervalMs — change both together, or better, neither.

// A panel: one drawn chart, one or two lines. A panel that draws two lines
// (disk read/write, network down/up) is exported as two real columns rather
// than one combined one, so "plot this column against time" stays a valid
// operation in a spreadsheet.
//
// The four entries the charts window passes reproduce the defs[] table in
// ChartsWindow::OnPaint exactly - panel order CPU, Memory, Disk, Network,
// with 100.0 for the two percent panels and 0.0 (auto-scale) for the two
// byte-rate panels.
struct ChartSeriesInfo {
    const wchar_t* name = nullptr;
    const wchar_t* unit = nullptr;                 // percent / bytes_per_second
    const std::vector<double>* seriesA = nullptr;  // required
    const std::vector<double>* seriesB = nullptr;  // nullptr = single line
    double fixedMax = 0.0;                         // > 0 = fixed scale
    const wchar_t* nameB = nullptr;                // name of the second line
};

// Status of one exported series. Computed in the same pass that produces
// the values, so a caller can say "this panel had no data" instead of
// silently shipping a file of empty cells.
struct ChartSeriesStats {
    size_t count = 0;          // samples present in the history buffer
    size_t emitted = 0;        // rows written for this panel
    size_t unknown = 0;        // samples replaced by an empty cell
    bool empty = true;         // nothing to plot
    bool degenerate = true;    // no two known samples differ
    bool twoSeries = false;    // panel draws a second line
    double knownMin = 0.0;
    double knownMax = 0.0;
    bool shareX = true;        // the panel uses the file's sample axis
    ZoomRect defaultZoom;      // what ResetPanelZoom() would return
};

// The sentinel for "no reading". It is an internal format value only:
// SeriesAsRecorded() / SeriesAsDrawn() / ExportToCsvCell() all turn it into
// an empty cell, so -1 can never reach a file. See the comment block in
// ChartExport.cpp for the full reasoning.
const double kChartUnknown = -1.0;

// A row is filled in by the caller, not by the sampler: the time base is the
// caller's business - the charts window keeps a tick count, a live capture
// knows absolute timestamps, and neither belongs baked in here. Supply one
// row per tick (value / haveTimestamp / timestampMs / timestampIso /
// ageSec) and it is used verbatim; supply none and the exporter derives
// 'sample' and 'time_sec' from the buffer index and the documented default
// cadence, leaving 'timestamp_iso' empty - which the header comment block
// states explicitly, so no reader is left guessing.
struct ChartSample {
    double value = kChartUnknown;  // kChartUnknown means "no reading"
    bool haveTimestamp = false;
    ULONGLONG timestampMs = 0;     // GetTickCount64()-style milliseconds
    SYSTEMTIME timestampIso = {};  // UTC
    size_t ageSec = 0;             // seconds since the first sample
};

struct ChartExport {
    std::vector<ChartSample> samples;
    std::wstring generatedIsoUtc;  // stamp for the header comment
    std::wstring note;             // free text appended to the comment
    const wchar_t* app = L"WinTCP";
    const wchar_t* appVersion = L"";
};

// UTF-8 CSV document for the whole panel set. Bytes are UTF-8, the decimal
// separator is always '.', and line endings are CRLF (RFC 4180, and the only
// form Excel on Windows accepts without a Text Import Wizard). The first
// lines are '#' comments - provenance, encoding, the empty-cell rule and one
// metadata line per panel - followed by the header row and the data rows.
std::string SeriesToCsvUtf8(const std::vector<ChartSeriesInfo>& series,
                            const ChartExport& ex,
                            std::vector<ChartSeriesStats>* outStats = nullptr);

// Same text as SeriesToCsvUtf8, encoded UTF-16 and without a BOM. The same
// builder produces both, so the two cannot drift apart column by column.
std::wstring SeriesToCsvWide(const std::vector<ChartSeriesInfo>& series,
                             const ChartExport& ex,
                             std::vector<ChartSeriesStats>* outStats = nullptr);

// SeriesToCsvUtf8 with a UTF-8 BOM (EF BB BF) in front, so Excel decodes the
// file as UTF-8 instead of guessing from the system code page. Separate from
// the default so the plain form stays the byte-exact RFC 4180 document.
std::string SeriesToCsvUtf8Bom(const std::vector<ChartSeriesInfo>& series,
                              const ChartExport& ex,
                              std::vector<ChartSeriesStats>* outStats = nullptr);

// The samples exactly as recorded: unknown (kChartUnknown) and any non-finite
// value become a NaN, everything else is left verbatim. This is what the
// 'value' column contains.
std::vector<double> SeriesAsRecorded(const std::vector<double>& raw,
                                     size_t* unknownCount = nullptr);

// The samples as the panel *draws* them: SeriesAsRecorded() plus the clamp
// OnPaint applies before it converts to pixels (negative -> 0, above the
// axis top -> vHi). 'changed' reports whether anything had to be altered.
// This is what the 'value_drawn' column contains, and therefore the series
// a plotter should use if it wants to reproduce the screen exactly.
std::vector<double> SeriesAsDrawn(const std::vector<double>& raw,
                                  const ZoomRect& def, bool* changed,
                                  size_t* unknownCount = nullptr);

// A sentinel that no spreadsheet can plot. Empty is the only safe answer:
// -1, 0, NaN and "n/a" are all *values* to Excel (it charts the -1 as a
// dip below the axis, and treats 0 as a real reading), whereas a blank cell
// is a gap. kChartUnknown, NaN and +/-inf all produce an empty field.
// Trailing separators are still written by the caller, so columns stay
// aligned.
std::string ExportToCsvCell(double value);

}  // namespace wintcp

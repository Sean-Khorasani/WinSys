// ChartExport.cpp
// SPDX-License-Identifier: Apache-2.0
// chart series serialisation and per-panel zoom reset.
// See ChartExport.h for the API contract. Nothing here touches a HWND, so
// every decision in this file is assertable from a plain main().

#include "ChartExport.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <limits>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

#include "Utils.h"   // WideToUtf8 / Utf8ToWide (the project's converters)

namespace wintcp {
namespace {

// Floor for a flat (all samples equal) series, in value units. The screen
// maps vLo to the bottom pixel and vHi to the top one, so a flat line drawn
// under a vHi == vLo window lands one pixel *below* the plot and is
// invisible. A one-unit window centred on the value is the smallest thing
// that still contains the data.
const double kMinValueSpan = 1.0;

// Floor for an auto-scaled byte-rate panel, in bytes/second. Mirrors the
// 64 KiB floor in ChartsWindow::OnPaint: without it a panel sitting at a
// few bytes/second renders one enormous spike per sample.
const double kMinAutoScale = 64.0 * 1024.0;

// 20% headroom above the largest sample, exactly as OnPaint does it, so the
// auto-scaled panels draw the same ceiling the export reports.
const double kAutoHeadroom = 1.2;

// Per-notch step sizes for the wheel zoom: the sample window keeps 7/8 of
// its length and the value window keeps half. Both are floored, so a long
// scroll cannot walk an axis down to zero width.
const size_t kWheelSampleNum = 7u;
const size_t kWheelSampleDen = 8u;
const double kWheelValueFactor = 0.5;

// Text bounds for the locale-independent formatters below. A double's longest
// round-trippable spelling is 24 characters, a 64-bit integer's is 20, and an
// ISO-8601 UTC timestamp is exactly 20 digits and punctuation - so 40 and 32
// are slack per call rather than a shared maximum, and every one of the three
// formatters truncates rather than overruns.
constexpr size_t kDoubleTextChars = 40;
constexpr size_t kIntTextChars = 32;

bool IsFiniteValue(double v) {
    return std::isfinite(v);
}

bool IsNaN(double v) {
    return v != v;
}

size_t SampleCount(const ZoomRect& z) {
    return (z.kHi < z.kLo) ? 0u : (z.kHi - z.kLo + 1u);
}

double SpanOf(const ZoomRect& z) {
    return z.vHi - z.vLo;
}

// A value window a caller is allowed to divide by.
bool UsableWindow(double lo, double hi) {
    return IsFiniteValue(lo) && IsFiniteValue(hi) && hi > lo;
}

bool SameRect(const ZoomRect& a, const ZoomRect& b) {
    return a.kLo == b.kLo && a.kHi == b.kHi && a.vLo == b.vLo && a.vHi == b.vHi;
}

// Round 'v' up to the next 1-2-5 x 10^n step so an axis label reads
// 100 MB/s rather than 96.3482... MB/s, and so the ceiling does not jitter
// on every tick.
double NiceCeil(double v) {
    if (!IsFiniteValue(v) || v <= 0.0) return 0.0;
    const double mag = std::pow(10.0, std::floor(std::log10(v)));
    const double norm = v / mag;                 // 1.0 .. 10.0
    double step = 10.0;
    if (norm <= 1.0) step = 1.0;
    else if (norm <= 2.0) step = 2.0;
    else if (norm <= 5.0) step = 5.0;
    return step * mag;
}

// Largest finite non-negative sample across both series; 0.0 when there is
// none. Shared by the auto-scale and by the metadata block, so the ceiling
// the file advertises is the one the panel drew against.
double MaxFinite(const std::vector<double>& a, const std::vector<double>* b) {
    double m = 0.0;
    for (double v : a) {
        if (IsFiniteValue(v) && v > m) m = v;
    }
    if (b != nullptr) {
        for (double v : *b) {
            if (IsFiniteValue(v) && v > m) m = v;
        }
    }
    return m;
}

bool MinMaxFinite(const std::vector<double>& a, const std::vector<double>* b,
                  double* lo, double* hi) {
    bool first = true;
    double mn = 0.0;
    double mx = 0.0;
    for (double v : a) {
        if (!IsFiniteValue(v)) continue;
        if (first) { mn = mx = v; first = false; }
        else { mn = (std::min)(mn, v); mx = (std::max)(mx, v); }
    }
    if (b != nullptr) {
        for (double v : *b) {
            if (!IsFiniteValue(v)) continue;
            if (first) { mn = mx = v; first = false; }
            else { mn = (std::min)(mn, v); mx = (std::max)(mx, v); }
        }
    }
    if (lo != nullptr) *lo = first ? 0.0 : mn;
    if (hi != nullptr) *hi = first ? 0.0 : mx;
    return !first;
}

// ---- locale-independent number formatting ---------------------------------
// std::to_chars is the whole guarantee, and the reason it is used rather
// than a stream: the standard specifies that it produces "the minimal number
// of characters such that parsing the result with std::from_chars recovers
// the value exactly", with no locale parameter and no facet lookup, so
// LC_NUMERIC and std::locale::global cannot reach it. (An
// ostringstream imbued with std::locale::classic() is equally immune, but
// MSVC will not compile <sstream> without /EHsc - C4530 - and the project
// does not pass /EHsc.) The corresponding trap is real and common: a single
// printf("%f")/strtod/strtof in the same translation unit would honour
// LC_NUMERIC, turn '.' into ',' for a German user, and shift every following
// column by one. There is no floating-point printf or strtod in this file,
// and the two printf-family calls that do exist (below) format integers and
// punctuation only, which no locale or code page rewrites.
std::string FormatNumber(double v) {
    if (!IsFiniteValue(v)) return std::string();
    char buf[kDoubleTextChars] = {0};
    const std::to_chars_result r = std::to_chars(buf, buf + sizeof(buf) - 1, v);
    if (r.ec != std::errc()) return std::string();
    return std::string(buf, r.ptr);
}

std::string FormatI64(long long v) {
    char buf[kIntTextChars] = {0};
    const std::to_chars_result r = std::to_chars(buf, buf + sizeof(buf) - 1, v);
    if (r.ec != std::errc()) return std::string();
    return std::string(buf, r.ptr);
}

std::string FormatSize(size_t v) {
    return FormatI64(static_cast<long long>(v));
}

std::string FormatU64(ULONGLONG v) {
    wchar_t wbuf[kIntTextChars];
    ::swprintf_s(wbuf, L"%llu", v);
    char buf[kIntTextChars] = {0};
    if (::WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf,
                              static_cast<int>(sizeof(buf)), nullptr,
                              nullptr) == 0) {
        return std::string();
    }
    return std::string(buf);
}

std::string FormatIsoUtc(const SYSTEMTIME& st) {
    // Digits and punctuation only.
    char buf[kIntTextChars] = {0};
    const int n = ::sprintf_s(
        buf, "%04u-%02u-%02uT%02u:%02u:%02uZ",
        static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond));
    if (n < 0) return std::string();
    return std::string(buf, static_cast<size_t>(n));
}

std::string Utf8Of(const wchar_t* s) {
    return (s == nullptr) ? std::string() : WideToUtf8(s);
}

std::string Utf8Of(const std::wstring& s) {
    return WideToUtf8(s);
}

// "<panel> (<unit>)": one column that says both which panel a value belongs
// to and what it measures, which is what makes the file usable after a
// "melt to rows" in a spreadsheet.
std::string SeriesColumnName(const ChartSeriesInfo& s) {
    std::string n = Utf8Of(s.name);
    n += " (";
    n += Utf8Of(s.unit);
    n += ")";
    return n;
}

std::string SeriesColumnNameB(const ChartSeriesInfo& s) {
    std::string n = Utf8Of(s.name);
    n += " ";
    n += (s.nameB != nullptr) ? Utf8Of(s.nameB) : std::string("b");
    n += " (";
    n += Utf8Of(s.unit);
    n += ")";
    return n;
}

// RFC 4180: a field is quoted when it contains a comma, a quote, CR or LF,
// and every embedded quote is doubled. An empty field is emitted as nothing
// at all rather than as a bare pair of quotes, so an unknown value is an
// empty cell and not a cell containing "".
std::string QuoteNarrow(const std::string& field) {
    if (field.find_first_of(",\"\r\n") == std::string::npos) return field;
    std::string out;
    out.reserve(field.size() + 2);
    out.push_back('"');
    for (char c : field) {
        if (c == '"') out += "\"\"";
        else out.push_back(c);
    }
    out.push_back('"');
    return out;
}

// One document builder for both encodings, so the UTF-8 and UTF-16 forms
// cannot drift apart column by column. CharT is char (UTF-8 passthrough) or
// wchar_t (UTF-8 -> UTF-16). Every string in this file is handled as UTF-8
// and only widened at the last moment, which keeps the quoting logic to
// exactly one implementation: ', " , CR and LF are single bytes in UTF-8
// and single UTF-16 units for the same characters, so a quoting decision
// taken on the UTF-8 form is the right one for the wide form too.
template <typename CharT>
std::basic_string<CharT> ToText(const std::string& utf8) {
    if constexpr (std::is_same<CharT, wchar_t>::value) {
        return Utf8ToWide(utf8.c_str());
    } else {
        return utf8;
    }
}

template <typename CharT>
void PutField(std::basic_string<CharT>* out, const std::string& utf8,
              bool quote) {
    out->append(ToText<CharT>(quote ? QuoteNarrow(utf8) : utf8));
}

template <typename CharT>
void PutComma(std::basic_string<CharT>* out) {
    out->push_back(static_cast<CharT>(','));
}

template <typename CharT>
void PutEol(std::basic_string<CharT>* out) {
    out->push_back(static_cast<CharT>('\r'));
    out->push_back(static_cast<CharT>('\n'));
}

template <typename CharT>
void PutComment(std::basic_string<CharT>* out, const std::string& utf8) {
    PutField<CharT>(out, "# " + utf8, true);
    PutEol<CharT>(out);
}

const wchar_t* ChartColumnHeader(int col) {
    switch (col) {
        case kChartColSample:     return L"sample";
        case kChartColTimeSec:    return L"time_sec";
        case kChartColISO:        return L"timestamp_iso";
        case kChartColValue:      return L"value";
        case kChartColValueDrawn: return L"value_drawn";
        case kChartColSeriesA:    return L"series_a";
        case kChartColValueB:     return L"value_b";
        case kChartColSeriesB:    return L"series_b";
        default:                  return L"unnamed";
    }
}

const std::vector<double>& EmptySeries() {
    static const std::vector<double> kEmpty;
    return kEmpty;
}

}  // namespace

// ---------------------------------------------------------------------------
// 7.7b - zoom
// ---------------------------------------------------------------------------
// The default is the FULL RANGE, and that is the entire reason a default
// exists at all. The alternatives were rejected on sight:
//   * "1.0x" - a scale factor has no meaning unless it is relative to
//     something, and once samples drop off the end of the capped history
//     buffer the factor would describe a range that no longer exists. Reset
//     would then reveal *older* data than before the zoom, which users
//     describe as "the reset made it worse".
//   * zero - 0..0 is a division by zero waiting to happen and draws nothing.
// The full range is also the only answer that stays correct no matter how
// much history is buffered, whether the panel is empty, and whether the
// series is flat - so a reset is always meaningful instead of
// sometimes-an-error.

const ZoomRect& DefaultZoom() {
    // 0..1 is the neutral default: a non-zero-height window, so even a
    // caller that divides by the span before it has data is safe. A panel
    // with data always uses the overload below instead.
    static const ZoomRect kNeutral = {0, 0, 0.0, kMinValueSpan};
    return kNeutral;
}

ZoomRect DefaultZoomForFixedMax(double fixedMax) {
    ZoomRect z;
    if (UsableWindow(0.0, fixedMax)) {
        z.vLo = 0.0;
        z.vHi = fixedMax;
    } else {
        // A caller that asked for a fixed scale but passed a junk one must
        // not be handed a zero-height axis.
        z.vLo = 0.0;
        z.vHi = kMinValueSpan;
    }
    return z;
}

ZoomRect DefaultZoom(const std::vector<double>& a,
                     const std::vector<double>* b, double fixedMax) {
    ZoomRect z = DefaultZoomForFixedMax(fixedMax);
    const size_t n = (std::max)(a.size(), (b != nullptr) ? b->size() : 0u);
    z.kLo = 0;
    z.kHi = (n > 0) ? (n - 1u) : 0u;

    if (UsableWindow(0.0, fixedMax)) {
        // Percent panels: 0..100 is the definition of the unit, so neither
        // the data nor a wheel notch may move the axis.
        return z;
    }
    if (n == 0) return z;          // vHi is already >= 1
    // The auto-scale uses NiceCeil (a 1-2-5 decade step) on top of OnPaint's
    // headroom. A rounding-up *step* rather than OnPaint's raw
    // max * 1.2 is the one deliberate difference, and it is what makes this
    // the one place that decides the panel's axis: an axis that re-derived
    // itself from the samples on every tick would crawl while the user
    // watches, and a raw max * 1.2 renders as "96.3 MB/s" and re-renders as
    // "97.1 MB/s" a second later. The constant is the same 64 KiB floor
    // OnPaint uses, so the two agree on shape and differ only in labelling.
    const double yMax = (std::max)(NiceCeil(MaxFinite(a, b)) * kAutoHeadroom,
                                   kMinAutoScale);
    z.vLo = 0.0;
    z.vHi = UsableWindow(0.0, yMax) ? yMax : kMinAutoScale;
    return z;
}

bool FitValueWindow(const std::vector<double>& a, const std::vector<double>* b,
                    ZoomRect* out) {
    if (out == nullptr) return false;
    const double nice = NiceCeil(MaxFinite(a, b));
    if (!UsableWindow(0.0, nice)) return false;   // no finite data to frame
    ZoomRect z;
    z.kLo = 0;
    z.kHi = 0;
    z.vLo = 0.0;
    z.vHi = nice;
    *out = z;
    return true;
}

ZoomRect ClampZoom(const ZoomRect& z, size_t n, const ZoomRect& def) {
    ZoomRect r;
    r.kLo = 0;
    r.kHi = 0;
    r.vLo = 0.0;
    r.vHi = kMinValueSpan;        // never zero, never non-finite

    if (n > 0) {
        const size_t last = n - 1u;
        if (z.kLo < z.kHi && z.kHi <= last) {
            r.kLo = z.kLo;
            r.kHi = z.kHi;
        } else if (z.kLo == z.kHi && z.kLo <= last) {
            r.kLo = z.kLo;        // a deliberate single-sample window
            r.kHi = z.kLo;
        } else {
            r.kLo = 0;            // out of bounds / inverted: take it all
            r.kHi = last;
        }
    }
    // n <= 1 keeps kLo == kHi == 0 - a single-point window, which is what
    // the window's own drawing code already special-cases, and why
    // SampleCount() can never hand a caller "0 of 0" to divide by.

    // Candidate value window: the requested one if usable, otherwise the
    // canonical default, otherwise the neutral default. All three are
    // non-zero-height by construction.
    double lo = z.vLo;
    double hi = z.vHi;
    if (!UsableWindow(lo, hi)) {
        lo = def.vLo;
        hi = def.vHi;
    }
    if (!UsableWindow(lo, hi)) {
        lo = 0.0;
        hi = kMinValueSpan;
    }
    // Widen around the window's own centre until the floor width holds. A
    // degenerate (high == low) request therefore becomes a legal window
    // centred on the degenerate value - the divide-by-zero case, made safe
    // at the single choke point every zoom path goes through.
    double span = hi - lo;
    if (!IsFiniteValue(span) || span < kMinValueSpan) span = kMinValueSpan;
    const double centre = 0.5 * (lo + hi);
    r.vLo = centre - 0.5 * span;
    r.vHi = centre + 0.5 * span;
    return r;
}

ZoomRect ZoomByWheel(const ZoomRect& z, size_t n, const ZoomRect& def,
                     int wheelDelta, double anchor) {
    const ZoomRect base = ClampZoom(z, n, def);
    if (wheelDelta == 0 || n < 2) return base;

    ZoomRect r = base;
    const size_t last = n - 1u;
    if (base.kHi == base.kLo) r.kHi = last;   // single point: widen to all

    if (wheelDelta > 0) {
        // Sample axis: shrink towards the middle of the current window,
        // never below one sample. Integer maths on purpose - a fractional
        // index would land on a different point for every notch.
        const size_t len = r.kHi - r.kLo;
        const size_t keep = (std::max)(
            static_cast<size_t>(1), (len * kWheelSampleNum) / kWheelSampleDen);
        const size_t mid = r.kLo + (len - keep) / 2u;
        const size_t lo = (std::min)(mid, last);
        const size_t hi = (std::min)(lo + keep, last);
        r.kLo = lo;
        r.kHi = (hi > lo) ? hi : last;

        // Value axis: halve the window around the anchor - the panel's
        // current reading, so the newest sample stays framed. The window is
        // never allowed past the canonical default, so a wheel cannot scroll
        // the axis off into a region that shows nothing. When there is no
        // anchor (every sample unknown) the current centre is used, and the
        // span floor in ClampZoom guarantees a non-zero result.
        double lo2 = base.vLo;
        double hi2 = base.vHi;
        double centre = 0.5 * (base.vLo + base.vHi);
        if (!IsNaN(anchor) && IsFiniteValue(anchor)) centre = anchor;
        const double half = 0.5 * (base.vHi - base.vLo) * kWheelValueFactor;
        // A narrowed window that no longer CONTAINS the anchor is rejected
        // outright and the wider window is kept. This is the flat-series
        // case - the anchor sits in the middle of a 64 KiB auto-scaled axis
        // and the new window would be 1 unit wide - and it is also what
        // keeps a zoom from walking the data off its own panel. The
        // subtraction here and the division the screen does with these
        // bounds are precisely the arithmetic that produces inf/nan when
        // high == low, so the degenerate case never reaches it.
        if (UsableWindow(centre - half, centre + half) && anchor >= centre - half &&
            anchor <= centre + half) {
            lo2 = centre - half;
            hi2 = centre + half;
        }
        if (UsableWindow(def.vLo, def.vHi)) {
            if (lo2 < def.vLo) { lo2 = def.vLo; hi2 = lo2 + (def.vHi - def.vLo); }
            if (hi2 > def.vHi) { hi2 = def.vHi; lo2 = hi2 - (def.vHi - def.vLo); }
        }
        if (UsableWindow(lo2, hi2)) { r.vLo = lo2; r.vHi = hi2; }
    }
    // wheelDelta < 0: the sample axis goes back to the full range, which is
    // what "zoom out" means when the full range is the default; the value
    // axis keeps following the data.
    return ClampZoom(r, n, def);
}

ZoomRect ZoomByWheel(const ZoomRect& z, const std::vector<double>& a,
                     const std::vector<double>* b, double fixedMax,
                     int wheelDelta) {
    const ZoomRect def = DefaultZoom(a, b, fixedMax);
    // The newest finite sample is the value the user is looking at, so it is
    // the one a wheel must keep framed.
    double anchor = std::numeric_limits<double>::quiet_NaN();
    const std::vector<double>* latest = nullptr;
    for (const std::vector<double>* s : {&a, b}) {
        if (s != nullptr && !s->empty()) latest = s;
    }
    if (latest != nullptr) {
        for (size_t i = latest->size(); i > 0; --i) {
            const double v = (*latest)[i - 1];
            if (IsFiniteValue(v) && v >= 0.0) { anchor = v; break; }
        }
    }
    return ZoomByWheel(z, a.size(), def, wheelDelta, anchor);
}

ZoomRect ResetPanelZoom(const std::vector<double>& a,
                        const std::vector<double>* b, double fixedMax) {
    return DefaultZoom(a, b, fixedMax);
}

bool IsDefaultZoom(const ZoomRect& z, const std::vector<double>& a,
                   const std::vector<double>* b, double fixedMax) {
    return SameRect(z, DefaultZoom(a, b, fixedMax));
}

std::vector<ZoomRect> ResetAllPanelZoom(
    const std::vector<std::vector<double>>& seriesA,
    const std::vector<const std::vector<double>*>& seriesB,
    const std::vector<double>& fixedMax) {
    const size_t panels = seriesA.size();
    if (panels == 0) return std::vector<ZoomRect>();     // safe no-op
    std::vector<ZoomRect> out(panels);
    for (size_t i = 0; i < panels; ++i) {
        const std::vector<double>* b =
            (i < seriesB.size()) ? seriesB[i] : nullptr;
        const double fx = (i < fixedMax.size()) ? fixedMax[i] : 0.0;
        out[i] = ResetPanelZoom(seriesA[i], b, fx);
    }
    return out;
}

// ---------------------------------------------------------------------------
// 7.7a - CSV export
// ---------------------------------------------------------------------------
// The kChartUnknown trap, stated once. A sample that could not be read must
// not reach a spreadsheet as a number, and this codebase already uses
// -1.0 for "unknown" (ProcStats::cpuPct, and the negative-means-unknown
// convention through the sampler). Serialising that -1.0 makes it
// indistinguishable from a real reading, and a spreadsheet will happily
// chart it as a dip below the axis. So the sentinel stays an *internal*
// value: SeriesAsRecorded() turns it into a NaN, ExportToCsvCell() turns a
// NaN into an empty cell, and -1.0 never reaches a byte of the output.
// The price is one representation - a gap - instead of a labelled one; the
// benefit is that a gap is the only thing every consumer (Excel,
// LibreOffice, Google Sheets, pandas, plotly, R) reads as "no data" rather
// than as 0, -1, #N/A or an error.
// (kChartUnknown itself is declared in ChartExport.h, so a TU that only
// reads the series structs has the sentinel without a link dependency.)

std::string ExportToCsvCell(double value) {
    // Blank for a NaN, an infinity or anything else non-finite - including
    // the unknown sentinel, which callers reach through
    // SeriesAsRecorded()/SeriesAsDrawn() first. The row separators are the
    // caller's job, so a blank keeps its column: the remaining fields on
    // the line still line up.
    if (!IsFiniteValue(value)) return std::string();
    return FormatNumber(value);
}

std::vector<double> SeriesAsRecorded(const std::vector<double>& raw,
                                     size_t* unknownCount) {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    std::vector<double> out;
    out.reserve(raw.size());
    size_t unknown = 0;
    for (double v : raw) {
        if (v == kChartUnknown || !IsFiniteValue(v)) {
            ++unknown;
            out.push_back(nan);
        } else {
            out.push_back(v);
        }
    }
    if (unknownCount != nullptr) *unknownCount = unknown;
    return out;
}

std::vector<double> SeriesAsDrawn(const std::vector<double>& raw,
                                  const ZoomRect& def, bool* changed,
                                  size_t* unknownCount) {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    std::vector<double> out;
    out.reserve(raw.size());
    size_t unknown = 0;
    bool dirty = false;
    for (double v : raw) {
        if (v == kChartUnknown || !IsFiniteValue(v)) {
            ++unknown;
            dirty = true;
            out.push_back(nan);
            continue;
        }
        // Everything else is clamped exactly the way OnPaint's plot() lambda
        // clamps before converting to pixels, so the export can never report
        // a value the panel refused to draw.
        if (v < 0.0) { v = 0.0; dirty = true; }
        if (IsFiniteValue(def.vHi) && v > def.vHi) { v = def.vHi; dirty = true; }
        out.push_back(v);
    }
    if (changed != nullptr) *changed = dirty;
    if (unknownCount != nullptr) *unknownCount = unknown;
    return out;
}

namespace {

// The whole document, for either encoding. Fixed column order:
//
//   sample, time_sec, timestamp_iso
//   then, per exported panel, in the order the panels were given:
//     value, value_drawn, series_a        [+ value_b, series_b when the
//                                          panel draws a second line]
//
// 'value' is the sample as recorded (unknown -> empty), 'value_drawn' is the
// same sample after the panel's own clamp, and 'series_a' is "<panel>
// (<unit>)" so the column survives a melt to rows in a spreadsheet. The
// first three columns are the x axis and are the same for every panel, so
// the file plots directly with the sample index as the abscissa.
template <typename CharT>
std::basic_string<CharT> BuildCsvDocument(const std::vector<ChartSeriesInfo>& series,
                                         const ChartExport& ex,
                                         std::vector<ChartSeriesStats>* outStats) {
    typedef std::basic_string<CharT> Str;
    if (outStats != nullptr) outStats->assign(series.size(), ChartSeriesStats());
    if (series.empty()) return Str();

    // ---- normalise once, in one pass per series --------------------------
    // 'recA'/'recB' are the samples as recorded, 'drwA'/'drwB' the samples
    // as the panel draws them. Unknown (kChartUnknown) and any non-finite
    // value become a NaN in both, and ExportToCsvCell() turns a NaN into an
    // empty cell - so the sentinel cannot reach the file from any column.
    std::vector<ZoomRect> defs(series.size());
    std::vector<std::vector<double> > recA(series.size());
    std::vector<std::vector<double> > recB(series.size());
    std::vector<std::vector<double> > drwA(series.size());
    std::vector<std::vector<double> > drwB(series.size());
    std::vector<std::string> nameA(series.size());
    std::vector<std::string> nameB(series.size());
    std::vector<ChartSeriesStats> stats(series.size());
    size_t rows = ex.samples.size();

    for (size_t i = 0; i < series.size(); ++i) {
        const ChartSeriesInfo& s = series[i];
        const std::vector<double>& rawA =
            (s.seriesA != nullptr) ? *s.seriesA : EmptySeries();
        defs[i] = DefaultZoom(rawA, s.seriesB, s.fixedMax);
        size_t unknown = 0;
        recA[i] = SeriesAsRecorded(rawA, &unknown);
        drwA[i] = SeriesAsDrawn(rawA, defs[i], nullptr, &unknown);
        if (s.seriesB != nullptr) {
            recB[i] = SeriesAsRecorded(*s.seriesB, &unknown);
            drwB[i] = SeriesAsDrawn(*s.seriesB, defs[i], nullptr, &unknown);
            nameB[i] = SeriesColumnNameB(s);
        }
        nameA[i] = SeriesColumnName(s);
        rows = (std::max)(rows, recA[i].size());
        if (!recB[i].empty()) rows = (std::max)(rows, recB[i].size());
        if (!drwA[i].empty()) rows = (std::max)(rows, drwA[i].size());
        if (!drwB[i].empty()) rows = (std::max)(rows, drwB[i].size());

        ChartSeriesStats& st = stats[i];
        st.twoSeries = (s.seriesB != nullptr);
        st.count = rawA.size();
        st.emitted = (std::max)(recA[i].size(),
                                (s.seriesB != nullptr) ? recB[i].size() : 0u);
        st.unknown = unknown;
        st.defaultZoom = defs[i];
        st.empty = (recA[i].empty() && recB[i].empty());
        st.shareX = true;
        MinMaxFinite(drwA[i], recB.empty() || drwB[i].empty() ? nullptr : &drwB[i],
                     &st.knownMin, &st.knownMax);
        st.degenerate = st.empty || !(st.knownMax > st.knownMin);
    }
    if (outStats != nullptr) *outStats = stats;

    // ---- x axis -----------------------------------------------------------
    // The sample index and the age column are derived from the data, not
    // from 'ex.samples': the charts window keeps a tick count, not a vector
    // of timestamps, and a caller that does have a sample row per tick gets
    // its own stamps (and an ISO column) used. Without this a file exported
    // straight from a history buffer would have a permanently blank
    // time_sec column, and 'age' is derivable from a buffer index alone.
    // The interval is only claimed when the caller actually supplied
    // timestamps, so the header never states a cadence it had to guess.
    bool anyStamp = false;
    ULONGLONG intervalMs = kChartDefaultSampleIntervalMs;
    bool intervalKnown = false;
    for (size_t i = 0; i < ex.samples.size(); ++i) {
        if (!ex.samples[i].haveTimestamp) continue;
        anyStamp = true;
        if (i > 0 && ex.samples[i - 1].haveTimestamp && !intervalKnown) {
            const ULONGLONG a = ex.samples[i - 1].timestampMs;
            const ULONGLONG b = ex.samples[i].timestampMs;
            if (b > a) {
                intervalMs = b - a;
                intervalKnown = true;
            }
        }
    }

    // ---- header block -----------------------------------------------------
    // Pre-size guess: ~1 KB of header/comments, ~192 chars per series line,
    // ~48 per data row. An underestimate only costs a realloc; an overestimate
    // costs memory. Deliberately rough — exact sizing would duplicate the
    // formatting code it is trying to get ahead of.
    constexpr size_t kCsvHeaderBytes = 1024;
    constexpr size_t kCsvSeriesBytes = 192;
    constexpr size_t kCsvRowBytes = 48;
    Str out;
    out.reserve(kCsvHeaderBytes + series.size() * kCsvSeriesBytes +
                rows * kCsvRowBytes);

    PutComment<CharT>(&out, "WinTCP chart series export");
    PutComment<CharT>(&out,
                      "generator: " + Utf8Of(ex.app) + " " +
                          Utf8Of(ex.appVersion));
    PutComment<CharT>(&out, "generated_utc: " + Utf8Of(ex.generatedIsoUtc));
    if (!ex.note.empty()) PutComment<CharT>(&out, "note: " + Utf8Of(ex.note));
    PutComment<CharT>(&out,
                      std::string("sample_interval_ms: ") +
                          (intervalKnown ? FormatU64(intervalMs)
                                        : std::string("unknown (assumed ") +
                                              FormatU64(intervalMs) +
                                              " for time_sec)"));
    PutComment<CharT>(&out,
                      anyStamp
                          ? "sample, time_sec and timestamp_iso are filled "
                            "(UTC)"
                          : "sample and time_sec are filled; timestamp_iso is "
                            "empty (the caller supplied no absolute time "
                            "base, so only the relative age is known)");
    PutComment<CharT>(&out,
                      "an empty value cell means no reading - never 0 and "
                      "never a sentinel number");
    PutComment<CharT>(&out,
                      "value = the sample as recorded; value_drawn = the same "
                      "sample after the panel's clamp, i.e. what the panel "
                      "shows");
    PutComment<CharT>(&out,
                      "decimal separator is '.' regardless of the user "
                      "locale; encoding is UTF-8");

    // Per-series metadata, so a spreadsheet user never has to guess which
    // panel a column belongs to, what unit it carries, or what the default
    // axis is. One '#' comment line per panel.
    PutComment<CharT>(&out,
                      "series index,name,unit,has_b,count,emitted,unknown,"
                      "empty,degenerate,min,max,share_x,default_v_lo,"
                      "default_v_hi");
    for (size_t i = 0; i < series.size(); ++i) {
        const ChartSeriesInfo& s = series[i];
        const ChartSeriesStats& st = stats[i];
        std::string line = "series ";
        line += FormatSize(i);
        line += ",";
        line += Utf8Of(s.name);
        line += ",";
        line += Utf8Of(s.unit);
        line += ",";
        line += (st.twoSeries ? "true" : "false");
        line += ",";
        line += FormatSize(st.count);
        line += ",";
        line += FormatSize(st.emitted);
        line += ",";
        line += FormatSize(st.unknown);
        line += ",";
        line += (st.empty ? "true" : "false");
        line += ",";
        line += (st.degenerate ? "true" : "false");
        line += ",";
        line += FormatNumber(st.knownMin);
        line += ",";
        line += FormatNumber(st.knownMax);
        line += ",";
        line += (st.shareX ? "true" : "false");
        line += ",";
        line += FormatNumber(st.defaultZoom.vLo);
        line += ",";
        line += FormatNumber(st.defaultZoom.vHi);
        // Quoted like every other field: a panel called `Disk, read` must
        // not split this metadata row into two.
        PutField<CharT>(&out, line, true);
        PutEol<CharT>(&out);
    }

    // ---- header row -------------------------------------------------------
    PutField<CharT>(&out, Utf8Of(ChartColumnHeader(kChartColSample)), true);
    PutComma<CharT>(&out);
    PutField<CharT>(&out, Utf8Of(ChartColumnHeader(kChartColTimeSec)), true);
    PutComma<CharT>(&out);
    PutField<CharT>(&out, Utf8Of(ChartColumnHeader(kChartColISO)), true);
    for (const ChartSeriesInfo& s : series) {
        PutComma<CharT>(&out);
        PutField<CharT>(&out, Utf8Of(ChartColumnHeader(kChartColValue)), true);
        PutComma<CharT>(&out);
        PutField<CharT>(&out, Utf8Of(ChartColumnHeader(kChartColValueDrawn)),
                        true);
        PutComma<CharT>(&out);
        PutField<CharT>(&out, SeriesColumnName(s), true);
        if (s.seriesB != nullptr) {
            PutComma<CharT>(&out);
            PutField<CharT>(&out, Utf8Of(ChartColumnHeader(kChartColValueB)),
                            true);
            PutComma<CharT>(&out);
            PutField<CharT>(&out, SeriesColumnNameB(s), true);
        }
    }
    PutEol<CharT>(&out);

    // ---- data rows --------------------------------------------------------
    // Iterate the longest series: a panel that sampled more often (or was
    // reset later) must not be truncated to the length of the shortest one.
    // Panels that do not share the sample axis are still written, with an
    // empty cell in the rows they have no sample for - the share_x column in
    // the metadata says which panels line up.
    for (size_t r = 0; r < rows; ++r) {
        PutField<CharT>(&out, FormatSize(r), false);
        PutComma<CharT>(&out);
        if (anyStamp && r < ex.samples.size()) {
            PutField<CharT>(
                &out, FormatNumber(static_cast<double>(ex.samples[r].ageSec)),
                false);
            PutComma<CharT>(&out);
            if (ex.samples[r].haveTimestamp) {
                PutField<CharT>(&out, FormatIsoUtc(ex.samples[r].timestampIso),
                                false);
            }
            // else: the separator above is already in place, so the cell is
            // empty and every later column keeps its position.
        } else {
            // No absolute time base from the caller: age is the sample index
            // times the interval (1 s for the charts window) and the ISO
            // column stays empty, which the header says out loud.
            PutField<CharT>(
                &out,
                FormatNumber(static_cast<double>(r) *
                             (static_cast<double>(intervalMs) / 1000.0)),
                false);
            PutComma<CharT>(&out);
        }
        for (size_t i = 0; i < series.size(); ++i) {
            // Unknown samples (a NaN after the normalisation above) and
            // samples the panel never had both come out of ExportToCsvCell()
            // as an empty field; the commas around them are unconditional,
            // which is the whole reason the columns cannot drift apart.
            PutComma<CharT>(&out);
            PutField<CharT>(&out,
                            (r < recA[i].size()) ? ExportToCsvCell(recA[i][r])
                                                 : std::string(),
                            false);
            PutComma<CharT>(&out);
            PutField<CharT>(&out,
                            (r < drwA[i].size()) ? ExportToCsvCell(drwA[i][r])
                                                 : std::string(),
                            false);
            PutComma<CharT>(&out);
            PutField<CharT>(&out, nameA[i], true);
            if (series[i].seriesB != nullptr) {
                PutComma<CharT>(&out);
                PutField<CharT>(&out,
                                (r < recB[i].size()) ? ExportToCsvCell(recB[i][r])
                                                     : std::string(),
                                false);
                PutComma<CharT>(&out);
                PutField<CharT>(&out, nameB[i], true);
            }
        }
        PutEol<CharT>(&out);
    }
    return out;
}

}  // namespace

std::string SeriesToCsvUtf8(const std::vector<ChartSeriesInfo>& series,
                            const ChartExport& ex,
                            std::vector<ChartSeriesStats>* outStats) {
    return BuildCsvDocument<char>(series, ex, outStats);
}

std::string SeriesToCsvUtf8Bom(const std::vector<ChartSeriesInfo>& series,
                              const ChartExport& ex,
                              std::vector<ChartSeriesStats>* outStats) {
    // The BOM is EF BB BF, the Unicode signature. It is what makes Excel
    // (and Excel Online, and LibreOffice on Windows) decode a .csv as UTF-8
    // instead of guessing from the system code page - without it a process
    // called "café.exe" becomes "cafÃ©.exe". It is offered separately rather
    // than always prepended so the default output is the byte-exact RFC 4180
    // document that a strict parser (and every diff of two exports) wants;
    // pass withBom = true to WriteUtf8FileWithBom() when the file is meant
    // to be double-clicked in Excel.
    static const char kBom[3] = {'\xEF', '\xBB', '\xBF'};
    std::string out;
    out += kBom;
    out += SeriesToCsvUtf8(series, ex, outStats);
    return out;
}

std::wstring SeriesToCsvWide(const std::vector<ChartSeriesInfo>& series,
                             const ChartExport& ex,
                             std::vector<ChartSeriesStats>* outStats) {
    // Same text as SeriesToCsvUtf8 (same builder, so no drift), UTF-16, and
    // deliberately without a BOM: the BOM is a UTF-8-file convention, and
    // WriteUtf8FileWithBom() already turns the narrow form into a file. This
    // entry point is for a wide string a UI wants to hand to the clipboard
    // or to a string-based file writer.
    return BuildCsvDocument<wchar_t>(series, ex, outStats);
}

}  // namespace wintcp

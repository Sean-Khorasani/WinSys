// ChartsWindow.h
// SPDX-License-Identifier: Apache-2.0
// Performance graphs window: four live line charts (CPU %,
// memory used %, disk read/write B/s, network receive/send B/s) sampled
// once per second with a 120-sample history. Modeless, owned by the main
// window, toggled from View > Performance graphs. All data comes from
// in-box system APIs (GetSystemTimes, GlobalMemoryStatusEx, PDH
// PhysicalDisk counters via locale-independent English counter paths,
// GetIfTable2 64-bit octets) - no third-party code.
//
// Hardening: per-source sample validity (each panel shows
// "collecting…" / "n/a" on its own), the 1 s timer runs only while the
// window is visible, transient PDH failures are tolerated before the
// query is torn down, and the window enforces a minimum size.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>
#include <vector>

namespace wintcp {

class ChartsWindow {
public:
    ChartsWindow() = default;
    ~ChartsWindow();

    ChartsWindow(const ChartsWindow&) = delete;
    ChartsWindow& operator=(const ChartsWindow&) = delete;

    // Show (or reveal) the window; centers over 'owner' on first show.
    void Show(HWND owner, bool dark);
    void Close();                        // destroy (app shutdown path)
    bool IsOpen() const { return hwnd_ != nullptr; }
    bool IsVisible() const;
    HWND Handle() const { return hwnd_; }

    void SetDark(bool dark);

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam,
                                       LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    void StartSampling();                // 1 s timer (visible windows only)
    void StopSampling();
    void OnTimer();
    void OnPaint();
    void CenterOnOwner(HWND owner);
    void CreateFonts();
    void DeleteFonts();
    void CleanupPdh();
    // The window is display-only no longer. Two focusable buttons -
    // Copy (a values table identical to the captions, for keyboard and
    // screen-reader users) and Export (the full histories as CSV through
    // the existing ChartExport module) - plus ValuesText, the one
    // derivation captions, clipboard and accessible name all share.
    void ExportCharts();
    void CopyValues();
    std::wstring ValuesText() const;

    // One sampler tick. Every source validates independently and pushes
    // only real readings, so no panel ever shows a fabricated 0.
    void Sample();

    HWND hwnd_ = nullptr;
    bool dark_ = false;
    HFONT font_ = nullptr;
    HFONT boldFont_ = nullptr;
    // In-window Export/Copy buttons (focusable, so the values they
    // carry are keyboard-reachable). Owned children, nulled on destroy.
    HWND hwndExport_ = nullptr;
    HWND hwndCopy_ = nullptr;
    UINT_PTR timerOn_ = 0;

    // History (oldest -> newest), capped at kMaxSamples.
    static const size_t kMaxSamples = 120;
    std::vector<double> cpuHist_;
    std::vector<double> memHist_;
    std::vector<double> diskReadHist_;
    std::vector<double> diskWriteHist_;
    std::vector<double> netRecvHist_;
    std::vector<double> netSendHist_;

    // Current values for the panel captions.
    double cpuPct_ = 0.0;
    double memPct_ = 0.0;
    ULONGLONG memUsed_ = 0;
    ULONGLONG memTotal_ = 0;
    double diskReadBps_ = 0.0;
    double diskWriteBps_ = 0.0;
    double netRecvBps_ = 0.0;
    double netSendBps_ = 0.0;
    bool diskAvailable_ = true;

    // Sampler baselines.
    FILETIME prevIdle_ = {};
    FILETIME prevKernel_ = {};
    FILETIME prevUser_ = {};
    bool haveCpuBase_ = false;
    ULONGLONG prevNetIn_ = 0;
    ULONGLONG prevNetOut_ = 0;
    ULONGLONG prevNetTick_ = 0;
    bool haveNetBase_ = false;

    // PDH disk counters (pdh.lib). Resolved with PdhAddEnglishCounterW so
    // the counter path works on any system locale; a failure (counters
    // disabled) marks the disk chart "n/a" and retries every 10 s.
    void* pdhQuery_ = nullptr;    // HQUERY (kept opaque to avoid pdh.h here)
    void* pdhRead_ = nullptr;     // HCOUNTER
    void* pdhWrite_ = nullptr;    // HCOUNTER
    int pdhRetryIn_ = 0;          // ticks until next re-open attempt
    int pdhFails_ = 0;            // consecutive collect/format failures

    static const wchar_t* kClassName;
};

}  // namespace wintcp

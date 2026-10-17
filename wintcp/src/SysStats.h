// SysStats.h
// SPDX-License-Identifier: Apache-2.0
// Headless system-wide stats sampler: CPU %, memory, disk B/s, network B/s.
// Extracted from ChartsWindow::Sample so the CLI (`stat`, `top`) and scripts
// can read the same numbers without a window. No HWND anywhere in this file.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <cstdint>

namespace wintcp {

// One system-wide sample. Each source validates independently: a source that
// cannot be read reports known=false and leaves its panel at "n/a" rather
// than a fabricated 0.
struct SystemStats {
    bool cpuKnown = false;
    double cpuPct = 0.0;            // 0..100

    bool memKnown = false;
    ULONGLONG memUsed = 0;
    ULONGLONG memTotal = 0;
    double memPct = 0.0;            // 0..100

    bool diskKnown = false;         // false when PDH counters are disabled
    double diskReadBps = 0.0;
    double diskWriteBps = 0.0;

    bool netKnown = false;
    double netRecvBps = 0.0;
    double netSendBps = 0.0;
    ULONGLONG netTickMs = 0;        // tick of this sample (for rate math)
};

// Not thread-safe; one per thread (CLI owns one, GUI charts own their own
// inside ChartsWindow). Never throws.
class SystemStatsSampler {
public:
    SystemStatsSampler();
    ~SystemStatsSampler();

    SystemStatsSampler(const SystemStatsSampler&) = delete;
    SystemStatsSampler& operator=(const SystemStatsSampler&) = delete;

    // One sample. The first call primes CPU/network baselines and reports
    // them unknown; disk needs two PDH collects before a rate exists.
    SystemStats Sample();

    void Clear();                   // drop baselines + tear down PDH query

private:
    void CleanupPdh();

    FILETIME prevIdle_ = {};
    FILETIME prevKernel_ = {};
    FILETIME prevUser_ = {};
    bool haveCpuBase_ = false;

    ULONGLONG prevNetIn_ = 0;
    ULONGLONG prevNetOut_ = 0;
    ULONGLONG prevNetTick_ = 0;
    bool haveNetBase_ = false;

    void* pdhQuery_ = nullptr;      // HQUERY (opaque to avoid pdh.h here)
    void* pdhRead_ = nullptr;       // HCOUNTER
    void* pdhWrite_ = nullptr;      // HCOUNTER
    int pdhRetryIn_ = 0;
    int pdhFails_ = 0;
};

}  // namespace wintcp

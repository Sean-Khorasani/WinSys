// WebMetrics.h
// SPDX-License-Identifier: Apache-2.0
// Metrics collector for the Web UI. Runs on a background thread, owns its
// own PDH query and samplers, and stores samples in bounded ring buffers.
//
// THREADING: The sampler thread is created with CreateThread (not std::thread,
// per the code comment in WebUi.cpp). It owns its own PDH query and sampler
// objects. The main thread reads snapshots under a short lock.
//
// RING BUFFERS: Two tiers.
//   Tier A: 1 s x 900 points (15 min) - for live charts
//   Tier B: 10 s x 2160 points (6 h) - for history
//
// The first rate sample is not valid (no previous sample to diff against);
// it is discarded. Wildcard PDH instances change at runtime; re-enumerate on
// a slow timer and tolerate PDH_NO_DATA / PDH_CSTATUS_NO_OBJECT / PDH_MORE_DATA.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace wintcp {

// One timestamped sample of all metrics.
struct MetricsSample {
    uint64_t tickMs = 0;        // GetTickCount64() at sample time
    uint64_t unixTime = 0;      // Unix epoch seconds

    // CPU
    bool cpuTotalKnown = false;
    double cpuTotal = 0.0;      // 0..100

    // Per-core CPU (index = core number)
    std::vector<double> cpuCore;    // 0..100, empty if unavailable
    std::vector<bool> cpuCoreKnown;

    // Memory
    bool memUsedKnown = false;
    uint64_t memUsed = 0;
    bool memTotalKnown = false;
    uint64_t memTotal = 0;

    // Disk (per instance, e.g. "0 C:")
    std::map<std::wstring, double> diskReadBps;   // instance -> bytes/s
    std::map<std::wstring, double> diskWriteBps;
    std::map<std::wstring, bool> diskReadKnown;
    std::map<std::wstring, bool> diskWriteKnown;

    // Network (per instance, e.g. "Ethernet")
    std::map<std::wstring, double> netRxBps;      // instance -> bytes/s
    std::map<std::wstring, double> netTxBps;
    std::map<std::wstring, bool> netRxKnown;
    std::map<std::wstring, bool> netTxKnown;

    // GPU (per engine type)
    std::map<std::wstring, double> gpuEnginePct;  // engine type -> 0..100
    std::map<std::wstring, bool> gpuEngineKnown;
    bool gpuVramKnown = false;
    uint64_t gpuVramUsed = 0;
};

// Bounded ring buffer for metrics samples. Thread-safe.
class MetricsRingBuffer {
public:
    explicit MetricsRingBuffer(size_t capacity);
    ~MetricsRingBuffer() = default;

    // Add a sample. Overwrites the oldest if full.
    void Push(const MetricsSample& sample);

    // Get samples since the given Unix time (inclusive).
    // Returns at most maxSamples, newest first.
    std::vector<MetricsSample> Since(uint64_t unixTime, size_t maxSamples) const;

    // Get the latest sample.
    bool Latest(MetricsSample* out) const;

    size_t Size() const;
    size_t Capacity() const;

    // Clear all samples.
    void Clear();

private:
    mutable std::mutex mutex_;
    std::vector<MetricsSample> buffer_;
    size_t head_ = 0;   // next write position
    size_t size_ = 0;
};

// Background metrics collector. Owns its own PDH query and samplers.
// Not thread-safe for concurrent Start/Stop; the caller serialises those.
class MetricsCollector {
public:
    MetricsCollector();
    ~MetricsCollector();

    MetricsCollector(const MetricsCollector&) = delete;
    MetricsCollector& operator=(const MetricsCollector&) = delete;

    // Start the background sampling thread. Returns false on failure.
    bool Start();

    // Stop the background thread and wait for it to exit.
    void Stop();

    // Get a snapshot of the latest sample (thread-safe).
    bool GetLatest(MetricsSample* out) const;

    // Get samples from the ring buffer (thread-safe).
    std::vector<MetricsSample> GetHistory(uint64_t since, size_t maxSamples) const;

    // Get the ring buffer for direct access (e.g. for testing).
    const MetricsRingBuffer& RingBuffer() const { return ring_; }

    // Check if the collector is running.
    bool IsRunning() const { return running_; }

    // Force a re-enumeration of PDH instances (e.g. after a device change).
    void Reenumerate();

    // Set the idle timeout (default 60 s). After this many milliseconds
    // without a GetLatest call, the sampler drops to idle cadence.
    void SetIdleTimeoutMs(uint64_t ms) { idleTimeoutMs_ = ms; }

    // Set whether to keep collecting while idle (default false).
    void SetKeepCollectingWhileIdle(bool keep) { keepCollectingWhileIdle_ = keep; }

private:
    static DWORD WINAPI ThreadProc(LPVOID param);
    void Run();

    // PDH query management
    bool OpenPdhQuery();
    void ClosePdhQuery();
    bool AddCounters();
    bool CollectSample(MetricsSample* out);

    // Re-enumerate wildcard instances
    void ReenumerateInstances();

    // Counter handles (owned by the sampler thread)
    PDH_HCOUNTER pdhCpuTotal_ = nullptr;
    PDH_HCOUNTER pdhCpuCore_ = nullptr;
    PDH_HCOUNTER pdhMemUsed_ = nullptr;
    PDH_HCOUNTER pdhMemTotal_ = nullptr;
    std::vector<PDH_HCOUNTER> pdhDiskRead_;
    std::vector<PDH_HCOUNTER> pdhDiskWrite_;
    std::vector<PDH_HCOUNTER> pdhNetRx_;
    std::vector<PDH_HCOUNTER> pdhNetTx_;
    std::vector<PDH_HCOUNTER> pdhGpuEngine_;
    std::vector<PDH_HCOUNTER> pdhGpuVram_;

    HANDLE thread_ = nullptr;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};

    // PDH query handle (owned by the sampler thread)
    PDH_HQUERY pdhQuery_ = nullptr;

    // Ring buffer: tier A (1 s x 900)
    MetricsRingBuffer ring_;

    // Previous sample for rate calculation
    mutable std::mutex prevMutex_;
    MetricsSample prevSample_;
    bool havePrev_ = false;

    // Re-enumeration timer
    uint64_t lastReenumerateMs_ = 0;

    // Idle detection
    mutable uint64_t lastAccessMs_ = 0;
    uint64_t idleTimeoutMs_ = 60000;
    bool keepCollectingWhileIdle_ = false;
};

}  // namespace wintcp

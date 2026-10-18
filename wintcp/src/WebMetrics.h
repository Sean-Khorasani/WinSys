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

// ws2tcpip.h must come first: netioapi.h only declares MIB_IF_ROW2 and
// GetIfTable2() when _WS2IPDEF_ (from ws2ipdef.h) is already defined. See the
// same note at the top of SysStats.cpp.
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
// MIB_IF_TABLE2 / GetIfTable2 live in netioapi.h (shared), not iphlpapi.h.
#include <iphlpapi.h>
#include <netioapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>          // GetPerformanceInfo

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace wintcp {

// Strip the internal drive index from a PDH disk instance name: "0 C:" -> "C:".
// A name without the "<digits><space>" prefix is returned unchanged. Free
// function rather than a private member so the unit tests can reach it.
std::wstring DiskInstanceLabel(const std::wstring& instance);

// Reduce a \GPU Engine(*) instance name to its engine type: the trailing
// "engtype_3D" (or "engtype_Compute", "engtype_VideoDecode", ...) becomes
// "3D". Summing every process's share of an engine is scheduler busy time, not
// utilisation - the UI labels it that way. A name without an "engtype_" segment
// is returned unchanged.
std::wstring GpuEngineTypeLabel(const std::wstring& instance);

// One timestamped sample of all metrics.
//
// Every field is independently "known". A source that cannot be read leaves its
// value alone and the emitter turns that into null plus a reason; it never
// becomes 0, because 0 means "idle" and that is a different statement (C-6).
struct MetricsSample {
    uint64_t tickMs = 0;        // GetTickCount64() at sample time
    uint64_t unixTime = 0;      // Unix epoch seconds

    // ---- CPU ----------------------------------------------------------
    bool cpuTotalKnown = false;
    double cpuTotal = 0.0;      // 0..100
    // Per-core CPU, index = core number, ordered by (group, core).
    std::vector<double> cpuCore;
    std::vector<bool> cpuCoreKnown;

    // ---- Memory -------------------------------------------------------
    bool memUsedKnown = false;
    uint64_t memUsed = 0;       // GlobalMemoryStatusEx: total - available
    bool memTotalKnown = false;
    uint64_t memTotal = 0;
    bool memAvailableKnown = false;
    uint64_t memAvailable = 0;
    // Composition, for the Performance page's memory bar. "Cache" is the
    // standby+modified+free list pool - bytes the OS is holding but can reclaim,
    // which is NOT the same as "available", so it is labelled separately.
    bool memCacheKnown = false;
    uint64_t memCache = 0;
    bool memKernelPagedKnown = false;
    uint64_t memKernelPaged = 0;
    bool memKernelNonPagedKnown = false;
    uint64_t memKernelNonPaged = 0;
    // Commit charge: the number Windows actually promises to back.
    bool memCommitLimitKnown = false;
    uint64_t memCommitLimit = 0;
    bool memCommitPeakKnown = false;
    uint64_t memCommitPeak = 0;
    bool memPagedPoolTotalKnown = false;
    uint64_t memPagedPoolTotal = 0;   // page file size, when one exists
    bool memPagedPoolUsedKnown = false;
    uint64_t memPagedPoolUsed = 0;

    // ---- Disk (per instance, e.g. "0 C:") -----------------------------
    std::map<std::wstring, double> diskReadBps;   // instance -> bytes/s
    std::map<std::wstring, double> diskWriteBps;
    std::map<std::wstring, bool> diskReadKnown;
    std::map<std::wstring, bool> diskWriteKnown;
    // Active time, queue depth and latency per instance. These are what turn a
    // throughput number into an answer to "is this disk healthy?".
    std::map<std::wstring, double> diskActivePct;
    std::map<std::wstring, bool> diskActiveKnown;
    std::map<std::wstring, double> diskQueueLength;
    std::map<std::wstring, bool> diskQueueKnown;
    std::map<std::wstring, double> diskLatencyMs;
    std::map<std::wstring, bool> diskLatencyKnown;

    // ---- Volumes (capacity; NOT throughput) ---------------------------
    struct VolumeInfo {
        uint64_t totalBytes = 0;
        uint64_t freeBytes = 0;
        std::wstring fileSystem;
        std::wstring label;
        bool known = false;
    };
    std::map<std::wstring, VolumeInfo> volumes;   // "C:" -> info

    // ---- Network (per instance, e.g. "Ethernet") ----------------------
    std::map<std::wstring, double> netRxBps;      // instance -> bytes/s
    std::map<std::wstring, double> netTxBps;
    std::map<std::wstring, bool> netRxKnown;
    std::map<std::wstring, bool> netTxKnown;
    // Link speed in bits/s, and the interface's current operational state.
    std::map<std::wstring, uint64_t> netLinkBits;
    std::map<std::wstring, bool> netLinkKnown;
    std::map<std::wstring, bool> netUp;           // 1 Gbps test-bit / operstate

    // ---- GPU (per engine type) ----------------------------------------
    std::map<std::wstring, double> gpuEnginePct;  // engine type -> 0..100
    std::map<std::wstring, bool> gpuEngineKnown;
    bool gpuVramKnown = false;
    uint64_t gpuVramUsed = 0;

    // ---- System-wide counters (cheap, no PDH) -------------------------
    bool uptimeKnown = false;
    uint64_t uptimeSeconds = 0;
    bool processCountKnown = false;
    uint32_t processCount = 0;
    bool threadCountKnown = false;
    uint32_t threadCount = 0;
    bool handleCountKnown = false;
    uint32_t handleCount = 0;
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

    // Get samples from the tier-A ring buffer (thread-safe).
    std::vector<MetricsSample> GetHistory(uint64_t since, size_t maxSamples) const;

    // Get samples from the tier-B ring buffer (10 s x 2160 = 6 h).
    std::vector<MetricsSample> GetHistoryTierB(uint64_t since,
                                               size_t maxSamples) const;

    // Which tier a history request asked for. Both are always being written -
    // tier B is a decimated copy pushed by the sampler thread, not a second
    // PDH pass, so it costs nothing extra.
    enum class Tier : unsigned char { A, B };
    std::vector<MetricsSample> GetHistory(Tier tier, uint64_t since,
                                          size_t maxSamples) const;

    // Get the ring buffer for direct access (e.g. for testing).
    const MetricsRingBuffer& RingBuffer() const { return ring_; }

    // Check if the collector is running.
    bool IsRunning() const { return running_; }

    // True when the per-core wildcard counter was added successfully. Decided
    // once in Start(), before the sampler thread exists, so reading it later is
    // safe. Unlike inspecting the latest sample it does not report "unavailable"
    // merely because the first sample has not landed yet - which made
    // /api/capabilities flip-flop on the first poll.
    bool PerCoreAvailable() const { return pdhCpuCore_ != nullptr; }

    // Force a re-enumeration of PDH instances (e.g. after a device change).
    // Thread-safe: it only raises a flag. The sampler thread owns the counter
    // handles and performs the re-enumeration between samples.
    void Reenumerate();

    // Set the idle timeout (default 60 s). After this many milliseconds
    // without a GetLatest/GetHistory call, the sampler drops from 1 Hz to
    // 0.1 Hz. Set to 0 to always sample at full rate.
    void SetIdleTimeoutMs(uint64_t ms) { idleTimeoutMs_.store(ms); }

    // Set whether to keep sampling at full rate while idle (default false).
    void SetKeepCollectingWhileIdle(bool keep) { keepCollectingWhileIdle_.store(keep); }

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

    // One wildcard counter family.
//
// PDH hands out ONE handle for a wildcard counter and tracks new instances on
// its own, so the handle is added once and never re-added. Names and values
// then come back together in a single PdhGetFormattedCounterArray call, which
// is what makes it impossible to pair disk 0's bytes/s with disk 1's name -
// the hazard an index-aligned vector of handles invites.
struct InstanceGroup {
    PDH_HCOUNTER handle = nullptr;
    // PDH names physical disks "<drive index> <volume>", e.g. "0 C:". The index
    // is internal to Windows, so it is stripped to make the sampler agree with
    // the volume list.
    bool stripDriveIndex = false;
    // \GPU Engine(*) instances are named
    // "pid_1234_luid_..._eng_3_engtype_3D": one per process per engine. They
    // are collapsed to the engine type so the UI gets one number per engine
    // rather than hundreds of per-process rows.
    bool collapseToEngineType = false;
};
    bool ReadGroup(const InstanceGroup& group,
                   std::map<std::wstring, double>* values,
                   std::map<std::wstring, bool>* known) const;
    static void ClearGroup(InstanceGroup* group);
    bool ReadScalar(PDH_HCOUNTER counter, double* value) const;
    // Split a raw instance name into the display label. Disk instances look
    // like "0 C:"; the leading index is an internal drive number the UI does not
    // need, and stripping it makes "0 C:" and "0 D:" line up with the volume
    // list the user sees.

    // Collect volume capacities. Walks the mount table, so it is a filesystem
    // call - it runs on the sampler thread, never inside a request.
    void CollectVolumes(MetricsSample* out) const;
    // Collect link speed and up/down per adapter from the IP Helper table.
    void CollectAdapters(MetricsSample* out) const;
    // Collect uptime, process/thread/handle counts.
    void CollectSystemCounts(MetricsSample* out) const;

    // Counter handles (owned by the sampler thread)
    PDH_HCOUNTER pdhCpuTotal_ = nullptr;
    PDH_HCOUNTER pdhCpuCore_ = nullptr;
    PDH_HCOUNTER pdhMemUsed_ = nullptr;
    PDH_HCOUNTER pdhMemTotal_ = nullptr;
    PDH_HCOUNTER pdhMemCache_ = nullptr;
    PDH_HCOUNTER pdhMemKernelPaged_ = nullptr;
    PDH_HCOUNTER pdhMemKernelNonPaged_ = nullptr;
    PDH_HCOUNTER pdhMemCommitLimit_ = nullptr;
    PDH_HCOUNTER pdhMemCommitPeak_ = nullptr;
    PDH_HCOUNTER pdhPageFileBytes_ = nullptr;

    InstanceGroup diskRead_;
    InstanceGroup diskWrite_;
    InstanceGroup diskActive_;
    InstanceGroup diskQueue_;
    InstanceGroup diskLatency_;
    InstanceGroup netRx_;
    InstanceGroup netTx_;
    InstanceGroup gpuEngine_;
    InstanceGroup gpuVram_;

    HANDLE thread_ = nullptr;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    // Set by Reenumerate() from any thread; acted on by the sampler thread. The
    // counter vectors are owned exclusively by the sampler thread, so an
    // external caller must never mutate them itself - doing so raced with
    // CollectSample() on the very same vectors.
    std::atomic<bool> reenumerateRequested_{false};

    // PDH query handle (owned by the sampler thread)
    PDH_HQUERY pdhQuery_ = nullptr;

    // Ring buffers. Tier A is 1 s x 900 (15 min); tier B is 10 s x 2160 (6 h).
    // Tier B receives a decimated copy of the same sample - it is not a second
    // PDH pass, so the extra memory is the only cost.
    MetricsRingBuffer ring_;
    MetricsRingBuffer ringB_;
    // Sampler-thread only: how many 1 Hz samples since the last tier-B push.
    uint32_t sinceTierB_ = 0;
    static constexpr uint32_t kTierBStride = 10;

    // Re-enumeration timer (sampler thread only)
    uint64_t lastReenumerateMs_ = 0;
    // Set after a re-enumeration so the first sample is discarded: removing and
    // re-adding a counter throws away PDH's rate baseline, and the sample taken
    // immediately afterwards is not a real reading.
    bool skipNextSample_ = false;

    // Idle detection. Written by request threads, read by the sampler thread.
    mutable std::atomic<uint64_t> lastAccessMs_{0};
    std::atomic<uint64_t> idleTimeoutMs_{60000};
    std::atomic<bool> keepCollectingWhileIdle_{false};
};

}  // namespace wintcp

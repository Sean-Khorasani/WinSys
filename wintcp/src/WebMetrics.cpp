// WebMetrics.cpp
// SPDX-License-Identifier: Apache-2.0
// Metrics collector implementation for the Web UI.

#include "WebMetrics.h"

#include <pdh.h>
#include <pdhmsg.h>

#include <cmath>
#include <cstdio>
#include <ctime>
#include <cwchar>
#include <algorithm>
#include <utility>

namespace wintcp {
namespace {

// IF_TYPE_SOFTWARE_LOOPBACK is 24. Spelled out here, as SysStats.cpp and
// ChartsWindow.cpp do, so the three samplers cannot drift on what "loopback"
// means to them.
constexpr ULONG kIfTypeSoftwareLoopback = 24;

// Get current Unix time.
uint64_t NowUnix() {
    return static_cast<uint64_t>(std::time(nullptr));
}

// Format a PDH counter value as double.
double PdhValueToDouble(const PDH_FMT_COUNTERVALUE& val) {
    return static_cast<double>(val.doubleValue);
}

// Parse a PDH processor instance name of the form "0,3" (group, core) or a
// bare "3". Hand-rolled: swscanf is deprecated under /W4 /WX and this is four
// lines of work.
bool ParseProcessorInstance(const std::wstring& name, long* group, long* core) {
    size_t i = 0;
    const auto number = [&name, &i](long* out) {
        if (i >= name.size() || name[i] < L'0' || name[i] > L'9') return false;
        long value = 0;
        while (i < name.size() && name[i] >= L'0' && name[i] <= L'9') {
            if (value > 100000) return false;         // implausible; not a core
            value = value * 10 + (name[i] - L'0');
            ++i;
        }
        *out = value;
        return true;
    };
    if (!number(group)) return false;
    *core = *group;
    if (i < name.size() && name[i] == L',') {
        ++i;
        if (!number(core)) return false;
    }
    return i == name.size();
}

// Read a wildcard counter's instances. PDH has no size query: you ask with a
// zero-length buffer, get PDH_MORE_DATA back with a byte count, then ask again.
//
// Two traps, both hit in practice:
//   * The byte count PDH reports is an OVER-estimate - 876 bytes for 26 items of
//     a 24-byte struct - so a buffer sized exactly count*sizeof(item) comes back
//     as PDH_MORE_DATA again. Allocate with headroom and grow on MORE_DATA.
//   * PDH_FMT_COUNTERVALUE_ITEM_W::szName is an LPWSTR into PDH-owned memory,
//     valid only until the next PDH call on that query. Copy it out at once.
//
// `numericOrder` sorts instances by their (group, core) numbers - instances are
// named "0,0", "0,1", "0,10", ... so a plain wcscmp would order core 10 before
// core 2 and reshuffle the series between samples.
bool ReadCounterArray(PDH_HCOUNTER counter, std::vector<double>* values,
                      std::vector<bool>* known, bool numericOrder) {
    if (counter == nullptr || values == nullptr || known == nullptr) return false;

    DWORD bytes = 0;
    DWORD count = 0;
    const PDH_STATUS size = ::PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE,
                                                          &bytes, &count, nullptr);
    if (size != PDH_MORE_DATA && size != ERROR_SUCCESS) return false;
    if (count == 0 || count > 4096) return false;

    // Headroom, because PDH's byte estimate overshoots the real struct size.
    std::vector<PDH_FMT_COUNTERVALUE_ITEM_W> items(count + 32);
    DWORD got = 0;
    PDH_STATUS status = PDH_MORE_DATA;
    for (int attempt = 0; attempt < 3 && status == PDH_MORE_DATA; ++attempt) {
        DWORD inBytes = static_cast<DWORD>(items.size() * sizeof(items[0]));
        DWORD outCount = 0;
        status = ::PdhGetFormattedCounterArray(counter, PDH_FMT_DOUBLE, &inBytes,
                                               &outCount, items.data());
        got = outCount;
        if (status != PDH_MORE_DATA) break;
        const DWORD needed = inBytes / static_cast<DWORD>(sizeof(items[0])) + 32;
        if (needed <= items.size()) items.resize(items.size() * 2 + 32);
        else items.resize(needed);
    }
    if (status != ERROR_SUCCESS || got == 0) return false;
    items.resize(got);

    // Copy the names before anything else can invalidate them, and drop "_Total":
    // it is an aggregate, not a core, and must never become cpu.core.N.
    std::vector<std::pair<std::pair<long, long>, PDH_FMT_COUNTERVALUE>> parsed;
    parsed.reserve(items.size());
    for (const auto& item : items) {
        const std::wstring name = item.szName != nullptr ? item.szName : L"";
        if (name.empty() || name == L"_Total") continue;
        long group = 0, core = 0;
        if (!numericOrder) continue;
        if (!ParseProcessorInstance(name, &group, &core)) continue;
        parsed.emplace_back(std::make_pair(group, core), item.FmtValue);
    }
    std::sort(parsed.begin(), parsed.end(),
              [](const std::pair<std::pair<long, long>, PDH_FMT_COUNTERVALUE>& a,
                 const std::pair<std::pair<long, long>, PDH_FMT_COUNTERVALUE>& b) {
                  return a.first < b.first;
              });

    values->clear();
    known->clear();
    values->reserve(parsed.size());
    known->reserve(parsed.size());
    for (const auto& entry : parsed) {
        const PDH_FMT_COUNTERVALUE& v = entry.second;
        const bool valid = v.CStatus == PDH_CSTATUS_VALID_DATA ||
                           v.CStatus == PDH_CSTATUS_NEW_DATA;
        values->push_back(valid ? PdhValueToDouble(v) : 0.0);
        known->push_back(valid);                 // unknown is never 0
    }
    return !values->empty();
}

}  // namespace

// ---- MetricsRingBuffer ------------------------------------------------------

MetricsRingBuffer::MetricsRingBuffer(size_t capacity) : buffer_(capacity) {}

void MetricsRingBuffer::Push(const MetricsSample& sample) {
    // A zero-capacity ring would make the modulo below a division by zero, and
    // on x86 that is an integer-divide exception which terminates the process.
    // Nothing constructs one in the product, but the unit test does, and a
    // buffer that cannot be constructed safely is a trap for the next caller.
    if (buffer_.empty()) return;
    std::lock_guard<std::mutex> lock(mutex_);
    buffer_[head_] = sample;
    head_ = (head_ + 1) % buffer_.size();
    if (size_ < buffer_.size()) ++size_;
}

std::vector<MetricsSample> MetricsRingBuffer::Since(uint64_t unixTime, size_t maxSamples) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MetricsSample> result;
    if (size_ == 0) return result;

    size_t idx = (head_ + buffer_.size() - 1) % buffer_.size();
    for (size_t i = 0; i < size_ && result.size() < maxSamples; ++i) {
        if (buffer_[idx].unixTime >= unixTime) {
            result.push_back(buffer_[idx]);
        }
        idx = (idx + buffer_.size() - 1) % buffer_.size();
    }
    std::reverse(result.begin(), result.end());
    return result;
}

bool MetricsRingBuffer::Latest(MetricsSample* out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (size_ == 0 || out == nullptr) return false;
    size_t idx = (head_ + buffer_.size() - 1) % buffer_.size();
    *out = buffer_[idx];
    return true;
}

size_t MetricsRingBuffer::Size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return size_;
}

size_t MetricsRingBuffer::Capacity() const {
    return buffer_.capacity();
}

void MetricsRingBuffer::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    head_ = 0;
    size_ = 0;
}

// ---- MetricsCollector --------------------------------------------------------

MetricsCollector::MetricsCollector() : ring_(900), ringB_(2160) {}

MetricsCollector::~MetricsCollector() {
    Stop();
}

bool MetricsCollector::Start() {
    if (running_.load()) return true;

    if (!OpenPdhQuery()) {
        return false;
    }

    stopRequested_.store(false);
    running_.store(true);
    thread_ = ::CreateThread(nullptr, 0, ThreadProc, this, 0, nullptr);
    if (thread_ == nullptr) {
        running_.store(false);
        ClosePdhQuery();
        return false;
    }
    return true;
}

void MetricsCollector::Stop() {
    if (!running_.load()) return;
    stopRequested_.store(true);
    if (thread_ != nullptr) {
        ::WaitForSingleObject(thread_, 5000);
        ::CloseHandle(thread_);
        thread_ = nullptr;
    }
    running_.store(false);
    ClosePdhQuery();
}

bool MetricsCollector::GetLatest(MetricsSample* out) const {
    lastAccessMs_.store(::GetTickCount64());
    return ring_.Latest(out);
}

std::vector<MetricsSample> MetricsCollector::GetHistory(uint64_t since, size_t maxSamples) const {
    lastAccessMs_.store(::GetTickCount64());
    return ring_.Since(since, maxSamples);
}

std::vector<MetricsSample> MetricsCollector::GetHistoryTierB(uint64_t since,
                                                            size_t maxSamples) const {
    lastAccessMs_.store(::GetTickCount64());
    return ringB_.Since(since, maxSamples);
}

std::vector<MetricsSample> MetricsCollector::GetHistory(Tier tier, uint64_t since,
                                                       size_t maxSamples) const {
    return tier == Tier::B ? GetHistoryTierB(since, maxSamples)
                           : GetHistory(since, maxSamples);
}

void MetricsCollector::Reenumerate() {
    // Only raise the flag. The counter vectors belong to the sampler thread;
    // mutating them from a request thread raced with CollectSample().
    reenumerateRequested_.store(true);
}

DWORD WINAPI MetricsCollector::ThreadProc(LPVOID param) {
    auto* self = static_cast<MetricsCollector*>(param);
    if (self != nullptr) self->Run();
    return 0;
}

void MetricsCollector::Run() {
    lastReenumerateMs_ = ::GetTickCount64();
    // Devices come and go (a USB NIC, a removable volume). Five minutes is
    // frequent enough to notice and rare enough that discarding one sample for
    // the lost rate baseline is invisible on a 1 Hz chart.
    constexpr uint64_t kReenumerateEveryMs = 5 * 60 * 1000;
    while (!stopRequested_.load()) {
        // Re-enumeration first: a fresh counter has no baseline yet, so the
        // sample this pass would take is thrown away.
        const uint64_t loopStartMs = ::GetTickCount64();
        if (reenumerateRequested_.exchange(false) ||
            loopStartMs - lastReenumerateMs_ > kReenumerateEveryMs) {
            ReenumerateInstances();
            lastReenumerateMs_ = loopStartMs;
            skipNextSample_ = true;
        }

        MetricsSample sample;
        if (CollectSample(&sample) && !skipNextSample_) {
            ring_.Push(sample);
            // Decimate into tier B on a fixed stride. Using the stride rather
            // than a wall-clock comparison keeps the 6 h buffer evenly spaced
            // and exactly kTierBStride samples behind the live tier.
            if (++sinceTierB_ >= kTierBStride) {
                sinceTierB_ = 0;
                ringB_.Push(sample);
            }
        }
        skipNextSample_ = false;

        // Idle cadence (C-8: a sampler that never sleeps is a permanent tax).
        //
        // 1 s while something is watching, 10 s once idle. The original loop
        // slept 100 ms between samples, which is 10 Hz: 900 ring-buffer slots
        // (the documented 15 minutes at 1 Hz) were gone in 90 seconds, and the
        // "1 s x 900" tier in the plan was silently a "100 ms x 900" tier.
        const uint64_t idleTimeout = idleTimeoutMs_.load();
        const uint64_t sinceAccess = loopStartMs - lastAccessMs_.load();
        const bool idle = !keepCollectingWhileIdle_.load() && idleTimeout > 0 &&
                          sinceAccess > idleTimeout;
        const DWORD stepMs = idle ? 10000 : 1000;
        const ULONGLONG stepEnd = ::GetTickCount64() + stepMs;
        while (::GetTickCount64() < stepEnd) {
            if (stopRequested_.load()) break;
            ::Sleep(50);
        }
    }
}

bool MetricsCollector::OpenPdhQuery() {
    PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &pdhQuery_);
    if (status != ERROR_SUCCESS) return false;
    return AddCounters();
}

void MetricsCollector::ClosePdhQuery() {
    if (pdhQuery_ != nullptr) {
        ::PdhCloseQuery(pdhQuery_);
        pdhQuery_ = nullptr;
    }
}

bool MetricsCollector::AddCounters() {
    if (pdhQuery_ == nullptr) return false;

    // "% Processor Utility" exists ONLY under "Processor Information" - the
    // plain "\Processor(_Total)\% Processor Utility" path fails to add with
    // PDH_CSTATUS_NO_COUNTER. (_Total) is an explicit instance, not a wildcard:
    // it reads back reliably through PdhGetFormattedCounterValue. Per-core comes
    // from the wildcard handle below through PdhGetFormattedCounterArray.
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Processor Information(_Total)\\% Processor Utility",
        0, &pdhCpuTotal_);

    if (::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Processor Information(*)\\% Processor Utility",
        0, &pdhCpuCore_) != ERROR_SUCCESS) {
        pdhCpuCore_ = nullptr;      // /api/capabilities reports perCore=false
    }

    // Memory composition. Each is independent: a Server SKU or a container can
    // refuse some, and a refused counter must leave its own field unknown
    // rather than zeroing the whole memory panel.
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Committed Bytes", 0, &pdhMemUsed_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Commit Limit", 0, &pdhMemTotal_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Cache Bytes", 0, &pdhMemCache_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Pool Paged Bytes", 0, &pdhMemKernelPaged_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Pool Nonpaged Bytes", 0, &pdhMemKernelNonPaged_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Commit Limit", 0, &pdhMemCommitLimit_);
    // "Peak" is a separate counter from "Limit" despite the shared name.
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Commit Limit", 0, &pdhMemCommitPeak_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Paging File(_Total)\\% Usage", 0, &pdhPageFileBytes_);

    ReenumerateInstances();
    return true;
}

// Read one scalar counter into a double, leaving *known false on any failure.
bool MetricsCollector::ReadScalar(PDH_HCOUNTER counter, double* value) const {
    if (counter == nullptr || value == nullptr) return false;
    PDH_FMT_COUNTERVALUE val = {};
    if (::PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &val) != ERROR_SUCCESS) {
        return false;
    }
    *value = PdhValueToDouble(val);
    return true;
}

bool MetricsCollector::CollectSample(MetricsSample* out) {
    if (out == nullptr || pdhQuery_ == nullptr) return false;

    PDH_STATUS status = ::PdhCollectQueryData(pdhQuery_);
    if (status != ERROR_SUCCESS && status != PDH_NO_DATA) {
        return false;
    }

    double v = 0.0;

    if (ReadScalar(pdhCpuTotal_, &v)) {
        out->cpuTotalKnown = true;
        out->cpuTotal = v;
    }

    // Per-core CPU. A wildcard counter must be read with the ARRAY API; reading
    // it as a single value is what previously made cpuCore stay empty while
    // /api/capabilities advertised perCore=true.
    ReadCounterArray(pdhCpuCore_, &out->cpuCore, &out->cpuCoreKnown,
                     /*sortByName=*/true);

    if (ReadScalar(pdhMemUsed_, &v)) {
        out->memUsedKnown = true;
        out->memUsed = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhMemTotal_, &v)) {
        out->memTotalKnown = true;
        out->memTotal = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhMemCache_, &v)) {
        out->memCacheKnown = true;
        out->memCache = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhMemKernelPaged_, &v)) {
        out->memKernelPagedKnown = true;
        out->memKernelPaged = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhMemKernelNonPaged_, &v)) {
        out->memKernelNonPagedKnown = true;
        out->memKernelNonPaged = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhMemCommitLimit_, &v)) {
        out->memCommitLimitKnown = true;
        out->memCommitLimit = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhMemCommitPeak_, &v)) {
        out->memCommitPeakKnown = true;
        out->memCommitPeak = static_cast<uint64_t>(v);
    }
    if (ReadScalar(pdhPageFileBytes_, &v)) {
        out->memPagedPoolTotalKnown = true;
        out->memPagedPoolTotal = static_cast<uint64_t>(v);
    }

    // Per-instance groups. Each counter family is read independently so a disk
    // that disappears takes only its own row down, not the whole disk panel.
    ReadGroup(diskRead_,   &out->diskReadBps,   &out->diskReadKnown);
    ReadGroup(diskWrite_,  &out->diskWriteBps,  &out->diskWriteKnown);
    ReadGroup(diskActive_, &out->diskActivePct, &out->diskActiveKnown);
    ReadGroup(diskQueue_,  &out->diskQueueLength, &out->diskQueueKnown);
    ReadGroup(diskLatency_,&out->diskLatencyMs, &out->diskLatencyKnown);
    ReadGroup(netRx_,      &out->netRxBps,      &out->netRxKnown);
    ReadGroup(netTx_,      &out->netTxBps,      &out->netTxKnown);
    ReadGroup(gpuEngine_,  &out->gpuEnginePct,  &out->gpuEngineKnown);

    // GPU VRAM is a level, not a rate, so it sums the adapter-memory wildcard.
    // Summing is the right shape here because the instances are one per process
    // per adapter, and "dedicated bytes in use across all processes" is the
    // number a user is asking for.
    {
        std::map<std::wstring, double> vram;
        std::map<std::wstring, bool> vramKnown;
        if (ReadGroup(gpuVram_, &vram, &vramKnown)) {
            double total = 0.0;
            for (const auto& kv : vram) total += kv.second;
            out->gpuVramKnown = true;
            out->gpuVramUsed = static_cast<uint64_t>(total);
        }
    }

    CollectVolumes(out);
    CollectAdapters(out);
    CollectSystemCounts(out);

    // GlobalMemoryStatusEx is cheap and authoritative for used/total/available,
    // which is what the KPI cards show. PDH "Committed Bytes" is a different
    // number (commit charge) and must not be presented as "used".
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (::GlobalMemoryStatusEx(&mem)) {
        out->memTotalKnown = true;
        out->memTotal = mem.ullTotalPhys;
        out->memAvailableKnown = true;
        out->memAvailable = mem.ullAvailPhys;
        out->memUsedKnown = true;
        out->memUsed = mem.ullTotalPhys - mem.ullAvailPhys;
    }

    out->tickMs = ::GetTickCount64();
    out->unixTime = NowUnix();
    return true;
}

// Read every instance of one wildcard counter.
//
// Names and values arrive in the SAME array, in the same order, from a single
// call. That is the whole point: the earlier design kept a vector of handles and
// a parallel vector of names, which had to be refreshed together or a value
// would be attributed to the wrong disk.
bool MetricsCollector::ReadGroup(const InstanceGroup& group,
                                 std::map<std::wstring, double>* values,
                                 std::map<std::wstring, bool>* known) const {
    if (values == nullptr || known == nullptr) return false;
    values->clear();
    known->clear();
    if (group.handle == nullptr) return false;

    // PDH has no size query: ask with a zero-length buffer, get PDH_MORE_DATA
    // back with a byte count, then ask again. The byte count is an
    // over-estimate, so the buffer is allocated generously and the count is
    // capped - a wildcard counter on a busy machine can legitimately name
    // hundreds of GPU engines, and an uncapped count would let PDH write past
    // the allocation.
    DWORD bytes = 0;
    DWORD count = 0;
    PDH_STATUS status = ::PdhGetFormattedCounterArray(
        group.handle, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, &bytes, &count, nullptr);
    if (status != PDH_MORE_DATA || count == 0 || count > 65536) {
        // No instances yet, or the counter vanished. Report nothing rather than
        // an empty-but-"known" set: the caller turns this into null plus a
        // reason (C-6).
        return false;
    }
    std::vector<BYTE> buffer(bytes + 4096);
    count = 0;
    status = ::PdhGetFormattedCounterArray(
        group.handle, PDH_FMT_DOUBLE | PDH_FMT_NOSCALE, &bytes, &count,
        reinterpret_cast<PPDH_FMT_COUNTERVALUE_ITEM_W>(buffer.data()));
    if (status != ERROR_SUCCESS || count == 0) return false;

    auto* items = reinterpret_cast<PPDH_FMT_COUNTERVALUE_ITEM_W>(buffer.data());
    bool any = false;
    for (DWORD i = 0; i < count; ++i) {
        if (items[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA &&
            items[i].FmtValue.CStatus != PDH_CSTATUS_NEW_DATA) {
            // No reading this pass. Leaving the label out entirely is the honest
            // answer; marking it known-with-zero would read as "idle disk".
            continue;
        }
        const wchar_t* raw = items[i].szName;
        if (raw == nullptr || raw[0] == L'\0') continue;
        // "_Total" is a pseudo-instance PDH synthesises for every wildcard. It
        // is an aggregate of the rows beside it, so keeping it would double
        // count the machine's total against the sum of its parts. The CPU-core
        // reader drops it for the same reason.
        if (raw[0] == L'_' && ::_wcsicmp(raw, L"_Total") == 0) continue;
        std::wstring label(raw);
        if (group.stripDriveIndex) label = DiskInstanceLabel(label);
        if (group.collapseToEngineType) label = GpuEngineTypeLabel(label);
        // Several instances collapse to one label (the GPU case), so a
        // repeated label accumulates rather than overwrites.
        (*values)[label] += PdhValueToDouble(items[i].FmtValue);
        (*known)[label] = true;
        any = true;
    }
    return any;
}

// Walk the mount table for volume capacities. Sampler thread only: this is a
// filesystem call, and C-8 forbids doing it inside a request.
void MetricsCollector::CollectVolumes(MetricsSample* out) const {
    if (out == nullptr) return;
    DWORD needed = ::GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if ((needed & (1u << i)) == 0) continue;
        const std::wstring root = std::wstring(1, static_cast<wchar_t>(L'A' + i)) + L":\\";
        ULARGE_INTEGER avail = {};
        ULARGE_INTEGER total = {};
        if (!::GetDiskFreeSpaceExW(root.c_str(), &avail, &total, nullptr)) continue;
        MetricsSample::VolumeInfo info;
        info.known = true;
        info.totalBytes = static_cast<uint64_t>(total.QuadPart);
        info.freeBytes = static_cast<uint64_t>(avail.QuadPart);

        wchar_t fsName[64] = {};
        wchar_t volName[256] = {};
        if (::GetVolumeInformationW(root.c_str(), volName, 256, nullptr, nullptr,
                                    nullptr, fsName, 64) != FALSE) {
            info.fileSystem.assign(fsName);
            info.label.assign(volName);
        }
        out->volumes[std::wstring(1, static_cast<wchar_t>(L'A' + i)) + L":"] = info;
    }
}

// Link speed and up/down per adapter, from the IP Helper table. Sampler thread
// only, for the same reason as CollectVolumes.
void MetricsCollector::CollectAdapters(MetricsSample* out) const {
    if (out == nullptr) return;
    // GetIfTable2 hands back a block the caller must free with FreeMibTable;
    // asking for the size first would mean freeing it twice.
    PMIB_IF_TABLE2 table = nullptr;
    if (::GetIfTable2(&table) != NO_ERROR || table == nullptr) return;

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IF_ROW2& row = table->Table[i];
        // Loopback carries no link speed and no meaningful throughput, and
        // including it would put a second "Ethernet"-like row in the adapter
        // list. SysStats excludes it for the same reason.
        if (row.Type == kIfTypeSoftwareLoopback) continue;
        if (row.Type != IF_TYPE_ETHERNET_CSMACD && row.Type != IF_TYPE_IEEE80211 &&
            row.Type != IF_TYPE_PPP && row.Type != IF_TYPE_TUNNEL) {
            continue;
        }
        // Alias is the friendly adapter name ("Ethernet"); Description is the
        // hardware string. Copy it out here because the whole table is freed at
        // the end of this scope. Alias is preferred because it matches the
        // instance name the PDH network counters use, which is what lets the UI
        // join the two without a lookup table.
        std::wstring label(row.Alias);
        if (label.empty()) label = row.Description;
        if (label.empty()) continue;

        if (row.TransmitLinkSpeed != 0) {
            out->netLinkBits[label] = static_cast<uint64_t>(row.TransmitLinkSpeed);
            out->netLinkKnown[label] = true;
        }
        // IF_OPER_STATUS: 1 is IfOperStatusUp. Spelled as a literal because the
        // SDK enum is only visible with a newer _WIN32_WINNT than this
        // project's headers declare.
        out->netUp[label] = (static_cast<int>(row.OperStatus) == 1);
    }
    ::FreeMibTable(table);
}

void MetricsCollector::CollectSystemCounts(MetricsSample* out) const {
    if (out == nullptr) return;
    // GetTickCount64 counts since boot, which is exactly the uptime, and it
    // needs no syscall and no privileges.
    out->uptimeKnown = true;
    out->uptimeSeconds = ::GetTickCount64() / 1000;

    PERFORMANCE_INFORMATION perf = {};
    perf.cb = sizeof(perf);
    if (::GetPerformanceInfo(&perf, sizeof(perf))) {
        out->processCountKnown = true;
        out->processCount = perf.ProcessCount;
        out->threadCountKnown = true;
        out->threadCount = perf.ThreadCount;
        out->handleCountKnown = true;
        out->handleCount = perf.HandleCount;
    }
}

// Release one group. PdhRemoveCounter must be called before the query closes,
// so this is shared by ReenumerateInstances and the teardown path.
void MetricsCollector::ClearGroup(InstanceGroup* g) {
    if (g == nullptr) return;
    if (g->handle != nullptr) {
        ::PdhRemoveCounter(g->handle);
        g->handle = nullptr;
    }
}

std::wstring DiskInstanceLabel(const std::wstring& instance) {
    // PDH names physical disks "<drive index> <volume>": "0 C:", "1 D:".
    // Drop the index so the sampler and the volume list agree on "C:".
    size_t i = 0;
    while (i < instance.size() && instance[i] >= L'0' && instance[i] <= L'9') ++i;
    if (i > 0 && i < instance.size() && instance[i] == L' ') {
        return instance.substr(i + 1);
    }
    return instance;
}

std::wstring GpuEngineTypeLabel(const std::wstring& instance) {
    // \GPU Engine(*) instances are named
    //   "pid_1234_luid_0x..._phys_0_eng_3_engtype_3D"
    // - one per process, per physical adapter, per engine. The UI wants one
    // number per engine TYPE, so everything from the LAST "engtype_" onwards is
    // the label. LAST rather than first: taking the first would rely on a
    // segment ordering PDH does not document.
    static const wchar_t kTag[] = L"engtype_";
    const size_t tagLen = sizeof(kTag) / sizeof(kTag[0]) - 1;
    if (instance.size() <= tagLen) return instance;
    const size_t pos = instance.rfind(kTag);
    if (pos == std::wstring::npos) {
        // Not an engine instance. \GPU Adapter Memory(*) uses
        // "luid_0x..._phys_0" names, and those must survive unchanged rather
        // than collapse to an empty label.
        return instance;
    }
    const size_t valueStart = pos + tagLen;
    if (valueStart >= instance.size()) return instance;   // no value: keep as-is
    return instance.substr(valueStart);
}

void MetricsCollector::ReenumerateInstances() {
    ClearGroup(&diskRead_);
    ClearGroup(&diskWrite_);
    ClearGroup(&diskActive_);
    ClearGroup(&diskQueue_);
    ClearGroup(&diskLatency_);
    ClearGroup(&netRx_);
    ClearGroup(&netTx_);
    ClearGroup(&gpuEngine_);
    ClearGroup(&gpuVram_);

    // Add each wildcard counter exactly once. PDH tracks new instances on the
    // handle by itself, so nothing here has to be repeated: a USB NIC that
    // appears an hour later is picked up by the very next ReadGroup with no
    // re-add and no lost rate baseline. The reason the previous version had a
    // five-minute re-enumeration pass at all was that it was caching instance
    // NAMES; reading names and values together removes that cache and with it
    // the whole class of "the list is stale" bug.
    const auto add = [this](InstanceGroup* group, const wchar_t* path,
                            bool stripDriveIndex, bool collapseToEngineType) {
        PDH_HCOUNTER handle = nullptr;
        if (::PdhAddEnglishCounterW(pdhQuery_, path, 0, &handle) != ERROR_SUCCESS ||
            handle == nullptr) {
            return;
        }
        group->handle = handle;
        group->stripDriveIndex = stripDriveIndex;
        group->collapseToEngineType = collapseToEngineType;
    };

    // Disk health, not just throughput: active time answers "is it busy",
    // queue depth answers "is it keeping up", latency answers "is it stalling".
    add(&diskRead_,   L"\\PhysicalDisk(*)\\Disk Read Bytes/sec", true, false);
    add(&diskWrite_,  L"\\PhysicalDisk(*)\\Disk Write Bytes/sec", true, false);
    add(&diskActive_, L"\\PhysicalDisk(*)\\% Disk Time", true, false);
    add(&diskQueue_,  L"\\PhysicalDisk(*)\\Current Disk Queue Length", true, false);
    add(&diskLatency_,L"\\PhysicalDisk(*)\\Avg. Disk sec/Transfer", true, false);

    add(&netRx_, L"\\Network Interface(*)\\Bytes Received/sec", false, false);
    add(&netTx_, L"\\Network Interface(*)\\Bytes Sent/sec", false, false);

    // GPU counters are absent on machines without a supported adapter, so both
    // adds are allowed to fail silently; /api/capabilities reports gpu=false
    // when neither produced an instance.
    add(&gpuEngine_, L"\\GPU Engine(*)\\Utilization Percentage", false, true);
    add(&gpuVram_,   L"\\GPU Adapter Memory(*)\\Dedicated Usage", false, false);
}

}  // namespace wintcp

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

MetricsCollector::MetricsCollector() : ring_(900) {}

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

    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Committed Bytes", 0, &pdhMemUsed_);
    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Memory\\Commit Limit", 0, &pdhMemTotal_);

    ReenumerateInstances();
    return true;
}

bool MetricsCollector::CollectSample(MetricsSample* out) {
    if (out == nullptr || pdhQuery_ == nullptr) return false;

    PDH_STATUS status = ::PdhCollectQueryData(pdhQuery_);
    if (status != ERROR_SUCCESS && status != PDH_NO_DATA) {
        return false;
    }

    PDH_FMT_COUNTERVALUE cpuVal = {};
    status = ::PdhGetFormattedCounterValue(pdhCpuTotal_, PDH_FMT_DOUBLE, nullptr, &cpuVal);
    if (status == ERROR_SUCCESS) {
        out->cpuTotalKnown = true;
        out->cpuTotal = PdhValueToDouble(cpuVal);
    }

    // Per-core CPU. A wildcard counter must be read with the ARRAY API; reading
    // it as a single value is what previously made cpuCore stay empty while
    // /api/capabilities advertised perCore=true.
    ReadCounterArray(pdhCpuCore_, &out->cpuCore, &out->cpuCoreKnown,
                     /*sortByName=*/true);

    PDH_FMT_COUNTERVALUE memUsedVal = {};
    status = ::PdhGetFormattedCounterValue(pdhMemUsed_, PDH_FMT_DOUBLE, nullptr, &memUsedVal);
    if (status == ERROR_SUCCESS) {
        out->memUsedKnown = true;
        out->memUsed = static_cast<uint64_t>(PdhValueToDouble(memUsedVal));
    }

    PDH_FMT_COUNTERVALUE memTotalVal = {};
    status = ::PdhGetFormattedCounterValue(pdhMemTotal_, PDH_FMT_DOUBLE, nullptr, &memTotalVal);
    if (status == ERROR_SUCCESS) {
        out->memTotalKnown = true;
        out->memTotal = static_cast<uint64_t>(PdhValueToDouble(memTotalVal));
    }

    for (size_t i = 0; i < pdhDiskRead_.size(); ++i) {
        if (pdhDiskRead_[i] == nullptr) continue;
        PDH_FMT_COUNTERVALUE val = {};
        status = ::PdhGetFormattedCounterValue(pdhDiskRead_[i], PDH_FMT_DOUBLE, nullptr, &val);
        if (status == ERROR_SUCCESS) {
            std::wstring inst = L"disk" + std::to_wstring(i);
            out->diskReadBps[inst] = PdhValueToDouble(val);
            out->diskReadKnown[inst] = true;
        }
    }
    for (size_t i = 0; i < pdhDiskWrite_.size(); ++i) {
        if (pdhDiskWrite_[i] == nullptr) continue;
        PDH_FMT_COUNTERVALUE val = {};
        status = ::PdhGetFormattedCounterValue(pdhDiskWrite_[i], PDH_FMT_DOUBLE, nullptr, &val);
        if (status == ERROR_SUCCESS) {
            std::wstring inst = L"disk" + std::to_wstring(i);
            out->diskWriteBps[inst] = PdhValueToDouble(val);
            out->diskWriteKnown[inst] = true;
        }
    }

    for (size_t i = 0; i < pdhNetRx_.size(); ++i) {
        if (pdhNetRx_[i] == nullptr) continue;
        PDH_FMT_COUNTERVALUE val = {};
        status = ::PdhGetFormattedCounterValue(pdhNetRx_[i], PDH_FMT_DOUBLE, nullptr, &val);
        if (status == ERROR_SUCCESS) {
            std::wstring inst = L"net" + std::to_wstring(i);
            out->netRxBps[inst] = PdhValueToDouble(val);
            out->netRxKnown[inst] = true;
        }
    }
    for (size_t i = 0; i < pdhNetTx_.size(); ++i) {
        if (pdhNetTx_[i] == nullptr) continue;
        PDH_FMT_COUNTERVALUE val = {};
        status = ::PdhGetFormattedCounterValue(pdhNetTx_[i], PDH_FMT_DOUBLE, nullptr, &val);
        if (status == ERROR_SUCCESS) {
            std::wstring inst = L"net" + std::to_wstring(i);
            out->netTxBps[inst] = PdhValueToDouble(val);
            out->netTxKnown[inst] = true;
        }
    }

    out->tickMs = ::GetTickCount64();
    out->unixTime = NowUnix();
    return true;
}

void MetricsCollector::ReenumerateInstances() {
    for (auto& h : pdhDiskRead_) if (h) { ::PdhRemoveCounter(h); h = nullptr; }
    for (auto& h : pdhDiskWrite_) if (h) { ::PdhRemoveCounter(h); h = nullptr; }
    for (auto& h : pdhNetRx_) if (h) { ::PdhRemoveCounter(h); h = nullptr; }
    for (auto& h : pdhNetTx_) if (h) { ::PdhRemoveCounter(h); h = nullptr; }
    pdhDiskRead_.clear();
    pdhDiskWrite_.clear();
    pdhNetRx_.clear();
    pdhNetTx_.clear();

    PDH_HCOUNTER h = nullptr;
    if (::PdhAddEnglishCounterW(pdhQuery_, L"\\PhysicalDisk(*)\\Disk Read Bytes/sec", 0, &h) == ERROR_SUCCESS) {
        pdhDiskRead_.push_back(h);
    }
    if (::PdhAddEnglishCounterW(pdhQuery_, L"\\PhysicalDisk(*)\\Disk Write Bytes/sec", 0, &h) == ERROR_SUCCESS) {
        pdhDiskWrite_.push_back(h);
    }
    if (::PdhAddEnglishCounterW(pdhQuery_, L"\\Network Interface(*)\\Bytes Received/sec", 0, &h) == ERROR_SUCCESS) {
        pdhNetRx_.push_back(h);
    }
    if (::PdhAddEnglishCounterW(pdhQuery_, L"\\Network Interface(*)\\Bytes Sent/sec", 0, &h) == ERROR_SUCCESS) {
        pdhNetTx_.push_back(h);
    }
}

}  // namespace wintcp

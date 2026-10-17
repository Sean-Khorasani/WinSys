// WebMetrics.cpp
// SPDX-License-Identifier: Apache-2.0
// Metrics collector implementation for the Web UI.

#include "WebMetrics.h"

#include <pdh.h>
#include <pdhmsg.h>

#include <cmath>
#include <cstdio>
#include <ctime>
#include <algorithm>

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
    lastAccessMs_ = ::GetTickCount64();
    return ring_.Latest(out);
}

std::vector<MetricsSample> MetricsCollector::GetHistory(uint64_t since, size_t maxSamples) const {
    lastAccessMs_ = ::GetTickCount64();
    return ring_.Since(since, maxSamples);
}

void MetricsCollector::Reenumerate() {
    std::lock_guard<std::mutex> lock(prevMutex_);
    ReenumerateInstances();
}

DWORD WINAPI MetricsCollector::ThreadProc(LPVOID param) {
    auto* self = static_cast<MetricsCollector*>(param);
    if (self != nullptr) self->Run();
    return 0;
}

void MetricsCollector::Run() {
    while (!stopRequested_.load()) {
        MetricsSample sample;
        if (CollectSample(&sample)) {
            ring_.Push(sample);
        }
        for (int i = 0; i < 10 && !stopRequested_.load(); ++i) {
            ::Sleep(100);
        }

        uint64_t now = ::GetTickCount64();
        if (now - lastReenumerateMs_ > 30000) {
            ReenumerateInstances();
            lastReenumerateMs_ = now;
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

    ::PdhAddEnglishCounterW(pdhQuery_,
        L"\\Processor Information(*)\\% Processor Utility",
        0, &pdhCpuTotal_);

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

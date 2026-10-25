// ConnectionEventCollector.h
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "EventDecoder.h"
#include "ProcessInstanceCache.h"
#include "BoundedEventQueue.h"
#include <atomic>
#include <deque>
#include <mutex>
#include <memory>
#include <map>

namespace wintcp {
class LifecycleFlowModel;

struct ConnectionCollectorStatus {
    bool running = false;
    std::uint64_t decoded = 0;
    std::uint64_t queueLost = 0;
    std::uint64_t schemaRejected = 0;
    std::uint64_t eventsLost = 0;
    std::uint64_t buffersLost = 0;
    std::uint64_t historyEvicted = 0;
    std::uint64_t qpcFrequency = 0;
    ULONG traceResult = ERROR_SUCCESS;
    std::uint64_t attributed = 0;
    bool clockStable = true;
    std::uint64_t clockMappingGeneration = 0;
    std::uint64_t clockRecoveries = 0;
    std::uint64_t lateRecords = 0, flowEvicted = 0, reorderFlushes = 0;
    std::uint64_t published = 0;
};

struct QpcClockUpdate {
    bool sampleAccepted = false;
    bool mappingChanged = false;
    bool recovered = false;
    bool stable = false;
    std::uint64_t generation = 0;
};

// Piecewise QPC-to-FILETIME mapping. A discontinuity starts a new generation;
// identity attribution resumes only after two consistent reliable samples.
class QpcClockMapper {
public:
    bool Reset(std::uint64_t qpc, std::uint64_t fileTime,
               std::uint64_t frequency);
    QpcClockUpdate Observe(std::uint64_t qpc, std::uint64_t fileTime,
                           bool reliable);
    bool Project(std::uint64_t qpc, std::uint64_t* fileTime) const;
    bool Stable() const { return stable_; }
    std::uint64_t Generation() const { return generation_; }
    std::uint64_t Recoveries() const { return recoveries_; }
private:
    std::uint64_t frequency_ = 0;
    std::uint64_t anchorQpc_ = 0;
    std::uint64_t anchorFileTime_ = 0;
    std::uint64_t generation_ = 0;
    std::uint64_t recoveries_ = 0;
    unsigned consistentSamples_ = 0;
    bool stable_ = false;
};

std::string TraceObservationJson(const TraceObservation& observation,
                                 const std::string& epoch,
                                 std::uint64_t qpcFrequency);
GUID LifecycleSessionOwnerGuid(const std::wstring& ownerScope);
bool LifecycleSessionOwnerMatches(const GUID& observed, const GUID& expected);

// Broker-only coordinator. Exactly one instance feeds all engine consumers;
// no recipe/UI starts a global kernel logger. Callbacks only copy bounded data.
class ConnectionEventCollector {
public:
    explicit ConnectionEventCollector(std::wstring ownerScope);
    ~ConnectionEventCollector();
    ConnectionEventCollector(const ConnectionEventCollector&) = delete;
    ConnectionEventCollector& operator=(const ConnectionEventCollector&) = delete;
    bool Start(std::string* error);
    bool Stop(std::string* error);
    ConnectionCollectorStatus Status() const;
    std::vector<TraceObservation> ReadAfter(std::uint64_t sequence,
                                           std::size_t limit,
                                           std::uint64_t* firstRetained = nullptr) const;
    std::uint64_t FirstRetainedSequence() const;
    std::uint64_t LastSourceSequence() const { return nextSequence_.load(); }
    std::uint64_t LastPublishedSequence() const { return published_.load(); }
    const std::string& Epoch() const { return epoch_; }

private:
    struct RawRecord {
        EVENT_HEADER header = {};
        ETW_BUFFER_CONTEXT context = {};
        std::vector<unsigned char> payload;
        std::uint64_t sequence = 0;
        std::uint64_t receivedUtcMs = 0;
        std::uint64_t receivedFileTime = 0;
        std::uint64_t receivedQpc = 0;
        bool clockSampleReliable = false;
    };
    static VOID WINAPI EventThunk(EVENT_RECORD* record);
    static ULONG WINAPI BufferThunk(EVENT_TRACE_LOGFILEW* buffer);
    static DWORD WINAPI TraceThread(void* context);
    static DWORD WINAPI DecodeThread(void* context);
    void OnEvent(EVENT_RECORD* record) noexcept;
    void DecodeLoop();
    void Attribute(const RawRecord& raw, TraceObservation* observation);
    void Publish(std::vector<TraceObservation> observations);
    TRACEHANDLE session_ = 0;
    std::atomic<TRACEHANDLE> trace_{INVALID_PROCESSTRACE_HANDLE};
    HANDLE traceThread_ = nullptr;
    HANDLE decoderThread_ = nullptr;
    std::wstring sessionName_;
    std::wstring ownerScope_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<std::uint64_t> nextSequence_{0}, decoded_{0}, rejected_{0};
    std::atomic<std::uint64_t> eventsLost_{0}, buffersLost_{0}, historyEvicted_{0};
    std::atomic<ULONG> traceResult_{ERROR_SUCCESS};
    std::atomic<std::uint64_t> qpcFrequency_{0};
    std::atomic<std::uint64_t> attributed_{0};
    std::atomic<bool> clockStable_{true};
    std::atomic<std::uint64_t> clockMappingGeneration_{0}, clockRecoveries_{0};
    QpcClockMapper clockMapper_;
    ProcessInstanceCache identities_;
    struct ProcessImageHint {
        std::uint64_t startQpc = 0;
        std::uint64_t endQpc = 0;
        std::uint64_t key = 0;
        bool keyKnown = false;
        std::string imageName;
    };
    std::map<std::uint32_t, ProcessImageHint> processImageHints_;
    std::string epoch_;
    std::unique_ptr<LifecycleFlowModel> normalizer_;
    std::atomic<std::uint64_t> published_{0}, lateRecords_{0}, flowEvicted_{0}, reorderFlushes_{0};
    BoundedEventQueue<RawRecord> queue_{16384, 8 * 1024 * 1024};
    mutable std::mutex historyMutex_;
    std::deque<TraceObservation> history_;
    std::size_t historyBytes_ = 0;
};

}  // namespace wintcp

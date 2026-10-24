// ConnectionEventCollector.cpp
// SPDX-License-Identifier: Apache-2.0
#include "ConnectionEventCollector.h"
#include "LifecycleFlowModel.h"
#include <objbase.h>
#include <chrono>
#include <cstring>
#include <utility>
#include <limits>
#include <cstdio>

namespace wintcp {
namespace {
constexpr std::size_t kMaxQueueRecords = 16384;
constexpr std::size_t kMaxQueueBytes = 8 * 1024 * 1024;
constexpr std::size_t kMaxHistoryRecords = 16384;
constexpr std::size_t kMaxHistoryBytes = 16 * 1024 * 1024;
constexpr ULONG kPropertiesBytes = sizeof(EVENT_TRACE_PROPERTIES) + 512 * sizeof(wchar_t);

struct ProfilePrivilege {
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES previous = {};
    bool enabled = false;
    ProfilePrivilege() {
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                &token)) return;
        TOKEN_PRIVILEGES requested = {};
        requested.PrivilegeCount = 1;
        if (!::LookupPrivilegeValueW(nullptr, SE_SYSTEM_PROFILE_NAME,
                                    &requested.Privileges[0].Luid)) return;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD bytes = sizeof(previous);
        ::SetLastError(ERROR_SUCCESS);
        enabled = ::AdjustTokenPrivileges(token, FALSE, &requested, sizeof(previous),
                                          &previous, &bytes) &&
            ::GetLastError() == ERROR_SUCCESS;
    }
    ~ProfilePrivilege() {
        if (enabled) (void)::AdjustTokenPrivileges(token, FALSE, &previous, 0, nullptr, nullptr);
        if (token != nullptr) ::CloseHandle(token);
    }
};

struct ClockCapture {
    std::uint64_t fileTime = 0, qpc = 0, span = 0;
};

ClockCapture CaptureClock() {
    LARGE_INTEGER before = {}, after = {};
    if (!::QueryPerformanceCounter(&before)) return {};
    FILETIME time = {};
    ::GetSystemTimeAsFileTime(&time);
    if (!::QueryPerformanceCounter(&after) || before.QuadPart < 0 ||
        after.QuadPart < before.QuadPart) return {};
    const std::uint64_t ticks = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) |
        time.dwLowDateTime;
    const auto first = static_cast<std::uint64_t>(before.QuadPart);
    const auto last = static_cast<std::uint64_t>(after.QuadPart);
    return {ticks, first + (last - first) / 2, last - first};
}

bool ProjectTime(std::uint64_t anchorQpc, std::uint64_t anchorTime,
                  std::uint64_t target, std::uint64_t frequency, std::uint64_t* out) {
    if (frequency == 0 || frequency > 1000000000000ULL || target < anchorQpc) return false;
    const auto delta = target - anchorQpc;
    const auto seconds = delta / frequency;
    if (seconds > ((std::numeric_limits<std::uint64_t>::max)() - anchorTime) / 10000000ULL)
        return false;
    const auto fraction = (delta % frequency) * 10000000ULL / frequency;
    const auto time = anchorTime + seconds * 10000000ULL;
    if (time > (std::numeric_limits<std::uint64_t>::max)() - fraction) return false;
    *out = time + fraction;
    return true;
}

std::string IsoTime(std::uint64_t ticks) {
    FILETIME time = {};
    time.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
    time.dwLowDateTime = static_cast<DWORD>(ticks);
    SYSTEMTIME value = {};
    if (ticks == 0 || !::FileTimeToSystemTime(&time, &value)) return {};
    char text[40] = {};
    std::snprintf(text, sizeof(text), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        value.wYear, value.wMonth, value.wDay, value.wHour, value.wMinute,
        value.wSecond, value.wMilliseconds);
    return text;
}

bool QueryLiveIdentity(std::uint32_t pid, NetworkProcessIdentity* identity,
                        ClockCapture* clock, std::string* reason) {
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (process == nullptr) { *reason = "process_lookup_unavailable"; return false; }
    FILETIME creation = {}, exit = {}, kernel = {}, user = {};
    wchar_t path[32768] = {};
    DWORD length = 32768;
    bool valid = ::GetProcessTimes(process, &creation, &exit, &kernel, &user) &&
        ::QueryFullProcessImageNameW(process, 0, path, &length);
    *clock = CaptureClock();
    valid = valid && ::WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    ::CloseHandle(process);
    if (!valid || clock->qpc == 0) { *reason = "process_exited_or_identity_unavailable"; return false; }
    const int bytes = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path,
        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0 || bytes > 1024) { *reason = "process_image_path_unavailable"; return false; }
    NetworkProcessIdentity result;
    result.pid = pid;
    result.creationTimeFileTime = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) |
        creation.dwLowDateTime;
    result.creationTimeKnown = result.creationTimeFileTime != 0;
    result.imagePath.resize(static_cast<std::size_t>(bytes));
    if (!result.creationTimeKnown || ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        path, static_cast<int>(length), &result.imagePath[0], bytes, nullptr, nullptr) != bytes) {
        *reason = "process_image_path_unavailable"; return false;
    }
    *identity = std::move(result);
    return true;
}
}  // namespace

ConnectionEventCollector::ConnectionEventCollector() = default;

ConnectionEventCollector::~ConnectionEventCollector() {
    std::string error;
    if (!Stop(&error)) {
        // Only the optional helper owns this class. Ending that process releases
        // its dynamic filters; no callback can outlive destroyed state. A failed
        // ETW stop may still require later reconciliation of the owned session.
        ::TerminateProcess(::GetCurrentProcess(), ERROR_TIMEOUT);
    }
}

bool ConnectionEventCollector::Start(std::string* error) {
    if (error == nullptr) return false;
    error->clear();
    if (running_.load()) return true;
    if (!Stop(error)) return false;
    LARGE_INTEGER frequency = {};
    if (!::QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        frequency.QuadPart > 1000000000000LL) {
        traceResult_ = ERROR_NOT_SUPPORTED;
        *error = "qpc_unavailable"; return false;
    }
    qpcFrequency_ = static_cast<std::uint64_t>(frequency.QuadPart);
    const auto anchor = CaptureClock();
    if (anchor.qpc == 0 || anchor.span > qpcFrequency_.load() / 100) {
        *error = "clock_anchor_unavailable"; return false;
    }
    anchorQpc_ = anchor.qpc;
    anchorFileTime_ = anchor.fileTime;
    clockStable_ = true;
    identities_.Clear();
    attributed_ = 0;
    GUID guid = {};
    wchar_t identity[40] = {};
    if (FAILED(::CoCreateGuid(&guid)) || !::StringFromGUID2(guid, identity, 40)) {
        traceResult_ = ERROR_GEN_FAILURE;
        *error = "trace_identity_unavailable"; return false;
    }
    sessionName_ = L"WinTCP.Lifecycle." + std::wstring(identity);
    epoch_.clear();
    for (const wchar_t c : std::wstring(identity)) {
        if (c >= L'0' && c <= L'9') epoch_.push_back(static_cast<char>(c));
        else if (c >= L'A' && c <= L'F') epoch_.push_back(static_cast<char>(c - L'A' + 'a'));
        else if (c >= L'a' && c <= L'f') epoch_.push_back(static_cast<char>(c));
    }
    normalizer_ = std::make_unique<LifecycleFlowModel>(epoch_, qpcFrequency_.load());
    std::vector<unsigned char> memory(kPropertiesBytes, 0);
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(memory.data());
    properties->Wnode.BufferSize = kPropertiesBytes;
    properties->Wnode.Guid = guid;  // Never SystemTraceControlGuid or another owner's GUID.
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 1;  // Preserve raw QPC ticks for later time mapping.
    properties->LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE;
    properties->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP | EVENT_TRACE_FLAG_PROCESS;
    properties->BufferSize = 64;
    properties->MinimumBuffers = 16;
    properties->MaximumBuffers = 128;
    properties->FlushTimer = 1;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ProfilePrivilege privilege;
    if (!privilege.enabled) {
        traceResult_ = ERROR_PRIVILEGE_NOT_HELD;
        *error = "system_profile_privilege_unavailable";
        return false;
    }
    const ULONG started = ::StartTraceW(&session_, sessionName_.c_str(), properties);
    if (started != ERROR_SUCCESS) {
        traceResult_ = started;
        session_ = 0;
        *error = (started == ERROR_NO_SYSTEM_RESOURCES || started == ERROR_ALREADY_EXISTS
            ? "trace_session_conflict:" : "trace_start_failed:") + std::to_string(started);
        return false;
    }
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName = &sessionName_[0];
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Context = this;
    logfile.EventRecordCallback = &EventThunk;
    logfile.BufferCallback = &BufferThunk;
    trace_ = ::OpenTraceW(&logfile);
    if (trace_ == INVALID_PROCESSTRACE_HANDLE) {
        const DWORD code = ::GetLastError();
        (void)Stop(error);
        traceResult_ = code;
        *error = "trace_consumer_open_failed:" + std::to_string(code);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(historyMutex_);
        history_.clear();
        historyBytes_ = 0;
    }
    nextSequence_ = 0; decoded_ = 0; queueLost_ = 0; rejected_ = 0;
    eventsLost_ = 0; buffersLost_ = 0; historyEvicted_ = 0;
    traceResult_ = ERROR_SUCCESS;
    published_ = 0; lateRecords_ = 0; flowEvicted_ = 0; reorderFlushes_ = 0;
    stopping_ = false;
    running_ = true;
    decoderThread_ = ::CreateThread(nullptr, 0, &DecodeThread, this, 0, nullptr);
    if (decoderThread_ != nullptr)
        traceThread_ = ::CreateThread(nullptr, 0, &TraceThread, this, 0, nullptr);
    if (decoderThread_ == nullptr || traceThread_ == nullptr) {
        const DWORD code = ::GetLastError();
        (void)Stop(error);
        traceResult_ = code;
        *error = "trace_worker_start_failed:" + std::to_string(code);
        return false;
    }
    return true;
}

bool ConnectionEventCollector::Stop(std::string* error) {
    stopping_ = true;
    ready_.notify_all();
    if (session_ != 0) {
        std::vector<unsigned char> memory(kPropertiesBytes, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(memory.data());
        properties->Wnode.BufferSize = kPropertiesBytes;
        // Only the exact handle/name created by this object is ever stopped.
        const ULONG result = ::ControlTraceW(session_, sessionName_.c_str(), properties,
                                             EVENT_TRACE_CONTROL_STOP);
        if (result != ERROR_SUCCESS && result != ERROR_WMI_INSTANCE_NOT_FOUND) {
            if (error) *error = "trace_stop_failed:" + std::to_string(result);
            return false;
        }
        eventsLost_ = properties->EventsLost;
        buffersLost_ = properties->RealTimeBuffersLost;
        session_ = 0;
    }
    if (trace_ != INVALID_PROCESSTRACE_HANDLE) {
        (void)::CloseTrace(trace_);
        trace_ = INVALID_PROCESSTRACE_HANDLE;
    }
    for (HANDLE* thread : {&traceThread_, &decoderThread_}) {
        if (*thread == nullptr) continue;
        if (::WaitForSingleObject(*thread, 5000) != WAIT_OBJECT_0) {
            if (error) *error = "trace_worker_stop_timeout";
            return false;
        }
        ::CloseHandle(*thread);
        *thread = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        queueLost_ += static_cast<std::uint64_t>(queue_.size());
        queue_.clear();
        queueBytes_ = 0;
    }
    running_ = false;
    if (error) error->clear();
    return true;
}

VOID WINAPI ConnectionEventCollector::EventThunk(EVENT_RECORD* record) {
    if (record && record->UserContext)
        static_cast<ConnectionEventCollector*>(record->UserContext)->OnEvent(record);
}

ULONG WINAPI ConnectionEventCollector::BufferThunk(EVENT_TRACE_LOGFILEW* buffer) {
    if (buffer && buffer->Context) {
        auto* owner = static_cast<ConnectionEventCollector*>(buffer->Context);
        owner->eventsLost_.store(buffer->EventsLost);
        return owner->stopping_.load() ? FALSE : TRUE;
    }
    return FALSE;
}

void ConnectionEventCollector::OnEvent(EVENT_RECORD* record) noexcept {
    if (stopping_.load() ||
        ClassifyLifecycleEvent(record->EventHeader) == LifecycleType::Unsupported) return;
    try {
        const std::uint64_t sequence = ++nextSequence_;
        if (record->UserData == nullptr || record->UserDataLength == 0 ||
            record->UserDataLength > 4096) { ++queueLost_; return; }
        RawRecord copied;
        copied.header = record->EventHeader;
        copied.context = record->BufferContext;
        copied.sequence = sequence;
        const auto clock = CaptureClock();
        copied.receivedFileTime = clock.fileTime;
        copied.receivedQpc = clock.qpc;
        copied.clockSampleReliable = clock.qpc != 0 && clock.span <= qpcFrequency_.load() / 100;
        copied.receivedUtcMs = clock.fileTime >= 116444736000000000ULL
            ? (clock.fileTime - 116444736000000000ULL) / 10000 : 0;
        const auto* bytes = static_cast<const unsigned char*>(record->UserData);
        copied.payload.assign(bytes, bytes + record->UserDataLength);
        const std::size_t size = sizeof(RawRecord) + copied.payload.size();
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (queue_.size() >= kMaxQueueRecords || size > kMaxQueueBytes - queueBytes_) {
                ++queueLost_; return;
            }
            queue_.push_back(std::move(copied));
            queueBytes_ += size;
        }
        ready_.notify_one();
    } catch (...) { ++queueLost_; }
}

DWORD WINAPI ConnectionEventCollector::TraceThread(void* context) {
    auto* owner = static_cast<ConnectionEventCollector*>(context);
    TRACEHANDLE trace = owner->trace_.load();
    const ULONG result = ::ProcessTrace(&trace, 1, nullptr, nullptr);
    owner->traceResult_ = owner->stopping_.load() && result == ERROR_CANCELLED
        ? ERROR_SUCCESS : result;
    owner->running_ = false;
    owner->stopping_ = true;
    owner->ready_.notify_all();
    return 0;
}

DWORD WINAPI ConnectionEventCollector::DecodeThread(void* context) {
    try { static_cast<ConnectionEventCollector*>(context)->DecodeLoop(); }
    catch (...) {
        auto* owner = static_cast<ConnectionEventCollector*>(context);
        owner->traceResult_ = ERROR_UNHANDLED_EXCEPTION;
        owner->running_ = false;
        owner->stopping_ = true;
        owner->ready_.notify_all();
    }
    return 0;
}

void ConnectionEventCollector::DecodeLoop() {
    for (;;) {
        RawRecord raw;
        bool haveRecord = false, finish = false;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            ready_.wait_for(lock, std::chrono::milliseconds(50),
                [this] { return stopping_.load() || !queue_.empty(); });
            finish = stopping_.load();
            if (!finish && !queue_.empty()) {
                raw = std::move(queue_.front());
                queue_.pop_front();
                queueBytes_ -= sizeof(RawRecord) + raw.payload.size();
                haveRecord = true;
            }
        }
        LARGE_INTEGER clock = {};
        (void)::QueryPerformanceCounter(&clock);
        const auto now = clock.QuadPart > 0 ? static_cast<std::uint64_t>(clock.QuadPart) : 0;
        if (finish) { if (normalizer_) Publish(normalizer_->Drain(now, true)); return; }
        if (!haveRecord) { if (normalizer_) Publish(normalizer_->Drain(now)); continue; }
        EVENT_RECORD record = {};
        record.EventHeader = raw.header;
        record.BufferContext = raw.context;
        record.UserDataLength = static_cast<USHORT>(raw.payload.size());
        record.UserData = raw.payload.data();
        DecodedLifecycleRecord decoded;
        std::string error;
        if (raw.header.TimeStamp.QuadPart <= 0 ||
            DecodeLifecycleRecord(&record, &decoded, &error) != EventDecodeResult::Decoded) {
            ++rejected_;
            if (normalizer_) Publish(normalizer_->Drain(now));
            continue;
        }
        TraceObservation observation;
        observation.sequence = raw.sequence;
        observation.sourceQpc = static_cast<std::uint64_t>(raw.header.TimeStamp.QuadPart);
        observation.receivedUtcMs = raw.receivedUtcMs;
        observation.descriptor = raw.header.EventDescriptor;
        observation.provider = raw.header.ProviderId;
        observation.headerFlags = raw.header.Flags;
        observation.decoded = std::move(decoded);
        Attribute(raw, &observation);
        ++decoded_;
        if (normalizer_) Publish(normalizer_->Push(std::move(observation), now));
    }
}

void ConnectionEventCollector::Publish(std::vector<TraceObservation> observations) {
    if (normalizer_) {
        lateRecords_ = normalizer_->LateRecords();
        flowEvicted_ = normalizer_->EvictedFlows();
        reorderFlushes_ = normalizer_->CapacityFlushes();
    }
    if (observations.empty()) return;
    std::lock_guard<std::mutex> lock(historyMutex_);
    for (auto& observation : observations) {
        observation.publicationSequence = ++published_;
        const auto bytes = TraceObservationBytes(observation);
        while (!history_.empty() && (history_.size() >= kMaxHistoryRecords ||
                                     historyBytes_ + bytes > kMaxHistoryBytes)) {
            historyBytes_ -= TraceObservationBytes(history_.front());
            history_.pop_front();
            ++historyEvicted_;
        }
        if (bytes > kMaxHistoryBytes) { ++historyEvicted_; continue; }
        historyBytes_ += bytes;
        history_.push_back(std::move(observation));
    }
}

ConnectionCollectorStatus ConnectionEventCollector::Status() const {
    return {running_.load(), decoded_.load(), queueLost_.load(), rejected_.load(),
        eventsLost_.load(), buffersLost_.load(), historyEvicted_.load(),
        qpcFrequency_.load(), traceResult_.load(), attributed_.load(), clockStable_.load(),
        lateRecords_.load(), flowEvicted_.load(), reorderFlushes_.load(), published_.load()};
}

void ConnectionEventCollector::Attribute(const RawRecord& raw, TraceObservation* observation) {
    const auto frequency = qpcFrequency_.load();
    const auto sourceQpc = observation->sourceQpc;
    observation->process.pid = observation->decoded.pid;
    const auto observeClock = [&](std::uint64_t qpc, std::uint64_t utc) {
        std::uint64_t projected = 0;
        if (!ProjectTime(anchorQpc_, anchorFileTime_, qpc, frequency, &projected)) return false;
        const auto difference = utc >= projected ? utc - projected : projected - utc;
        if (difference > 500000) clockStable_ = false;  // 50 ms discontinuity/drift bound.
        return clockStable_.load();
    };
    if (raw.clockSampleReliable && observeClock(raw.receivedQpc, raw.receivedFileTime) &&
        ProjectTime(anchorQpc_, anchorFileTime_, sourceQpc, frequency, &observation->occurredFileTime))
        observation->timeReason.clear();
    else observation->timeReason = clockStable_.load()
        ? "source_clock_sample_uncertain" : "clock_mapping_unstable";
    if (identities_.Find(observation->decoded.pid, sourceQpc, &observation->process)) {
        observation->identityReason = "verified_cached_interval";
        ++attributed_;
        return;
    }
    observation->process.pid = observation->decoded.pid;
    NetworkProcessIdentity live;
    ClockCapture query;
    if (!QueryLiveIdentity(observation->decoded.pid, &live, &query, &observation->identityReason))
        return;
    // Matching a previously verified handle identity extends its lifetime
    // interval even across a wall-clock adjustment; PID alone never does.
    const bool wasKnown = identities_.HasInstance(live.pid, live.creationTimeFileTime);
    bool bound = identities_.RevalidateLive(live, sourceQpc, query.qpc);
    if (wasKnown && !bound && !identities_.HasInstance(live.pid, live.creationTimeFileTime)) {
        observation->identityReason = "cached_identity_conflict";
        return;
    }
    if (!bound && query.span <= frequency / 100 && observeClock(query.qpc, query.fileTime) &&
        observation->timeReason.empty() && observation->occurredFileTime >= 1000000 &&
        live.creationTimeFileTime <= observation->occurredFileTime - 1000000)
        bound = identities_.Remember(live, sourceQpc, query.qpc);
    if (bound) {
        observation->process = std::move(live);
        observation->identityReason = "verified_live_interval";
        ++attributed_;
    } else observation->identityReason = clockStable_.load()
        ? "event_instance_not_verified" : "clock_mapping_unstable";
}

std::vector<TraceObservation> ConnectionEventCollector::ReadAfter(std::uint64_t sequence,
    std::size_t limit, std::uint64_t* firstRetained) const {
    std::vector<TraceObservation> result;
    if (limit > 500) limit = 500;
    if (limit == 0) return result;
    std::lock_guard<std::mutex> lock(historyMutex_);
    if (firstRetained) *firstRetained = history_.empty() ? 0 : history_.front().publicationSequence;
    for (const auto& observation : history_) {
        if (observation.publicationSequence <= sequence) continue;
        result.push_back(observation);
        if (result.size() >= limit) break;
    }
    return result;
}

std::uint64_t ConnectionEventCollector::FirstRetainedSequence() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    return history_.empty() ? 0 : history_.front().publicationSequence;
}

std::string TraceObservationJson(const TraceObservation& observation,
                                 const std::string& epoch,
                                 std::uint64_t qpcFrequency) {
    const auto& decoded = observation.decoded;
    const char* kind = "unknown";
    switch (decoded.type) {
    case LifecycleType::TcpConnect: kind = "tcp_connect"; break;
    case LifecycleType::TcpAccept: kind = "tcp_accept"; break;
    case LifecycleType::TcpDisconnect: kind = "tcp_disconnect"; break;
    case LifecycleType::UdpSend: kind = "udp_send"; break;
    case LifecycleType::UdpReceive: kind = "udp_receive"; break;
    case LifecycleType::ProcessStart: kind = "process_start"; break;
    case LifecycleType::ProcessExit: kind = "process_exit"; break;
    case LifecycleType::ProcessRundown: kind = "process_rundown"; break;
    default: break;
    }
    wchar_t wideGuid[40] = {};
    char guid[80] = {};
    if (::StringFromGUID2(observation.provider, wideGuid, 40))
        (void)::WideCharToMultiByte(CP_UTF8, 0, wideGuid, -1, guid, sizeof(guid), nullptr, nullptr);
    const auto endpoint = [](const NetworkEndpoint& value) {
        return !value.known ? std::string("null") :
            "{\"address\":" + NetworkJsonQuote(value.address) +
            ",\"port\":" + std::to_string(value.port) +
            ",\"scopeId\":null,\"scopeReason\":\"not_reported_by_schema\"}";
    };
    const bool identityKnown = ProcessActionable(observation.process) &&
        observation.process.pid == decoded.pid;
    const std::string occurred = observation.timeReason.empty()
        ? IsoTime(observation.occurredFileTime) : std::string();
    const std::string rawId = epoch + ":etw-" + std::to_string(observation.sequence);
    std::string result = "{\"schemaVersion\":1,\"eventId\":" + NetworkJsonQuote(epoch +
        ":etw-" + std::to_string(observation.sequence)) +
        ",\"source\":\"etw_raw\",\"normalized\":false,\"kind\":" + NetworkJsonQuote(kind) +
        ",\"sourceSequence\":\"" + std::to_string(observation.sequence) +
        "\",\"publicationSequence\":\"" + std::to_string(observation.publicationSequence) +
        "\",\"sourceQpc\":\"" + std::to_string(observation.sourceQpc) +
        "\",\"qpcFrequency\":\"" + std::to_string(qpcFrequency) +
        "\",\"receivedUtcMs\":\"" + std::to_string(observation.receivedUtcMs) +
        "\",\"occurredAtUtc\":" + (occurred.empty() ? "null" : NetworkJsonQuote(occurred)) +
        ",\"timeReason\":" + (occurred.empty() ? NetworkJsonQuote(observation.timeReason.empty()
            ? "time_format_unavailable" : observation.timeReason) : "null") +
        ",\"timebaseId\":" + (occurred.empty() ? "null" : NetworkJsonQuote(epoch + ":qpc-1")) +
        ",\"timeConfidence\":" + NetworkJsonQuote(occurred.empty() ? "unknown" : "mapped") +
        ",\"timeUncertaintyMs\":" + (occurred.empty() ? "null" : "60") +
        ",\"process\":{\"pid\":" + std::to_string(decoded.pid) +
        ",\"creationTimeFileTime\":" + (identityKnown
            ? "\"" + std::to_string(observation.process.creationTimeFileTime) + "\"" : "null") +
        ",\"imagePath\":" + (identityKnown ? NetworkJsonQuote(observation.process.imagePath) : "null") +
        ",\"identityReason\":" + (identityKnown ? "null" : NetworkJsonQuote(observation.identityReason)) +
        ",\"identityEvidence\":" + (identityKnown ? NetworkJsonQuote(observation.identityReason) : "null") +
        "},\"family\":" + NetworkJsonQuote(decoded.family) +
        ",\"sourceEndpoint\":" + endpoint(decoded.source) +
        ",\"destinationEndpoint\":" + endpoint(decoded.destination) +
        ",\"local\":null,\"remote\":null,\"endpointReason\":\"role_normalization_pending\",\"bytes\":" +
        (decoded.bytesKnown ? "\"" + std::to_string(decoded.bytes) + "\"" : "null") +
        ",\"correlationKey\":" + (decoded.correlationKeyKnown
            ? "\"" + std::to_string(decoded.correlationKey) + "\"" : "null") +
        ",\"descriptor\":{\"provider\":" + NetworkJsonQuote(guid) +
        ",\"id\":" + std::to_string(observation.descriptor.Id) +
        ",\"opcode\":" + std::to_string(observation.descriptor.Opcode) +
        ",\"version\":" + std::to_string(observation.descriptor.Version) +
        ",\"headerFlags\":" + std::to_string(observation.headerFlags) + "}";
    if (!observation.lifecycle.available) return result + ",\"derived\":null}";
    const auto& annotation = observation.lifecycle;
    NetworkEvent event;
    event.eventId = epoch + ":normalized-" + std::to_string(observation.sequence);
    event.sourceSequence = std::to_string(observation.sequence);
    const bool processEvent = decoded.type == LifecycleType::ProcessStart || decoded.type == LifecycleType::ProcessExit;
    const bool udp = decoded.type == LifecycleType::UdpSend || decoded.type == LifecycleType::UdpReceive;
    event.source = processEvent ? "etw_process" : udp ? "etw_udp" : "etw_tcp";
    event.kind = annotation.kind;
    event.occurredAtUtc = occurred;
    event.monotonicNs = annotation.monotonicNs;
    event.timebaseId = epoch + ":qpc";
    if (observation.receivedUtcMs <=
        ((std::numeric_limits<std::uint64_t>::max)() - 116444736000000000ULL) / 10000)
        event.receivedAtUtc = IsoTime(observation.receivedUtcMs * 10000 + 116444736000000000ULL);
    if (identityKnown) event.process = observation.process;
    event.process.pid = decoded.pid;
    event.flowId = annotation.flowId;
    event.flowGeneration = annotation.generation;
    event.lateArrival = annotation.late;
    event.incompleteChronology = annotation.incomplete;
    event.chronologyReason = annotation.chronologyReason;
    event.endpointRoleConfidence = annotation.roleConfidence;
    event.firstObservedMidSession = annotation.midSession;
    event.transport = processEvent ? "" : udp ? "udp" : "tcp";
    event.family = decoded.family;
    event.local = annotation.local;
    event.remote = annotation.remote;
    event.direction = annotation.direction;
    event.interfaceReason = "not_reported_by_source";
    event.confidence = annotation.roleConfidence.empty() ? "observed" : annotation.roleConfidence;
    event.evidenceIds = {rawId};
    event.coverageId = epoch;
    if (!processEvent && !udp) event.tcpState = decoded.type == LifecycleType::TcpDisconnect ? "closed" : "established";
    return result + ",\"derived\":" + NetworkEventJson(event) + "}";
}
}  // namespace wintcp

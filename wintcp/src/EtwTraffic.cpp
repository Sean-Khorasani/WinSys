// EtwTraffic.cpp
// SPDX-License-Identifier: Apache-2.0
// See EtwTraffic.h for the researched event layout. Everything here is
// defensive: any failure (no elevation, logger already in use, OpenTrace
// failure) tears the session down and reports a readable reason.

#include "EtwTraffic.h"

#include <cstring>
#include <vector>

#include "Utils.h"

namespace wintcp {
namespace {

const wchar_t kKernelLoggerName[] = L"NT Kernel Logger";

// SystemTraceControlGuid - required in Wnode.Guid for the kernel logger.
const GUID kSystemTraceControlGuid = {
    0x9e814aad, 0x3204, 0x11d2,
    {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};

// EVENT_TRACE_PROPERTIES + room for both variable-length name strings.
const DWORD kPropBytes =
    sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAX_PATH * sizeof(WCHAR);

// How long Stop() waits for the ProcessTrace thread after CloseTrace() has
// unblocked it, before abandoning it. Generous: the consumer drains up to 8 MB
// of buffered TcpIp events (FlushTimer 1 s) before ProcessTrace returns, which
// is milliseconds in practice. The bound exists only so a ProcessTrace that
// never returns (kernel logger wedged) cannot keep the process alive - the
// owner leaks this object precisely so abandoning the thread is safe.
constexpr DWORD kEtwStopTimeoutMs = 5000;

// One consumer instance per process (the app owns a single EtwTraffic).
// Atomic: it is published by the UI thread and read by the ETW callback
// thread, so an unsynchronised plain pointer is a data race (and a second
// instance used to silently steal the callbacks from the first).
std::atomic<EtwTraffic*> gEtwInstance{nullptr};

}  // namespace

EtwTraffic::~EtwTraffic() {
    Stop();
}

bool EtwTraffic::Start(std::wstring& errorMessage) {
    errorMessage.clear();
    if (Running()) return true;

    // Single consumer per process: the ETW callback is dispatched through
    // one file-static pointer, so a second live instance would silently
    // steal events from the first. Refuse rather than misbehave.
    EtwTraffic* expected = nullptr;
    if (!gEtwInstance.compare_exchange_strong(expected, this)) {
        errorMessage = L"Per-PID traffic counters are already running in "
                       L"this process.";
        return false;
    }

    std::vector<BYTE> mem(kPropBytes, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(mem.data());
    props->Wnode.BufferSize = kPropBytes;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;                 // QPC timestamps
    props->Wnode.Guid = kSystemTraceControlGuid;
    // ETW logger pool, in one place so the four numbers cannot drift apart.
    // The comments below are the measurement that chose them, kept verbatim.
    // B4: dev constants, no config knobs — elevated internals, measured once.
    constexpr ULONG kEtwBufferKb = 64;     // KB per buffer
    constexpr ULONG kEtwMinBuffers = 32;
    constexpr ULONG kEtwMaxBuffers = 128;  // 128 x 64 KB = 8 MB ceiling
    constexpr ULONG kEtwFlushSec = 1;
    props->BufferSize = kEtwBufferKb;
    // the elevated ground-truth probe measured ~18% real-time
    // event loss under a 64 MB burst with 16/64 buffers; widen the pool
    // (max 128 x 64 KB = 8 MB) so totals stay close under load. Loss
    // under extreme pressure remains possible - ETW is best-effort, as
    // in every other consumer (TaskExplorer, PerfView).
    props->MinimumBuffers = kEtwMinBuffers;
    props->MaximumBuffers = kEtwMaxBuffers;
    // Flush real-time buffers at least once per second: without this the
    // events linger in the logger until a buffer fills, and a user who
    // refreshes right after some traffic can still see empty cells
    // (observed in the elevated run - the consumer caught up only
    // seconds later). 1 s is the cheapest deterministic upper bound.
    props->FlushTimer = kEtwFlushSec;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // stream, no log file
    props->EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;

    const ULONG status = ::StartTraceW(&session_, kKernelLoggerName, props);
    if (status != ERROR_SUCCESS) {
        session_ = 0;
        gEtwInstance.store(nullptr);
        if (status == ERROR_ACCESS_DENIED) {
            errorMessage =
                L"Starting the per-PID traffic counters failed.\r\n\r\n"
                L"The ETW NT Kernel Logger can only be started by an "
                L"elevated process.\r\n\r\n"
                L"Run WinTCP as administrator and toggle the menu item "
                L"again.\r\n"
                L"The rest of the application works without it.";
        } else if (status == ERROR_ALREADY_EXISTS) {
            errorMessage =
                L"Starting the per-PID traffic counters failed:\r\n\r\n"
                L"another tool (e.g. Process Monitor or xperf) is already "
                L"using the NT Kernel Logger.\r\n\r\n"
                L"Stop the other trace session and try again.";
        } else {
            errorMessage =
                L"Starting the ETW kernel logger failed:\r\n" +
                FormatSystemError(status);
        }
        return false;
    }

    // Real-time consumer attached to the just-created session.
    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName = const_cast<LPWSTR>(kKernelLoggerName);
    logfile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &EtwTraffic::EventThunk;

    trace_ = ::OpenTraceW(&logfile);
    if (trace_ == INVALID_PROCESSTRACE_HANDLE) {
        const ULONG openErr = ::GetLastError();
        trace_ = INVALID_PROCESSTRACE_HANDLE;
        gEtwInstance.store(nullptr);
        StopSession();
        errorMessage = L"OpenTrace failed:\n" + FormatSystemError(openErr);
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(lock_);
        totals_.clear();   // fresh accounting per session
    }

    stopping_.store(false);
    thread_ = ::CreateThread(nullptr, 0, &EtwTraffic::ThreadProc, this, 0,
                             nullptr);
    if (thread_ == nullptr) {
        const DWORD thrErr = ::GetLastError();
        gEtwInstance.store(nullptr);
        ::CloseTrace(trace_);
        trace_ = INVALID_PROCESSTRACE_HANDLE;
        // We got here only because StartTraceW succeeded above, so
        // session_ is a session this process created and StopSession()
        // only ever stops our own. A pre-existing NT Kernel Logger is
        // never touched: StartTraceW reports ERROR_ALREADY_EXISTS in that
        // case and returns through the failure path above, which leaves
        // session_ == 0 and StopSession() a no-op.
        StopSession();
        errorMessage = L"CreateThread failed:\n" + FormatSystemError(thrErr);
        return false;
    }

    running_.store(true, std::memory_order_release);
    return true;
}

void EtwTraffic::Stop() {
    if (!Running() && thread_ == nullptr && session_ == 0 &&
        trace_ == INVALID_PROCESSTRACE_HANDLE)
        return;

    // Ask in-flight callbacks to stop doing work before we start tearing
    // down, so only the callback already inside the lock has to finish.
    stopping_.store(true, std::memory_order_release);

    StopSession();          // ControlTrace(STOP): stop the logger generating events

    // Close the real-time consumer handle BEFORE waiting on the thread.
    //
    // CloseTrace() is what actually makes ProcessTrace() return (it comes back
    // with ERROR_CANCELLED). This function used to wait on the thread FIRST
    // and close the trace only AFTERWARD, on the theory that
    // ControlTrace(STOP) alone would return ProcessTrace - but the NT Kernel
    // Logger real-time consumer does not reliably return on STOP, so the
    // INFINITE wait then blocked the UI thread inside WM_DESTROY forever: the
    // window closed but wintcp-gui.exe never exited. Close first, then wait.
    if (trace_ != INVALID_PROCESSTRACE_HANDLE) {
        ::CloseTrace(trace_);
        trace_ = INVALID_PROCESSTRACE_HANDLE;
    }

    if (thread_ != nullptr) {
        // Bounded join. On the normal path CloseTrace() has unblocked
        // ProcessTrace and this returns almost immediately. The bound is
        // defence in depth against a ProcessTrace wedged in the kernel: the
        // process must be free to exit. Abandoning such a thread is safe
        // because (1) it touches only `this`, which the owner leaks on purpose
        // (MainWindow's EtwTraffic* is never freed - see MainWindow.h), and
        // (2) stopping_ is already set, so any draining callback does no
        // further work, and gEtwInstance is cleared below so EventThunk sends
        // nothing here.
        ::WaitForSingleObject(thread_, kEtwStopTimeoutMs);
        ::CloseHandle(thread_);
        thread_ = nullptr;
    }
    // Only now is it safe to release the instance and drop the running flag.
    if (gEtwInstance.load() == this) gEtwInstance.store(nullptr);
    running_.store(false, std::memory_order_release);
}

void EtwTraffic::StopSession() {
    if (session_ == 0) return;
    std::vector<BYTE> mem(kPropBytes, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(mem.data());
    props->Wnode.BufferSize = kPropBytes;
    ::ControlTraceW(session_, kKernelLoggerName, props,
                    EVENT_TRACE_CONTROL_STOP);
    session_ = 0;
}

std::map<DWORD, PidTraffic> EtwTraffic::Snapshot() const {
    std::lock_guard<std::mutex> lk(lock_);
    return totals_;
}

VOID WINAPI EtwTraffic::EventThunk(PEVENT_RECORD rec) {
    EtwTraffic* inst = gEtwInstance.load(std::memory_order_acquire);
    if (inst != nullptr && rec != nullptr) inst->OnEvent(rec);
}

// Successive throwing events past this count abandon the session (see
// OnEvent). Sized so a genuinely corrupt stream trips it within a second at
// any realistic event rate, while isolated hiccups never accumulate: the
// counter resets on every success.
constexpr int kMaxConsecutiveEventFailures = 100;

DWORD WINAPI EtwTraffic::ThreadProc(LPVOID param) {
    // ProcessTrace reports failures by return code, but a throw underneath it
    // (or in teardown) must still not take the process down.
    (void)RunGuarded([&] { static_cast<EtwTraffic*>(param)->ProcessLoop(); });
    return 0;
}

void EtwTraffic::ProcessLoop() {
    if (trace_ != INVALID_PROCESSTRACE_HANDLE) {
        ::ProcessTrace(&trace_, 1, nullptr, nullptr);  // blocks until stop
    }
}

void EtwTraffic::OnEvent(const EVENT_RECORD* rec) {
    // A callback already in flight when Stop() ran must not touch the maps.
    if (stopping_.load(std::memory_order_acquire)) return;
    // R2: an event that throws is skipped, not fatal. Past the threshold of
    // CONSECUTIVE failures the session is abandoned (stopping_ gates every
    // later event): totals freeze at last-known instead of dying with the
    // process. Surfacing mid-run ETW death in the UI is a separate task
    // (watchdog) — this one only guarantees survival.
    if (RunGuarded([&] { OnEventGuarded(rec); }).empty()) {
        eventFails_ = 0;
    } else if (++eventFails_ >= kMaxConsecutiveEventFailures) {
        stopping_.store(true, std::memory_order_release);
    }
}

void EtwTraffic::OnEventGuarded(const EVENT_RECORD* rec) {
    const EVENT_HEADER& h = rec->EventHeader;
    const TrafficDirection dir = ClassifyNetworkEvent(
        h.ProviderId, h.EventDescriptor.Id, h.EventDescriptor.Opcode);
    if (dir == TrafficDirection::None) return;

    // Fixed layout: PID @0, size @4 in every MOF group (see header).
    DWORD pid = 0;
    DWORD size = 0;
    if (!ParseTrafficPayload(rec->UserData, rec->UserDataLength, &pid, &size))
        return;

    std::lock_guard<std::mutex> lk(lock_);
    PidTraffic& t = totals_[pid];
    if (dir == TrafficDirection::Sent)
        t.tx += size;
    else
        t.rx += size;
}

// ---------------------------------------------------------------------------
// pure helpers - shared with the event stream above and with
// --selftest, which feeds synthetic descriptors/payloads through them.

TrafficDirection ClassifyNetworkEvent(const GUID& provider, USHORT id,
                                      USHORT opcode) {
    if (!::IsEqualGUID(provider, kTcpIpProviderGuid) &&
        !::IsEqualGUID(provider, kUdpIpProviderGuid)) {
        return TrafficDirection::None;
    }
    // Classic MOF events carry the type in Opcode (Id is 0) - proven by
    // the elevated ground-truth probe; accept Id as well in case a future
    // build fills it. Anything else (e.g. opcode 18, the per-segment
    // receive variant) must NOT be counted or receives would double.
    USHORT type = 0;
    if (opcode == 10 || opcode == 11 || opcode == 26 || opcode == 27)
        type = opcode;
    else if (id == 10 || id == 11 || id == 26 || id == 27)
        type = id;
    else
        return TrafficDirection::None;
    return (type == 10 || type == 26) ? TrafficDirection::Sent
                                      : TrafficDirection::Received;
}

bool ParseTrafficPayload(const void* data, DWORD length, DWORD* pid,
                         DWORD* size) {
    if (data == nullptr || length < 8) return false;
    const auto* bytes = static_cast<const BYTE*>(data);
    DWORD p = 0;
    DWORD s = 0;
    std::memcpy(&p, bytes, sizeof(p));
    std::memcpy(&s, bytes + sizeof(p), sizeof(s));
    if (p == 0 || s == 0) return false;   // idle PID / connect-style events
    if (pid != nullptr) *pid = p;
    if (size != nullptr) *size = s;
    return true;
}

}  // namespace wintcp

// EtwTraffic.h
// SPDX-License-Identifier: Apache-2.0
// Per-PID traffic counters: a real-time consumer of the ETW
// NT Kernel Logger with EVENT_TRACE_FLAG_NETWORK_TCPIP. Counts bytes per
// PID from the classic MOF TcpIp/UdpIp send/receive events.
//
// Starting the kernel logger needs Administrator rights; on a normal
// user session Start() fails with a human-readable reason and the rest
// of the application works unchanged (graceful fallback: a non-admin
// per-socket source sits underneath, see SocketTraffic.h).
//
// Payload research (MSDN MOF classes): every relevant event begins with
//   uint32 PID;   // offset 0
//   uint32 size;  // offset 4
// regardless of protocol/address family, so only those 8 bytes are read;
// addresses/ports are irrelevant for per-PID accounting.
//
// Event type location - PROVEN on this machine (elevated probe,
// 40443 events): classic MOF events carry their type (10 = send v4,
// 11 = receive v4, 26/27 = v6 send/receive; EVENT_TRACE_TYPE_SEND/
// RECEIVE from evntrace.h) in EventDescriptor.**Opcode** while
// EventDescriptor.**Id** is always 0. The original consumer filtered on
// Id and therefore silently discarded every event - that was the
// "running as administrator still shows empty cells" defect. The pure
// helpers below encode the fix and are exercised by --selftest.
// Provider GUIDs:
//   TcpIp {9a280ac0-c8e0-11d1-84e2-00c04fb998a2} / UdpIp {bf3a50c5-...}

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>   // full EVENT_HEADER/EVENT_RECORD + PROCESS_TRACE_MODE_*

#include <atomic>
#include <map>
#include <mutex>
#include <string>

#include "Connection.h"        // PidTraffic (shared with the refresh worker)
#include "EtwTrafficTypes.h"  // GUIDs, TrafficDirection, the pure helpers

namespace wintcp {

// The pure classifier/payload helpers (TrafficDirection and the provider
// GUIDs) are declared in EtwTrafficTypes.h so --selftest can exercise them
// without pulling in evntcons.h.

class EtwTraffic {
public:
    EtwTraffic() = default;
    ~EtwTraffic();

    EtwTraffic(const EtwTraffic&) = delete;
    EtwTraffic& operator=(const EtwTraffic&) = delete;

    // Start the NT Kernel Logger + a real-time consumer thread.
    // Returns false and fills 'errorMessage' (ready for a MessageBox)
    // when the session cannot be created - typically ERROR_ACCESS_DENIED
    // because the process is not elevated.
    bool Start(std::wstring& errorMessage);

    // Stop the session and the consumer thread. Safe to call when not
    // running; the destructor calls it too.
    //
    // The join is BOUNDED and the owner (MainWindow) leaks this object on
    // purpose (see the EtwTraffic* member) so that abandoning a thread that is
    // genuinely wedged in the kernel is safe - the detached thread still has
    // valid memory to write its final events into. Ordering matters and was
    // the root cause of "close the window and wintcp-gui.exe never exits":
    // StopSession() alone does not reliably return ProcessTrace for the NT
    // Kernel Logger real-time consumer, so we CloseTrace() - the call that
    // DOES make ProcessTrace() return - BEFORE waiting on the thread, then
    // wait a bounded time rather than INFINITE. Waiting before closing, as
    // this used to, deadlocked the UI thread inside WM_DESTROY.
    void Stop();

    // Safe to call from the UI thread on every refresh (the status bar does).
    bool Running() const { return running_.load(std::memory_order_acquire); }

    // Cumulative per-PID totals since Start(), copied under the lock.
    std::map<DWORD, PidTraffic> Snapshot() const;

    // Feed ONE event record through the production path - classify, parse,
    // take the totals lock, update the per-PID map - exactly as the consumer
    // does.
    //
    // Public for the same reason ClassifyNetworkEvent / ParseTrafficPayload
    // are (see EtwTrafficTypes.h): the plan requires a measured before/after
    // before this hot path may be changed, and the only way to time it is to
    // drive it with synthetic records. In production the sole caller is
    // EventThunk, on the ProcessTrace thread. Calling it when not running is
    // harmless - `stopping_` is false and the totals are just a map - which is
    // what lets a benchmark use a stack instance with no session behind it.
    void OnEvent(const EVENT_RECORD* rec);

private:
    static VOID WINAPI EventThunk(PEVENT_RECORD rec);
    static DWORD WINAPI ThreadProc(LPVOID param);
    void ProcessLoop();
    void StopSession();
    // Throwing half of OnEvent, above. Split out so the containment in
    // OnEvent covers exactly the parsing/mutation and nothing else.
    void OnEventGuarded(const EVENT_RECORD* rec);

    ULONG64 session_ = 0;   // TRACEHANDLE of the kernel logger session
    ULONG64 trace_ = INVALID_PROCESSTRACE_HANDLE;  // OpenTrace handle
    HANDLE thread_ = nullptr;
    // Read from the UI thread (Running()), written here - must be atomic.
    std::atomic<bool> running_{false};
    // Set by Stop() before the join so a callback already in flight on the
    // ETW thread does no further work while the shutdown proceeds.
    std::atomic<bool> stopping_{false};
    // Consecutive OnEvent failures (R2). Written only by the ETW thread, so
    // no atomic needed; past the threshold the session is abandoned rather
    // than allowed to corrupt totals event by event.
    int eventFails_ = 0;

    mutable std::mutex lock_;
    std::map<DWORD, PidTraffic> totals_;
};

}  // namespace wintcp

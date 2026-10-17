// SocketTraffic.h
// SPDX-License-Identifier: Apache-2.0
// non-admin per-PID TCP byte totals.
//
// Windows exposes live per-PID network bytes to standard users through
// exactly one proven path: duplicate a process's socket handle into our
// process and read SIO_TCP_INFO (TCP_INFO_v0.BytesIn/BytesOut), which the
// kernel fills per socket without any privilege. This sampler walks the
// system handle table (SystemExtendedHandleInformation - undocumented but
// stable, the Process Explorer/Hacker lineage), duplicates only the socket
// handles of the PIDs that currently have connection rows, and folds the
// reads into cumulative per-PID totals with the same contract as the ETW
// source: ConnectionStore::SetTraffic(pid, rx, tx).
//
// State rules (see MergeSample, unit-tested via --selftest):
//  * a socket that disappears from a SCANNED process is retired into the
//    PID's total, so totals never drop when a connection closes;
//  * a handle value that comes back with SMALLER counters was reused for
//    a new socket - the old socket is retired first;
//  * a PID that loses its connection rows is forgotten entirely (PID
//    reuse cannot inherit another process's totals);
//  * a process that cannot be opened (protected/dead) keeps its last
//    known state instead of being misread as "all sockets closed".
//
// Limits, documented in README: TCP only (UDP sockets expose no byte
// counters), sockets that open+close entirely between two refreshes are
// missed, SIO_TCP_INFO needs Windows 10 1709+ (Supported() is false
// otherwise - the app then behaves exactly as before, i.e. needs admin).

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_set>
#include <utility>
#include <vector>

#include "Connection.h"

namespace wintcp {

// One TCP socket read this pass: cumulative bytes of that socket.
struct SocketSample {
    DWORD pid = 0;
    ULONG_PTR handle = 0;      // handle value in the owning process
    ULONGLONG bytesIn = 0;
    ULONGLONG bytesOut = 0;
    // Kernel-reported connection age (TCP_INFO_v0::ConnectionTimeMs) and the
    // 4-tuple it belongs to, so the store can attach a real age to the row
    // instead of only "how long WinTCP has watched it". Both are additive:
    // the traffic totals above never depend on them.
    ULONGLONG ageMs = 0;
    std::wstring localAddress;
    UINT localPort = 0;
    std::wstring remoteAddress;
    UINT remotePort = 0;
    // TCP congestion state, in MILLISECONDS for the two RTT fields. Zero
    // means "the kernel reported nothing", never "zero latency" - the
    // distinction is preserved per-field in TcpInfoExtras and copied here.
    unsigned rttMs = 0;
    unsigned minRttMs = 0;
    ULONGLONG cwnd = 0;
    ULONGLONG retransBytes = 0;
    bool rttKnown = false;
    bool cwndKnown = false;
    bool retransKnown = false;
    bool timestamps = false;
    bool timestampsKnown = false;
};

// One socket handle worth reading, decided from the handle table alone.
// Split out from SocketSample because it is what the WALK produces and
// SocketSample is what a WORKER produces - and the split is what makes the
// stall survivable: collecting targets issues no ioctl, so the walk always
// finishes even when every call behind it does not.
struct ProbeTarget {
    DWORD pid = 0;
    ULONG_PTR handle = 0;
    // The kernel's object-type index for this handle. Carried so a WORKER can
    // record "this type is a socket" without going back to the table - the
    // type filter is the biggest saving in the whole scan, and the only place
    // that learns it is the place that already paid for the ioctl.
    USHORT typeIndex = 0;
};

class SocketTrafficSampler {
public:
    SocketTrafficSampler();
    // A scan thread wedged in SIO_TCP_INFO cannot be cancelled, so this object
    // must outlive the process: MainWindow heap-allocates it and never frees
    // it. The destructor exists only so a cleanly-finished thread's handle is
    // released, and it never blocks.
    ~SocketTrafficSampler();

    SocketTrafficSampler(const SocketTrafficSampler&) = delete;
    SocketTrafficSampler& operator=(const SocketTrafficSampler&) = delete;

    // False when SIO_TCP_INFO is unavailable (pre-Windows 10 1709); the
    // caller must then not arm the fallback at all.
    bool Supported() const { return supported_; }

    // Live scan: enumerate the system handle table, duplicate the socket
    // handles of 'pids' and read SIO_TCP_INFO, then fold the results.
    //
    // THREADING / TIMEOUT. The handle scan runs on a short-lived helper
    // thread, not on the caller's, and gives up on it after kScanTimeoutMs.
    // SIO_TCP_INFO is issued against a socket handle DUPLICATED OUT OF
    // ANOTHER PROCESS, and for some of those sockets the kernel call does not
    // return: a socket mid-handshake, or one whose owner is not scheduled,
    // blocks indefinitely. Measured on this machine, one such socket left the
    // call blocked past 90s. Since this runs on the refresh worker, a single
    // uncooperative socket froze the whole connection list - not just the
    // traffic columns - for as long as it lasted.
    //
    // The abandoned thread keeps its duplicated handles and exits when the
    // kernel returns; the next pass starts a fresh one. That is deliberate:
    // the thread is already stuck in the kernel and cannot be cancelled, and
    // terminating it would leave the duplicated handle open. Sockets skipped
    // this way simply report no sample, so the PID keeps its last known
    // totals rather than being wrongly reported as closed.
    //
    // One consequence is handled in the destructor: a detached thread still
    // stuck in the kernel would keep the process alive at exit, so the app
    // appeared to hang after doing all its work. The destructor therefore
    // lets an in-flight scan finish and, if it is wedged, deliberately leaks
    // this object rather than freeing memory the thread is still reading.
    // See ~SocketTrafficSampler.
    //
    // Not re-entrant: one scan at a time, and the totals are only read
    // (under kScanTimeoutMs) from the pass that did finish.
    std::map<DWORD, PidTraffic> Sample(const std::vector<DWORD>& pids);

    // How long a scan may run before Sample gives up on it. Long enough that
    // a healthy machine never trips it (a full pass measures tens of
    // milliseconds), short enough that a wedged one is not a user-visible
    // freeze.
    //
    // It is now a CEILING, not the wait: Sample waits for workers only while
    // they are still completing targets, and gives up after kNoProgressMs of
    // silence. On a machine with no uncooperative socket this is never reached
    // and the pass ends when the queue is drained; on a machine with one, the
    // pass ends as soon as everything that could be read has been.
    // Verdict: stays a dev constant, no CLI/config knob. These numbers are
    // measurements of THIS machine class, not preferences: a flag
    // would invite cargo-cult tuning, and a pathological host is
    // d2probe-plus-rebuild territory.
    static const int kScanTimeoutMs = 4000;

    // How long a pass waits while its workers complete NOTHING before deciding
    // the rest of the queue is unreachable.
    //
    // 250 ms, not the full budget, because a worker that is going to answer
    // does so in single-digit milliseconds for every socket measured on this
    // machine except the one that took 28 s - and that one was never going to
    // answer at all. The value only has to exceed the slowest healthy call by a
    // comfortable margin; 250 ms is about two orders of magnitude above
    // anything observed and about a sixteenth of the old fixed wait.
    static const int kNoProgressMs = 250;

    // How many threads read the queue in one pass. PUBLIC because it is a
    // contract, not an implementation detail: the pool is consumed one-per-
    // stall, so its size decides whether anything behind a stall gets read at
    // all, and --selftest pins that it stays above the observed stall count.
    //
    // WHY A POOL AND NOT ONE. Measured on this machine (reproduced by
    // temp/d2probe.cpp, which walks this host's sockets one at a time and
    // times every call):
    //
    //   of 391 sockets walked:  4 answered SIO_TCP_INFO
    //                           387 failed at once (WSAENOTSOCK/WSAENOTCONN)
    //                           1 call took 28,281 ms  (a tailscaled socket)
    //                           the next was still running after 90 s
    //                                                       (a postgres one)
    //
    // The call is neither deadlocked nor cancellable - it STALLS. A walk that
    // issued it inline ended at the first stall, and every socket behind it in
    // the table went unread that pass. That is the problem this fixes.
    //
    // WHY NOT ONE THREAD PER SOCKET, the obvious answer. Measured too: 4,278
    // concurrent SIO_TCP_INFO calls left 2,265 of them unfinished after 90 s.
    // They queue behind each other in the driver, so fanning out without bound
    // turns one stall into thousands - a worse failure, and one that looks
    // identical in the status line.
    //
    // WHY SIXTEEN. A stalled worker cannot be cancelled, so the pool empties
    // one socket at a time; once k sockets wedge, nothing else can be read
    // that pass. Four workers - exactly the number of stalls seen in one walk -
    // were entirely consumed by them: progress stopped the moment the fourth
    // wedged, and tailscaled.exe went back to reporting no data at all.
    // Sixteen drains the same queue in milliseconds once those four are gone.
    //
    // Sixteen is safe because the healthy call is ~0 ms (387 of 391 sockets
    // answered or failed instantly), so pool size costs nothing healthy, while
    // the fan-out that actually broke the driver was 4,278 - two orders of
    // magnitude larger. RememberStalled() bounds the lasting cost: a socket
    // that stalls once is never retried, so the leak is one thread per DISTINCT
    // bad socket rather than one per refresh. Without it a single postgres
    // socket would leak a thread every refresh for as long as the app is open.
    static const int kProbeWorkers = 16;

    // Pure state logic, split out for --selftest:
    //  'observed' - sockets read successfully this pass,
    //  'scanned'  - PIDs whose handle table was readable (their missing
    //               sockets count as closed; unscanned PIDs keep state),
    //  'pids'     - all PIDs that currently have connection rows.
    void MergeSample(const std::vector<SocketSample>& observed,
                     const std::vector<DWORD>& scanned,
                     const std::vector<DWORD>& pids);

    // Current cumulative totals (retired + live) for 'pids'; PIDs with no
    // data are omitted so the store leaves their cells at "—".
    std::map<DWORD, PidTraffic> Totals(const std::vector<DWORD>& pids) const;

    // Kernel-reported ages of the live sockets of 'pids', one entry per
    // socket that reported a non-zero ConnectionTimeMs. Read from the SAME
    // scan the traffic totals come from, so asking for ages costs no extra
    // handle-table pass. A single-shot `list` gets a real age from this; it
    // never has a "first seen" to fall back on.
    std::vector<SocketAge> Ages(const std::vector<DWORD>& pids) const;

    // Per-socket TCP congestion state (RTT, min RTT, cwnd, retransmits),
    // from the same TCP_INFO_v0 reading as Ages() and Bytes().
    //
    // A separate call rather than widening SocketBytes for the same reason
    // Bytes() is separate from Totals(): a caller that wants process totals
    // must not be handed per-socket numbers, and vice versa. Widening either
    // would make "did you mean per socket or per process" a question nobody can
    // answer from the signature later.
    std::vector<SocketTcpInfo> TcpInfo(const std::vector<DWORD>& pids) const;

    // Per-SOCKET cumulative byte counters, from the same scan. This is the
    // only source that observes one socket rather than a whole process, so it
    // is the only one allowed to mark a row `perRowBytes` - which is what
    // makes the per-connection Speed column (and `speed:`) work at all.
    //
    // Deliberately a separate call rather than widening PidTraffic: a caller
    // that wants only process totals must not be handed per-socket numbers it
    // might sum into a per-process figure and get N times the real traffic.
    std::vector<SocketBytes> Bytes(const std::vector<DWORD>& pids) const;

    // How many scans were dropped by the kScanTimeoutMs budget. Non-zero means
    // this machine has sockets whose SIO_TCP_INFO does not return, and the
    // traffic columns are falling back to last-known totals for those PIDs.
    unsigned TimeoutCount() const;

    // How many passes could not read the handle table at all.
    //
    // DISTINCT from TimeoutCount(), and the distinction is the whole point. A
    // timeout drops one pass's readings and keeps the previous totals; a
    // whole-pass failure merges NOTHING, so every traffic cell for that pass is
    // blank rather than stale. Both look like "no traffic" in a table, and
    // before this counter there was no way to tell them apart from outside.
    //
    // It also existed as a bare `catch (...) { tableOk = false; }` with no
    // counter and no report - a swallowed failure whose only symptom was an
    // empty table. Counting it is what lets a consumer say "the scan failed"
    // instead of leaving the reader to guess.
    //
    // HONESTLY: nothing in the gates exercises the increment. ScanHandles can
    // only throw std::bad_alloc from the queue's push_back, so on any machine
    // with memory this stays 0. It is bookkeeping for a path that is supposed
    // to be unreachable, and the counters around it only assert that it starts
    // at zero and never decreases - NOT that a failure is counted. Do not read
    // those checks as coverage of the increment.
    unsigned ScanFailureCount() const;

    // ---- what the scan could not measure, and said so ----

    // How many DISTINCT sockets this process has given up on because
    // SIO_TCP_INFO did not return.
    //
    // This is the exact-reporting half, and it exists so a consumer can
    // tell the two things that look identical in a cell: a connection that
    // moved zero bytes, and a connection that was never measured. Previously
    // the tool had no way to express the second, so a partial scan was
    // indistinguishable from an idle one.
    unsigned UnreadableCount() const;

    // Forget sockets whose SIO_TCP_INFO did not return, so no later pass pays
    // for them again. See stalled_.
    void RememberStalled(const std::vector<ProbeTarget>& stalled);

    // Best-effort settle for a process that is about to exit, so the CLI does
    // not linger behind a thread the kernel is holding.
    //
    // EXIT CONTRACT. Scans run DETACHED, so a `list --traffic` that found a
    // socket whose SIO_TCP_INFO never returns leaves a thread still inside the
    // kernel at exit - and a detached thread keeps the whole process alive, so
    // the command printed its rows and then hung forever, leaking one process
    // per invocation. This waits out the remaining budget and reports whether
    // something is still running; the CLI then exits hard instead of returning
    // (main.cpp). Waits at most kScanTimeoutMs: a thread still stuck after that
    // is abandoned, and the sampler must be left allocated (see the destructor
    // note) because freeing memory a live thread is reading would be the crash
    // this design avoids. Returns true when every scan thread has finished.
    bool ShutdownScanForExit();

    // Upper bound on sockets tracked per PID. Overflow is retired into
    // the PID total (never discarded), so this only bounds memory, not
    // accuracy of the running total. Without it a process that churns
    // through handles grew its map without limit.
    static const size_t kMaxLiveSocketsPerPid = 512;

    // Upper bound on remembered-stalled sockets. Beyond this the set is
    // cleared wholesale rather than grown: a machine with more than this
    // many uncooperative sockets is pathological, and an unbounded set on a
    // long-running GUI session is its own slow leak.
    static const size_t kStalledCap = 4096;

private:
    struct LiveSock {
        ULONGLONG in = 0;
        ULONGLONG out = 0;
        ULONGLONG ageMs = 0;              // kernel-reported, 0 = unknown
        std::wstring localAddress;
        UINT localPort = 0;
        std::wstring remoteAddress;
        UINT remotePort = 0;
        // In MILLISECONDS - see the TcpInfoExtras comment in the .cpp for
        // why the conversion happens at the read boundary rather than here.
        unsigned rttMs = 0;
        unsigned minRttMs = 0;
        ULONGLONG cwnd = 0;
        ULONGLONG retransBytes = 0;
        bool rttKnown = false;
        bool cwndKnown = false;
        bool retransKnown = false;
        bool timestamps = false;
        bool timestampsKnown = false;
    };

    // All state one scan pass touches. Deliberately a per-pass value, not a
    // member, and owned by a heap allocation rather than a local: when a scan
    // is abandoned in the kernel its worker threads are still alive and still
    // hold a pointer to this, so a second pass must not share a buffer, a type
    // set or a work queue with it. Sharing the reused handle-table buffer
    // between two live passes would be a data race on megabytes.
    struct ScanScratch {
        std::vector<BYTE> enumBuf;
        std::unordered_set<USHORT> socketTypes;
        bool typesKnown = false;
        // Which pass this is. A scan that timed out keeps its workers alive and
        // is superseded by the next one, so the late pass must be able to
        // recognise that it is no longer current and not touch the shared
        // totals. See the merge in Sample().
        unsigned generation = 0;

        // The PIDs this pass was asked about, kept here so the worker pool can
        // be started without threading a reference through every frame.
        std::vector<DWORD> pids;

        // ---- the work queue ----
        // The handles worth reading, decided WITHOUT issuing an ioctl. Walking
        // the handle table is pure bookkeeping and cannot block; it is the
        // SIO_TCP_INFO behind each entry that can. Separating the two is what
        // lets the reads be farmed out to workers - see kProbeWorkers.
        std::vector<ProbeTarget> queue;
        // Hands each worker a distinct index, never repeating one. That is the
        // whole mutual exclusion: no two workers can hold the same slot.
        std::atomic<size_t> cursor{0};
        // 2 = this target is finished. Compared against `cursor` to decide
        // whether the pass completed: if the cursor ran past the end and
        // every slot is 2, it did; otherwise the slots past the cursor are the
        // sockets whose call has not returned.
        std::atomic<size_t> finished{0};
        // Workers spawned BY THIS PASS, counted separately from the sampler's
        // liveThreads_, which is a process-wide total across every pass.
        // Teardown of THIS scratch may only wait on THIS pass's workers: a
        // pass whose own workers have all exited must not block on one an
        // earlier pass left wedged inside SIO_TCP_INFO - those belong to a
        // scratch that pass already abandoned and they can still run for
        // minutes (measured 28 s and >90 s). Counting the global total
        // here is what made `list --traffic --watch ... --count N` hang for
        // ever: pass 1 wedges its pool, pass 2 has nothing left to read, and
        // pass 2 then waits on pass 1's stuck threads with no deadline.
        std::atomic<int> liveInPass{0};
        // Workers publish here rather than into Sample()'s locals, and take
        // dataLock to do it: a worker that outlives the budget may still push
        // while the scan thread reads.
        std::vector<SocketSample> observed;
        std::set<DWORD> opened;
        // pid -> source process handle, cached. Restoring this after the
        // worker split is not a micro-optimisation: the walk reads 391 socket
        // handles spread over 48 PIDs on this machine, and without the cache
        // that is 391 OpenProcess calls per pass instead of 48. Measured at
        // ~4.6 s per one-shot `list --traffic` with the cache dropped against
        // ~0.6 s with it, on a machine where every healthy ioctl is ~0 ms -
        // the pass was spending all its time asking for process handles, not
        // reading sockets.
        //
        // Shared, so it needs dataLock like `observed` does. The entries are
        // owned by the scratch and closed by nobody, deliberately: a worker
        // that outlives the pass must not find a handle closed under it. They
        // are released by CloseCachedSources() once every worker has finished.
        std::map<DWORD, HANDLE> sources;
        std::mutex dataLock;
        // Workers each learn socket type indices independently; merging them
        // needs a lock. Contention is nil - a handful of indices per pass -
        // but the access is still shared mutable state.
        std::mutex typesLock;
        // Set by the scan thread when every target is done; the workers poll
        // nothing, the thread polls this.
        std::atomic<bool> done{false};

        void Finish() {
            finished.fetch_add(1, std::memory_order_acq_rel);
        }
    };

    // Release the per-PID source handles a completed pass opened. Only safe
    // once every worker has returned - which is why Sample calls it on exactly
    // the branch where the scratch is about to be deleted anyway.
    static void CloseCachedSources(ScanScratch& scratch);

    // Pull the next target, or nullptr when the queue is drained.
    ProbeTarget* NextTarget(ScanScratch& scratch);

    // Read one target and publish it. Runs on a worker thread; the ioctl
    // inside may never return, which is why this is never called from the
    // thread the refresh worker is waiting on.
    void ProbeTargetOne(const ProbeTarget& t, ScanScratch& scratch);

    void ScanHandles(ScanScratch& scratch);

private:
    // Fold ONE socket's reading into the totals the moment it is read, rather
    // than accumulating a pass and merging it at the end.
    //
    // WHY. A single socket whose SIO_TCP_INFO never returns blocks the pass at
    // that point, and the pass only merged at its end - so one uncooperative
    // socket cost EVERY socket on the machine its age and byte counters, and
    // the machine reported `totals=0 ages=0` for all of them. Measured on this
    // box with 53 PIDs. Per-socket folding means the sockets read before the
    // hang keep their data, and only the hanging one is lost.
    //
    // Takes stateLock_ itself, so the caller must NOT already hold it. Closing
    // a socket is NOT detected this way: that still needs the end-of-pass view
    // of which handles went missing, so a pass that completes still merges
    // normally and retires them.
    void PublishOne(const SocketSample& s);

    // Discover the kernel's socket object-type indices from OUR OWN process
    // (see ScanHandles). Without this the first pass has an empty type set
    // and the type filter cannot reject anything. Returns the index set.
    static std::unordered_set<USHORT> LearnOwnSocketTypes();

    std::map<DWORD, std::map<ULONG_PTR, LiveSock>> live_;  // pid -> socket
    std::map<DWORD, PidTraffic> retired_;                  // pid -> closed
    // Sockets whose SIO_TCP_INFO did not return, ever. See kProbeWorkers for
    // the measurement that motivates this and RememberStalled() for the
    // consequence: without it, one uncooperative socket leaks a wedged worker
    // thread on EVERY refresh, which is unbounded and would eventually exhaust
    // the process's thread quota on a machine that stays up for days.
    //
    // Keyed by (pid, handle) and never cleared: a socket that stalled once
    // will stall again, and the handle value is only reused once the socket
    // closes - at which point the entry is stale but harmless, because the
    // worst a stale entry can do is skip a handle that has since become a
    // different, working socket. Bounding memory matters more than that
    // hypothetical, and kStalledCap keeps even that bounded.
    std::set<std::pair<DWORD, ULONG_PTR>> stalled_;
    // Seed for every new pass, discovered once in the constructor. Copied
    // into each ScanScratch so a pass never shares it with another.
    std::unordered_set<USHORT> socketTypes_;
    bool supported_ = false;

    // Guards live_/retired_/the in-flight flags. A scan runs on a helper
    // thread; its MergeSample and this class's Totals both take this.
    mutable std::mutex stateLock_;
    bool scanInFlight_ = false;   // a helper thread is currently scanning
    // Bumped every time a pass starts. A superseded pass compares against it
    // and drops its result instead of merging it.
    unsigned generation_ = 0;
    // A scan that overran its budget is abandoned mid-kernel. A new one is
    // allowed immediately; the abandoned thread holds only its own scratch.
    volatile bool scanAbandoned_ = false;
    // Scan THREADS that have been started and not yet returned. Distinct from
    // scanInFlight_, which a timeout clears so the next pass may start: the
    // thread itself is still running and still keeps the process alive.
    std::atomic<int> liveThreads_{0};
    // Number of scans dropped by the timeout, for the status line. Surfaced
    // so a machine where this fires is visible rather than quietly showing
    // stale traffic.
    mutable std::atomic<unsigned> timeouts_{0};
    // Passes whose handle-table read threw. See ScanFailureCount() for why this
    // is separate from timeouts_ and what it does and does not prove.
    mutable std::atomic<unsigned> scanFailures_{0};

    // Owns ONE pass's scratch, and frees it only when no worker of that
    // pass can still be reading it.
    //
    // WHY NOT A PLAIN unique_ptr, which is the obvious thing and would be
    // WRONG here. A plain unique_ptr frees on every exit including a throw, and
    // a worker wedged inside SIO_TCP_INFO holds this pointer - the same reason
    // the sampler itself is deliberately never freed (see ShutdownScanForExit).
    // An exception unwinding while a worker is still live would therefore turn a
    // leak into exactly the use-after-free the design exists to avoid.
    //
    // So the test lives in the destructor, where it is evaluated on the normal
    // path AND on an unwind alike, which is the property the raw pair did not
    // have: `new ScanScratch()` ... `delete scratch` leaked unconditionally if
    // anything in between threw - including the merge, which allocates - and it
    // leaked even when every worker HAD finished and the delete would have been
    // safe. Now the leak happens when it is required and nowhere else.
    class ScratchOwner {
    public:
        explicit ScratchOwner(ScanScratch* s) : s_(s) {}
        ~ScratchOwner() {
            if (s_ == nullptr) return;
            if (s_->liveInPass.load(std::memory_order_acquire) == 0) {
                CloseCachedSources(*s_);
                delete s_;
            }
            // Otherwise a worker is still inside the kernel holding s_. Leaking
            // is the ONLY safe action and is deliberate. Counted by Sample(),
            // which is the only place that knows a pass was abandoned.
        }
        ScratchOwner(const ScratchOwner&) = delete;
        ScratchOwner& operator=(const ScratchOwner&) = delete;
        ScanScratch* operator->() const { return s_; }
        ScanScratch* get() const { return s_; }
        // Give up ownership without freeing. Only for the abandon path, where
        // the free is being skipped DELIBERATELY rather than skipped by an
        // exception - the one case that is a decision rather than a mistake.
        ScanScratch* release() {
            ScanScratch* p = s_;
            s_ = nullptr;
            return p;
        }

    private:
        ScanScratch* s_;
    };
};

}  // namespace wintcp
